//! Receiver-driven BDX serving over an authenticated Matter exchange.
//!
//! The source is read one negotiated block at a time. Keep image lookup and
//! authorization policy in the caller, then pass the selected source here.

use core::future::Future;
use core::pin::Pin;

use embassy_futures::select::{select, Either};

pub use matter_bdx::BdxStatusCode;
use matter_bdx::{
    BdxError as CodecError, BdxMessage, CounterMessage, MessageType, ReceiveAccept,
    TransferControl, TransferInit, BDX_VERSION,
};

use crate::error::Error;
use crate::sc::{GeneralCode, OpCode};
use crate::transport::exchange::{Exchange, MessageMeta};

/// Matter Protocol ID for Bulk Data Exchange.
pub const PROTO_ID_BDX: u16 = 0x0002;

/// A bounded, random-access image source used by [`serve`].
pub trait BlockSource {
    /// The source-specific read error.
    type Error;

    /// Return the image length in bytes.
    fn len(&self) -> u64;

    /// Fill the supplied block from `offset`. Implementations must fill the
    /// whole slice or return an error.
    fn read_at(&self, offset: u64, block: &mut [u8]) -> Result<(), Self::Error>;
}

/// Errors produced while serving a BDX transfer.
#[derive(Debug)]
pub enum ProviderError<E> {
    /// Matter transport or message error.
    Matter(Error),
    /// Image source read failed.
    Source(E),
    /// BDX body could not be decoded.
    Codec(CodecError),
    /// The exchange was not established with an authenticated CASE peer.
    UnauthenticatedPeer,
    /// The receiver cancelled the transfer by closing its Matter session.
    Cancelled,
    /// The peer sent a message that is invalid for this transfer state.
    UnexpectedMessage,
}

impl<E> From<Error> for ProviderError<E> {
    fn from(error: Error) -> Self {
        Self::Matter(error)
    }
}

/// Serve one receiver-driven BDX transfer over `exchange`.
///
/// `source` must already be selected and authorized for this exchange. The
/// exchange must use CASE; PASE and plaintext sessions are rejected. At most
/// one negotiated block is allocated at a time.
pub async fn serve<S: BlockSource>(
    exchange: &mut Exchange<'_>,
    source: &S,
    expected_designator: &[u8],
    max_block_size: u16,
) -> Result<(), ProviderError<S::Error>> {
    serve_with_cancel(
        exchange,
        source,
        expected_designator,
        max_block_size,
        core::future::pending::<()>(),
    )
    .await
}

/// Serve a BDX transfer and observe cancellation between Matter sends.
///
/// Reliable sends are allowed to finish before cancellation is handled. This
/// keeps their MRP retransmission state valid so the provider can send a BDX
/// StatusReport without dropping the surrounding CASE session.
pub async fn serve_with_cancel<S, F>(
    exchange: &mut Exchange<'_>,
    source: &S,
    expected_designator: &[u8],
    max_block_size: u16,
    cancellation: F,
) -> Result<(), ProviderError<S::Error>>
where
    S: BlockSource,
    F: Future<Output = ()>,
{
    let mut cancellation = core::pin::pin!(cancellation);
    if exchange.authenticated_peer_identity().is_err() {
        return Err(ProviderError::UnauthenticatedPeer);
    }

    let init = recv_bdx_or_cancel::<S::Error, F>(exchange, cancellation.as_mut()).await?;
    let BdxMessage::ReceiveInit(init) = init else {
        send_abort(exchange, BdxStatusCode::UnexpectedMessage).await?;
        return Err(ProviderError::UnexpectedMessage);
    };
    let length = source.len();
    if let Err(status) = validate_init(&init, expected_designator, max_block_size, length) {
        send_abort(exchange, status).await?;
        return Err(ProviderError::UnexpectedMessage);
    }

    let block_size = init.max_block_size.min(max_block_size);
    let accept = ReceiveAccept {
        control: TransferControl::RECEIVER_DRIVE,
        version: BDX_VERSION,
        max_block_size: block_size,
        start_offset: 0,
        length,
        metadata: Vec::new(),
    };
    send_bdx(exchange, MessageType::ReceiveAccept, &accept.encode()).await?;

    let mut offset = 0u64;
    let mut next_counter = 0u32;
    let mut last_response: Option<(u32, MessageType, Vec<u8>)> = None;
    loop {
        match recv_bdx_or_cancel::<S::Error, F>(exchange, cancellation.as_mut()).await? {
            BdxMessage::BlockQuery(query)
                if last_response.as_ref().is_some_and(|(counter, _, _)| {
                    is_duplicate_query(query.block_counter, next_counter, *counter)
                }) =>
            {
                if let Some((_, message_type, payload)) = last_response.as_ref() {
                    send_bdx(exchange, *message_type, payload).await?;
                }
            }
            BdxMessage::BlockQuery(query) if query.block_counter == next_counter => {
                let Some(block_len) = next_block_len(offset, length, block_size) else {
                    send_abort(exchange, BdxStatusCode::UnexpectedMessage).await?;
                    return Err(ProviderError::UnexpectedMessage);
                };
                let mut body = vec![0; 4 + block_len];
                body[..4].copy_from_slice(&next_counter.to_le_bytes());
                if let Err(error) = source.read_at(offset, &mut body[4..]) {
                    send_abort(exchange, BdxStatusCode::Unknown).await?;
                    return Err(ProviderError::Source(error));
                }
                offset += block_len as u64;
                let eof = offset == length;
                let message_type = if eof {
                    MessageType::BlockEof
                } else {
                    MessageType::Block
                };
                send_bdx(exchange, message_type, &body).await?;
                last_response = Some((next_counter, message_type, body));
                if eof {
                    break;
                }
                let Some(counter) = next_counter.checked_add(1) else {
                    send_abort(exchange, BdxStatusCode::BadBlockCounter).await?;
                    return Err(ProviderError::UnexpectedMessage);
                };
                next_counter = counter;
            }
            BdxMessage::BlockQuery(_) => {
                send_abort(exchange, BdxStatusCode::BadBlockCounter).await?;
                return Err(ProviderError::UnexpectedMessage);
            }
            _ => {
                send_abort(exchange, BdxStatusCode::UnexpectedMessage).await?;
                return Err(ProviderError::UnexpectedMessage);
            }
        }
    }

    let Some((last_counter, final_type, final_payload)) = last_response else {
        return Err(ProviderError::UnexpectedMessage);
    };
    loop {
        match recv_bdx_or_cancel::<S::Error, F>(exchange, cancellation.as_mut()).await? {
            BdxMessage::BlockQuery(query) if query.block_counter == last_counter => {
                send_bdx(exchange, final_type, &final_payload).await?;
            }
            BdxMessage::BlockAckEof(CounterMessage { block_counter })
                if block_counter == last_counter =>
            {
                return Ok(())
            }
            BdxMessage::BlockAckEof(_) => {
                send_abort(exchange, BdxStatusCode::BadBlockCounter).await?;
                return Err(ProviderError::UnexpectedMessage);
            }
            _ => {
                send_abort(exchange, BdxStatusCode::UnexpectedMessage).await?;
                return Err(ProviderError::UnexpectedMessage);
            }
        }
    }
}

fn validate_init(
    init: &TransferInit,
    expected_designator: &[u8],
    max_block_size: u16,
    image_length: u64,
) -> Result<(), BdxStatusCode> {
    if !init.control.contains(TransferControl::RECEIVER_DRIVE)
        || init.control.contains(TransferControl::SENDER_DRIVE)
        || init.version != BDX_VERSION
        || init.max_block_size == 0
        || max_block_size == 0
        || init.start_offset != 0
        || !designator_matches(&init.file_designator, expected_designator)
    {
        return Err(BdxStatusCode::TransferMethodNotSupported);
    }
    if init.max_length != 0 && image_length > init.max_length {
        return Err(BdxStatusCode::LengthTooLarge);
    }
    Ok(())
}

fn designator_matches(actual: &[u8], expected: &[u8]) -> bool {
    actual == expected
}

fn is_duplicate_query(query_counter: u32, next_counter: u32, last_counter: u32) -> bool {
    query_counter == last_counter && query_counter < next_counter
}

fn next_block_len(offset: u64, length: u64, block_size: u16) -> Option<usize> {
    if block_size == 0 || offset > length {
        return None;
    }
    Some((length - offset).min(u64::from(block_size)) as usize)
}

async fn recv_bdx<E>(exchange: &mut Exchange<'_>) -> Result<BdxMessage, ProviderError<E>> {
    let rx = exchange.recv().await?;
    decode_bdx_message(exchange, rx).await
}

async fn recv_bdx_or_cancel<E, F>(
    exchange: &mut Exchange<'_>,
    cancellation: Pin<&mut F>,
) -> Result<BdxMessage, ProviderError<E>>
where
    F: Future<Output = ()>,
{
    let rx = match select(exchange.recv(), cancellation).await {
        Either::First(result) => result?,
        Either::Second(()) => {
            send_abort(exchange, BdxStatusCode::Unknown).await?;
            return Err(ProviderError::Cancelled);
        }
    };
    decode_bdx_message(exchange, rx).await
}

async fn decode_bdx_message<E>(
    exchange: &mut Exchange<'_>,
    rx: crate::transport::exchange::RxMessage<'_>,
) -> Result<BdxMessage, ProviderError<E>> {
    let meta = rx.meta();
    if meta.proto_id == crate::sc::PROTO_ID_SECURE_CHANNEL
        && meta.proto_opcode == OpCode::StatusReport as u8
    {
        drop(rx);
        return Err(ProviderError::Cancelled);
    }
    if meta.proto_id != PROTO_ID_BDX {
        drop(rx);
        send_abort(exchange, BdxStatusCode::UnexpectedMessage).await?;
        return Err(ProviderError::UnexpectedMessage);
    }
    let Some(message_type) = MessageType::from_u8(meta.proto_opcode) else {
        drop(rx);
        send_abort(exchange, BdxStatusCode::UnexpectedMessage).await?;
        return Err(ProviderError::UnexpectedMessage);
    };
    match BdxMessage::decode(message_type, rx.payload()) {
        Ok(message) => Ok(message),
        Err(error) => {
            drop(rx);
            send_abort(exchange, BdxStatusCode::BadMessageContents).await?;
            Err(ProviderError::Codec(error))
        }
    }
}

async fn send_bdx<E>(
    exchange: &mut Exchange<'_>,
    message_type: MessageType,
    payload: &[u8],
) -> Result<(), ProviderError<E>> {
    exchange
        .send(
            MessageMeta::new(PROTO_ID_BDX, message_type.to_u8(), true),
            payload,
        )
        .await?;
    Ok(())
}

async fn send_abort<E>(
    exchange: &mut Exchange<'_>,
    status: BdxStatusCode,
) -> Result<(), ProviderError<E>> {
    let payload = status_report_payload(status);
    exchange.send(OpCode::StatusReport.meta(), &payload).await?;
    Ok(())
}

/// Abort an active BDX exchange with a protocol StatusReport.
pub async fn abort(exchange: &mut Exchange<'_>, status: BdxStatusCode) -> Result<(), Error> {
    let payload = status_report_payload(status);
    exchange.send(OpCode::StatusReport.meta(), &payload).await
}

fn status_report_payload(status: BdxStatusCode) -> [u8; 8] {
    let mut payload = [0; 8];
    payload[..2].copy_from_slice(&(GeneralCode::Failure as u16).to_le_bytes());
    payload[2..6].copy_from_slice(&u32::from(PROTO_ID_BDX).to_le_bytes());
    payload[6..].copy_from_slice(&status.to_u16().to_le_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use super::{
        designator_matches, is_duplicate_query, next_block_len, status_report_payload,
        validate_init,
    };
    use matter_bdx::{BdxStatusCode, TransferControl, TransferInit, BDX_VERSION};

    #[test]
    fn receive_init_requires_exact_expected_designator() {
        assert!(designator_matches(b"firmware.bin", b"firmware.bin"));
        assert!(!designator_matches(b"firmware.bin", b"firmware.bin\0"));
        assert!(!designator_matches(b"firmware.bin", b"Firmware.bin"));
    }

    #[test]
    fn repeated_block_query_retransmits_only_the_last_sent_block() {
        assert!(is_duplicate_query(2, 3, 2));
        assert!(!is_duplicate_query(3, 3, 2));
        assert!(!is_duplicate_query(1, 3, 2));
    }

    #[test]
    fn abort_is_encoded_as_a_failure_status_report_for_bdx() {
        let payload = status_report_payload(BdxStatusCode::BadBlockCounter);
        assert_eq!(&payload[..2], &1u16.to_le_bytes());
        assert_eq!(
            &payload[2..6],
            &u32::from(super::PROTO_ID_BDX).to_le_bytes()
        );
        assert_eq!(
            &payload[6..],
            &BdxStatusCode::BadBlockCounter.to_u16().to_le_bytes()
        );
    }

    #[test]
    fn block_length_is_bounded_by_remaining_bytes_and_negotiated_size() {
        assert_eq!(next_block_len(0, 11, 4), Some(4));
        assert_eq!(next_block_len(8, 11, 4), Some(3));
        assert_eq!(next_block_len(11, 11, 4), Some(0));
        assert_eq!(next_block_len(12, 11, 4), None);
        assert_eq!(next_block_len(0, 11, 0), None);
        assert_eq!(next_block_len(0, 0, 4), Some(0));
    }

    #[test]
    fn receive_init_must_be_receiver_driven_without_resumption() {
        let valid = TransferInit {
            control: TransferControl::RECEIVER_DRIVE,
            version: BDX_VERSION,
            max_block_size: 64,
            start_offset: 0,
            max_length: 0,
            file_designator: Vec::new(),
            metadata: Vec::new(),
        };
        assert_eq!(validate_init(&valid, b"", 1024, 10), Ok(()));

        let mut named = valid.clone();
        named.file_designator = b"firmware.bin".to_vec();
        assert_eq!(validate_init(&named, b"firmware.bin", 1024, 10), Ok(()));
        assert_eq!(
            validate_init(&named, b"other.bin", 1024, 10),
            Err(BdxStatusCode::TransferMethodNotSupported)
        );

        let mut invalid = valid.clone();
        invalid.control = TransferControl::SENDER_DRIVE;
        assert_eq!(
            validate_init(&invalid, b"", 1024, 10),
            Err(BdxStatusCode::TransferMethodNotSupported)
        );

        let mut invalid = valid;
        invalid.start_offset = 1;
        assert_eq!(
            validate_init(&invalid, b"", 1024, 10),
            Err(BdxStatusCode::TransferMethodNotSupported)
        );
    }
}
