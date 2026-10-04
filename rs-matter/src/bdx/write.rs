/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

//! The *send* side of the BDX streaming engine: the [`BdxWriter`] handle and the
//! two ways to obtain one - [`BdxUploadInitiator`] (initiate an upload) and
//! [`BdxDownloadResponder`] (respond to a peer's download).

use super::nego::*;
use super::*;

/// The number of source bytes this sender intends to transfer.
///
/// A definite extent includes zero: a known-empty source sends one empty EOF.
/// On an initiating wire message, zero is encoded as indefinite; the sender
/// retains its local empty-source intent independently of that wire convention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TransferExtent {
    /// The source determines its end while streaming.
    Indefinite,
    /// Exactly this many bytes, excluding any start offset.
    Definite(u64),
}

impl TransferExtent {
    pub(super) const fn length(self) -> Option<u64> {
        match self {
            Self::Indefinite => None,
            Self::Definite(length) => Some(length),
        }
    }
}

/// A writer over a BDX transfer - the Sender side.
///
/// Obtained from [`Exchange::upload`](BdxUploadInitiator::upload) on the initiating side, or
/// from [`BdxDownloadResponder::reply`] on the responding side. [`write`](Self::write)
/// stages and sends the data, driving the protocol as needed;
/// [`finish`](Self::finish) flushes the final block and completes the transfer.
/// It also implements [`embedded_io_async::Write`] (delegating to the inherent
/// `write`).
///
/// The caller supplies the staging buffer `buf`, which doubles as the upper bound
/// on the block size (so there is no hidden, MCU-unfriendly internal allocation).
/// It must be non-empty.
pub struct BdxWriter<'a, 'b> {
    exchange: Exchange<'a>,
    drive: Drive,
    /// The caller-provided staging buffer. At most `max_block_size` of its bytes
    /// hold the block currently being assembled.
    buf: &'b mut [u8],
    max_block_size: usize,
    /// Driver: the counter for the next block to send. Follower: the expected
    /// counter of the next `BlockQuery`.
    counter: u32,
    block_len: usize,
    emitted: u64,
    extent: TransferExtent,
    state: WriterState,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WriterState {
    Negotiating { max_length: Option<u64> },
    Accepting,
    Active,
    Sending,
    Finishing,
    Finished,
    Cancelled,
}

impl<'a, 'b> BdxWriter<'a, 'b> {
    fn new(
        exchange: Exchange<'a>,
        drive: Drive,
        buf: &'b mut [u8],
        max_block_size: u16,
        extent: TransferExtent,
        state: WriterState,
    ) -> Self {
        // We can never stage more than the buffer holds; negotiation already
        // bounded `max_block_size`, but clamp defensively.
        let max_block_size = (max_block_size as usize).min(buf.len());

        Self {
            exchange,
            drive,
            buf,
            max_block_size,
            counter: 0,
            block_len: 0,
            emitted: 0,
            extent,
            state,
        }
    }

    /// Complete a prepared download negotiation by sending `ReceiveAccept`.
    ///
    /// If this future is dropped while the acceptance message is in flight, the
    /// writer remains in the accepting state and can be cancelled. Acceptance
    /// cannot be retried after it has started.
    pub async fn accept(&mut self, extent: TransferExtent) -> Result<(), Error> {
        let WriterState::Negotiating { max_length } = self.state else {
            return Err(ErrorCode::Invalid.into());
        };
        if max_length
            .is_some_and(|max| !matches!(extent, TransferExtent::Definite(length) if length <= max))
        {
            return Err(ErrorCode::Invalid.into());
        }

        self.extent = extent;
        self.state = WriterState::Accepting;
        send_accept(
            &mut self.exchange,
            true,
            TransferControl::select(self.drive == Drive::Driver),
            self.max_block_size as u16,
            extent.length(),
        )
        .await?;

        self.state = WriterState::Active;
        Ok(())
    }

    /// Cancel an active transfer and report `TransferFailedUnknownError` to the peer.
    ///
    /// This is an async operation because BDX cancellation is a wire message, so it
    /// must be awaited explicitly. If a pending write future is no longer needed,
    /// drop that future and call `cancel` on the writer it borrowed.
    pub async fn cancel(&mut self) -> Result<(), Error> {
        match self.state {
            WriterState::Cancelled | WriterState::Finished => return Ok(()),
            WriterState::Negotiating { .. }
            | WriterState::Accepting
            | WriterState::Active
            | WriterState::Sending
            | WriterState::Finishing => {}
        }

        // If sending the report fails or the future is dropped while awaiting it,
        // subsequent writer calls must not emit any more BDX blocks.
        self.state = WriterState::Cancelled;

        // A previous Block may still be awaiting its MRP acknowledgement after
        // the caller dropped `commit`. Drain that send before starting the
        // StatusReport transaction, which cannot share the exchange's MRP slot.
        self.exchange.wait_for_retransmission_ack().await?;

        super::nego::send_abort_report_draining_query(
            &mut self.exchange,
            BdxStatus::TransferFailedUnknownError,
        )
        .await?;
        Ok(())
    }

    /// Stage and send `data`, returning the number of bytes accepted (`< data.len()`
    /// only when the current block fills; call again with the remainder). A full
    /// block stays staged until more data arrives or the transfer is finished, so
    /// the final full block can be sent as `BlockEof`.
    ///
    /// This is also the [`embedded_io_async::Write`] implementation; the inherent
    /// method is kept so callers need not import the trait.
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, Error> {
        if self.state != WriterState::Active {
            return Err(ErrorCode::Invalid.into());
        }

        if data.is_empty() {
            return Ok(0);
        }

        // Validate the whole offered slice before copying or sending a staged
        // block. A rejected overshoot must leave previously accepted bytes intact.
        self.block_end(
            self.block_len
                .checked_add(data.len())
                .ok_or(ErrorCode::Invalid)?,
        )?;

        if self.block_len == self.max_block_size {
            // The nonempty continuation proves an indefinite transfer exceeds
            // one block; the preceding full block cannot be its sole EOF.
            self.send_block(self.block_len, false).await?;
        }

        let space = self.max_block_size - self.block_len;
        let n = space.min(data.len());
        self.buf[self.block_len..self.block_len + n].copy_from_slice(&data[..n]);
        self.block_len += n;

        Ok(n)
    }

    /// The largest block this writer will send (and the length of the buffer
    /// returned by [`block_buf`](Self::block_buf)).
    pub fn max_block_size(&self) -> usize {
        self.max_block_size
    }

    /// The writer's own staging buffer (exactly [`max_block_size`](Self::max_block_size)
    /// bytes), to be filled in place and then sent with [`commit`](Self::commit).
    ///
    /// This is the zero-extra-buffer alternative to [`write`](Self::write): a
    /// caller streaming from another source (a flash region, a socket) can read
    /// straight into this slice instead of into its own buffer and copying. Do not
    /// interleave it with [`write`](Self::write), which stages into the same space.
    /// Access fails while accepted write bytes are staged or an operation is in
    /// flight, preventing those bytes from being silently replaced.
    pub fn block_buf(&mut self) -> Result<&mut [u8], Error> {
        if self.state != WriterState::Active || self.block_len != 0 {
            return Err(ErrorCode::Invalid.into());
        }

        Ok(&mut self.buf[..self.max_block_size])
    }

    /// Send `len` bytes - previously written into [`block_buf`](Self::block_buf) -
    /// as one block. At the declared extent this sends `BlockEof` and waits for
    /// its acknowledgement. `len` must not exceed the buffer or declared extent.
    /// An indefinite first block is ambiguous; use a definite extent, or stream
    /// through [`write`](Self::write) and explicitly finish its last block.
    pub async fn commit(&mut self, len: usize) -> Result<(), Error> {
        if self.state != WriterState::Active || self.block_len != 0 {
            return Err(ErrorCode::Invalid.into());
        }

        if self.extent == TransferExtent::Indefinite && self.emitted == 0 {
            return Err(ErrorCode::Invalid.into());
        }

        self.send_block(len, false).await
    }

    /// Flush the final (possibly empty) block and complete the transfer.
    ///
    /// This is idempotent after a final commit/flush. A declared extent must be
    /// satisfied exactly. The borrowed writer remains available for cancellation
    /// if this future is dropped or the source ends prematurely.
    pub async fn finish(&mut self) -> Result<(), Error> {
        let len = self.block_len;
        self.finish_with_len(len).await
    }

    /// Send `len` bytes from [`block_buf`](Self::block_buf) as the final
    /// `BlockEof` and complete the transfer. `len` must not exceed
    /// [`max_block_size`](Self::max_block_size). If this future is dropped while
    /// waiting for the peer's final acknowledgement, call [`cancel`](Self::cancel)
    /// to report failure and make the writer terminal.
    pub async fn finish_with_len(&mut self, len: usize) -> Result<(), Error> {
        if self.state == WriterState::Finished && len == 0 {
            return Ok(());
        }
        if self.block_len != 0 && len != self.block_len {
            return Err(ErrorCode::Invalid.into());
        }

        self.send_block(len, true).await
    }

    /// Deliver all staged bytes. Reaching a definite extent sends the final EOF;
    /// after its acknowledgement later flush/finish calls emit nothing.
    ///
    /// A nonempty first flush is rejected if the extent is indefinite or the
    /// declared transfer fits in one block but is not yet complete. Successful
    /// flush cannot retain buffered bytes or split a one-block transfer into a
    /// non-final block and an empty EOF. Rejection preserves the staged bytes.
    pub async fn flush(&mut self) -> Result<(), Error> {
        if self.state == WriterState::Finished {
            return Ok(());
        }
        if self.state != WriterState::Active {
            return Err(ErrorCode::Invalid.into());
        }
        if self.block_len == 0 && self.extent != TransferExtent::Definite(0) {
            return Ok(());
        }
        if self.block_len != 0 && self.extent == TransferExtent::Indefinite && self.emitted == 0 {
            return Err(ErrorCode::Invalid.into());
        }

        self.send_block(self.block_len, false).await
    }

    fn block_end(&self, len: usize) -> Result<u64, Error> {
        let len = u64::try_from(len).map_err(|_| ErrorCode::Invalid)?;
        let end = self.emitted.checked_add(len).ok_or(ErrorCode::Invalid)?;
        if matches!(self.extent, TransferExtent::Definite(length) if end > length) {
            return Err(ErrorCode::Invalid.into());
        }
        Ok(end)
    }

    /// Send the staged bytes as one block, driving/awaiting acknowledgement per
    /// the negotiated drive mode.
    async fn send_block(&mut self, len: usize, finish: bool) -> Result<(), Error> {
        if self.state != WriterState::Active || len > self.max_block_size {
            return Err(ErrorCode::Invalid.into());
        }

        let end = self.block_end(len)?;
        let is_eof = match self.extent {
            TransferExtent::Indefinite => finish,
            TransferExtent::Definite(length) => {
                if finish && end != length {
                    return Err(ErrorCode::Invalid.into());
                }
                if end != length && length <= self.max_block_size as u64 {
                    // The entire transfer must fit in its sole data-bearing EOF.
                    return Err(ErrorCode::Invalid.into());
                }
                end == length
            }
        };
        if len == 0 && !is_eof {
            return Err(ErrorCode::Invalid.into());
        }

        self.block_len = len;
        // Set the phase before *any* await. Dropping a query/send/ACK wait must
        // leave cancellation as the only operation that can use this exchange.
        self.state = if is_eof {
            WriterState::Finishing
        } else {
            WriterState::Sending
        };
        let counter = self.counter;

        if matches!(self.drive, Drive::Follower) {
            // Receiver-driven: wait to be asked for this block.
            self.recv_control(OpCode::BlockQuery, counter).await?;
        }

        let opcode = if is_eof {
            OpCode::BlockEof
        } else {
            OpCode::Block
        };
        {
            let data = &self.buf[..len];
            self.exchange
                .send_with(|_, wb| {
                    Block {
                        block_counter: counter,
                        data,
                    }
                    .write(wb)?;
                    Ok(Some(opcode.into()))
                })
                .await?;
        }
        if matches!(self.drive, Drive::Driver) {
            let ack = if is_eof {
                OpCode::BlockAckEof
            } else {
                OpCode::BlockAck
            };
            self.recv_control(ack, counter).await?;
        } else if is_eof {
            // Receiver-driven: the receiver acknowledges the final block.
            self.recv_control(OpCode::BlockAckEof, counter).await?;
        }

        if is_eof {
            self.exchange.acknowledge().await?;
        }

        self.emitted = end;
        self.block_len = 0;
        self.counter = self.counter.wrapping_add(1);
        self.state = if is_eof {
            WriterState::Finished
        } else {
            WriterState::Active
        };

        Ok(())
    }

    /// Await a specific counter-only control message and validate its counter.
    async fn recv_control(&mut self, expected: OpCode, expected_counter: u32) -> Result<(), Error> {
        enum Outcome {
            Ok,
            BadCounter,
            Unexpected,
            Aborted(Error),
        }

        self.exchange.recv_fetch().await?;
        let meta = self.exchange.rx()?.meta();
        let outcome = {
            let payload = self.exchange.rx()?.payload();
            match classify(&meta, payload) {
                Ok(op) if op == expected => {
                    if BlockQuery::parse(payload)?.block_counter == expected_counter {
                        Outcome::Ok
                    } else {
                        Outcome::BadCounter
                    }
                }
                Ok(_) => Outcome::Unexpected,
                Err(e) => Outcome::Aborted(e),
            }
        };

        self.exchange.rx_done()?;

        match outcome {
            Outcome::Ok => Ok(()),
            Outcome::BadCounter => {
                super::nego::abort(&mut self.exchange, BdxStatus::BadBlockCounter).await
            }
            Outcome::Unexpected => {
                super::nego::abort(&mut self.exchange, BdxStatus::UnexpectedMessage).await
            }
            Outcome::Aborted(e) => Err(e),
        }
    }
}

impl embedded_io_async::ErrorType for BdxWriter<'_, '_> {
    type Error = Error;
}

impl embedded_io_async::Write for BdxWriter<'_, '_> {
    async fn write(&mut self, data: &[u8]) -> Result<usize, Self::Error> {
        BdxWriter::write(self, data).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        BdxWriter::flush(self).await
    }
}

/// An extension trait for initiating a BDX *upload*: `upload` makes this node the
/// (typically driving) Sender and returns a [`BdxWriter`].
pub trait BdxUploadInitiator<'a> {
    /// Initiate a BDX upload of `file_designator`, negotiate the transfer, and
    /// return a writer ready to stream the data. `buf` is the (non-empty) staging
    /// buffer the writer assembles blocks in; its length bounds the block size.
    ///
    /// `offset` (when `Some` and non-zero) declares that the data written to the
    /// returned writer begins at that byte offset of the file - e.g. to resume an
    /// interrupted upload. The receiver may refuse with
    /// [`StartOffsetNotSupported`](BdxStatus::StartOffsetNotSupported); otherwise
    /// the caller is responsible for feeding only the bytes from `offset` onward.
    /// `extent` declares the remaining source bytes and determines final framing.
    async fn upload<'b>(
        self,
        buf: &'b mut [u8],
        file_designator: &[u8],
        offset: Option<u64>,
        extent: TransferExtent,
    ) -> Result<BdxWriter<'a, 'b>, Error>;
}

impl<'a> BdxUploadInitiator<'a> for Exchange<'a> {
    async fn upload<'b>(
        mut self,
        buf: &'b mut [u8],
        file_designator: &[u8],
        offset: Option<u64>,
        extent: TransferExtent,
    ) -> Result<BdxWriter<'a, 'b>, Error> {
        if buf.is_empty() {
            // An empty staging buffer would propose a max block size of 0 and yield
            // a writer that can never make progress; reject it up front.
            return Err(ErrorCode::Invalid.into());
        }

        // We can never send a block larger than our staging buffer or our TX buffer.
        let pmbs = buf.len().min(MAX_TX_BLOCK_SIZE as usize) as u16;
        send_init(
            &mut self,
            OpCode::SendInit,
            pmbs,
            offset,
            file_designator,
            extent.length(),
        )
        .await?;

        match recv_accept(&mut self, false).await? {
            // We are the sender: we drive iff sender-drive was selected.
            Some((tc, mbs, _length)) => {
                let drive = if tc.sender_drive {
                    Drive::Driver
                } else {
                    Drive::Follower
                };
                Ok(BdxWriter::new(
                    self,
                    drive,
                    buf,
                    mbs,
                    extent,
                    WriterState::Active,
                ))
            }
            None => super::nego::abort(&mut self, BdxStatus::TransferMethodNotSupported).await,
        }
    }
}

/// The responding side of a [`download`](super::BdxDownloadInitiator::download): a peer requested a
/// download (sent a `ReceiveInit`), so this node becomes the Sender. Inspect the
/// request via [`fd`](Self::fd), then [`reply`](Self::reply) to obtain a
/// [`BdxWriter`], or [`reject`](Self::reject) it.
pub struct BdxDownloadResponder<'a> {
    exchange: Exchange<'a>,
    transfer_control: TransferControl,
    max_block_size: u16,
    start_offset: u64,
    requested_length: Option<u64>,
}

impl<'a> BdxDownloadResponder<'a> {
    /// Receive the incoming `ReceiveInit` on `exchange`, holding it until
    /// [`reply`](Self::reply)/[`reject`](Self::reject).
    pub async fn accept(mut exchange: Exchange<'a>) -> Result<Self, Error> {
        let (transfer_control, max_block_size, requested_length, start_offset) =
            recv_init_hold(&mut exchange, OpCode::ReceiveInit).await?;

        Ok(Self {
            exchange,
            transfer_control,
            max_block_size,
            start_offset,
            requested_length,
        })
    }

    /// The file designator the initiator requested (borrowed from the held init).
    pub fn fd(&self) -> &[u8] {
        held_fd(&self.exchange)
    }

    /// The byte offset of the file from which the initiator asked the transfer to
    /// begin (`0` for a transfer from the start): the sender should start sending
    /// from here, and advertise the *remaining* length in [`reply`](Self::reply).
    /// Reject with [`StartOffsetNotSupported`](BdxStatus::StartOffsetNotSupported)
    /// if the offset cannot be honored.
    pub fn start_offset(&self) -> u64 {
        self.start_offset
    }

    /// The definite transfer length requested by the initiator, if any.
    ///
    /// A missing length or a requested length of zero represents an
    /// indefinite-length transfer.
    pub fn requested_length(&self) -> Option<u64> {
        self.requested_length
    }

    /// Prepare to accept the transfer, staging blocks in the caller-provided
    /// buffer `buf` (its length bounds the block size). The returned writer is
    /// still negotiating; call [`BdxWriter::accept`] to send `ReceiveAccept`.
    /// This split lets the caller cancel even while that message is in flight.
    pub async fn prepare_reply<'b>(
        mut self,
        buf: &'b mut [u8],
    ) -> Result<BdxWriter<'a, 'b>, Error> {
        if buf.is_empty() {
            // Our staging buffer is unusable, so we can never serve a block. Reject
            // the peer gracefully rather than panicking on the block-size clamp below.
            self.exchange.rx_done()?;
            return super::nego::abort(&mut self.exchange, BdxStatus::TransferFailedUnknownError)
                .await;
        }

        // Prefer to let the initiating receiver drive (its `BdxReader` is the
        // "driving receiver"); otherwise drive ourselves.
        let tc = self.transfer_control;
        let drive = if tc.receiver_drive {
            Drive::Follower
        } else if tc.sender_drive {
            Drive::Driver
        } else {
            self.exchange.rx_done()?;
            return super::nego::abort(&mut self.exchange, BdxStatus::TransferMethodNotSupported)
                .await;
        };

        // Cap the receiver's proposed block size by our staging buffer and TX buffer.
        let cap = buf.len().min(MAX_TX_BLOCK_SIZE as usize) as u16;
        let mbs = self.max_block_size.clamp(1, cap);

        self.exchange.rx_done()?;

        Ok(BdxWriter::new(
            self.exchange,
            drive,
            buf,
            mbs,
            TransferExtent::Indefinite,
            WriterState::Negotiating {
                max_length: self.requested_length,
            },
        ))
    }

    /// Accept the transfer and start sending, staging blocks in the (non-empty)
    /// caller-provided buffer `buf` (its length bounds the block size). `extent`
    /// advertises and enforces the remaining transfer length when known.
    pub async fn reply<'b>(
        self,
        buf: &'b mut [u8],
        extent: TransferExtent,
    ) -> Result<BdxWriter<'a, 'b>, Error> {
        let mut writer = self.prepare_reply(buf).await?;
        writer.accept(extent).await?;
        Ok(writer)
    }

    /// Reject the transfer with the given status (e.g. `FileDesignatorUnknown`).
    pub async fn reject(mut self, status: BdxStatus) -> Result<(), Error> {
        self.exchange.rx_done()?;
        send_status_report(&mut self.exchange, status).await
    }
}
