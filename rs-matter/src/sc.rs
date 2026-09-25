/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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

use core::borrow::Borrow;
use core::future::Future;
use core::mem::MaybeUninit;

use num_derive::FromPrimitive;

use crate::crypto::{
    Aead, CanonAeadKeyRef, Crypto, CryptoSensitive, CryptoSensitiveRef, Digest, AEAD_NONCE_LEN,
    AEAD_TAG_LEN,
};
use crate::dm::ChangeNotify;
use crate::error::{Error, ErrorCode};
use crate::respond::ExchangeHandler;
use crate::tlv::{FromTLV, ToTLV};
use crate::transport::exchange::{Exchange, MessageMeta};
use crate::utils::init::InitMaybeUninit;
use crate::utils::storage::{ReadBuf, WriteBuf};

use case::Case;
use pase::PaseResponder;

pub mod busy;
pub mod case;
pub mod pase;

/* Interaction Model ID as per the Matter Spec */
pub const PROTO_ID_SECURE_CHANNEL: u16 = 0x00;

/// Authenticated data carried by a Matter ICD Check-In message.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct IcdCheckInData {
    /// Device-generated Check-In counter.
    pub counter: u32,
    /// Active Mode Threshold in seconds.
    pub active_mode_threshold: u16,
}

/// The validated position of a Check-In counter in its registration window.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct IcdCheckInCounter {
    pub offset: u32,
    pub refresh_needed: bool,
}

/// Decrypt and authenticate an ICD Check-In payload in place.
///
/// The payload is the 13-byte nonce followed by AES-CCM ciphertext and a
/// 16-byte MIC. The decrypted body begins with the little-endian counter and
/// active-mode threshold. The nonce must equal the first 13 bytes of
/// HMAC-SHA-256(key, counter_le).
pub fn decode_icd_check_in<C: Crypto>(
    crypto: &C,
    key: CanonAeadKeyRef<'_>,
    payload: &mut [u8],
) -> Result<IcdCheckInData, Error> {
    const MIN_CIPHERTEXT_LEN: usize = 4 + 2 + AEAD_TAG_LEN;
    const MIN_PAYLOAD_LEN: usize = AEAD_NONCE_LEN + MIN_CIPHERTEXT_LEN;

    if payload.len() < MIN_PAYLOAD_LEN {
        return Err(ErrorCode::Invalid.into());
    }

    let (received_nonce, encrypted) = payload.split_at_mut(AEAD_NONCE_LEN);
    let nonce: &[u8; AEAD_NONCE_LEN] = (&*received_nonce).try_into().unwrap();
    let mut aead = crypto.aead()?;
    let plaintext = aead.decrypt_in_place(key, CryptoSensitiveRef::new(nonce), &[], encrypted)?;

    let counter = u32::from_le_bytes(plaintext[..4].try_into().unwrap());
    let mut hmac = crypto.hmac(key)?;
    hmac.update(&counter.to_le_bytes())?;
    let mut digest = CryptoSensitive::<32>::new();
    hmac.finish(&mut digest)?;

    use subtle::ConstantTimeEq;
    if !bool::from(received_nonce.ct_eq(&digest.access()[..AEAD_NONCE_LEN])) {
        return Err(ErrorCode::Invalid.into());
    }

    Ok(IcdCheckInData {
        counter,
        active_mode_threshold: u16::from_le_bytes(plaintext[4..6].try_into().unwrap()),
    })
}

/// Validate a Check-In counter against the offset last accepted for its registration.
///
/// Counters use wrapping arithmetic. A strictly increasing offset is accepted;
/// reaching the upper half of the counter space signals that registration refresh
/// is due. Duplicate, stale and out-of-order counters return `None`.
pub const fn validate_icd_check_in_counter(
    counter_start: u32,
    last_offset: u32,
    counter: u32,
) -> Option<IcdCheckInCounter> {
    let offset = counter.wrapping_sub(counter_start);
    if offset <= last_offset {
        None
    } else {
        Some(IcdCheckInCounter {
            offset,
            refresh_needed: offset >= 0x8000_0000,
        })
    }
}

#[cfg(test)]
mod icd_tests {
    use super::*;
    use crate::crypto::{test_only_crypto, Aead, CryptoSensitive, CryptoSensitiveRef, Digest};

    #[test]
    fn check_in_decoder_authenticates_nonce_and_decrypts_counter_and_threshold() {
        let crypto = test_only_crypto();
        let key = [0x42; 16];
        let counter = 0x1234_5678_u32;
        let threshold = 900_u16;
        let counter_bytes = counter.to_le_bytes();

        let mut hmac = crypto.hmac(CryptoSensitiveRef::new(&key)).unwrap();
        hmac.update(&counter_bytes).unwrap();
        let mut digest = CryptoSensitive::<32>::new();
        hmac.finish(&mut digest).unwrap();
        let mut nonce = [0; 13];
        nonce.copy_from_slice(&digest.access()[..13]);

        let mut encrypted = [0; 22];
        encrypted[..4].copy_from_slice(&counter_bytes);
        encrypted[4..6].copy_from_slice(&threshold.to_le_bytes());
        let mut aead = crypto.aead().unwrap();
        aead.encrypt_in_place(
            CryptoSensitiveRef::new(&key),
            CryptoSensitiveRef::new(&nonce),
            &[],
            &mut encrypted,
            6,
        )
        .unwrap();

        let mut payload = [0; 35];
        payload[..13].copy_from_slice(&nonce);
        payload[13..].copy_from_slice(&encrypted);

        let check_in =
            decode_icd_check_in(&crypto, CryptoSensitiveRef::new(&key), &mut payload).unwrap();

        assert_eq!(check_in.counter, counter);
        assert_eq!(check_in.active_mode_threshold, threshold);
    }

    #[test]
    fn check_in_counter_rejects_replay_and_marks_counter_refresh() {
        assert_eq!(
            validate_icd_check_in_counter(100, 4, 104),
            None,
            "the last accepted offset is replayed"
        );
        assert_eq!(
            validate_icd_check_in_counter(100, 4, 105),
            Some(IcdCheckInCounter {
                offset: 5,
                refresh_needed: false,
            })
        );
        assert_eq!(
            validate_icd_check_in_counter(0, 0, 0x8000_0000),
            Some(IcdCheckInCounter {
                offset: 0x8000_0000,
                refresh_needed: true,
            })
        );
    }
}

#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OpCode {
    MsgCounterSyncReq = 0x00,
    MsgCounterSyncResp = 0x01,
    MRPStandAloneAck = 0x10,
    PBKDFParamRequest = 0x20,
    PBKDFParamResponse = 0x21,
    PASEPake1 = 0x22,
    PASEPake2 = 0x23,
    PASEPake3 = 0x24,
    CASESigma1 = 0x30,
    CASESigma2 = 0x31,
    CASESigma3 = 0x32,
    CASESigma2Resume = 0x33,
    StatusReport = 0x40,
    IcdCheckInMessage = 0x50,
}

impl OpCode {
    pub fn meta(&self) -> MessageMeta {
        MessageMeta {
            proto_id: PROTO_ID_SECURE_CHANNEL,
            proto_opcode: *self as u8,
            reliable: !matches!(self, Self::MRPStandAloneAck | Self::IcdCheckInMessage),
        }
    }

    pub fn is_tlv(&self) -> bool {
        !matches!(
            self,
            Self::MRPStandAloneAck
                | Self::StatusReport
                | Self::MsgCounterSyncReq
                | Self::MsgCounterSyncResp
                | Self::IcdCheckInMessage
        )
    }
}

impl From<OpCode> for MessageMeta {
    fn from(op: OpCode) -> Self {
        op.meta()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SCStatusCodes {
    SessionEstablishmentSuccess = 0,
    NoSharedTrustRoots = 1,
    InvalidParameter = 2,
    CloseSession = 3,
    Busy = 4,
    SessionNotFound = 5,
}

impl SCStatusCodes {
    pub fn reliable(&self) -> bool {
        // CloseSession and Busy are sent without the R flag raised
        !matches!(self, SCStatusCodes::CloseSession | SCStatusCodes::Busy)
    }

    pub fn as_report<'a>(&self, payload: &'a [u8]) -> StatusReport<'a> {
        let general_code = match self {
            SCStatusCodes::SessionEstablishmentSuccess => GeneralCode::Success,
            SCStatusCodes::CloseSession => GeneralCode::Success,
            SCStatusCodes::Busy => GeneralCode::Busy,
            SCStatusCodes::InvalidParameter
            | SCStatusCodes::NoSharedTrustRoots
            | SCStatusCodes::SessionNotFound => GeneralCode::Failure,
        };

        StatusReport {
            general_code,
            proto_id: PROTO_ID_SECURE_CHANNEL as u32,
            proto_code: *self as u16,
            proto_data: payload,
        }
    }
}

pub async fn complete_with_status(
    exchange: &mut Exchange<'_>,
    status_code: SCStatusCodes,
    payload: &[u8],
) -> Result<(), Error> {
    exchange
        .send_with(|_, wb| sc_write(wb, status_code, payload))
        .await
}

pub fn sc_write(
    wb: &mut WriteBuf,
    status_code: SCStatusCodes,
    payload: &[u8],
) -> Result<Option<MessageMeta>, Error> {
    status_code.as_report(payload).write(wb)?;

    Ok(Some(
        OpCode::StatusReport.meta().reliable(status_code.reliable()),
    ))
}

#[allow(dead_code)]
#[derive(FromPrimitive, PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GeneralCode {
    Success = 0,
    Failure = 1,
    BadPrecondition = 2,
    OutOfRange = 3,
    BadRequest = 4,
    Unsupported = 5,
    Unexpected = 6,
    ResourceExhausted = 7,
    Busy = 8,
    Timeout = 9,
    Continue = 10,
    Aborted = 11,
    InvalidArgument = 12,
    NotFound = 13,
    AlreadyExists = 14,
    PermissionDenied = 15,
    DataLoss = 16,
}

/// Represents the session parameters
/// that might present in a "PBKDFParamRequest" or "CASE-Sigma1" message
#[derive(FromTLV, ToTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1)]
pub(crate) struct SessionParameters {
    /// Session Idle Interval
    sii: Option<u32>,
    /// Session Active Interval
    sai: Option<u32>,
    /// Session Active Threshold
    sat: Option<u16>,
    /// Data Model Revision
    dm_revision: Option<u16>,
    /// Interaction Model Revision
    im_revision: Option<u16>,
    /// Specification Version
    spec_version: Option<u32>,
    /// Maximum number of paths per invoke
    max_paths_per_invoke: Option<u16>,
}

/// Represents a Status Report message, as per "Appendix D: Status Report Messages" of the Matter Spec.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StatusReport<'a> {
    pub general_code: GeneralCode,
    pub proto_id: u32,
    pub proto_code: u16,
    pub proto_data: &'a [u8],
}

impl<'a> StatusReport<'a> {
    pub fn read<T>(pb: &'a mut ReadBuf<T>) -> Result<Self, Error>
    where
        T: Borrow<[u8]>,
    {
        Ok(Self {
            general_code: num::FromPrimitive::from_u16(pb.le_u16()?)
                .ok_or(ErrorCode::InvalidOpcode)?,
            proto_id: pb.le_u32()?,
            proto_code: pb.le_u16()?,
            proto_data: pb.as_slice(),
        })
    }

    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        wb.le_u16(self.general_code as u16)?;
        wb.le_u32(self.proto_id)?;
        wb.le_u16(self.proto_code)?;
        wb.copy_from_slice(self.proto_data)?;

        Ok(())
    }
}

/// Handle messages related to the Secure Channel
pub struct SecureChannel<'a, C> {
    crypto: C,
    notify: &'a dyn ChangeNotify,
}

impl<'a, C: Crypto> SecureChannel<'a, C> {
    #[inline(always)]
    pub const fn new(crypto: C, notify: &'a dyn ChangeNotify) -> Self {
        Self { crypto, notify }
    }

    pub async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        if exchange.rx().is_err() {
            exchange.recv_fetch().await?;
        }

        let meta = exchange.rx()?.meta();
        if meta.proto_id != PROTO_ID_SECURE_CHANNEL {
            Err(ErrorCode::InvalidProto)?;
        }

        match meta.opcode()? {
            OpCode::PBKDFParamRequest => {
                let mut pase = MaybeUninit::uninit(); // TODO LARGE BUFFER
                pase.init_with(PaseResponder::init(&self.crypto, self.notify))
                    .handle(exchange)
                    .await
            }
            OpCode::CASESigma1 => {
                let mut case = MaybeUninit::uninit(); // TODO LARGE BUFFER
                case.init_with(Case::init(&self.crypto))
                    .handle(exchange)
                    .await
            }
            opcode => {
                error!("Invalid opcode: {:?}", opcode);
                Err(ErrorCode::InvalidOpcode.into())
            }
        }
    }
}

impl<C: Crypto> ExchangeHandler for SecureChannel<'_, C> {
    fn handle(&self, exchange: &mut Exchange<'_>) -> impl Future<Output = Result<(), Error>> {
        SecureChannel::handle(self, exchange)
    }
}

/// Check that the opcode of the received message matches the expected one.
/// Logs an error if that's not the case, and if the opcode is `StatusReport`,
/// it also logs the details of the status report.
fn check_opcode(exchange: &Exchange<'_>, opcode: OpCode) -> Result<(), Error> {
    let meta = exchange.rx()?.meta();
    let their_opcode = meta.opcode::<OpCode>()?;

    if their_opcode == opcode {
        Ok(())
    } else {
        error!("Invalid opcode: {:?}, expected: {:?}", their_opcode, opcode);

        if matches!(their_opcode, OpCode::StatusReport) {
            let mut rb = ReadBuf::new(exchange.rx()?.payload());

            // Show the status code details in the log
            match StatusReport::read(&mut rb) {
                Ok(status_report) => error!("Status Report: {:?}", status_report),
                Err(e) => error!("Failed to parse Status Report: {:?}", e),
            }
        }

        Err(ErrorCode::Invalid.into())
    }
}
