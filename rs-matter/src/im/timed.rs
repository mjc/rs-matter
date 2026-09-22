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

//! This module contains types related to the Timed Request feature in the Matter Interaction Model.

use core::time::Duration;

use crate::error::Error;
use crate::tlv::{FromTLV, TLVTag, TLVWrite, ToTLV, TLV};
use crate::utils::epoch::Epoch;

use super::INTERACTION_MODEL_REVISION;

/// A structure representing a timed request in the Interaction Model.
///
/// Corresponds to the `TimedRequestMessage` struct in the Interaction Model.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, FromTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TimedReq {
    /// The timeout duration in milliseconds for the request.
    pub timeout: u16,
}

impl ToTLV for TimedReq {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.start_struct(tag)?;
        tw.u16(&TLVTag::Context(0), self.timeout)?;
        tw.u8(&TLVTag::Context(255), INTERACTION_MODEL_REVISION)?;
        tw.end_container()
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        [
            Ok(TLV::structure(tag)),
            Ok(TLV::u16(TLVTag::Context(0), self.timeout)),
            Ok(TLV::u8(TLVTag::Context(255), INTERACTION_MODEL_REVISION)),
            Ok(TLV::end_container()),
        ]
        .into_iter()
    }
}

impl TimedReq {
    /// Returns the moment in time - since the system epoch - when the request
    /// following this timed request should be considered expired.
    pub fn timeout_instant(&self, epoch: Epoch) -> Duration {
        unwrap!(epoch().checked_add(Duration::from_millis(self.timeout as _)))
    }
}
