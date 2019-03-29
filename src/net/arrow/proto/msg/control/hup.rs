// Copyright 2017 click2stream, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::mem;

use bytes::BytesMut;

use crate::utils;

use crate::net::arrow::proto::codec::{Encode, FromBytes};
use crate::net::arrow::proto::error::DecodeError;
use crate::net::arrow::proto::msg::control::ControlMessageBody;
use crate::net::arrow::proto::msg::MessageBody;

/// HUP message.
#[repr(packed)]
pub struct HupMessage {
    /// Session ID (note: the upper 8 bits are reserved).
    pub session_id: u32,
    /// Error code.
    pub error_code: u32,
}

impl HupMessage {
    /// Create a new HUP message for a given session ID and error code.
    pub fn new(session_id: u32, error_code: u32) -> HupMessage {
        HupMessage {
            session_id: session_id & ((1 << 24) - 1),
            error_code: error_code,
        }
    }
}

impl Encode for HupMessage {
    fn encode(&self, buf: &mut BytesMut) {
        let be_msg = HupMessage {
            session_id: self.session_id.to_be(),
            error_code: self.error_code.to_be(),
        };

        buf.extend_from_slice(utils::as_bytes(&be_msg))
    }
}

impl MessageBody for HupMessage {
    fn len(&self) -> usize {
        mem::size_of::<HupMessage>()
    }
}

impl ControlMessageBody for HupMessage {}

impl FromBytes for HupMessage {
    fn from_bytes(bytes: &[u8]) -> Result<Option<HupMessage>, DecodeError> {
        if bytes.len() != mem::size_of::<HupMessage>() {
            return Err(DecodeError::from(
                "malformed Arrow Control Protocol HUP message",
            ));
        }

        let ptr = bytes.as_ptr() as *const HupMessage;
        let msg = unsafe { &*ptr };

        let res = HupMessage {
            session_id: u32::from_be(msg.session_id),
            error_code: u32::from_be(msg.error_code),
        };

        Ok(Some(res))
    }
}
