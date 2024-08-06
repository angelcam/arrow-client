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

/// ACK message.
#[repr(packed)]
pub struct AckMessage {
    pub err: u32,
}

impl AckMessage {
    /// Create a new ACK message for a given error code.
    pub fn new(err: u32) -> Self {
        Self { err }
    }
}

impl Encode for AckMessage {
    fn encode(&self, buf: &mut BytesMut) {
        let be_msg = Self {
            err: self.err.to_be(),
        };

        buf.extend_from_slice(utils::as_bytes(&be_msg))
    }
}

impl MessageBody for AckMessage {
    fn len(&self) -> usize {
        mem::size_of::<Self>()
    }
}

impl ControlMessageBody for AckMessage {}

impl FromBytes for AckMessage {
    fn from_bytes(bytes: &[u8]) -> Result<Option<Self>, DecodeError> {
        if bytes.len() != mem::size_of::<Self>() {
            return Err(DecodeError::new(
                "malformed Arrow Control Protocol ACK message",
            ));
        }

        let ptr = bytes.as_ptr() as *const Self;

        let msg = unsafe { ptr.read_unaligned() };

        let res = Self {
            err: u32::from_be(msg.err),
        };

        Ok(Some(res))
    }
}
