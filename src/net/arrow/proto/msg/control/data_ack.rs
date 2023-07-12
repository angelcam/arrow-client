// Copyright 2023 click2stream, Inc.
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

/// DATA_ACK message.
#[repr(packed)]
pub struct DataAckMessage {
    /// Session ID (note: the upper 8 bits are reserved).
    pub session_id: u32,
    /// ACK length.
    pub length: u32,
}

impl DataAckMessage {
    /// Create a new DATA_ACK message for a given session.
    pub fn new(session_id: u32, length: u32) -> Self {
        Self {
            session_id: session_id & ((1 << 24) - 1),
            length,
        }
    }
}

impl Encode for DataAckMessage {
    fn encode(&self, buf: &mut BytesMut) {
        let be_msg = Self {
            session_id: self.session_id.to_be(),
            length: self.length.to_be(),
        };

        buf.extend_from_slice(utils::as_bytes(&be_msg))
    }
}

impl MessageBody for DataAckMessage {
    fn len(&self) -> usize {
        mem::size_of::<Self>()
    }
}

impl ControlMessageBody for DataAckMessage {}

impl FromBytes for DataAckMessage {
    fn from_bytes(bytes: &[u8]) -> Result<Option<Self>, DecodeError> {
        if bytes.len() != mem::size_of::<Self>() {
            return Err(DecodeError::new(
                "malformed Arrow Control Protocol DATA_ACK message",
            ));
        }

        let ptr = bytes.as_ptr() as *const Self;
        let msg = unsafe { &*ptr };

        let res = Self {
            session_id: u32::from_be(msg.session_id),
            length: u32::from_be(msg.length),
        };

        Ok(Some(res))
    }
}
