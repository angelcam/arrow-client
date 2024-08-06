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

/// CONNECT message.
#[repr(packed)]
pub struct ConnectMessage {
    /// Service ID.
    pub service_id: u16,
    /// Session ID (note: the upper 8 bits are reserved).
    pub session_id: u32,
}

impl Encode for ConnectMessage {
    fn encode(&self, buf: &mut BytesMut) {
        let be_msg = Self {
            service_id: self.service_id.to_be(),
            session_id: self.session_id.to_be(),
        };

        buf.extend_from_slice(utils::as_bytes(&be_msg))
    }
}

impl MessageBody for ConnectMessage {
    fn len(&self) -> usize {
        mem::size_of::<Self>()
    }
}

impl ControlMessageBody for ConnectMessage {}

impl FromBytes for ConnectMessage {
    fn from_bytes(bytes: &[u8]) -> Result<Option<Self>, DecodeError> {
        if bytes.len() != mem::size_of::<Self>() {
            return Err(DecodeError::new(
                "malformed Arrow Control Protocol CONNECT message",
            ));
        }

        let ptr = bytes.as_ptr() as *const Self;

        let msg = unsafe { ptr.read_unaligned() };

        let res = Self {
            service_id: u16::from_be(msg.service_id),
            session_id: u32::from_be(msg.session_id),
        };

        Ok(Some(res))
    }
}
