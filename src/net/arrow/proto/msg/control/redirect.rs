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

use std::str;

use bytes::BytesMut;

use crate::net::arrow::proto::codec::{Encode, FromBytes};
use crate::net::arrow::proto::error::DecodeError;
use crate::net::arrow::proto::msg::control::ControlMessageBody;
use crate::net::arrow::proto::msg::MessageBody;

/// REDIRECT message.
pub struct RedirectMessage {
    pub target: String,
}

impl Encode for RedirectMessage {
    fn encode(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(self.target.as_bytes());
        buf.extend_from_slice(&[0]);
    }
}

impl MessageBody for RedirectMessage {
    fn len(&self) -> usize {
        self.target.as_bytes().len() + 1
    }
}

impl ControlMessageBody for RedirectMessage {}

impl FromBytes for RedirectMessage {
    fn from_bytes(bytes: &[u8]) -> Result<Option<RedirectMessage>, DecodeError> {
        let length = bytes.len();

        if length == 0 || bytes[length - 1] != 0 {
            return Err(DecodeError::from(
                "malformed Arrow Control Protocol REDIRECT message",
            ));
        }

        let bytes = &bytes[..length - 1];
        let target = str::from_utf8(bytes)
            .map_err(|_| DecodeError::from("malformed Arrow Control Protocol REDIRECT message"))?;

        let msg = RedirectMessage {
            target: target.to_string(),
        };

        Ok(Some(msg))
    }
}
