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

use utils;

use net::arrow::proto::codec::Encode;
use net::arrow::proto::msg::MessageBody;
use net::arrow::proto::msg::control::ControlMessageBody;

/// STATUS message.
#[repr(packed)]
pub struct StatusMessage {
    request_id:      u16,
    status_flags:    u32,
    active_sessions: u32,
}

impl Encode for StatusMessage {
    fn encode(&self, buf: &mut BytesMut) {
        let be_msg = StatusMessage {
            request_id:      self.request_id.to_be(),
            status_flags:    self.status_flags.to_be(),
            active_sessions: self.active_sessions.to_be()
        };

        buf.extend(utils::as_bytes(&be_msg))
    }
}

impl MessageBody for StatusMessage {
    fn len(&self) -> usize {
        mem::size_of::<StatusMessage>()
    }
}

impl ControlMessageBody for StatusMessage {
}
