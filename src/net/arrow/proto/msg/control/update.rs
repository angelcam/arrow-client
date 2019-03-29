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

use bytes::BytesMut;

use crate::net::arrow::proto::codec::Encode;
use crate::net::arrow::proto::msg::control::{ControlMessageBody, SimpleServiceTable};
use crate::net::arrow::proto::msg::MessageBody;

/// UPDATE message.
pub struct UpdateMessage {
    svc_table: SimpleServiceTable,
}

impl UpdateMessage {
    /// Create a new UPDATE message.
    pub fn new(svc_table: SimpleServiceTable) -> UpdateMessage {
        UpdateMessage {
            svc_table: svc_table,
        }
    }
}

impl Encode for UpdateMessage {
    fn encode(&self, buf: &mut BytesMut) {
        self.svc_table.encode(buf)
    }
}

impl MessageBody for UpdateMessage {
    fn len(&self) -> usize {
        self.svc_table.len()
    }
}

impl ControlMessageBody for UpdateMessage {}
