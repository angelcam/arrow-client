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

use net::arrow::proto::Encode;
use net::arrow::proto::buffer::OutputBuffer;
use net::arrow::proto::msg::MessageBody;
use net::arrow::proto::msg::control::ControlMessageBody;
use net::arrow::proto::msg::control::svc_table::ServiceTable;

/// UPDATE message.
pub struct UpdateMessage {
    svc_table: ServiceTable,
}

impl Encode for UpdateMessage {
    fn encode(&self, buf: &mut OutputBuffer) {
        self.svc_table.encode(buf)
    }
}

impl MessageBody for UpdateMessage {
    fn len(&self) -> usize {
        self.svc_table.len()
    }
}

impl ControlMessageBody for UpdateMessage {
}
