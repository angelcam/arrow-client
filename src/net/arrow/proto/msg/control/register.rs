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
use net::arrow::proto::msg::control::{
    ControlMessageBody,
    SimpleServiceTable,
};

use net::raw::ether::MacAddr;

/// REGISTER message header.
#[repr(packed)]
#[allow(dead_code)]
struct RegisterMessageHeader {
    uuid:   [u8; 16],
    mac:    [u8; 6],
    passwd: [u8; 16],
}

impl RegisterMessageHeader {
    /// Create a new REGISTER message header.
    fn new(
        mac: MacAddr,
        uuid: [u8; 16],
        password: [u8; 16]) -> RegisterMessageHeader {
        RegisterMessageHeader {
            uuid:   uuid,
            mac:    mac.octets(),
            passwd: password,
        }
    }
}

impl Encode for RegisterMessageHeader {
    fn encode(&self, buf: &mut BytesMut) {
        buf.extend(utils::as_bytes(self))
    }
}

/// REGISTER message.
pub struct RegisterMessage {
    header:    RegisterMessageHeader,
    svc_table: SimpleServiceTable,
}

impl RegisterMessage {
    /// Create a new REGISTER message.
    pub fn new(
        mac: MacAddr,
        uuid: [u8; 16],
        password: [u8; 16],
        svc_table: SimpleServiceTable) -> RegisterMessage {
        let header = RegisterMessageHeader::new(mac, uuid, password);

        RegisterMessage {
            header:    header,
            svc_table: svc_table,
        }
    }
}

impl Encode for RegisterMessage {
    fn encode(&self, buf: &mut BytesMut) {
        self.header.encode(buf);
        self.svc_table.encode(buf);
    }
}

impl MessageBody for RegisterMessage {
    fn len(&self) -> usize {
        mem::size_of::<RegisterMessageHeader>() + self.svc_table.len()
    }
}

impl ControlMessageBody for RegisterMessage {
}
