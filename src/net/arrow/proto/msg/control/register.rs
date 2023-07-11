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

use crate::net::arrow::proto::codec::Encode;
use crate::net::arrow::proto::msg::control::{ControlMessageBody, SimpleServiceTable};
use crate::net::arrow::proto::msg::MessageBody;
use crate::net::raw::ether::MacAddr;

/// REGISTER message header.
#[repr(packed)]
#[allow(dead_code)]
struct RegisterMessageHeader {
    uuid: [u8; 16],
    key: [u8; 16],
    mac: [u8; 6],
    window_size: u16,
    flags: u32,
}

impl RegisterMessageHeader {
    /// Create a new REGISTER message header.
    fn new(uuid: [u8; 16], key: [u8; 16], mac: MacAddr) -> Self {
        Self {
            uuid,
            key,
            mac: mac.octets(),
            window_size: u16::MAX,
            flags: 0,
        }
    }
}

impl Encode for RegisterMessageHeader {
    fn encode(&self, buf: &mut BytesMut) {
        let be_header = Self {
            uuid: self.uuid,
            key: self.key,
            mac: self.mac,
            window_size: self.window_size.to_be(),
            flags: self.flags.to_be(),
        };

        buf.extend_from_slice(utils::as_bytes(&be_header))
    }
}

/// REGISTER message.
pub struct RegisterMessage {
    header: RegisterMessageHeader,
    extended_info: String,
    svc_table: SimpleServiceTable,
}

impl RegisterMessage {
    /// Flag indicating that the client can be used as a gateway.
    pub const FLAG_GATEWAY_MODE: u32 = 0x01;

    /// Create a new REGISTER message.
    pub fn new(uuid: [u8; 16], key: [u8; 16], mac: MacAddr, svc_table: SimpleServiceTable) -> Self {
        Self {
            header: RegisterMessageHeader::new(uuid, key, mac),
            extended_info: String::new(),
            svc_table,
        }
    }

    /// Set session window size.
    ///
    /// The default window size is `65_535`.
    pub fn with_window_size(mut self, window_size: u16) -> Self {
        self.header.window_size = window_size;
        self
    }

    /// Set flags.
    pub fn with_flags(mut self, flags: u32) -> Self {
        self.header.flags = flags;
        self
    }

    /// Set extended info.
    pub fn with_extended_info<T>(mut self, extended_info: T) -> Self
    where
        T: ToString,
    {
        self.extended_info = extended_info.to_string();
        self
    }
}

impl Encode for RegisterMessage {
    fn encode(&self, buf: &mut BytesMut) {
        self.header.encode(buf);

        buf.extend_from_slice(self.extended_info.as_bytes());
        buf.extend_from_slice(&[0]);

        self.svc_table.encode(buf);
    }
}

impl MessageBody for RegisterMessage {
    fn len(&self) -> usize {
        mem::size_of::<RegisterMessageHeader>()
            + self.extended_info.len()
            + 1
            + self.svc_table.len()
    }
}

impl ControlMessageBody for RegisterMessage {}
