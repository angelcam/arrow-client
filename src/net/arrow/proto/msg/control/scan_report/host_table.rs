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
use crate::net::arrow::proto::msg::MessageBody;
use crate::net::utils::IpAddrEx;
use crate::scanner::HostRecord;

/// Host table element header.
#[repr(packed)]
struct ElementHeader {
    flags: u8,
    mac: [u8; 6],
    ip_version: u8,
    ip_addr: [u8; 16],
    port_count: u16,
}

impl<'a> From<&'a Element> for ElementHeader {
    fn from(element: &'a Element) -> Self {
        let ports = element.host.ports();

        Self {
            flags: element.host.flags,
            mac: element.host.mac.octets(),
            ip_version: element.host.ip.version(),
            ip_addr: element.host.ip.bytes(),
            port_count: ports.len() as u16,
        }
    }
}

impl Encode for ElementHeader {
    fn encode(&self, buf: &mut BytesMut) {
        let be_header = Self {
            flags: self.flags,
            mac: self.mac,
            ip_version: self.ip_version,
            ip_addr: self.ip_addr,
            port_count: self.port_count.to_be(),
        };

        buf.extend_from_slice(utils::as_bytes(&be_header))
    }
}

/// Host table element.
struct Element {
    host: HostRecord,
}

impl Element {
    /// Create a new host table element.
    fn new(host: HostRecord) -> Self {
        Self { host }
    }
}

impl Encode for Element {
    fn encode(&self, buf: &mut BytesMut) {
        ElementHeader::from(self).encode(buf);

        for port in self.host.ports() {
            buf.extend_from_slice(utils::as_bytes(&port.to_be()));
        }
    }
}

impl MessageBody for Element {
    fn len(&self) -> usize {
        let ports = self.host.ports();

        mem::size_of::<ElementHeader>() + (ports.len() * mem::size_of::<u16>())
    }
}

/// Host table header.
#[repr(packed)]
struct HostTableHeader {
    count: u32,
}

impl<'a> From<&'a HostTable> for HostTableHeader {
    fn from(table: &'a HostTable) -> Self {
        Self {
            count: table.hosts.len() as u32,
        }
    }
}

impl Encode for HostTableHeader {
    fn encode(&self, buf: &mut BytesMut) {
        let be_header = Self {
            count: self.count.to_be(),
        };

        buf.extend_from_slice(utils::as_bytes(&be_header))
    }
}

/// Host table.
pub struct HostTable {
    hosts: Vec<Element>,
}

impl<I> From<I> for HostTable
where
    I: IntoIterator<Item = HostRecord>,
{
    fn from(hosts: I) -> Self {
        let hosts = hosts.into_iter().map(Element::new).collect::<Vec<_>>();

        Self { hosts }
    }
}

impl Encode for HostTable {
    fn encode(&self, buf: &mut BytesMut) {
        HostTableHeader::from(self).encode(buf);

        for host in &self.hosts {
            host.encode(buf);
        }
    }
}

impl MessageBody for HostTable {
    fn len(&self) -> usize {
        let mut len = mem::size_of::<HostTableHeader>();

        for host in &self.hosts {
            len += host.len();
        }

        len
    }
}
