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

use std::collections::HashSet;
use std::collections::hash_set::Iter as HashSetIterator;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use net::raw::ether::MacAddr;

pub const HR_FLAG_ARP: u8  = 0x01;
pub const HR_FLAG_ICMP: u8 = 0x02;

/// Host record (i.e. a scan report element).
#[derive(Clone)]
pub struct HostRecord {
    pub flags: u8,
    pub mac:   MacAddr,
    pub ip:    IpAddr,

    ports: HashSet<u16>,
}

impl HostRecord {
    /// Create a new instance of host record.
    pub fn new(mac: MacAddr, ip: IpAddr, flags: u8) -> HostRecord {
        HostRecord {
            flags: flags,
            mac:   mac,
            ip:    ip,
            ports: HashSet::new()
        }
    }

    /// Add a given port.
    pub fn add_port(&mut self, port: u16) {
        self.ports.insert(port);
    }

    /// Add ports from a given iterator.
    pub fn add_ports<I>(&mut self, ports: I)
        where I: IntoIterator<Item=u16> {
        self.ports.extend(ports)
    }

    /// Get port iterator.
    pub fn ports(&self) -> PortIterator {
        PortIterator::new(self)
    }

    /// Get socket address iterator.
    pub fn socket_addrs(&self) -> SocketAddrIterator {
        SocketAddrIterator::new(self)
    }
}

/// Port iterator.
pub struct PortIterator<'a> {
    inner: HashSetIterator<'a, u16>,
}

impl<'a> PortIterator<'a> {
    /// Create a new port iterator from a given hash set iterator.
    fn new(host: &'a HostRecord) -> PortIterator<'a> {
        PortIterator {
            inner: host.ports.iter()
        }
    }
}

impl<'a> Iterator for PortIterator<'a> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        self.inner.next()
            .map(|port| *port)
    }
}

impl<'a> ExactSizeIterator for PortIterator<'a> {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Socket address iterator.
pub struct SocketAddrIterator<'a> {
    port_iterator: PortIterator<'a>,
    mac_addr:      MacAddr,
    ip_addr:       IpAddr,
}

impl<'a> SocketAddrIterator<'a> {
    /// Create a new socket address iterator for a given host info.
    fn new(host: &'a HostRecord) -> SocketAddrIterator<'a> {
        SocketAddrIterator {
            port_iterator: host.ports(),
            mac_addr:      host.mac,
            ip_addr:       host.ip,
        }
    }
}

impl<'a> Iterator for SocketAddrIterator<'a> {
    type Item = (MacAddr, SocketAddr);

    fn next(&mut self) -> Option<(MacAddr, SocketAddr)> {
        if let Some(port) = self.port_iterator.next() {
            let res = match self.ip_addr {
                IpAddr::V4(ip_addr) => SocketAddr::V4(SocketAddrV4::new(ip_addr, port)),
                IpAddr::V6(ip_addr) => SocketAddr::V6(SocketAddrV6::new(ip_addr, port, 0, 0))
            };

            Some((self.mac_addr, res))
        } else {
            None
        }
    }
}

impl<'a> ExactSizeIterator for SocketAddrIterator<'a> {
    fn len(&self) -> usize {
        self.port_iterator.len()
    }
}
