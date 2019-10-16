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

pub mod host;

use std::collections::hash_map::Iter as HashMapIterator;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::net::raw::ether::MacAddr;
use crate::svc_table::{Service, ServiceIdentifier};

pub use self::host::HR_FLAG_ARP;
pub use self::host::HR_FLAG_ICMP;

pub use self::host::HostRecord;

type HostRecordIdentifier = (MacAddr, IpAddr);

/// Scan report.
#[derive(Clone, Default)]
pub struct ScanResult {
    hosts: HashMap<HostRecordIdentifier, HostRecord>,
    services: HashMap<ServiceIdentifier, Service>,
}

impl ScanResult {
    /// Create a new network scan report.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a given host.
    pub fn add_host(&mut self, mac: MacAddr, ip: IpAddr, flags: u8) {
        let key = (mac, ip);

        if let Some(host) = self.hosts.get_mut(&key) {
            host.flags |= flags;
        } else {
            self.hosts.insert(key, HostRecord::new(mac, ip, flags));
        }
    }

    /// Add a given port into the corresponding host info. The host info is
    /// created if it is not already in the table.
    pub fn add_port(&mut self, mac: MacAddr, ip: IpAddr, port: u16) {
        let key = (mac, ip);

        self.hosts
            .entry(key)
            .or_insert_with(|| HostRecord::new(mac, ip, 0));

        if let Some(host) = self.hosts.get_mut(&key) {
            host.add_port(port);
        }
    }

    /// Add a given service.
    pub fn add_service(&mut self, svc: Service) {
        self.services.insert(svc.to_service_identifier(), svc);
    }

    /// Get host records.
    pub fn hosts(&self) -> HostRecordIterator {
        HostRecordIterator::new(self)
    }

    /// Get socket addresses.
    pub fn socket_addrs(&self) -> SocketAddrIterator {
        SocketAddrIterator::new(self)
    }

    /// Get services.
    pub fn services(&self) -> ServiceIterator {
        ServiceIterator::new(self)
    }

    /// Merge with a given scan report.
    pub fn merge(&mut self, other: Self) {
        for (key, other_host) in other.hosts {
            if let Some(host) = self.hosts.get_mut(&key) {
                host.add_ports(other_host.ports());
                host.flags |= other_host.flags;
            } else {
                self.hosts.insert(key, other_host);
            }
        }

        self.services.extend(other.services);
    }
}

/// Host record iterator.
pub struct HostRecordIterator<'a> {
    inner: HashMapIterator<'a, HostRecordIdentifier, HostRecord>,
}

impl<'a> HostRecordIterator<'a> {
    /// Create a new host record iterator for a given scan report.
    fn new(report: &'a ScanResult) -> HostRecordIterator<'a> {
        HostRecordIterator {
            inner: report.hosts.iter(),
        }
    }
}

impl<'a> Iterator for HostRecordIterator<'a> {
    type Item = &'a HostRecord;

    fn next(&mut self) -> Option<&'a HostRecord> {
        self.inner.next().map(|(_, host)| host)
    }
}

impl<'a> ExactSizeIterator for HostRecordIterator<'a> {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Service iterator.
pub struct ServiceIterator<'a> {
    inner: HashMapIterator<'a, ServiceIdentifier, Service>,
}

impl<'a> ServiceIterator<'a> {
    /// Create a new service iterator for a given scan report.
    fn new(report: &'a ScanResult) -> ServiceIterator<'a> {
        ServiceIterator {
            inner: report.services.iter(),
        }
    }
}

impl<'a> Iterator for ServiceIterator<'a> {
    type Item = &'a Service;

    fn next(&mut self) -> Option<&'a Service> {
        self.inner.next().map(|(_, service)| service)
    }
}

impl<'a> ExactSizeIterator for ServiceIterator<'a> {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Socket address iterator.
pub struct SocketAddrIterator<'a> {
    host_iterator: HostRecordIterator<'a>,
    saddr_iterator: Option<self::host::SocketAddrIterator<'a>>,
}

impl<'a> SocketAddrIterator<'a> {
    /// Create a new socket address iterator for a given scan report.
    fn new(report: &'a ScanResult) -> SocketAddrIterator<'a> {
        let mut host_iterator = report.hosts();

        let saddr_iterator = host_iterator.next().map(|host| host.socket_addrs());

        SocketAddrIterator {
            host_iterator,
            saddr_iterator,
        }
    }
}

impl<'a> Iterator for SocketAddrIterator<'a> {
    type Item = (MacAddr, SocketAddr);

    fn next(&mut self) -> Option<(MacAddr, SocketAddr)> {
        while self.saddr_iterator.is_some() {
            let saddr = self
                .saddr_iterator
                .as_mut()
                .and_then(|saddr_iterator| saddr_iterator.next());

            if saddr.is_some() {
                return saddr;
            }

            self.saddr_iterator = self.host_iterator.next().map(|host| host.socket_addrs());
        }

        None
    }
}
