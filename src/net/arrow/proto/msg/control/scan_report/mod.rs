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

use std::mem;

use std::net::{IpAddr, SocketAddr};
use std::collections::{HashMap, HashSet};
use std::collections::hash_set::Iter as HashSetIterator;
use std::collections::hash_map::Iter as HashMapIterator;

use bytes::BytesMut;

use utils;

use net::arrow::proto::codec::Encode;
use net::arrow::proto::msg::MessageBody;
use net::arrow::proto::msg::control::ControlMessageBody;
use net::arrow::proto::msg::control::svc_table::Service;
use net::raw::ether::MacAddr;

pub use self::host::HR_FLAG_ARP;
pub use self::host::HR_FLAG_ICMP;

pub use self::host::HostRecord;

/// Scan report header.
#[repr(packed)]
struct ScanReportHeader {
    host_count: u32,
}

impl<'a> From<&'a ScanReport> for ScanReportHeader {
    fn from(report: &'a ScanReport) -> ScanReportHeader {
        ScanReportHeader {
            host_count: report.hosts.len() as u32
        }
    }
}

impl Encode for ScanReportHeader {
    fn encode(&self, buf: &mut BytesMut) {
        let be_header = ScanReportHeader {
            host_count: self.host_count.to_be(),
        };

        buf.extend(utils::as_bytes(&be_header))
    }
}

type HostRecordKey = (MacAddr, IpAddr);

/// Scan report.
#[derive(Clone)]
pub struct ScanReport {
    hosts:    HashMap<HostRecordKey, HostRecord>,
    services: HashSet<Service>,
}

impl ScanReport {
    /// Create a new network scan report.
    pub fn new() -> ScanReport {
        ScanReport {
            hosts:    HashMap::new(),
            services: HashSet::new()
        }
    }

    /// Add a given host.
    pub fn add_host(&mut self, mac: MacAddr, ip: IpAddr, flags: u8) {
        let key = (mac, ip);
        if !self.hosts.contains_key(&key) {
            self.hosts.insert(key, HostRecord::new(mac, ip, flags));
        } else if let Some(host) = self.hosts.get_mut(&key) {
            host.flags |= flags;
        }
    }

    /// Get host info for a given host.
    pub fn get_host(&self, mac: MacAddr, ip: IpAddr) -> Option<&HostRecord> {
        self.hosts.get(&(mac, ip))
    }

    /// Get mutable host info for a given host.
    pub fn get_host_mut(
        &mut self,
        mac: MacAddr,
        ip: IpAddr) -> Option<&mut HostRecord> {
        self.hosts.get_mut(&(mac, ip))
    }

    /// Add a given port into the corresponding host info. The host info is
    /// created if it is not already in the table.
    pub fn add_port(&mut self, mac: MacAddr, ip: IpAddr, port: u16) {
        let key = (mac, ip);

        if !self.hosts.contains_key(&key) {
            self.hosts.insert(key, HostRecord::new(mac, ip, 0));
        }

        if let Some(host) = self.hosts.get_mut(&key) {
            host.add_port(port);
        }
    }

    /// Add a given service.
    pub fn add_service(&mut self, svc: Service) {
        self.services.insert(svc);
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
    pub fn merge(&mut self, other: ScanReport) {
        for (key, other_host) in other.hosts {
            if !self.hosts.contains_key(&key) {
                self.hosts.insert(key, other_host);
            } else if let Some(host) = self.hosts.get_mut(&key) {
                host.add_ports(other_host.ports());
                host.flags |= other_host.flags;
            }
        }

        self.services.extend(other.services);
    }
}

impl Encode for ScanReport {
    fn encode(&self, buf: &mut BytesMut) {
        ScanReportHeader::from(self)
            .encode(buf);

        for host in self.hosts.values() {
            host.encode(buf);
        }

        for svc in &self.services {
            svc.encode(buf);
        }

        Service::control()
            .encode(buf)
    }
}

impl MessageBody for ScanReport {
    fn len(&self) -> usize {
        let mut len = mem::size_of::<ScanReportHeader>();

        for host in self.hosts.values() {
            len += host.len();
        }

        for svc in &self.services {
            len += svc.len();
        }

        let control = Service::control();

        len + control.len()
    }
}

/// Host record iterator.
pub struct HostRecordIterator<'a> {
    inner: HashMapIterator<'a, HostRecordKey, HostRecord>,
}

impl<'a> HostRecordIterator<'a> {
    /// Create a new host record iterator for a given scan report.
    fn new(report: &'a ScanReport) -> HostRecordIterator<'a> {
        HostRecordIterator {
            inner: report.hosts.iter()
        }
    }
}

impl<'a> Iterator for HostRecordIterator<'a> {
    type Item = &'a HostRecord;

    fn next(&mut self) -> Option<&'a HostRecord> {
        self.inner.next()
            .map(|(_, host)| host)
    }
}

impl<'a> ExactSizeIterator for HostRecordIterator<'a> {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Service iterator.
pub struct ServiceIterator<'a> {
    inner: HashSetIterator<'a, Service>,
}

impl<'a> ServiceIterator<'a> {
    /// Create a new service iterator for a given scan report.
    fn new(report: &'a ScanReport) -> ServiceIterator<'a> {
        ServiceIterator {
            inner: report.services.iter()
        }
    }
}

impl<'a> Iterator for ServiceIterator<'a> {
    type Item = &'a Service;

    fn next(&mut self) -> Option<&'a Service> {
        self.inner.next()
    }
}

impl<'a> ExactSizeIterator for ServiceIterator<'a> {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Socket address iterator.
pub struct SocketAddrIterator<'a> {
    host_iterator:  HostRecordIterator<'a>,
    saddr_iterator: Option<self::host::SocketAddrIterator<'a>>,
}

impl<'a> SocketAddrIterator<'a> {
    /// Create a new socket address iterator for a given scan report.
    fn new(report: &'a ScanReport) -> SocketAddrIterator<'a> {
        let mut host_iterator = report.hosts();

        let saddr_iterator = host_iterator.next()
            .map(|host| host.socket_addrs());

        SocketAddrIterator {
            host_iterator:  host_iterator,
            saddr_iterator: saddr_iterator
        }
    }
}

impl<'a> Iterator for SocketAddrIterator<'a> {
    type Item = (MacAddr, SocketAddr);

    fn next(&mut self) -> Option<(MacAddr, SocketAddr)> {
        while self.saddr_iterator.is_some() {
            let saddr = self.saddr_iterator.as_mut()
                .and_then(|saddr_iterator| saddr_iterator.next());

            if saddr.is_some() {
                return saddr;
            }

            self.saddr_iterator = self.host_iterator.next()
                .map(|host| host.socket_addrs());
        }

        None
    }
}

/// SCAN_REPORT message header.
#[repr(packed)]
struct ScanReportMessageHeader {
    request_id: u16,
}

impl ScanReportMessageHeader {
    /// Create a new SCAN_REPORT message header.
    fn new(request_id: u16) -> ScanReportMessageHeader {
        ScanReportMessageHeader {
            request_id: request_id,
        }
    }
}

impl Encode for ScanReportMessageHeader {
    fn encode(&self, buf: &mut BytesMut) {
        let be_header = ScanReportMessageHeader {
            request_id: self.request_id.to_be(),
        };

        buf.extend(utils::as_bytes(&be_header))
    }
}

/// SCAN_REPORT message.
pub struct ScanReportMessage {
    header:      ScanReportMessageHeader,
    scan_report: ScanReport,
}

impl ScanReportMessage {
    /// Create a new SCAN_REPORT message.
    pub fn new(
        request_id: u16,
        scan_report: ScanReport) -> ScanReportMessage {
        ScanReportMessage {
            header:      ScanReportMessageHeader::new(request_id),
            scan_report: scan_report,
        }
    }
}

impl Encode for ScanReportMessage {
    fn encode(&self, buf: &mut BytesMut) {
        self.header.encode(buf);
        self.scan_report.encode(buf);
    }
}

impl MessageBody for ScanReportMessage {
    fn len(&self) -> usize {
        mem::size_of::<ScanReportMessageHeader>()
            + self.scan_report.len()
    }
}

impl ControlMessageBody for ScanReportMessage {
}
