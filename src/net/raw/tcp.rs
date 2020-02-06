// Copyright 2015 click2stream, Inc.
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

//! TCP packet definitions.

use std::io;
use std::mem;
use std::slice;

use std::io::Write;

use crate::net::raw;
use crate::utils;

use crate::net::raw::ether::packet::{PacketParseError, Result};
use crate::net::raw::ip::{Ipv4PacketBody, Ipv4PacketHeader};

pub const TCP_FLAG_NS: u16 = 1 << 8;
pub const TCP_FLAG_CWR: u16 = 1 << 7;
pub const TCP_FLAG_ECE: u16 = 1 << 6;
pub const TCP_FLAG_URG: u16 = 1 << 5;
pub const TCP_FLAG_ACK: u16 = 1 << 4;
pub const TCP_FLAG_PSH: u16 = 1 << 3;
pub const TCP_FLAG_RST: u16 = 1 << 2;
pub const TCP_FLAG_SYN: u16 = 1 << 1;
pub const TCP_FLAG_FIN: u16 = 1;

/// TCP packet.
pub struct TcpPacket {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub wsize: u16,
    pub uptr: u16,
    pub options: Box<[u32]>,
    pub data: Box<[u8]>,
}

impl TcpPacket {
    /// Create a new TCP packet.
    pub fn new(sport: u16, dport: u16, flags: u16, data: &[u8]) -> Self {
        let data = data.to_vec().into_boxed_slice();

        Self {
            sport,
            dport,
            seq: 0,
            ack: 0,
            flags,
            wsize: 8192,
            uptr: 0,
            options: Box::new([]),
            data,
        }
    }

    /// Parse a TCP packet from given data.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let size = mem::size_of::<RawTcpPacketHeader>();

        if data.len() < size {
            Err(PacketParseError::from(
                "unable to parse TCP packet, not enough data",
            ))
        } else {
            let ptr = data.as_ptr();

            let rh = unsafe { &*(ptr as *const RawTcpPacketHeader) };

            let doffset_flags = u16::from_be(rh.doffset_flags);
            let doffset = doffset_flags >> 12;
            let options_len = doffset as usize - (size >> 2);

            let offset_1 = size;
            let offset_2 = offset_1 + (options_len << 2);

            if offset_2 > data.len() {
                Err(PacketParseError::from(
                    "unable to parse TCP packet, not enough data",
                ))
            } else {
                let options = unsafe {
                    slice::from_raw_parts(ptr.offset(offset_1 as isize) as *const u32, options_len)
                };

                let payload = &data[offset_2..];

                let res = Self {
                    sport: u16::from_be(rh.sport),
                    dport: u16::from_be(rh.dport),
                    seq: u32::from_be(rh.seq),
                    ack: u32::from_be(rh.ack),
                    flags: doffset_flags & 0x01ff,
                    wsize: u16::from_be(rh.wsize),
                    uptr: u16::from_be(rh.uptr),
                    options: options.to_vec().into_boxed_slice(),
                    data: payload.to_vec().into_boxed_slice(),
                };

                Ok(res)
            }
        }
    }
}

impl Ipv4PacketBody for TcpPacket {
    fn serialize(&self, iph: &Ipv4PacketHeader, w: &mut dyn Write) -> io::Result<()> {
        let rh = RawTcpPacketHeader::new(iph, self);

        w.write_all(utils::as_bytes(&rh))?;
        w.write_all(utils::slice_as_bytes(&self.options))?;
        w.write_all(&self.data)?;

        Ok(())
    }

    fn len(&self, _: &Ipv4PacketHeader) -> usize {
        let header_size = mem::size_of::<RawTcpPacketHeader>();
        let option_size = mem::size_of::<u32>();

        header_size + option_size * self.options.len() + self.data.len()
    }
}

/// Packed representation of the TCP packet header.
#[repr(packed)]
struct RawTcpPacketHeader {
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    doffset_flags: u16,
    wsize: u16,
    checksum: u16,
    uptr: u16,
}

impl RawTcpPacketHeader {
    /// Create a new raw TCP packet header.
    fn new(iph: &Ipv4PacketHeader, tcp: &TcpPacket) -> Self {
        let mut ph = PseudoIpv4PacketHeader::new(iph);
        let doffset = 5 + tcp.options.len() as u16;
        let doffset_flags = (doffset << 12) | (tcp.flags & 0x01ff);
        let tcp_len = (doffset << 2) + tcp.data.len() as u16;
        let mut rh = Self {
            sport: tcp.sport.to_be(),
            dport: tcp.dport.to_be(),
            seq: tcp.seq.to_be(),
            ack: tcp.ack.to_be(),
            doffset_flags: doffset_flags.to_be(),
            wsize: tcp.wsize.to_be(),
            checksum: 0,
            uptr: 0,
        };

        ph.tcp_len = tcp_len.to_be();

        let mut sum = raw::utils::sum_type(&ph);
        sum = sum.wrapping_add(raw::utils::sum_type(&rh));
        sum = sum.wrapping_add(raw::utils::sum_slice(&tcp.options));
        sum = sum.wrapping_add(raw::utils::sum_slice(&tcp.data));

        rh.checksum = raw::utils::sum_to_checksum(sum).to_be();

        rh
    }
}

/// Pseudo IPv4 packet header for TCP checksum computation.
#[repr(packed)]
#[allow(dead_code)]
struct PseudoIpv4PacketHeader {
    src: [u8; 4],
    dst: [u8; 4],
    res: u8,
    protocol: u8,
    tcp_len: u16,
}

impl PseudoIpv4PacketHeader {
    /// Create a new pseudo IPv4 packet header.
    fn new(iph: &Ipv4PacketHeader) -> Self {
        Self {
            src: iph.src.octets(),
            dst: iph.dst.octets(),
            res: 0,
            protocol: iph.protocol.code(),
            tcp_len: 0,
        }
    }
}

pub mod scanner {
    use super::*;

    use std::slice;

    use std::net::Ipv4Addr;
    use std::ops::Range;
    use std::time::Duration;

    use bytes::Bytes;

    use crate::net::raw::pcap;

    use crate::net::raw::devices::EthernetDevice;
    use crate::net::raw::ether::packet::EtherPacket;
    use crate::net::raw::ether::MacAddr;
    use crate::net::raw::ip::Ipv4Packet;
    use crate::net::raw::pcap::Scanner;
    use crate::net::raw::utils::Serialize;

    /// TCP port range.
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub enum PortRange {
        Single(u16),
        Range(Range<u16>),
    }

    impl PortRange {
        /// Convert TCP port range into a Range<u16> instance.
        fn to_range(&self) -> Range<u16> {
            match *self {
                Self::Range(ref r) => r.clone(),
                Self::Single(p) => p..(p + 1),
            }
        }
    }

    impl From<u16> for PortRange {
        fn from(p: u16) -> Self {
            Self::Single(p)
        }
    }

    impl From<Range<u16>> for PortRange {
        fn from(r: Range<u16>) -> Self {
            Self::Range(r)
        }
    }

    /// Collection of ports for PortScanner. (This collection does not handle
    /// port overlaps.)
    #[derive(Debug, Clone)]
    pub struct PortCollection {
        ranges: Vec<PortRange>,
    }

    impl PortCollection {
        /// Create a new empty collection of ports.
        pub fn new() -> Self {
            Self { ranges: Vec::new() }
        }

        /// Add a single port or a range.
        pub fn add<T>(mut self, v: T) -> Self
        where
            PortRange: From<T>,
        {
            self.ranges.push(PortRange::from(v));
            self
        }

        /// Add all ports/ranges in a given slice.
        pub fn add_all<C, I>(mut self, c: C) -> Self
        where
            C: IntoIterator<Item = I>,
            PortRange: From<I>,
        {
            for i in c.into_iter() {
                self.ranges.push(PortRange::from(i));
            }
            self
        }

        /// Get port collection iterator.
        pub fn iter(&self) -> PortCollectionIterator<'_> {
            PortCollectionIterator::new(self.ranges.iter())
        }
    }

    /// Port collection iterator.
    #[derive(Clone)]
    pub struct PortCollectionIterator<'a> {
        iter: slice::Iter<'a, PortRange>,
        last: u16,
        port: u16,
    }

    impl<'a> PortCollectionIterator<'a> {
        fn new(iter: slice::Iter<'a, PortRange>) -> Self {
            Self {
                iter,
                last: 0,
                port: 0,
            }
        }
    }

    impl<'a> Iterator for PortCollectionIterator<'a> {
        type Item = u16;

        fn next(&mut self) -> Option<u16> {
            if self.port >= self.last {
                if let Some(r) = self.iter.next() {
                    let r = r.to_range();
                    self.port = r.start;
                    self.last = r.end;
                }
            }

            if self.port < self.last {
                let res = self.port;
                self.port += 1;
                Some(res)
            } else {
                None
            }
        }
    }

    type Host = (MacAddr, Ipv4Addr);
    type Service = (MacAddr, Ipv4Addr, u16);

    /// TCP port scanner.
    pub struct TcpPortScanner {
        device: EthernetDevice,
        scanner: Scanner,
    }

    impl TcpPortScanner {
        /// Scan given IPv4 hosts for open ports from a given collection of
        /// ports. (It's expected the hosts are accessible through a local
        /// Ethernet network, the EthernetDevice and the MAC address must
        /// be also specified.)
        pub fn scan_ipv4_hosts<HI: Iterator<Item = (MacAddr, Ipv4Addr)>>(
            device: &EthernetDevice,
            hosts: HI,
            endpoints: &PortCollection,
        ) -> pcap::Result<Vec<(MacAddr, Ipv4Addr, u16)>> {
            Self::new(device).scan(hosts, endpoints)
        }

        /// Create a new port scanner.
        fn new(device: &EthernetDevice) -> Self {
            Self {
                device: device.clone(),
                scanner: Scanner::new(&device.name),
            }
        }

        /// Scan a given IPv4 hosts for open ports from a given collection of
        /// ports.
        fn scan<HI: Iterator<Item = Host>>(
            &mut self,
            hosts: HI,
            endpoints: &PortCollection,
        ) -> pcap::Result<Vec<Service>> {
            let sport = 61234;
            let mut gen = TcpPortScannerPacketGenerator::new(&self.device, hosts, sport, endpoints);

            let mut generator = move || gen.next().map(Bytes::from);

            let filter = format!(
                "tcp and dst host {} and dst port {} and \
                 tcp[tcpflags] & tcp-syn != 0 and \
                 tcp[tcpflags] & tcp-ack != 0",
                self.device.ip_addr, sport
            );
            let packets = self.scanner.sr(
                &filter,
                &mut generator,
                Duration::from_secs(2),
                Some(Duration::from_secs(20)),
            )?;

            let mut services = Vec::new();

            for ep in packets {
                let eh = ep.header();

                if let Some(ip) = ep.body::<Ipv4Packet>() {
                    let iph = ip.header();

                    if let Some(tcp) = ip.body::<TcpPacket>() {
                        let hsrc = eh.src;
                        let psrc = iph.src;

                        services.push((hsrc, psrc, tcp.sport))
                    }
                }
            }

            Ok(services)
        }
    }

    /// Packet generator for the TCP port scanner.
    struct TcpPortScannerPacketGenerator<'a, HI: Iterator<Item = Host>> {
        device: EthernetDevice,
        hosts: HI,
        sport: u16,
        endpoints: &'a PortCollection,
        host: Option<Host>,
        ports: PortCollectionIterator<'a>,
        buffer: Vec<u8>,
    }

    impl<'a, HI: Iterator<Item = Host>> TcpPortScannerPacketGenerator<'a, HI>
    where
        HI: Iterator<Item = Host>,
    {
        /// Create a new packet generator.
        fn new(
            device: &EthernetDevice,
            mut hosts: HI,
            sport: u16,
            endpoints: &'a PortCollection,
        ) -> TcpPortScannerPacketGenerator<'a, HI> {
            let host = hosts.next();
            let ports = endpoints.iter();
            TcpPortScannerPacketGenerator {
                device: device.clone(),
                hosts,
                sport,
                endpoints,
                host,
                ports,
                buffer: Vec::new(),
            }
        }

        /// Get next packet.
        fn next(&mut self) -> Option<&[u8]> {
            if let Some((hdst, pdst)) = self.host {
                if let Some(port) = self.ports.next() {
                    let tcpp = TcpPacket::new(self.sport, port, TCP_FLAG_SYN, &[]);
                    let ipp = Ipv4Packet::tcp(self.device.ip_addr, pdst, 64, tcpp);
                    let pkt = EtherPacket::ipv4(self.device.mac_addr, hdst, ipp);

                    self.buffer.clear();

                    pkt.serialize(&mut self.buffer).unwrap();

                    Some(self.buffer.as_ref())
                } else {
                    self.host = self.hosts.next();
                    self.ports = self.endpoints.iter();
                    self.next()
                }
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::scanner::PortCollection;

    use crate::net::raw::ether::packet::EtherPacket;
    use crate::net::raw::ether::MacAddr;
    use crate::net::raw::ip::*;
    use crate::net::raw::utils::Serialize;

    use std::net::Ipv4Addr;

    #[test]
    fn test_port_collection() {
        let col = PortCollection::new()
            .add_all([3, 5].iter().cloned())
            .add(10..15)
            .add(100);

        let mut iter = col.iter();

        let ports = vec![3, 5, 10, 11, 12, 13, 14, 100];

        for p in ports {
            assert_eq!(p, iter.next().unwrap());
        }
    }

    #[test]
    fn test_tcp_packet() {
        let sip = Ipv4Addr::new(192, 168, 3, 7);
        let dip = Ipv4Addr::new(192, 168, 8, 1);
        let mac = MacAddr::new(0, 0, 0, 0, 0, 0);

        let data = [1, 2, 3];

        let tcp = TcpPacket::new(10, 20, TCP_FLAG_FIN | TCP_FLAG_SYN, &data);
        let ip = Ipv4Packet::tcp(sip, dip, 64, tcp);
        let pkt = EtherPacket::ipv4(mac, mac, ip);

        let mut buf = Vec::new();

        pkt.serialize(&mut buf).unwrap();

        let ep2 = EtherPacket::parse(buf.as_ref()).unwrap();

        let ipp1 = pkt.body::<Ipv4Packet>().unwrap();
        let ipp2 = ep2.body::<Ipv4Packet>().unwrap();

        let tcpp1 = ipp1.body::<TcpPacket>().unwrap();
        let tcpp2 = ipp2.body::<TcpPacket>().unwrap();

        assert_eq!(tcpp1.sport, tcpp2.sport);
        assert_eq!(tcpp1.dport, tcpp2.dport);
        assert_eq!(tcpp1.seq, tcpp2.seq);
        assert_eq!(tcpp1.ack, tcpp2.ack);
        assert_eq!(tcpp1.flags, tcpp2.flags);
        assert_eq!(tcpp1.wsize, tcpp2.wsize);
        assert_eq!(tcpp1.uptr, tcpp2.uptr);
        assert_eq!(tcpp1.options, tcpp2.options);
        assert_eq!(tcpp1.data, tcpp2.data);
    }
}
