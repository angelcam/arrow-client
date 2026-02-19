// Copyright 2025 Angelcam, Inc.
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

use bytes::{Buf, Bytes, BytesMut};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, SizeError, Unaligned,
    byteorder::network_endian::{U16, U32},
};

use crate::net::raw::{
    self,
    ether::packet::{PacketParseError, Result},
    ip::{Ipv4PacketBody, Ipv4PacketHeader},
};

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
    pub options: Bytes,
    pub data: Bytes,
}

impl TcpPacket {
    /// Create a new TCP packet.
    pub fn new(sport: u16, dport: u16, flags: u16, data: Bytes) -> Self {
        assert!(data.len() <= ((u16::MAX as usize) - std::mem::size_of::<RawTcpPacketHeader>()));

        Self {
            sport,
            dport,
            seq: 0,
            ack: 0,
            flags,
            wsize: 8192,
            uptr: 0,
            options: Bytes::new(),
            data,
        }
    }

    /// Parse a TCP packet from given data.
    pub fn parse(data: &mut Bytes) -> Result<Self> {
        let mut tmp = data.clone();

        let size = std::mem::size_of::<RawTcpPacketHeader>();

        let (rh, _) = RawTcpPacketHeader::ref_from_prefix(&tmp)
            .map_err(SizeError::from)
            .map_err(|_| PacketParseError::new("unable to parse TCP packet, not enough data"))?;

        let doffset_flags = rh.doffset_flags.get();

        let mut res = Self {
            sport: rh.sport.get(),
            dport: rh.dport.get(),
            seq: rh.seq.get(),
            ack: rh.ack.get(),
            flags: doffset_flags & 0x01ff,
            wsize: rh.wsize.get(),
            uptr: rh.uptr.get(),
            options: Bytes::new(),
            data: Bytes::new(),
        };

        let doffset = doffset_flags >> 12;

        tmp.advance(std::mem::size_of::<RawTcpPacketHeader>());

        let options_len = usize::checked_sub(doffset as usize, size >> 2)
            .ok_or_else(|| PacketParseError::new("invalid TCP header length"))?;

        let options_size = options_len << 2;

        if tmp.len() < options_size {
            return Err(PacketParseError::new(
                "unable to parse TCP packet, not enough data",
            ));
        }

        res.options = tmp.split_to(options_size);
        res.data = tmp.split_to(tmp.len());

        *data = tmp;

        Ok(res)
    }
}

impl Ipv4PacketBody for TcpPacket {
    fn serialize(&self, iph: &Ipv4PacketHeader, buf: &mut BytesMut) {
        let rh = RawTcpPacketHeader::new(iph, self);

        let header = rh.as_bytes();

        let total_len = header.len() + self.options.len() + self.data.len();

        buf.reserve(total_len);

        buf.extend_from_slice(header);
        buf.extend_from_slice(&self.options);
        buf.extend_from_slice(&self.data);
    }

    fn len(&self, _: &Ipv4PacketHeader) -> usize {
        std::mem::size_of::<RawTcpPacketHeader>() + self.options.len() + self.data.len()
    }
}

/// Packed representation of the TCP packet header.
#[derive(Copy, Clone, KnownLayout, Immutable, Unaligned, IntoBytes, FromBytes)]
#[repr(C)]
struct RawTcpPacketHeader {
    sport: U16,
    dport: U16,
    seq: U32,
    ack: U32,
    doffset_flags: U16,
    wsize: U16,
    checksum: U16,
    uptr: U16,
}

impl RawTcpPacketHeader {
    /// Create a new raw TCP packet header.
    fn new(iph: &Ipv4PacketHeader, tcp: &TcpPacket) -> Self {
        let mut ph = PseudoIpv4PacketHeader::new(iph);
        let doffset = 5 + (tcp.options.len() >> 2) as u16;
        let doffset_flags = (doffset << 12) | (tcp.flags & 0x01ff);
        let tcp_len = (doffset << 2) + tcp.data.len() as u16;
        let mut rh = Self {
            sport: U16::new(tcp.sport),
            dport: U16::new(tcp.dport),
            seq: U32::new(tcp.seq),
            ack: U32::new(tcp.ack),
            doffset_flags: U16::new(doffset_flags),
            wsize: U16::new(tcp.wsize),
            checksum: U16::ZERO,
            uptr: U16::new(tcp.uptr),
        };

        ph.tcp_len = U16::new(tcp_len);

        let mut sum = raw::utils::sum_type(&ph);

        sum = sum.wrapping_add(raw::utils::sum_type(&rh));
        sum = sum.wrapping_add(raw::utils::sum_slice(&tcp.options));
        sum = sum.wrapping_add(raw::utils::sum_slice(&tcp.data));

        rh.checksum = U16::new(raw::utils::sum_to_checksum(sum));

        rh
    }
}

/// Pseudo IPv4 packet header for TCP checksum computation.
#[derive(Copy, Clone, KnownLayout, Immutable, Unaligned, IntoBytes, FromBytes)]
#[repr(C)]
struct PseudoIpv4PacketHeader {
    src: [u8; 4],
    dst: [u8; 4],
    res: u8,
    protocol: u8,
    tcp_len: U16,
}

impl PseudoIpv4PacketHeader {
    /// Create a new pseudo IPv4 packet header.
    fn new(iph: &Ipv4PacketHeader) -> Self {
        Self {
            src: iph.src.octets(),
            dst: iph.dst.octets(),
            res: 0,
            protocol: iph.protocol.code(),
            tcp_len: U16::ZERO,
        }
    }
}

pub mod scanner {
    use std::{net::Ipv4Addr, ops::Range, slice, time::Duration};

    use bytes::{Bytes, BytesMut};

    use crate::net::raw::{
        devices::EthernetDevice,
        ether::{
            MacAddr,
            packet::{EtherPacket, EtherPacketType},
        },
        ip::{Ipv4Packet, Ipv4PacketType},
        pcap::{self, Scanner},
        utils::Serialize,
    };

    use super::{TCP_FLAG_SYN, TcpPacket};

    /// TCP port range.
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub enum PortRange {
        Single(u16),
        Range(Range<u16>),
    }

    impl PortRange {
        /// Convert TCP port range into a Range<u16> instance.
        #[allow(clippy::range_plus_one)]
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
    #[derive(Default, Debug, Clone)]
    pub struct PortCollection {
        ranges: Vec<PortRange>,
    }

    impl PortCollection {
        /// Create a new empty collection of ports.
        pub fn new() -> Self {
            Self::default()
        }

        /// Add a single port or a range.
        pub fn push<T>(mut self, v: T) -> Self
        where
            PortRange: From<T>,
        {
            self.ranges.push(PortRange::from(v));
            self
        }

        /// Add all ports/ranges in a given slice.
        pub fn push_all<C, I>(mut self, c: C) -> Self
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
            if self.port >= self.last
                && let Some(r) = self.iter.next()
            {
                let r = r.to_range();
                self.port = r.start;
                self.last = r.end;
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
                scanner: Scanner::new(device.name()),
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
            let mut g = TcpPortScannerPacketGenerator::new(&self.device, hosts, sport, endpoints);

            let mut generator = move || g.next();

            let filter = format!(
                "tcp and dst host {} and dst port {} and \
                 tcp[tcpflags] & tcp-syn != 0 and \
                 tcp[tcpflags] & tcp-ack != 0",
                self.device.ip(),
                sport
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
                let eb = ep.body();

                if eh.packet_type() == EtherPacketType::IPv4
                    && let Ok(ip) = Ipv4Packet::parse(&mut eb.clone())
                {
                    let iph = ip.header();
                    let ipb = ip.body();

                    if iph.protocol == Ipv4PacketType::TCP
                        && let Ok(tcp) = TcpPacket::parse(&mut ipb.clone())
                    {
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
        buffer: BytesMut,
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
                buffer: BytesMut::new(),
            }
        }

        /// Get next packet.
        fn next(&mut self) -> Option<Bytes> {
            while let Some((hdst, pdst)) = self.host {
                if let Some(port) = self.ports.next() {
                    let tcpp =
                        TcpPacket::new(self.sport, port, TCP_FLAG_SYN, Bytes::from_static(&[]));
                    let ipp = Ipv4Packet::tcp(self.device.ip_addr, pdst, 64, tcpp);
                    let pkt = EtherPacket::ipv4(self.device.mac_addr, hdst, ipp);

                    pkt.serialize(&mut self.buffer);

                    let pkt = self.buffer.split();

                    return Some(pkt.freeze());
                } else {
                    self.host = self.hosts.next();
                    self.ports = self.endpoints.iter();
                }
            }

            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::{Bytes, BytesMut};

    use crate::net::raw::{
        ether::{
            MacAddr,
            packet::{EtherPacket, EtherPacketType},
        },
        ip::{Ipv4Packet, Ipv4PacketType},
        utils::Serialize,
    };

    use super::{TCP_FLAG_FIN, TCP_FLAG_SYN, TcpPacket, scanner::PortCollection};

    #[test]
    fn test_port_collection() {
        let col = PortCollection::new()
            .push_all([3, 5].iter().cloned())
            .push(10..15)
            .push(100);

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

        let data = Bytes::from_static(&[1, 2, 3]);

        let tcp = TcpPacket::new(10, 20, TCP_FLAG_FIN | TCP_FLAG_SYN, data);
        let ip = Ipv4Packet::tcp(sip, dip, 64, tcp);
        let pkt = EtherPacket::ipv4(mac, mac, ip);

        let mut buf = BytesMut::new();

        pkt.serialize(&mut buf);

        let ep2 = EtherPacket::parse(&mut buf.freeze()).unwrap();

        let ipp1 = pkt.body();

        let ep2h = ep2.header();
        let ep2b = ep2.body();

        assert_eq!(ep2h.packet_type(), EtherPacketType::IPv4);

        let ipp2 = Ipv4Packet::parse(&mut ep2b.clone()).unwrap();

        let tcpp1 = ipp1.body();

        let ipp2h = ipp2.header();
        let ipp2b = ipp2.body();

        assert_eq!(ipp2h.protocol, Ipv4PacketType::TCP);

        let tcpp2 = TcpPacket::parse(&mut ipp2b.clone()).unwrap();

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
