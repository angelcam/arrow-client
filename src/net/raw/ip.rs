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

//! IP packet definitions.

use std::{
    any::Any,
    io::{self, Write},
    mem,
    net::Ipv4Addr,
};

use crate::{
    net::raw::{
        self,
        ether::packet::{EtherPacketBody, PacketParseError, Result},
        icmp::IcmpPacket,
        tcp::TcpPacket,
        utils::Serialize,
    },
    utils::{self, AsBytes},
};

pub const IP_PROTO_ICMP: u8 = 0x01;
pub const IP_PROTO_TCP: u8 = 0x06;
pub const IP_PROTO_UDP: u8 = 0x11;

/// IPv4 packet header.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Ipv4PacketHeader {
    pub version: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub ident: u16,
    pub flags: u8,
    pub foffset: u16,
    pub ttl: u8,
    pub protocol: Ipv4PacketType,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub options: Box<[u32]>,
    length: usize,
}

impl Ipv4PacketHeader {
    /// Create a new IPv4 header.
    pub fn new(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: Ipv4PacketType,
        ttl: u8,
    ) -> Ipv4PacketHeader {
        Ipv4PacketHeader {
            version: 4,
            dscp: 0,
            ecn: 0,
            ident: 0,
            flags: 0,
            foffset: 0,
            ttl,
            protocol,
            src,
            dst,
            options: Box::new([]),
            length: 0,
        }
    }

    /// Serialize header in-place using a given writer.
    fn serialize(&self, body: &dyn Ipv4PacketBody, w: &mut dyn Write) -> io::Result<()> {
        let rh = RawIpv4PacketHeader::new(self, body.len(self));

        let options = self.options.as_ref();

        w.write_all(rh.as_bytes())?;
        w.write_all(options.as_bytes())?;

        Ok(())
    }

    /// Read header from given raw representation.
    fn parse(data: &[u8]) -> Result<Ipv4PacketHeader> {
        let size = mem::size_of::<RawIpv4PacketHeader>();

        if data.len() < size {
            Err(PacketParseError::new(
                "unable to parse IPv4 packet, not enough data",
            ))
        } else {
            let ptr = data.as_ptr();

            let rh = unsafe { std::ptr::read_unaligned(ptr as *const RawIpv4PacketHeader) };

            let flags_foffset = u16::from_be(rh.flags_foffset);
            let ihl = rh.vihl & 0x0f;
            let options_len = ihl as usize - (size >> 2);
            let offset_1 = size as isize;

            if data.len() < (size + (options_len << 2)) {
                Err(PacketParseError::new(
                    "unable to parse IPv4 packet, not enough data",
                ))
            } else {
                let options = unsafe {
                    utils::vec_from_raw_parts_unaligned(
                        ptr.offset(offset_1) as *const u32,
                        options_len,
                    )
                };

                let res = Ipv4PacketHeader {
                    version: rh.vihl >> 4,
                    dscp: rh.dscp_ecn >> 2,
                    ecn: rh.dscp_ecn & 0x03,
                    ident: u16::from_be(rh.ident),
                    flags: (flags_foffset >> 13) as u8,
                    foffset: flags_foffset & 0x1fff,
                    ttl: rh.ttl,
                    protocol: Ipv4PacketType::from(rh.protocol),
                    src: Ipv4Addr::from(u32::from_be_bytes(rh.src)),
                    dst: Ipv4Addr::from(u32::from_be_bytes(rh.dst)),
                    options: options.into_boxed_slice(),
                    length: u16::from_be(rh.length) as usize,
                };

                Ok(res)
            }
        }
    }
}

/// Packed representation of the IPv4 packet header.
#[repr(C, packed)]
#[allow(dead_code)]
#[derive(Copy, Clone)]
struct RawIpv4PacketHeader {
    vihl: u8,
    dscp_ecn: u8,
    length: u16,
    ident: u16,
    flags_foffset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src: [u8; 4],
    dst: [u8; 4],
}

impl RawIpv4PacketHeader {
    /// Create a new raw IPv4 packet header.
    fn new(ip: &Ipv4PacketHeader, dlen: usize) -> RawIpv4PacketHeader {
        let size = mem::size_of::<RawIpv4PacketHeader>();
        let length = size + (ip.options.len() << 2) + dlen;
        let ihl = 5 + ip.options.len() as u8;
        let flags_foffset = ((ip.flags as u16) << 13) | (ip.foffset & 0x1fff);
        let mut rh = RawIpv4PacketHeader {
            vihl: (ip.version << 4) | (ihl & 0x0f),
            dscp_ecn: (ip.dscp << 2) | (ip.ecn & 0x03),
            length: (length as u16).to_be(),
            ident: ip.ident.to_be(),
            flags_foffset: flags_foffset.to_be(),
            ttl: ip.ttl,
            protocol: ip.protocol.code(),
            checksum: 0,
            src: ip.src.octets(),
            dst: ip.dst.octets(),
        };

        let mut sum = raw::utils::sum_type(&rh);
        sum = sum.wrapping_add(raw::utils::sum_slice(&ip.options));

        rh.checksum = raw::utils::sum_to_checksum(sum).to_be();

        rh
    }
}

/// IPv4 packet types.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Ipv4PacketType {
    ICMP,
    TCP,
    UDP,
    UNKNOWN(u8),
}

impl Ipv4PacketType {
    /// Get protocol code of this packet type.
    pub fn code(self) -> u8 {
        match self {
            Ipv4PacketType::ICMP => IP_PROTO_ICMP,
            Ipv4PacketType::TCP => IP_PROTO_TCP,
            Ipv4PacketType::UDP => IP_PROTO_UDP,
            Ipv4PacketType::UNKNOWN(pt) => pt,
        }
    }
}

impl From<u8> for Ipv4PacketType {
    /// Get IPv4 packet type from a given code.
    fn from(code: u8) -> Ipv4PacketType {
        match code {
            IP_PROTO_ICMP => Ipv4PacketType::ICMP,
            IP_PROTO_TCP => Ipv4PacketType::TCP,
            IP_PROTO_UDP => Ipv4PacketType::UDP,
            pt => Ipv4PacketType::UNKNOWN(pt),
        }
    }
}

/// Common trait for IPv4 body implementations.
pub trait Ipv4PacketBody: Send + Any {
    /// Serialize the packet body in-place using a given writer.
    fn serialize(&self, iph: &Ipv4PacketHeader, w: &mut dyn Write) -> io::Result<()>;

    /// Get body length.
    fn len(&self, iph: &Ipv4PacketHeader) -> usize;
}

impl Ipv4PacketBody for Vec<u8> {
    fn serialize(&self, _: &Ipv4PacketHeader, w: &mut dyn Write) -> io::Result<()> {
        w.write_all(self)
    }

    fn len(&self, _: &Ipv4PacketHeader) -> usize {
        Vec::<u8>::len(self)
    }
}

/// IPv4 packet.
pub struct Ipv4Packet {
    header: Ipv4PacketHeader,
    body: Box<dyn Ipv4PacketBody>,
}

impl Ipv4Packet {
    /// Create a new IPv4 packet.
    pub fn new<B>(header: Ipv4PacketHeader, body: B) -> Ipv4Packet
    where
        B: 'static + Ipv4PacketBody,
    {
        Ipv4Packet {
            header,
            body: Box::new(body),
        }
    }

    /// Create a new IPv4 packet with ICMP packet payload.
    pub fn icmp(saddr: Ipv4Addr, daddr: Ipv4Addr, ttl: u8, body: IcmpPacket) -> Ipv4Packet {
        Ipv4Packet::new(
            Ipv4PacketHeader::new(saddr, daddr, Ipv4PacketType::ICMP, ttl),
            body,
        )
    }

    /// Create a new IPv4 packet with TCP packet payload.
    pub fn tcp(saddr: Ipv4Addr, daddr: Ipv4Addr, ttl: u8, body: TcpPacket) -> Ipv4Packet {
        Ipv4Packet::new(
            Ipv4PacketHeader::new(saddr, daddr, Ipv4PacketType::TCP, ttl),
            body,
        )
    }

    /// Parse an IPv4 packet from given data.
    pub fn parse(data: &[u8]) -> Result<Ipv4Packet> {
        let hsize = mem::size_of::<RawIpv4PacketHeader>();

        if data.len() < hsize {
            Err(PacketParseError::new(
                "unable to parse IPv4 packet, not enough data",
            ))
        } else {
            let header = Ipv4PacketHeader::parse(data)?;
            let offset = hsize + (header.options.len() << 2);

            let payload = &data[offset..];

            let packet = match header.protocol {
                Ipv4PacketType::ICMP => Ipv4Packet::new(header, IcmpPacket::parse(payload)?),
                Ipv4PacketType::TCP => Ipv4Packet::new(header, TcpPacket::parse(payload)?),
                _ => Ipv4Packet::new(header, payload.to_vec()),
            };

            Ok(packet)
        }
    }

    /// Get packet header.
    pub fn header(&self) -> &Ipv4PacketHeader {
        &self.header
    }

    /// Get packet body.
    pub fn body<B>(&self) -> Option<&B>
    where
        B: 'static + Ipv4PacketBody,
    {
        <dyn Any>::downcast_ref(self.body.as_ref())
    }
}

impl Serialize for Ipv4Packet {
    fn serialize(&self, w: &mut dyn Write) -> io::Result<()> {
        self.header.serialize(self.body.as_ref(), w)?;
        self.body.serialize(&self.header, w)?;

        Ok(())
    }
}

impl EtherPacketBody for Ipv4Packet {}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::net::raw::ether::MacAddr;
    use crate::net::raw::ether::packet::EtherPacket;
    use crate::net::raw::tcp::*;
    use crate::net::raw::utils::Serialize;

    use std::net::Ipv4Addr;

    #[test]
    fn test_ip_packet() {
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

        let ipp1h = ipp1.header();
        let ipp2h = ipp2.header();

        assert_eq!(ipp1h.version, ipp2h.version);
        assert_eq!(ipp1h.dscp, ipp2h.dscp);
        assert_eq!(ipp1h.ecn, ipp2h.ecn);
        assert_eq!(ipp1h.ident, ipp2h.ident);
        assert_eq!(ipp1h.flags, ipp2h.flags);
        assert_eq!(ipp1h.foffset, ipp2h.foffset);
        assert_eq!(ipp1h.ttl, ipp2h.ttl);
        assert_eq!(ipp1h.protocol, ipp2h.protocol);
        assert_eq!(ipp1h.src, ipp2h.src);
        assert_eq!(ipp1h.dst, ipp2h.dst);
        assert_eq!(ipp1h.options, ipp2h.options);

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
