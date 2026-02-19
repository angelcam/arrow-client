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

use std::{any::Any, mem, net::Ipv4Addr};

use bytes::{Buf, Bytes, BytesMut};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, SizeError, Unaligned,
    byteorder::network_endian::U16,
};

use crate::net::raw::{
    self,
    ether::packet::{PacketParseError, Result},
    icmp::IcmpPacket,
    tcp::TcpPacket,
    utils::Serialize,
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
    pub options: Bytes,
}

impl Ipv4PacketHeader {
    /// Create a new IPv4 header.
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, protocol: Ipv4PacketType, ttl: u8) -> Self {
        Self {
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
            options: Bytes::new(),
        }
    }

    /// Serialize header in-place using a given writer.
    fn serialize(&self, body: &dyn Ipv4PacketBody, buf: &mut BytesMut) {
        let rh = RawIpv4PacketHeader::new(self, body.len(self));

        let header = rh.as_bytes();

        let total_len = header.len() + self.options.len();

        buf.reserve(total_len);

        buf.extend_from_slice(header);
        buf.extend_from_slice(&self.options);
    }

    /// Read header from given raw representation.
    fn parse(data: &mut Bytes) -> Result<Self> {
        let mut tmp = data.clone();

        let size = mem::size_of::<RawIpv4PacketHeader>();

        let (rh, _) = RawIpv4PacketHeader::ref_from_prefix(&tmp)
            .map_err(SizeError::from)
            .map_err(|_| PacketParseError::new("unable to parse IPv4 packet, not enough data"))?;

        let flags_foffset = rh.flags_foffset.get();

        let mut res = Self {
            version: rh.vihl >> 4,
            dscp: rh.dscp_ecn >> 2,
            ecn: rh.dscp_ecn & 0x03,
            ident: rh.ident.get(),
            flags: (flags_foffset >> 13) as u8,
            foffset: flags_foffset & 0x1fff,
            ttl: rh.ttl,
            protocol: Ipv4PacketType::from(rh.protocol),
            src: Ipv4Addr::from(u32::from_be_bytes(rh.src)),
            dst: Ipv4Addr::from(u32::from_be_bytes(rh.dst)),
            options: Bytes::new(),
        };

        let ihl = rh.vihl & 0x0f;

        tmp.advance(mem::size_of::<RawIpv4PacketHeader>());

        let options_len = usize::checked_sub(ihl as usize, size >> 2)
            .ok_or_else(|| PacketParseError::new("invalid IPv4 header length"))?;

        let options_size = options_len << 2;

        if tmp.len() < options_size {
            return Err(PacketParseError::new(
                "unable to parse IPv4 packet, not enough data",
            ));
        }

        res.options = tmp.split_to(options_size);

        *data = tmp;

        Ok(res)
    }
}

/// Raw IPv4 packet header.
#[derive(Copy, Clone, KnownLayout, Immutable, Unaligned, IntoBytes, FromBytes)]
#[repr(C)]
struct RawIpv4PacketHeader {
    vihl: u8,
    dscp_ecn: u8,
    length: U16,
    ident: U16,
    flags_foffset: U16,
    ttl: u8,
    protocol: u8,
    checksum: U16,
    src: [u8; 4],
    dst: [u8; 4],
}

impl RawIpv4PacketHeader {
    /// Create a new raw IPv4 packet header.
    fn new(ip: &Ipv4PacketHeader, dlen: usize) -> Self {
        let size = mem::size_of::<Self>();
        let length = size + ip.options.len() + dlen;
        let ihl = 5 + (ip.options.len() >> 2) as u8;
        let flags_foffset = ((ip.flags as u16) << 13) | (ip.foffset & 0x1fff);
        let mut rh = Self {
            vihl: (ip.version << 4) | (ihl & 0x0f),
            dscp_ecn: (ip.dscp << 2) | (ip.ecn & 0x03),
            length: U16::new(length as u16),
            ident: U16::new(ip.ident),
            flags_foffset: U16::new(flags_foffset),
            ttl: ip.ttl,
            protocol: ip.protocol.code(),
            checksum: U16::ZERO,
            src: ip.src.octets(),
            dst: ip.dst.octets(),
        };

        let mut sum = raw::utils::sum_type(&rh);

        sum = sum.wrapping_add(raw::utils::sum_slice(&ip.options));

        rh.checksum = U16::new(raw::utils::sum_to_checksum(sum));

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
            Self::ICMP => IP_PROTO_ICMP,
            Self::TCP => IP_PROTO_TCP,
            Self::UDP => IP_PROTO_UDP,
            Self::UNKNOWN(pt) => pt,
        }
    }
}

impl From<u8> for Ipv4PacketType {
    /// Get IPv4 packet type from a given code.
    fn from(code: u8) -> Self {
        match code {
            IP_PROTO_ICMP => Self::ICMP,
            IP_PROTO_TCP => Self::TCP,
            IP_PROTO_UDP => Self::UDP,
            pt => Self::UNKNOWN(pt),
        }
    }
}

/// Common trait for IPv4 body implementations.
pub trait Ipv4PacketBody: Send + Any {
    /// Serialize the packet body in-place using a given writer.
    fn serialize(&self, iph: &Ipv4PacketHeader, buf: &mut BytesMut);

    /// Get body length.
    fn len(&self, iph: &Ipv4PacketHeader) -> usize;
}

impl Ipv4PacketBody for Bytes {
    fn serialize(&self, _: &Ipv4PacketHeader, buf: &mut BytesMut) {
        buf.extend_from_slice(self)
    }

    fn len(&self, _: &Ipv4PacketHeader) -> usize {
        Bytes::len(self)
    }
}

/// IPv4 packet.
pub struct Ipv4Packet<B> {
    header: Ipv4PacketHeader,
    body: B,
}

impl<B> Ipv4Packet<B> {
    /// Create a new IPv4 packet.
    pub fn new(header: Ipv4PacketHeader, body: B) -> Self
    where
        B: Ipv4PacketBody,
    {
        Self { header, body }
    }

    /// Get packet header.
    pub fn header(&self) -> &Ipv4PacketHeader {
        &self.header
    }

    /// Get packet body.
    pub fn body(&self) -> &B {
        &self.body
    }
}

impl Ipv4Packet<IcmpPacket> {
    /// Create a new IPv4 packet with ICMP packet payload.
    pub fn icmp(saddr: Ipv4Addr, daddr: Ipv4Addr, ttl: u8, body: IcmpPacket) -> Self {
        Ipv4Packet::new(
            Ipv4PacketHeader::new(saddr, daddr, Ipv4PacketType::ICMP, ttl),
            body,
        )
    }
}

impl Ipv4Packet<TcpPacket> {
    /// Create a new IPv4 packet with TCP packet payload.
    pub fn tcp(saddr: Ipv4Addr, daddr: Ipv4Addr, ttl: u8, body: TcpPacket) -> Self {
        Ipv4Packet::new(
            Ipv4PacketHeader::new(saddr, daddr, Ipv4PacketType::TCP, ttl),
            body,
        )
    }
}

impl Ipv4Packet<Bytes> {
    /// Parse an IPv4 packet from given data.
    pub fn parse(data: &mut Bytes) -> Result<Self> {
        let header = Ipv4PacketHeader::parse(data)?;

        let body = data.split_to(data.len());

        let packet = Self::new(header, body);

        Ok(packet)
    }
}

impl<B> Serialize for Ipv4Packet<B>
where
    B: Ipv4PacketBody,
{
    fn serialize(&self, buf: &mut BytesMut) {
        self.header.serialize(&self.body, buf);
        self.body.serialize(&self.header, buf);
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
        tcp::{TCP_FLAG_FIN, TCP_FLAG_SYN, TcpPacket},
        utils::Serialize,
    };

    use super::{Ipv4Packet, Ipv4PacketType};

    #[test]
    fn test_ip_packet() {
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

        let ep2h = ep2.header();
        let ep2b = ep2.body();

        assert_eq!(ep2h.packet_type(), EtherPacketType::IPv4);

        let ipp1 = pkt.body();

        let ipp2 = Ipv4Packet::parse(&mut ep2b.clone()).unwrap();

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

        let tcpp1 = ipp1.body();

        assert_eq!(ipp2h.protocol, Ipv4PacketType::TCP);

        let ipp2b = ipp2.body();

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
