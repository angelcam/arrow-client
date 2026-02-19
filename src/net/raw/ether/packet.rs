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

use std::fmt::{self, Display, Formatter};

use bytes::{Buf, Bytes, BytesMut};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, SizeError, Unaligned,
    byteorder::network_endian::U16,
};

use crate::net::raw::{arp::ArpPacket, ether::MacAddr, ip::Ipv4Packet, utils::Serialize};

/// Packet parser error.
#[derive(Debug, Clone)]
pub struct PacketParseError {
    msg: String,
}

impl PacketParseError {
    /// Create a new error.
    pub fn new<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self {
            msg: msg.to_string(),
        }
    }
}

impl std::error::Error for PacketParseError {}

impl Display for PacketParseError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

/// Type alias for parser results.
pub type Result<T> = std::result::Result<T, PacketParseError>;

pub const ETYPE_ARP: u16 = 0x0806;
pub const ETYPE_IPV4: u16 = 0x0800;

/// Ethernet packet header.
#[derive(Debug, Copy, Clone)]
pub struct EtherPacketHeader {
    pub src: MacAddr,
    pub dst: MacAddr,
    pub etype: u16,
}

impl EtherPacketHeader {
    /// Create a new ethernet packet header.
    pub fn new(src: MacAddr, dst: MacAddr, etype: EtherPacketType) -> Self {
        Self {
            src,
            dst,
            etype: etype.code(),
        }
    }

    /// Get packet type.
    pub fn packet_type(&self) -> EtherPacketType {
        EtherPacketType::from(self.etype)
    }

    /// Read header from a given raw representation.
    fn parse(data: &mut Bytes) -> Result<Self> {
        let (rh, _) = RawEtherPacketHeader::ref_from_prefix(data)
            .map_err(SizeError::from)
            .map_err(|_| {
                PacketParseError::new("unable to parse ethernet packet, not enough data")
            })?;

        let res = Self {
            src: MacAddr::from(rh.src),
            dst: MacAddr::from(rh.dst),
            etype: rh.etype.get(),
        };

        data.advance(std::mem::size_of::<RawEtherPacketHeader>());

        Ok(res)
    }
}

impl Serialize for EtherPacketHeader {
    fn serialize(&self, buf: &mut BytesMut) {
        let rh = RawEtherPacketHeader {
            src: self.src.octets(),
            dst: self.dst.octets(),
            etype: U16::new(self.etype),
        };

        buf.extend_from_slice(rh.as_bytes())
    }
}

/// Packed representation of the Ethernet packet header.
#[derive(Copy, Clone, KnownLayout, Immutable, Unaligned, IntoBytes, FromBytes)]
#[repr(C)]
struct RawEtherPacketHeader {
    dst: [u8; 6],
    src: [u8; 6],
    etype: U16,
}

/// Ethernet packet types.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EtherPacketType {
    ARP,
    IPv4,
    UNKNOWN(u16),
}

impl EtherPacketType {
    /// Get system code of this packet type.
    pub fn code(self) -> u16 {
        match self {
            Self::ARP => ETYPE_ARP,
            Self::IPv4 => ETYPE_IPV4,
            Self::UNKNOWN(pt) => pt,
        }
    }
}

impl From<u16> for EtherPacketType {
    /// Get ethernet packet type from a given code.
    fn from(code: u16) -> Self {
        match code {
            ETYPE_ARP => Self::ARP,
            ETYPE_IPV4 => Self::IPv4,
            pt => Self::UNKNOWN(pt),
        }
    }
}

/// Ethernet packet.
pub struct EtherPacket<B> {
    header: EtherPacketHeader,
    body: B,
}

impl<B> EtherPacket<B> {
    /// Create a new ethernet packet.
    pub fn new(header: EtherPacketHeader, body: B) -> Self
    where
        B: Serialize,
    {
        Self { header, body }
    }

    /// Get packet header.
    pub fn header(&self) -> &EtherPacketHeader {
        &self.header
    }

    /// Get packet body.
    pub fn body(&self) -> &B {
        &self.body
    }
}

impl EtherPacket<ArpPacket> {
    /// Create a new ethernet packet with a given ARP packet payload.
    pub fn arp(src: MacAddr, dst: MacAddr, body: ArpPacket) -> Self {
        Self::new(EtherPacketHeader::new(src, dst, EtherPacketType::ARP), body)
    }
}

impl<B> EtherPacket<Ipv4Packet<B>>
where
    Ipv4Packet<B>: Serialize,
{
    /// Create a new ethernet packet with a given IPv4 packet payload.
    pub fn ipv4(src: MacAddr, dst: MacAddr, body: Ipv4Packet<B>) -> Self {
        Self::new(
            EtherPacketHeader::new(src, dst, EtherPacketType::IPv4),
            body,
        )
    }
}

impl EtherPacket<Bytes> {
    /// Parse a given ethernet packet.
    pub fn parse(data: &mut Bytes) -> Result<Self> {
        let header = EtherPacketHeader::parse(data)?;

        let body = data.split_to(data.len());

        let packet = Self::new(header, body);

        Ok(packet)
    }
}

impl<B> Serialize for EtherPacket<B>
where
    B: Serialize,
{
    fn serialize(&self, buf: &mut BytesMut) {
        self.header.serialize(buf);
        self.body.serialize(buf);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::BytesMut;

    use crate::net::raw::{
        arp::{ArpOperation, ArpPacket},
        ether::{MacAddr, packet::EtherPacket},
        utils::Serialize,
    };

    #[test]
    fn test_mac_addr() {
        let addr = MacAddr::new(1, 2, 3, 4, 5, 6);
        let octets = addr.octets();

        assert_eq!([1, 2, 3, 4, 5, 6], octets);

        let addr2 = MacAddr::from_slice(&octets);

        assert_eq!(octets, addr2.octets());
    }

    #[test]
    fn test_ether_packet() {
        let src = MacAddr::new(1, 2, 3, 4, 5, 6);
        let dst = MacAddr::new(6, 5, 4, 3, 2, 1);
        let sip = Ipv4Addr::new(192, 168, 3, 7);
        let dip = Ipv4Addr::new(192, 168, 8, 1);
        let arp = ArpPacket::ipv4_over_ethernet(ArpOperation::REQUEST, src, sip, dst, dip);
        let pkt = EtherPacket::arp(src, dst, arp);

        let mut buf = BytesMut::new();

        pkt.serialize(&mut buf);

        let ep2 = EtherPacket::parse(&mut buf.freeze()).unwrap();

        let pkth = pkt.header();
        let ep2h = ep2.header();

        assert_eq!(pkth.src.octets(), ep2h.src.octets());
        assert_eq!(pkth.dst.octets(), ep2h.dst.octets());
        assert_eq!(pkth.etype, ep2h.etype);
    }
}
