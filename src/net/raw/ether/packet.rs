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

use std::fmt;
use std::io;
use std::mem;
use std::result;

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::Write;

use crate::utils;

use crate::net::raw::arp::ArpPacket;
use crate::net::raw::ether::MacAddr;
use crate::net::raw::ip::Ipv4Packet;
use crate::net::raw::utils::Serialize;
use crate::utils::AsAny;

/// Packet parser error.
#[derive(Debug, Clone)]
pub struct PacketParseError {
    msg: String,
}

impl Error for PacketParseError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for PacketParseError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl<'a> From<&'a str> for PacketParseError {
    fn from(msg: &'a str) -> PacketParseError {
        PacketParseError {
            msg: msg.to_string(),
        }
    }
}

/// Type alias for parser results.
pub type Result<T> = result::Result<T, PacketParseError>;

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
    pub fn new(src: MacAddr, dst: MacAddr, etype: EtherPacketType) -> EtherPacketHeader {
        EtherPacketHeader {
            src: src,
            dst: dst,
            etype: etype.code(),
        }
    }

    /// Get packet type.
    pub fn packet_type(&self) -> EtherPacketType {
        EtherPacketType::from(self.etype)
    }

    /// Get raw header.
    fn raw_header(&self) -> RawEtherPacketHeader {
        RawEtherPacketHeader {
            src: self.src.octets(),
            dst: self.dst.octets(),
            etype: self.etype.to_be(),
        }
    }

    /// Read header from a given raw representation.
    fn parse(data: &[u8]) -> EtherPacketHeader {
        assert_eq!(data.len(), mem::size_of::<RawEtherPacketHeader>());

        let ptr = data.as_ptr();
        let ptr = ptr as *const RawEtherPacketHeader;

        let rh = unsafe { &*ptr };

        EtherPacketHeader {
            src: MacAddr::from_slice(&rh.src),
            dst: MacAddr::from_slice(&rh.dst),
            etype: u16::from_be(rh.etype),
        }
    }
}

impl Serialize for EtherPacketHeader {
    fn serialize(&self, w: &mut dyn Write) -> io::Result<()> {
        w.write_all(utils::as_bytes(&self.raw_header()))
    }
}

/// Packed representation of the Ethernet packet header.
#[repr(packed)]
struct RawEtherPacketHeader {
    dst: [u8; 6],
    src: [u8; 6],
    etype: u16,
}

/// Ethernet packet types.
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
            EtherPacketType::ARP => ETYPE_ARP,
            EtherPacketType::IPv4 => ETYPE_IPV4,
            EtherPacketType::UNKNOWN(pt) => pt,
        }
    }
}

impl From<u16> for EtherPacketType {
    /// Get ethernet packet type from a given code.
    fn from(code: u16) -> EtherPacketType {
        match code {
            ETYPE_ARP => EtherPacketType::ARP,
            ETYPE_IPV4 => EtherPacketType::IPv4,
            pt => EtherPacketType::UNKNOWN(pt),
        }
    }
}

/// Common trait for ethernet packet body implementations.
pub trait EtherPacketBody: AsAny + Send + Serialize {}

impl EtherPacketBody for Box<[u8]> {}

/// Ethernet packet.
pub struct EtherPacket {
    header: EtherPacketHeader,
    body: Box<dyn EtherPacketBody>,
}

impl EtherPacket {
    /// Create a new ethernet packet.
    pub fn new<B>(header: EtherPacketHeader, body: B) -> EtherPacket
    where
        B: 'static + EtherPacketBody,
    {
        EtherPacket {
            header: header,
            body: Box::new(body),
        }
    }

    /// Create a new ethernet packet with a given ARP packet payload.
    pub fn arp(src: MacAddr, dst: MacAddr, body: ArpPacket) -> EtherPacket {
        EtherPacket::new(EtherPacketHeader::new(src, dst, EtherPacketType::ARP), body)
    }

    /// Create a new ethernet packet with a given IPv4 packet payload.
    pub fn ipv4(src: MacAddr, dst: MacAddr, body: Ipv4Packet) -> EtherPacket {
        EtherPacket::new(
            EtherPacketHeader::new(src, dst, EtherPacketType::IPv4),
            body,
        )
    }

    /// Parse a given ethernet packet.
    pub fn parse(data: &[u8]) -> Result<EtherPacket> {
        let hsize = mem::size_of::<RawEtherPacketHeader>();

        if data.len() < hsize {
            Err(PacketParseError::from(
                "unable to parse ethernet packet, not enough data",
            ))
        } else {
            let header = EtherPacketHeader::parse(&data[..hsize]);

            let payload = &data[hsize..];

            let packet = match header.packet_type() {
                EtherPacketType::ARP => EtherPacket::new(header, ArpPacket::parse(payload)?),
                EtherPacketType::IPv4 => EtherPacket::new(header, Ipv4Packet::parse(payload)?),
                _ => EtherPacket::new(header, payload.to_vec().into_boxed_slice()),
            };

            Ok(packet)
        }
    }

    /// Get packet header.
    pub fn header(&self) -> &EtherPacketHeader {
        &self.header
    }

    /// Get packet body.
    pub fn body<B>(&self) -> Option<&B>
    where
        B: 'static + EtherPacketBody,
    {
        self.body.as_ref().as_any().downcast_ref()
    }
}

impl Serialize for EtherPacket {
    fn serialize(&self, w: &mut dyn Write) -> io::Result<()> {
        self.header.serialize(w)?;
        self.body.serialize(w)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::net::raw::arp::*;
    use crate::net::raw::utils::Serialize;

    use std::net::Ipv4Addr;

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
        let arp = ArpPacket::ipv4_over_ethernet(ArpOperation::REQUEST, &src, &sip, &dst, &dip);
        let pkt = EtherPacket::arp(src, dst, arp);

        let mut buf = Vec::new();

        pkt.serialize(&mut buf).unwrap();

        let ep2 = EtherPacket::parse(buf.as_ref()).unwrap();

        let pkth = pkt.header();
        let ep2h = ep2.header();

        assert_eq!(pkth.src.octets(), ep2h.src.octets());
        assert_eq!(pkth.dst.octets(), ep2h.dst.octets());
        assert_eq!(pkth.etype, ep2h.etype);
    }
}
