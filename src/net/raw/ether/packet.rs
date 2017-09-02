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

use std::io;
use std::mem;
use std::fmt;
use std::result;

use utils;

use std::io::Write;
use std::error::Error;
use std::fmt::{Display, Formatter};

use net::raw::ether::MacAddr;
use net::raw::utils::Serialize;

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
        PacketParseError { msg: msg.to_string() }
    }
}

/// Type alias for parser results.
pub type Result<T> = result::Result<T, PacketParseError>;

pub const ETYPE_ARP:  u16 = 0x0806;
pub const ETYPE_IPV4: u16 = 0x0800;

/// Ethernet packet header.
#[derive(Debug, Copy, Clone)]
pub struct EtherPacketHeader {
    pub src:   MacAddr,
    pub dst:   MacAddr,
    pub etype: u16,
}

impl EtherPacketHeader {
    /// Create a new ethernet packet header.
    pub fn new(src: MacAddr, dst: MacAddr, etype: u16) -> EtherPacketHeader {
        EtherPacketHeader {
            src:   src,
            dst:   dst,
            etype: etype
        }
    }

    /// Get packet type.
    pub fn packet_type(&self) -> EtherPacketType {
        EtherPacketType::from(self.etype)
    }

    /// Get raw header.
    fn raw_header(&self) -> RawEtherPacketHeader {
        RawEtherPacketHeader {
            src:   self.src.octets(),
            dst:   self.dst.octets(),
            etype: self.etype.to_be()
        }
    }

    /// Read header from a given raw representation.
    fn parse(data: &[u8]) -> EtherPacketHeader {
        assert_eq!(data.len(), mem::size_of::<RawEtherPacketHeader>());
        let ptr = data.as_ptr();
        let ptr = ptr as *const RawEtherPacketHeader;
        let rh  = unsafe {
            &*ptr
        };

        EtherPacketHeader {
            src:   MacAddr::from_slice(&rh.src),
            dst:   MacAddr::from_slice(&rh.dst),
            etype: u16::from_be(rh.etype)
        }
    }
}

impl Serialize for EtherPacketHeader {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(utils::as_bytes(&self.raw_header()))
    }
}

/// Packed representation of the Ethernet packet header.
#[repr(packed)]
#[derive(Debug, Copy, Clone)]
struct RawEtherPacketHeader {
    dst:   [u8; 6],
    src:   [u8; 6],
    etype: u16,
}

/// Ethernet packet types.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EtherPacketType {
    ARP,
    IPv4,
    UNKNOWN
}

impl EtherPacketType {
    /// Get system code of this packet type.
    pub fn code(self) -> u16 {
        match self {
            EtherPacketType::ARP  => ETYPE_ARP,
            EtherPacketType::IPv4 => ETYPE_IPV4,
            _ => panic!("no etype code for unknown packet type")
        }
    }
}

impl From<u16> for EtherPacketType {
    /// Get ethernet packet type from a given code.
    fn from(code: u16) -> EtherPacketType {
        match code {
            ETYPE_ARP  => EtherPacketType::ARP,
            ETYPE_IPV4 => EtherPacketType::IPv4,
            _ => EtherPacketType::UNKNOWN
        }
    }
}

/// Common trait for ethernet packet body implementations.
pub trait EtherPacketBody : Sized {
    /// Parse body from its raw representation.
    fn parse(data: &[u8]) -> Result<Self>;

    /// Serialize the packet body in-place using a given writer.
    fn serialize<W: Write>(
        &self,
        eh: &EtherPacketHeader,
        w: &mut W) -> io::Result<()>;

    /// Get type of this body.
    fn packet_type(&self) -> EtherPacketType;
}

impl EtherPacketBody for Vec<u8> {
    fn parse(data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    fn serialize<W: Write>(
        &self,
        _: &EtherPacketHeader,
        w: &mut W) -> io::Result<()> {
        w.write_all(self)
    }

    fn packet_type(&self) -> EtherPacketType {
        EtherPacketType::UNKNOWN
    }
}

/// Ethernet packet.
#[derive(Debug, Clone)]
pub struct EtherPacket<B: EtherPacketBody> {
    pub header: EtherPacketHeader,
    pub body:   B,
}

impl<B: EtherPacketBody> EtherPacket<B> {
    /// Create a new ethernet packet.
    pub fn new(header: EtherPacketHeader, body: B) -> EtherPacket<B> {
        EtherPacket {
            header: header,
            body:   body
        }
    }

    /// Create a new ethernet packet.
    pub fn create(
        src: MacAddr,
        dst: MacAddr,
        body: B) -> EtherPacket<B> {
        let pt     = body.packet_type();
        let header = EtherPacketHeader::new(src, dst, pt.code());
        EtherPacket::new(header, body)
    }

    /// Parse a given ethernet packet.
    pub fn parse(data: &[u8]) -> Result<EtherPacket<B>> {
        let hsize = mem::size_of::<RawEtherPacketHeader>();
        if data.len() < hsize {
            Err(PacketParseError::from("unable to parse ethernet packet, not enough data"))
        } else {
            let header = EtherPacketHeader::parse(&data[..hsize]);
            let body   = try!(B::parse(&data[hsize..]));
            let btype  = body.packet_type();
            if btype == EtherPacketType::UNKNOWN ||
                btype == EtherPacketType::from(header.etype) {
                Ok(EtherPacket::new(header, body))
            } else {
                Err(PacketParseError::from("expect and actual ethernet packet types do not match"))
            }
        }
    }
}

impl<B: EtherPacketBody> Serialize for EtherPacket<B> {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        try!(self.header.serialize(w));
        self.body.serialize(&self.header, w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use net::raw::arp::*;
    use net::raw::Serialize;

    use std::net::Ipv4Addr;

    #[test]
    fn test_mac_addr() {
        let addr   = MacAddr::new(1, 2, 3, 4, 5, 6);
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
        let arp = ArpPacket::ipv4_over_ethernet(ArpOperation::REQUEST,
            &src, &sip, &dst, &dip);
        let pkt = EtherPacket::create(src, dst, arp);

        let mut buf = Vec::new();

        pkt.serialize(&mut buf)
            .unwrap();

        let ep2 = EtherPacket::<ArpPacket>::parse(buf.as_ref())
            .unwrap();

        assert_eq!(pkt.header.src.octets(), ep2.header.src.octets());
        assert_eq!(pkt.header.dst.octets(), ep2.header.dst.octets());
        assert_eq!(pkt.header.etype,        ep2.header.etype);
    }
}
