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

//! IP packet definitions.

use std::io;
use std::mem;

use utils;
use net::raw;

use std::io::Write;
use std::net::Ipv4Addr;

use utils::Serialize;
use net::raw::ether::{Result, PacketParseError};
use net::raw::ether::{EtherPacketHeader, EtherPacketBody, EtherPacketType};

pub const IP_PROTO_ICMP: u8 = 0x01;
pub const IP_PROTO_TCP:  u8 = 0x06;
pub const IP_PROTO_UDP:  u8 = 0x11;

/// IPv4 packet header.
#[derive(Clone, Debug)]
pub struct Ipv4PacketHeader {
    pub version:  u8,
    pub dscp:     u8,
    pub ecn:      u8,
    pub ident:    u16,
    pub flags:    u8,
    pub foffset:  u16,
    pub ttl:      u8,
    pub protocol: u8,
    pub src:      Ipv4Addr,
    pub dst:      Ipv4Addr,
    pub options:  Vec<u32>,
    length:       usize,
}

impl Ipv4PacketHeader {
    /// Create a new IPv4 header.
    pub fn new(
        src: Ipv4Addr, 
        dst: Ipv4Addr, 
        protocol: u8,
        ttl: u8) -> Ipv4PacketHeader {
        Ipv4PacketHeader {
            version:  4,
            dscp:     0,
            ecn:      0,
            ident:    0,
            flags:    0,
            foffset:  0,
            ttl:      ttl,
            protocol: protocol,
            src:      src,
            dst:      dst,
            options:  Vec::new(),
            length:   0
        }
    }
    
    /// Serialize header in-place using a given writer.
    fn serialize<W: Write>(&self, dlen: usize, w: &mut W) -> io::Result<()> {
        let rh = RawIpv4PacketHeader::new(self, dlen);
        try!(w.write_all(utils::as_bytes(&rh)));
        w.write_all(utils::slice_as_bytes(&self.options))
    }
    
    /// Read header from given raw representation.
    fn parse(data: &[u8]) -> Result<Ipv4PacketHeader> {
        let size = mem::size_of::<RawIpv4PacketHeader>();
        if data.len() < size {
            Err(PacketParseError::from("unable to parse IPv4 packet, not enough data"))
        } else {
            let ptr = data.as_ptr();
            let ptr = ptr as *const RawIpv4PacketHeader;
            let rh  = unsafe {
                &*ptr
            };
            
            let flags_foffset = u16::from_be(rh.flags_foffset);
            let ihl           = rh.vihl & 0x0f;
            let options_len   = ihl as usize - (size >> 2);
            let offset_1      = size as isize;
            
            if data.len() < (size + (options_len << 2)) {
                Err(PacketParseError::from("unable to parse IPv4 packet, not enough data"))
            } else {
                let options = unsafe {
                    utils::vec_from_raw_parts(
                        ptr.offset(offset_1) as *const u32, 
                        options_len)
                };
                
                let res = Ipv4PacketHeader {
                    version:  rh.vihl >> 4,
                    dscp:     rh.dscp_ecn >> 2,
                    ecn:      rh.dscp_ecn & 0x03,
                    ident:    u16::from_be(rh.ident),
                    flags:    (flags_foffset >> 13) as u8,
                    foffset:  flags_foffset & 0x1fff,
                    ttl:      rh.ttl,
                    protocol: rh.protocol,
                    src:      raw::utils::slice_to_ipv4addr(&rh.src),
                    dst:      raw::utils::slice_to_ipv4addr(&rh.dst),
                    options:  options,
                    length:   u16::from_be(rh.length) as usize
                };
                
                Ok(res)
            }
        }
    }
}

/// Packed representation of the IPv4 packet header.
#[repr(packed)]
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
struct RawIpv4PacketHeader {
    vihl:          u8,
    dscp_ecn:      u8,
    length:        u16,
    ident:         u16,
    flags_foffset: u16,
    ttl:           u8,
    protocol:      u8,
    checksum:      u16,
    src:           [u8; 4],
    dst:           [u8; 4],
}

impl RawIpv4PacketHeader {
    /// Create a new raw IPv4 packet header.
    fn new(ip: &Ipv4PacketHeader, dlen: usize) -> RawIpv4PacketHeader {
        let size          = mem::size_of::<RawIpv4PacketHeader>();
        let length        = size + (ip.options.len() << 2) + dlen;
        let ihl           = 5 + ip.options.len() as u8;
        let flags_foffset = ((ip.flags as u16) << 13) | (ip.foffset & 0x1fff);
        let mut rh        = RawIpv4PacketHeader {
            vihl:          (ip.version << 4) | (ihl & 0x0f),
            dscp_ecn:      (ip.dscp << 2) | (ip.ecn & 0x03),
            length:        (length as u16).to_be(),
            ident:         ip.ident.to_be(),
            flags_foffset: flags_foffset.to_be(),
            ttl:           ip.ttl,
            protocol:      ip.protocol,
            checksum:      0,
            src:           ip.src.octets(),
            dst:           ip.dst.octets()
        };
        
        let mut sum = raw::utils::sum_type(&rh);
        sum += raw::utils::sum_slice(&ip.options);
        
        rh.checksum = raw::utils::sum_to_checksum(sum).to_be();
        
        rh
    }
}

/// IPv4 packet types.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Ipv4PacketType {
    ICMP,
    TCP,
    UDP,
    UNKNOWN
}

impl Ipv4PacketType {
    /// Get protocol code of this packet type.
    pub fn code(self) -> u8 {
        match self {
            Ipv4PacketType::ICMP => IP_PROTO_ICMP,
            Ipv4PacketType::TCP  => IP_PROTO_TCP,
            Ipv4PacketType::UDP  => IP_PROTO_UDP,
            _ => panic!("no protocol code for unknown IPv4 packet type")
        }
    }
}

impl From<u8> for Ipv4PacketType {
    /// Get IPv4 packet type from a given code.
    fn from(code: u8) -> Ipv4PacketType {
        match code {
            IP_PROTO_ICMP => Ipv4PacketType::ICMP,
            IP_PROTO_TCP  => Ipv4PacketType::TCP,
            IP_PROTO_UDP  => Ipv4PacketType::UDP,
            _ => Ipv4PacketType::UNKNOWN
        }
    }
}

/// Common trait for IPv4 body implementations.
pub trait Ipv4PacketBody : Sized {
    /// Parse body from its raw representation.
    fn parse(data: &[u8]) -> Result<Self>;
    
    /// Serialize the packet body in-place using a given writer.
    fn serialize<W: Write>(
        &self, 
        iph: &Ipv4PacketHeader, 
        w: &mut W) -> io::Result<()>;
    
    /// Get IPv4 packet type of this body.
    fn packet_type(&self) -> Ipv4PacketType;
    
    /// Get body length.
    fn len(&self) -> usize;
}

impl Ipv4PacketBody for Vec<u8> {
    fn parse(data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn serialize<W: Write>(
        &self, 
        _: &Ipv4PacketHeader, 
        w: &mut W) -> io::Result<()> {
        w.write_all(self)
    }
    
    fn packet_type(&self) -> Ipv4PacketType {
        Ipv4PacketType::UNKNOWN
    }
    
    fn len(&self) -> usize {
        Vec::<u8>::len(self)
    }
}

/// IPv4 packet.
#[derive(Debug, Clone)]
pub struct Ipv4Packet<B: Ipv4PacketBody> {
    pub header: Ipv4PacketHeader,
    pub body:   B,
}

impl<B: Ipv4PacketBody> Ipv4Packet<B> {
    /// Create a new IPv4 packet.
    pub fn new(header: Ipv4PacketHeader, body: B) -> Ipv4Packet<B> {
        Ipv4Packet {
            header: header,
            body:   body
        }
    }
    
    /// Create a new IPv4 packet.
    pub fn create(
        saddr: Ipv4Addr,
        daddr: Ipv4Addr,
        ttl:   u8,
        body:  B) -> Ipv4Packet<B> {
        let pt     = body.packet_type();
        let header = Ipv4PacketHeader::new(saddr, daddr, pt.code(), ttl);
        Ipv4Packet::new(header, body)
    }
}

impl<B: Ipv4PacketBody> EtherPacketBody for Ipv4Packet<B> {
    fn parse(data: &[u8]) -> Result<Ipv4Packet<B>> {
        let hsize = mem::size_of::<RawIpv4PacketHeader>();
        if data.len() < hsize {
            Err(PacketParseError::from("unable to parse IPv4 packet, not enough data"))
        } else {
            let header = try!(Ipv4PacketHeader::parse(data));
            let offset = hsize + (header.options.len() << 2);
            let body   = try!(B::parse(&data[offset..]));
            let btype  = body.packet_type();
            if btype == Ipv4PacketType::UNKNOWN || 
                btype == Ipv4PacketType::from(header.protocol) {
                Ok(Ipv4Packet::new(header, body))
            } else {
                Err(PacketParseError::from("expected and actual IPv4 packet types do not match"))
            }
        }
    }
    
    fn serialize<W: Write>(
        &self, 
        _: &EtherPacketHeader,
        w: &mut W) -> io::Result<()> {
        let dlen = self.body.len();
        try!(self.header.serialize(dlen, w));
        self.body.serialize(&self.header, w)
    }
    
    fn packet_type(&self) -> EtherPacketType {
        EtherPacketType::IPv4
    }
}

#[cfg(test)]
mod tests { 
    use super::*;
    
    use net::raw::tcp::*;
    use utils::Serialize;
    use net::utils::WriteBuffer;
    use net::raw::ether::{MacAddr, EtherPacket};
    
    use std::net::Ipv4Addr;
    
    #[test]
    fn test_ip_packet() {
        let sip = Ipv4Addr::new(192, 168, 3, 7);
        let dip = Ipv4Addr::new(192, 168, 8, 1);
        let mac = MacAddr::new(0, 0, 0, 0, 0, 0);
        
        let data = [1, 2, 3];
        
        let tcp = TcpPacket::new(10, 20, TCP_FLAG_FIN | TCP_FLAG_SYN, &data);
        let ip  = Ipv4Packet::create(sip, dip, 64, tcp);
        let pkt = EtherPacket::create(mac, mac, ip);
        
        let mut buf = WriteBuffer::new(0);
        
        pkt.serialize(&mut buf)
            .unwrap();
        
        let ep2 = EtherPacket::<Ipv4Packet<TcpPacket>>::parse(buf.as_bytes())
            .unwrap();
        
        let iph  = &pkt.body.header;
        let iph2 = &ep2.body.header;
        
        assert_eq!(iph.version,  iph2.version);
        assert_eq!(iph.dscp,     iph2.dscp);
        assert_eq!(iph.ecn,      iph2.ecn);
        assert_eq!(iph.ident,    iph2.ident);
        assert_eq!(iph.flags,    iph2.flags);
        assert_eq!(iph.foffset,  iph2.foffset);
        assert_eq!(iph.ttl,      iph2.ttl);
        assert_eq!(iph.protocol, iph2.protocol);
        assert_eq!(iph.src,      iph2.src);
        assert_eq!(iph.dst,      iph2.dst);
        assert_eq!(iph.options,  iph2.options);
        
        let tcp  = &pkt.body.body;
        let tcp2 = &ep2.body.body;
        
        assert_eq!(tcp.sport,   tcp2.sport);
        assert_eq!(tcp.dport,   tcp2.dport);
        assert_eq!(tcp.seq,     tcp2.seq);
        assert_eq!(tcp.ack,     tcp2.ack);
        assert_eq!(tcp.flags,   tcp2.flags);
        assert_eq!(tcp.wsize,   tcp2.wsize);
        assert_eq!(tcp.uptr,    tcp2.uptr);
        assert_eq!(tcp.options, tcp2.options);
        assert_eq!(tcp.data,    tcp2.data);
    }
}
