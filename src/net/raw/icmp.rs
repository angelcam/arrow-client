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

//! ICMP packet definitions.

use std::io;
use std::mem;

use std::io::Write;
use std::borrow::Borrow;

use utils;

use utils::Serialize;

use net::raw;

use net::raw::ether::{PacketParseError, Result};
use net::raw::ip::{Ipv4PacketHeader, Ipv4PacketType, Ipv4PacketBody};

const ICMP_TYPE_ECHO_REPLY: u8 = 0x00;
const ICMP_TYPE_ECHO:       u8 = 0x08;

/// ICMP packet type.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum IcmpPacketType {
    Echo,
    EchoReply,
    Unknown
}

impl IcmpPacketType {
    /// Get ICMP packet type code.
    fn code(&self) -> u8 {
        match self {
            &IcmpPacketType::Echo      => ICMP_TYPE_ECHO,
            &IcmpPacketType::EchoReply => ICMP_TYPE_ECHO_REPLY,
            &IcmpPacketType::Unknown => 
                panic!("no etype code for unknown packet type")
        }
    }
}

impl From<u8> for IcmpPacketType {
    fn from(code: u8) -> IcmpPacketType {
        match code {
            ICMP_TYPE_ECHO       => IcmpPacketType::Echo,
            ICMP_TYPE_ECHO_REPLY => IcmpPacketType::EchoReply,
            _ => IcmpPacketType::Unknown
        }
    }
}

/// ICMP packet.
#[derive(Debug, Clone)]
pub struct IcmpPacket<B> {
    pub icmp_type: IcmpPacketType,
    pub code:      u8,
    rest:          u32,
    body:          B
}

impl IcmpPacket<EmptyPayload> {
    /// Create a new echo request without payload.
    pub fn new_empty_echo_request(
        id: u16, 
        seq: u16) -> IcmpPacket<EmptyPayload> {
        IcmpPacket::new_echo_request(id, seq, EmptyPayload)
    }
}

impl<B: Borrow<[u8]>> IcmpPacket<B> {
    /// Create a new echo request.
    pub fn new_echo_request(id: u16, seq: u16, payload: B) -> IcmpPacket<B> {
        let id  = id as u32;
        let seq = seq as u32;
        IcmpPacket {
            icmp_type: IcmpPacketType::Echo,
            code:      0,
            rest:      (id << 16) | seq,
            body:      payload
        }
    }
    
    /// Get raw ICMP packet header.
    fn raw_header(&self) -> RawIcmpPacketHeader {
        let checksum = self.checksum();
        
        RawIcmpPacketHeader {
            icmp_type: self.icmp_type.code(),
            code:      self.code,
            checksum:  checksum.to_be(),
            rest:      self.rest.to_be()
        }
    }
    
    /// Get packet checksum.
    fn checksum(&self) -> u16 {
        let icmp_type = self.icmp_type.code() as u16;
        let icmp_code = self.code as u16;
        
        let body_bytes: &[u8] = self.body.borrow();
        
        let mut sum = ((icmp_type << 8) | icmp_code) as u32;
        
        sum += self.rest >> 16;
        sum += self.rest & 0xff;
        sum += raw::utils::sum_slice(body_bytes);
        
        raw::utils::sum_to_checksum(sum)
    }
}

impl<B: IcmpPacketBody> Ipv4PacketBody for IcmpPacket<B> {
    fn parse(data: &[u8]) -> Result<IcmpPacket<B>> {
        let size = mem::size_of::<RawIcmpPacketHeader>();
        if data.len() < size {
            Err(PacketParseError::from("unable to parse ICMP packet, not enough data"))
        } else {
            let ptr = data.as_ptr();
            let ptr = ptr as *const RawIcmpPacketHeader;
            let rh  = unsafe {
                &*ptr
            };
            
            let body = try!(B::parse(&data[size..]));
            
            let res = IcmpPacket {
                icmp_type: IcmpPacketType::from(rh.icmp_type),
                code:      rh.code,
                rest:      u32::from_be(rh.rest),
                body:      body
            };
            
            Ok(res)
        }
    }
    
    fn serialize<W: Write>(
        &self, 
        _: &Ipv4PacketHeader, 
        w: &mut W) -> io::Result<()> {
        let rh       = self.raw_header();
        let rh_bytes = utils::as_bytes(&rh);
        try!(w.write_all(rh_bytes));
        self.body.serialize(w)
    }
    
    fn packet_type(&self) -> Ipv4PacketType {
        Ipv4PacketType::ICMP
    }
    
    fn len(&self) -> usize {
        mem::size_of::<RawIcmpPacketHeader>() + self.body.len()
    }
}

/// Raw ICMP packet header.
#[repr(packed)]
#[derive(Debug, Copy, Clone)]
struct RawIcmpPacketHeader {
    icmp_type: u8,
    code:      u8,
    checksum:  u16,
    rest:      u32
}

pub trait IcmpPacketBody : Serialize + Sized + Borrow<[u8]> {
    /// Parse ICMP packet body.
    fn parse(data: &[u8]) -> Result<Self>;
    
    /// Get body length.
    fn len(&self) -> usize;
}

pub trait IcmpEchoPacket<P> {
    /// Get ICMP echo identifier.
    fn identifier(&self) -> u16;
    
    /// Get ICMP echo sequence number.
    fn seq_number(&self) -> u16;
    
    /// Get ICMP echo payload.
    fn payload(&self) -> &P;
}

impl<P> IcmpEchoPacket<P> for IcmpPacket<P> {
    fn identifier(&self) -> u16 {
        (self.rest >> 16) as u16
    }
    
    fn seq_number(&self) -> u16 {
        (self.rest & 0xff) as u16
    }
    
    fn payload(&self) -> &P {
        &self.body
    }
}

/// Empty payload to be used in combination with ICMP packets.
#[derive(Debug, Copy, Clone)]
pub struct EmptyPayload;

impl Borrow<[u8]> for EmptyPayload {
    fn borrow(&self) -> &[u8] {
        &[]
    }
}

impl Serialize for EmptyPayload {
    fn serialize<W: Write>(&self, _: &mut W) -> io::Result<()> {
        Ok(())
    }
}

impl IcmpPacketBody for EmptyPayload {
    fn parse(data: &[u8]) -> Result<EmptyPayload> {
        if data.is_empty() {
            Ok(EmptyPayload)
        } else {
            Err(PacketParseError::from("empty ICMP payload expected"))
        }
    }
    
    fn len(&self) -> usize {
        0
    }
}

impl IcmpPacketBody for Vec<u8> {
    fn parse(data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn len(&self) -> usize {
        Vec::<u8>::len(self)
    }
}

#[cfg(feature = "discovery")]
pub mod scanner {
    use super::*;
    
    use net::raw;
    use net::raw::pcap;
    
    use std::net::Ipv4Addr;
    
    use utils::Serialize;
    use net::utils::WriteBuffer;
    use net::raw::ip::Ipv4Packet;
    use net::raw::pcap::ThreadingContext;
    use net::raw::devices::EthernetDevice;
    use net::raw::ether::{MacAddr, EtherPacket};
    use net::raw::pcap::{Scanner, PacketGenerator};
    
    /// Type alias for the expected packet type.
    type ParsePacketType = EtherPacket<Ipv4Packet<IcmpPacket<Vec<u8>>>>;
    
    /// ICMP scanner.
    pub struct IcmpScanner {
        device:  EthernetDevice,
        scanner: Scanner,
        mask:    u32,
        network: u32
    }
    
    impl IcmpScanner {
        /// Scan a given device and return list of all active hosts.
        pub fn scan_device(
            tc: ThreadingContext, 
            device: &EthernetDevice) -> pcap::Result<Vec<(MacAddr, Ipv4Addr)>> {
            IcmpScanner::new(tc, device).scan()
        }
        
        /// Create a new scanner instance.
        fn new(
            tc: ThreadingContext, 
            device: &EthernetDevice) -> IcmpScanner {
            let mask    = raw::utils::ipv4addr_to_u32(&device.netmask);
            let addr    = raw::utils::ipv4addr_to_u32(&device.ip_addr);
            let network = addr & mask;
            
            IcmpScanner {
                device:  device.clone(),
                scanner: Scanner::new(tc, &device.name),
                mask:    mask,
                network: network
            }
        }
        
        /// Scan a given device and return list of all active hosts.
        fn scan(&mut self) -> pcap::Result<Vec<(MacAddr, Ipv4Addr)>> {
            let mut gen = IcmpPacketGenerator::new(&self.device);
            let filter  = format!("icmp and icmp[icmptype] = icmp-echoreply \
                                    and ip dst {}", self.device.ip_addr);
            let packets = try!(self.scanner.sr(&filter, &mut gen, 1000000000));
            
            let mut hosts = Vec::new();
            
            for p in packets {
                if let Ok(ep) = ParsePacketType::parse(&p) {
                    let iph = &ep.body.header;
                    let sha = ep.header.src;
                    let spa = iph.src;
                    let nwa = raw::utils::ipv4addr_to_u32(&spa) & self.mask;
                    // check if the received packet is from the same subnet
                    if nwa == self.network {
                        hosts.push((sha, spa));
                    }
                }
            }
            
            Ok(hosts)
        }
    }
    
    /// Packet generator for the ICMP scanner.
    struct IcmpPacketGenerator {
        device:  EthernetDevice,
        bcast:   MacAddr,
        current: u32,
        last:    u32,
        buffer:  WriteBuffer,
    }
    
    impl IcmpPacketGenerator {
        /// Create a new packet generator.
        fn new(device: &EthernetDevice) -> IcmpPacketGenerator {
            let bcast       = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
            let mask: u32   = raw::utils::ipv4addr_to_u32(&device.netmask);
            let addr: u32   = raw::utils::ipv4addr_to_u32(&device.ip_addr);
            let mut current = addr & mask;
            let last        = current | !mask;
            
            current += 1;
            
            IcmpPacketGenerator {
                device:  device.clone(),
                bcast:   bcast,
                current: current,
                last:    last,
                buffer:  WriteBuffer::new(0)
            }
        }
    }
    
    impl PacketGenerator for IcmpPacketGenerator {
        fn next<'a>(&'a mut self) -> Option<&'a [u8]> {
            if self.current < self.last {
                let icmp_id  = (self.current >> 16) as u16;
                let icmp_seq = (self.current & 0xff) as u16;
                
                let pdst = Ipv4Addr::from(self.current);
                
                let icmpp = IcmpPacket::new_empty_echo_request(
                    icmp_id, icmp_seq);
                let ipp   = Ipv4Packet::create(
                    self.device.ip_addr, pdst, 64, icmpp);
                let pkt   = EtherPacket::create(
                    self.device.mac_addr, self.bcast, ipp);
                
                self.buffer.clear();
                
                pkt.serialize(&mut self.buffer)
                    .unwrap();
                
                self.current += 1;
                
                Some(self.buffer.as_bytes())
            } else {
                None
            }
        }
    }
}
