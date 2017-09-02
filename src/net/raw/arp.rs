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

//! ARP packet definitions.

use std::io;
use std::mem;

use utils;

use std::io::Write;
use std::net::Ipv4Addr;

use net::raw::ether::MacAddr;
use net::raw::ether::{Result, PacketParseError};
use net::raw::ether::{EtherPacketHeader, EtherPacketBody, EtherPacketType};

/// ARP packet.
#[derive(Debug, Clone)]
pub struct ArpPacket {
    pub htype: u16,
    pub ptype: u16,
    pub hlen:  u8,
    pub plen:  u8,
    pub oper:  ArpOperation,
    pub sha:   Vec<u8>,
    pub spa:   Vec<u8>,
    pub tha:   Vec<u8>,
    pub tpa:   Vec<u8>,
}

/// ARP operation.
#[derive(Debug, Copy, Clone)]
pub enum ArpOperation {
    REQUEST = 1,
    REPLY   = 2,
}

impl From<u16> for ArpOperation {
    fn from(v: u16) -> ArpOperation {
        match v {
            1 => ArpOperation::REQUEST,
            2 => ArpOperation::REPLY,
            _ => panic!("illegal value passed as ARP operation")
        }
    }
}

const ARP_HTYPE_EHER: u16 = 0x0001;
const ARP_PTYPE_IPV4: u16 = 0x0800;

impl ArpPacket {
    /// Create a new ARP packet for IPv4 over Ethernet.
    pub fn ipv4_over_ethernet(
        oper: ArpOperation,
        sha: &MacAddr,
        spa: &Ipv4Addr,
        tha: &MacAddr,
        tpa: &Ipv4Addr) -> ArpPacket {
        ArpPacket {
            htype: ARP_HTYPE_EHER,
            ptype: ARP_PTYPE_IPV4,
            hlen:  6,
            plen:  4,
            oper:  oper,
            sha:   sha.octets().to_vec(),
            spa:   spa.octets().to_vec(),
            tha:   tha.octets().to_vec(),
            tpa:   tpa.octets().to_vec()
        }
    }
}

impl EtherPacketBody for ArpPacket {
    fn parse(data: &[u8]) -> Result<ArpPacket> {
        let size = mem::size_of::<RawArpPacketHeader>();
        if data.len() < size {
            Err(PacketParseError::from("unable to parse ARP packet, not enough data"))
        } else {
            let ptr = data.as_ptr();
            let ptr = ptr as *const RawArpPacketHeader;
            let rh  = unsafe {
                &*ptr
            };

            let hlen = rh.hlen as usize;
            let plen = rh.plen as usize;
            let required = size
                + (hlen << 1)
                + (plen << 1);

            if data.len() < required {
                Err(PacketParseError::from("unable to parse ARP packet, not enough data"))
            } else {
                let offset_1 = size;
                let offset_2 = offset_1 + hlen;
                let offset_3 = offset_2 + plen;
                let offset_4 = offset_3 + hlen;

                let res = ArpPacket {
                    htype: u16::from_be(rh.htype),
                    ptype: u16::from_be(rh.ptype),
                    hlen:  rh.hlen,
                    plen:  rh.plen,
                    oper:  ArpOperation::from(u16::from_be(rh.oper)),
                    sha:   data[offset_1..offset_1+hlen].to_vec(),
                    spa:   data[offset_2..offset_2+plen].to_vec(),
                    tha:   data[offset_3..offset_3+hlen].to_vec(),
                    tpa:   data[offset_4..offset_4+plen].to_vec()
                };

                Ok(res)
            }
        }
    }

    fn serialize<W: Write>(
        &self,
        _: &EtherPacketHeader,
        w: &mut W) -> io::Result<()> {
        let rh = RawArpPacketHeader::new(self);
        try!(w.write_all(utils::as_bytes(&rh)));
        try!(w.write_all(&self.sha));
        try!(w.write_all(&self.spa));
        try!(w.write_all(&self.tha));
        w.write_all(&self.tpa)
    }

    fn packet_type(&self) -> EtherPacketType {
        EtherPacketType::ARP
    }
}

/// Packed representation of ARP packet header.
#[repr(packed)]
#[derive(Debug, Copy, Clone)]
struct RawArpPacketHeader {
    htype: u16,
    ptype: u16,
    hlen:  u8,
    plen:  u8,
    oper:  u16,
}

impl RawArpPacketHeader {
    /// Create a new raw ARP packet header.
    fn new(arp: &ArpPacket) -> RawArpPacketHeader {
        RawArpPacketHeader {
            htype: arp.htype.to_be(),
            ptype: arp.ptype.to_be(),
            hlen:  arp.hlen,
            plen:  arp.plen,
            oper:  (arp.oper as u16).to_be()
        }
    }
}

#[cfg(feature = "discovery")]
pub mod scanner {
    use super::*;

    use net::raw;
    use net::raw::pcap;

    use std::net::Ipv4Addr;

    use net::raw::Serialize;
    use net::raw::pcap::ThreadingContext;
    use net::raw::devices::EthernetDevice;
    use net::raw::ether::{MacAddr, EtherPacket};
    use net::raw::pcap::{Scanner, PacketGenerator};

    /// IPv4 ARP scanner.
    pub struct Ipv4ArpScanner {
        device:  EthernetDevice,
        scanner: Scanner,
    }

    impl Ipv4ArpScanner {
        /// Scan a given device and return list of all active hosts.
        pub fn scan_device(
            tc: ThreadingContext,
            device: &EthernetDevice) -> pcap::Result<Vec<(MacAddr, Ipv4Addr)>> {
            Ipv4ArpScanner::new(tc, device).scan()
        }

        /// Create a new scanner instance.
        fn new(
            tc: ThreadingContext,
            device: &EthernetDevice) -> Ipv4ArpScanner {
            Ipv4ArpScanner {
                device:  device.clone(),
                scanner: Scanner::new(tc, &device.name)
            }
        }

        /// Scan a given device and return list of all active hosts.
        fn scan(&mut self) -> pcap::Result<Vec<(MacAddr, Ipv4Addr)>> {
            let mut gen    = Ipv4ArpScannerPacketGenerator::new(&self.device);
            let filter     = format!("arp and ether dst {}",
                                self.device.mac_addr);
            let packets    = try!(self.scanner.sr(&filter,
                                &mut gen, 1000000000));
            let mut hosts  = Vec::new();

            for p in packets {
                if let Ok(ep) = EtherPacket::<ArpPacket>::parse(&p) {
                    let sha = MacAddr::from_slice(&ep.body.sha);
                    let spa = raw::utils::slice_to_ipv4addr(&ep.body.spa);
                    hosts.push((sha, spa));
                }
            }

            Ok(hosts)
        }
    }

    /// Packet generator for the IPv4 ARP scanner.
    struct Ipv4ArpScannerPacketGenerator {
        device:  EthernetDevice,
        hdst:    MacAddr,
        bcast:   MacAddr,
        current: u32,
        last:    u32,
        buffer:  Vec<u8>,
    }

    impl Ipv4ArpScannerPacketGenerator {
        /// Create a new packet generator.
        fn new(device: &EthernetDevice) -> Ipv4ArpScannerPacketGenerator {
            let bcast       = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
            let hdst        = MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
            let mask: u32   = raw::utils::ipv4addr_to_u32(&device.netmask);
            let addr: u32   = raw::utils::ipv4addr_to_u32(&device.ip_addr);
            let mut current = addr & mask;
            let last        = current | !mask;

            current += 1;

            Ipv4ArpScannerPacketGenerator {
                device:  device.clone(),
                hdst:    hdst,
                bcast:   bcast,
                current: current,
                last:    last,
                buffer:  Vec::new(),
            }
        }
    }

    impl PacketGenerator for Ipv4ArpScannerPacketGenerator {
        fn next<'a>(&'a mut self) -> Option<&'a [u8]> {
            if self.current < self.last {
                let pdst = Ipv4Addr::from(self.current);
                let arpp = ArpPacket::ipv4_over_ethernet(ArpOperation::REQUEST,
                    &self.device.mac_addr, &self.device.ip_addr,
                    &self.hdst, &pdst);
                let pkt  = EtherPacket::create(
                    self.device.mac_addr, self.bcast, arpp);

                self.buffer.clear();

                pkt.serialize(&mut self.buffer)
                    .unwrap();

                self.current += 1;

                Some(self.buffer.as_ref())
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    use net::raw::Serialize;
    use net::raw::ether::{MacAddr, EtherPacket};

    #[test]
    fn test_arp_packet() {
        let sip  = Ipv4Addr::new(192, 168, 3, 7);
        let smac = MacAddr::new(1, 2, 3, 4, 5, 6);
        let dip  = Ipv4Addr::new(192, 168, 8, 1);
        let dmac = MacAddr::new(6, 5, 4, 3, 2, 1);

        let arp = ArpPacket::ipv4_over_ethernet(ArpOperation::REQUEST,
            &smac, &sip, &dmac, &dip);
        let pkt = EtherPacket::create(smac, dmac, arp);

        let mut buf = Vec::new();

        pkt.serialize(&mut buf)
            .unwrap();

        let ep2 = EtherPacket::<ArpPacket>::parse(buf.as_ref())
            .unwrap();

        let arp  = &pkt.body;
        let arp2 = &ep2.body;

        assert_eq!(arp.htype,        arp2.htype);
        assert_eq!(arp.ptype,        arp2.ptype);
        assert_eq!(arp.hlen,         arp2.hlen);
        assert_eq!(arp.plen,         arp2.plen);
        assert_eq!(arp.oper as i32,  arp2.oper as i32);
        assert_eq!(arp.sha,          arp2.sha);
        assert_eq!(arp.spa,          arp2.spa);
        assert_eq!(arp.tha,          arp2.tha);
        assert_eq!(arp.tpa,          arp2.tpa);
    }
}
