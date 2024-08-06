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

use std::io::Write;
use std::net::Ipv4Addr;

use crate::utils;

use crate::net::raw::ether::packet::{EtherPacketBody, PacketParseError, Result};
use crate::net::raw::ether::MacAddr;
use crate::net::raw::utils::Serialize;

/// ARP packet.
#[derive(Debug, Clone)]
pub struct ArpPacket {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub oper: ArpOperation,
    pub sha: Box<[u8]>,
    pub spa: Box<[u8]>,
    pub tha: Box<[u8]>,
    pub tpa: Box<[u8]>,
}

/// ARP operation.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ArpOperation {
    REQUEST,
    REPLY,
    UNKNOWN(u16),
}

impl ArpOperation {
    /// Get ARP operation code.
    pub fn code(self) -> u16 {
        match self {
            Self::REQUEST => 1,
            Self::REPLY => 2,
            Self::UNKNOWN(op) => op,
        }
    }
}

impl From<u16> for ArpOperation {
    fn from(v: u16) -> Self {
        match v {
            1 => Self::REQUEST,
            2 => Self::REPLY,
            op => Self::UNKNOWN(op),
        }
    }
}

const ARP_HTYPE_EHER: u16 = 0x0001;
const ARP_PTYPE_IPV4: u16 = 0x0800;

impl ArpPacket {
    /// Create a new ARP packet for IPv4 over Ethernet.
    pub fn ipv4_over_ethernet(
        oper: ArpOperation,
        sha: MacAddr,
        spa: Ipv4Addr,
        tha: MacAddr,
        tpa: Ipv4Addr,
    ) -> Self {
        Self {
            htype: ARP_HTYPE_EHER,
            ptype: ARP_PTYPE_IPV4,
            hlen: 6,
            plen: 4,
            oper,
            sha: sha.octets().to_vec().into_boxed_slice(),
            spa: spa.octets().to_vec().into_boxed_slice(),
            tha: tha.octets().to_vec().into_boxed_slice(),
            tpa: tpa.octets().to_vec().into_boxed_slice(),
        }
    }

    /// Parse given data.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let size = mem::size_of::<RawArpPacketHeader>();
        if data.len() < size {
            Err(PacketParseError::new(
                "unable to parse ARP packet, not enough data",
            ))
        } else {
            let ptr = data.as_ptr();
            let ptr = ptr as *const RawArpPacketHeader;

            let rh = unsafe { ptr.read_unaligned() };

            let hlen = rh.hlen as usize;
            let plen = rh.plen as usize;
            let required = size + (hlen << 1) + (plen << 1);

            if data.len() < required {
                Err(PacketParseError::new(
                    "unable to parse ARP packet, not enough data",
                ))
            } else {
                let offset_1 = size;
                let offset_2 = offset_1 + hlen;
                let offset_3 = offset_2 + plen;
                let offset_4 = offset_3 + hlen;

                let sha = &data[offset_1..offset_1 + hlen];
                let spa = &data[offset_2..offset_2 + plen];
                let tha = &data[offset_3..offset_3 + hlen];
                let tpa = &data[offset_4..offset_4 + plen];

                let res = Self {
                    htype: u16::from_be(rh.htype),
                    ptype: u16::from_be(rh.ptype),
                    hlen: rh.hlen,
                    plen: rh.plen,
                    oper: ArpOperation::from(u16::from_be(rh.oper)),
                    sha: sha.to_vec().into_boxed_slice(),
                    spa: spa.to_vec().into_boxed_slice(),
                    tha: tha.to_vec().into_boxed_slice(),
                    tpa: tpa.to_vec().into_boxed_slice(),
                };

                Ok(res)
            }
        }
    }
}

impl Serialize for ArpPacket {
    fn serialize(&self, w: &mut dyn Write) -> io::Result<()> {
        let rh = RawArpPacketHeader::new(self);

        w.write_all(utils::as_bytes(&rh))?;

        w.write_all(&self.sha)?;
        w.write_all(&self.spa)?;
        w.write_all(&self.tha)?;
        w.write_all(&self.tpa)?;

        Ok(())
    }
}

impl EtherPacketBody for ArpPacket {}

/// Packed representation of ARP packet header.
#[repr(packed)]
struct RawArpPacketHeader {
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    oper: u16,
}

impl RawArpPacketHeader {
    /// Create a new raw ARP packet header.
    fn new(arp: &ArpPacket) -> Self {
        let operation = arp.oper.code();

        Self {
            htype: arp.htype.to_be(),
            ptype: arp.ptype.to_be(),
            hlen: arp.hlen,
            plen: arp.plen,
            oper: operation.to_be(),
        }
    }
}

pub mod scanner {
    use super::*;

    use std::net::Ipv4Addr;
    use std::time::Duration;

    use bytes::Bytes;

    use crate::net::raw::pcap;

    use crate::net::raw::devices::EthernetDevice;
    use crate::net::raw::ether::packet::EtherPacket;
    use crate::net::raw::ether::MacAddr;
    use crate::net::raw::pcap::Scanner;
    use crate::net::raw::utils::Serialize;

    use crate::net::utils::Ipv4AddrEx;

    /// IPv4 ARP scanner.
    pub struct Ipv4ArpScanner {
        device: EthernetDevice,
        scanner: Scanner,
    }

    impl Ipv4ArpScanner {
        /// Scan a given device and return list of all active hosts.
        pub fn scan_device(device: &EthernetDevice) -> pcap::Result<Vec<(MacAddr, Ipv4Addr)>> {
            Self::new(device).scan()
        }

        /// Create a new scanner instance.
        fn new(device: &EthernetDevice) -> Self {
            Self {
                device: device.clone(),
                scanner: Scanner::new(device.name()),
            }
        }

        /// Scan a given device and return list of all active hosts.
        fn scan(&mut self) -> pcap::Result<Vec<(MacAddr, Ipv4Addr)>> {
            let bcast = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
            let hdst = MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
            let hsrc = self.device.mac_addr;
            let psrc = self.device.ip_addr;
            let mask = self.device.netmask.as_u32();
            let addr = self.device.ip_addr.as_u32();

            let end = addr | !mask;

            let mut current = (addr & mask) + 1;

            let mut buffer = Vec::new();

            let mut generator = move || {
                if current < end {
                    let pdst = Ipv4Addr::from(current);
                    let arpp = ArpPacket::ipv4_over_ethernet(
                        ArpOperation::REQUEST,
                        hsrc,
                        psrc,
                        hdst,
                        pdst,
                    );
                    let pkt = EtherPacket::arp(hsrc, bcast, arpp);

                    buffer.clear();

                    pkt.serialize(&mut buffer).unwrap();

                    current += 1;

                    let pkt = Bytes::copy_from_slice(&buffer);

                    Some(pkt)
                } else {
                    None
                }
            };

            let filter = format!("arp and ether dst {}", self.device.mac());

            let packets = self.scanner.sr(
                &filter,
                &mut generator,
                Duration::from_secs(2),
                Some(Duration::from_secs(20)),
            )?;

            let mut hosts = Vec::new();

            for ep in packets {
                if let Some(arp) = ep.body::<ArpPacket>() {
                    let sha = MacAddr::from_slice(arp.sha.as_ref());
                    let spa = Ipv4Addr::from_slice(arp.spa.as_ref());

                    hosts.push((sha, spa));
                }
            }

            Ok(hosts)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    use crate::net::raw::ether::packet::EtherPacket;
    use crate::net::raw::ether::MacAddr;
    use crate::net::raw::utils::Serialize;

    #[test]
    fn test_arp_packet() {
        let sip = Ipv4Addr::new(192, 168, 3, 7);
        let smac = MacAddr::new(1, 2, 3, 4, 5, 6);
        let dip = Ipv4Addr::new(192, 168, 8, 1);
        let dmac = MacAddr::new(6, 5, 4, 3, 2, 1);

        let arp = ArpPacket::ipv4_over_ethernet(ArpOperation::REQUEST, smac, sip, dmac, dip);
        let pkt = EtherPacket::arp(smac, dmac, arp);

        let mut buf = Vec::new();

        pkt.serialize(&mut buf).unwrap();

        let ep2 = EtherPacket::parse(buf.as_ref()).unwrap();

        let arpp1 = pkt.body::<ArpPacket>().unwrap();
        let arpp2 = ep2.body::<ArpPacket>().unwrap();

        assert_eq!(arpp1.htype, arpp2.htype);
        assert_eq!(arpp1.ptype, arpp2.ptype);
        assert_eq!(arpp1.hlen, arpp2.hlen);
        assert_eq!(arpp1.plen, arpp2.plen);
        assert_eq!(arpp1.oper, arpp2.oper);
        assert_eq!(arpp1.sha, arpp2.sha);
        assert_eq!(arpp1.spa, arpp2.spa);
        assert_eq!(arpp1.tha, arpp2.tha);
        assert_eq!(arpp1.tpa, arpp2.tpa);
    }
}
