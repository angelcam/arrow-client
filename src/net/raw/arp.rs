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

//! ARP packet definitions.

use std::net::Ipv4Addr;

use bytes::{Buf, Bytes, BytesMut};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, SizeError, Unaligned,
    byteorder::network_endian::U16,
};

use crate::net::raw::{
    ether::{
        MacAddr,
        packet::{PacketParseError, Result},
    },
    utils::Serialize,
};

/// ARP packet.
#[derive(Debug, Clone)]
pub struct ArpPacket {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub oper: ArpOperation,
    pub sha: Bytes,
    pub spa: Bytes,
    pub tha: Bytes,
    pub tpa: Bytes,
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
            sha: Bytes::copy_from_slice(&sha.octets()),
            spa: Bytes::copy_from_slice(&spa.octets()),
            tha: Bytes::copy_from_slice(&tha.octets()),
            tpa: Bytes::copy_from_slice(&tpa.octets()),
        }
    }

    /// Parse given data.
    pub fn parse(data: &mut Bytes) -> Result<Self> {
        let mut tmp = data.clone();

        let (rh, _) = RawArpPacketHeader::ref_from_prefix(&tmp)
            .map_err(SizeError::from)
            .map_err(|_| PacketParseError::new("unable to parse ARP packet, not enough data"))?;

        let mut res = Self {
            htype: rh.htype.get(),
            ptype: rh.ptype.get(),
            hlen: rh.hlen,
            plen: rh.plen,
            oper: ArpOperation::from(rh.oper.get()),
            sha: Bytes::new(),
            spa: Bytes::new(),
            tha: Bytes::new(),
            tpa: Bytes::new(),
        };

        let hlen = rh.hlen as usize;
        let plen = rh.plen as usize;

        tmp.advance(std::mem::size_of::<RawArpPacketHeader>());

        if tmp.len() < ((hlen + plen) << 1) {
            return Err(PacketParseError::new(
                "unable to parse ARP packet, not enough data",
            ));
        }

        res.sha = tmp.split_to(hlen);
        res.spa = tmp.split_to(plen);
        res.tha = tmp.split_to(hlen);
        res.tpa = tmp.split_to(plen);

        *data = tmp;

        Ok(res)
    }
}

impl Serialize for ArpPacket {
    fn serialize(&self, buf: &mut BytesMut) {
        let rh = RawArpPacketHeader::new(self);

        let header = rh.as_bytes();

        let total_len =
            header.len() + self.sha.len() + self.spa.len() + self.tha.len() + self.tpa.len();

        buf.reserve(total_len);

        buf.extend_from_slice(header);

        buf.extend_from_slice(&self.sha);
        buf.extend_from_slice(&self.spa);
        buf.extend_from_slice(&self.tha);
        buf.extend_from_slice(&self.tpa);
    }
}

/// Packed representation of ARP packet header.
#[derive(Copy, Clone, KnownLayout, Immutable, Unaligned, IntoBytes, FromBytes)]
#[repr(C)]
struct RawArpPacketHeader {
    htype: U16,
    ptype: U16,
    hlen: u8,
    plen: u8,
    oper: U16,
}

impl RawArpPacketHeader {
    /// Create a new raw ARP packet header.
    fn new(arp: &ArpPacket) -> Self {
        Self {
            htype: U16::new(arp.htype),
            ptype: U16::new(arp.ptype),
            hlen: arp.hlen,
            plen: arp.plen,
            oper: U16::new(arp.oper.code()),
        }
    }
}

pub mod scanner {
    use std::{net::Ipv4Addr, time::Duration};

    use bytes::BytesMut;

    use crate::net::raw::{
        devices::EthernetDevice,
        ether::{
            MacAddr,
            packet::{EtherPacket, EtherPacketType},
        },
        pcap::{self, Scanner},
        utils::Serialize,
    };

    use super::{ArpOperation, ArpPacket};

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
            let mask = u32::from(self.device.netmask);
            let addr = u32::from(self.device.ip_addr);

            let end = addr | !mask;

            let mut current = (addr & mask) + 1;

            let mut buffer = BytesMut::new();

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

                    pkt.serialize(&mut buffer);

                    current += 1;

                    let pkt = buffer.split();

                    Some(pkt.freeze())
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
                let eh = ep.header();
                let eb = ep.body();

                if eh.packet_type() == EtherPacketType::ARP
                    && let Ok(arp) = ArpPacket::parse(&mut eb.clone())
                {
                    let mut sha = [0u8; 6];
                    let mut spa = [0u8; 4];

                    sha.copy_from_slice(&arp.sha[..6]);
                    spa.copy_from_slice(&arp.spa[..4]);

                    let sha = MacAddr::from(sha);
                    let spa = Ipv4Addr::from(spa);

                    hosts.push((sha, spa));
                }
            }

            Ok(hosts)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::BytesMut;

    use crate::net::raw::{
        ether::{
            MacAddr,
            packet::{EtherPacket, EtherPacketType},
        },
        utils::Serialize,
    };

    use super::{ArpOperation, ArpPacket};

    #[test]
    fn test_arp_packet() {
        let sip = Ipv4Addr::new(192, 168, 3, 7);
        let smac = MacAddr::new(1, 2, 3, 4, 5, 6);
        let dip = Ipv4Addr::new(192, 168, 8, 1);
        let dmac = MacAddr::new(6, 5, 4, 3, 2, 1);

        let arp = ArpPacket::ipv4_over_ethernet(ArpOperation::REQUEST, smac, sip, dmac, dip);
        let pkt = EtherPacket::arp(smac, dmac, arp);

        let mut buf = BytesMut::new();

        pkt.serialize(&mut buf);

        let ep2 = EtherPacket::parse(&mut buf.freeze()).unwrap();

        let ep2h = ep2.header();
        let ep2b = ep2.body();

        assert_eq!(ep2h.packet_type(), EtherPacketType::ARP);

        let arpp1 = pkt.body();

        let arpp2 = ArpPacket::parse(&mut ep2b.clone()).unwrap();

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
