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

//! ICMP packet definitions.

use bytes::{Buf, Bytes, BytesMut};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, SizeError, Unaligned,
    byteorder::network_endian::{U16, U32},
};

use crate::net::raw::{
    self,
    ether::packet::{PacketParseError, Result},
    ip::{Ipv4PacketBody, Ipv4PacketHeader},
};

const ICMP_TYPE_ECHO_REPLY: u8 = 0x00;
const ICMP_TYPE_ECHO: u8 = 0x08;

/// ICMP packet type.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum IcmpPacketType {
    Echo,
    EchoReply,
    Unknown(u8),
}

impl IcmpPacketType {
    /// Get ICMP packet type code.
    fn code(self) -> u8 {
        match self {
            Self::Echo => ICMP_TYPE_ECHO,
            Self::EchoReply => ICMP_TYPE_ECHO_REPLY,
            Self::Unknown(pt) => pt,
        }
    }
}

impl From<u8> for IcmpPacketType {
    fn from(code: u8) -> Self {
        match code {
            ICMP_TYPE_ECHO => Self::Echo,
            ICMP_TYPE_ECHO_REPLY => Self::EchoReply,
            pt => Self::Unknown(pt),
        }
    }
}

/// ICMP packet.
pub struct IcmpPacket {
    icmp_type: IcmpPacketType,
    code: u8,
    rest: u32,
    body: Bytes,
}

impl IcmpPacket {
    /// Create a new echo request.
    pub fn echo_request(id: u16, seq: u16, body: Bytes) -> Self {
        let id = id as u32;
        let seq = seq as u32;

        Self {
            icmp_type: IcmpPacketType::Echo,
            code: 0,
            rest: (id << 16) | seq,
            body,
        }
    }

    /// Create a new echo request without payload.
    pub fn empty_echo_request(id: u16, seq: u16) -> Self {
        Self::echo_request(id, seq, Bytes::from_static(&[]))
    }

    /// Parse an ICMP packet from given data.
    pub fn parse(data: &mut Bytes) -> Result<Self> {
        let (rh, _) = RawIcmpPacketHeader::ref_from_prefix(data)
            .map_err(SizeError::from)
            .map_err(|_| PacketParseError::new("unable to parse ICMP packet, not enough data"))?;

        let mut res = Self {
            icmp_type: IcmpPacketType::from(rh.icmp_type),
            code: rh.code,
            rest: rh.rest.get(),
            body: Bytes::new(),
        };

        data.advance(std::mem::size_of::<RawIcmpPacketHeader>());

        res.body = data.split_to(data.len());

        Ok(res)
    }

    /// Get packet checksum.
    fn checksum(&self) -> u16 {
        let icmp_type = self.icmp_type.code() as u16;
        let icmp_code = self.code as u16;

        let payload = self.body.as_ref();

        let mut sum = ((icmp_type << 8) | icmp_code) as u32;

        sum = sum.wrapping_add(self.rest >> 16);
        sum = sum.wrapping_add(self.rest & 0xffff);
        sum = sum.wrapping_add(raw::utils::sum_slice(payload));

        raw::utils::sum_to_checksum(sum)
    }
}

impl Ipv4PacketBody for IcmpPacket {
    fn serialize(&self, _: &Ipv4PacketHeader, buf: &mut BytesMut) {
        let rh = RawIcmpPacketHeader {
            icmp_type: self.icmp_type.code(),
            code: self.code,
            checksum: U16::new(self.checksum()),
            rest: U32::new(self.rest),
        };

        let header = rh.as_bytes();

        let total_len = header.len() + self.body.len();

        buf.reserve(total_len);

        buf.extend_from_slice(header);
        buf.extend_from_slice(&self.body);
    }

    fn len(&self, _: &Ipv4PacketHeader) -> usize {
        std::mem::size_of::<RawIcmpPacketHeader>() + self.body.len()
    }
}

/// Raw ICMP packet header.
#[derive(Copy, Clone, KnownLayout, Immutable, Unaligned, IntoBytes, FromBytes)]
#[repr(C)]
struct RawIcmpPacketHeader {
    icmp_type: u8,
    code: u8,
    checksum: U16,
    rest: U32,
}

pub trait IcmpEchoPacket {
    /// Get ICMP echo identifier.
    fn identifier(&self) -> u16;

    /// Get ICMP echo sequence number.
    fn seq_number(&self) -> u16;

    /// Get ICMP echo payload.
    fn payload(&self) -> &[u8];
}

impl IcmpEchoPacket for IcmpPacket {
    fn identifier(&self) -> u16 {
        (self.rest >> 16) as u16
    }

    fn seq_number(&self) -> u16 {
        (self.rest & 0xff) as u16
    }

    fn payload(&self) -> &[u8] {
        self.body.as_ref()
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
        ip::Ipv4Packet,
        pcap::{self, Scanner},
        utils::Serialize,
    };

    use super::IcmpPacket;

    /// ICMP scanner.
    pub struct IcmpScanner {
        device: EthernetDevice,
        scanner: Scanner,
        mask: u32,
        network: u32,
    }

    impl IcmpScanner {
        /// Scan a given device and return list of all active hosts.
        pub fn scan_device(device: &EthernetDevice) -> pcap::Result<Vec<(MacAddr, Ipv4Addr)>> {
            Self::new(device).scan()
        }

        /// Create a new scanner instance.
        fn new(device: &EthernetDevice) -> Self {
            let mask = u32::from(device.netmask);
            let addr = u32::from(device.ip_addr);
            let network = addr & mask;

            Self {
                device: device.clone(),
                scanner: Scanner::new(device.name()),
                mask,
                network,
            }
        }

        /// Scan a given device and return list of all active hosts.
        fn scan(&mut self) -> pcap::Result<Vec<(MacAddr, Ipv4Addr)>> {
            let bcast = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
            let hsrc = self.device.mac_addr;
            let psrc = self.device.ip_addr;
            let mask = u32::from(self.device.netmask);
            let addr = u32::from(self.device.ip_addr);

            let end = addr | !mask;

            let mut current = (addr & mask) + 1;

            let mut buffer = BytesMut::new();

            let mut generator = move || {
                if current < end {
                    let icmp_id = (current >> 16) as u16;
                    let icmp_seq = (current & 0xff) as u16;

                    let pdst = Ipv4Addr::from(current);

                    let icmpp = IcmpPacket::empty_echo_request(icmp_id, icmp_seq);
                    let ipp = Ipv4Packet::icmp(psrc, pdst, 64, icmpp);
                    let pkt = EtherPacket::ipv4(hsrc, bcast, ipp);

                    pkt.serialize(&mut buffer);

                    current += 1;

                    let pkt = buffer.split();

                    Some(pkt.freeze())
                } else {
                    None
                }
            };

            let filter = format!(
                "icmp and icmp[icmptype] = icmp-echoreply \
                 and ip dst {}",
                self.device.ip()
            );

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

                if eh.packet_type() == EtherPacketType::IPv4
                    && let Ok(ip) = Ipv4Packet::parse(&mut eb.clone())
                {
                    let iph = ip.header();

                    let sha = eh.src;
                    let spa = iph.src;

                    let nwa = u32::from(spa) & self.mask;

                    if nwa == self.network {
                        hosts.push((sha, spa));
                    }
                }
            }

            Ok(hosts)
        }
    }
}
