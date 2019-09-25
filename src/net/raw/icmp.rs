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

use crate::net::raw;
use crate::utils;

use crate::net::raw::ether::packet::{PacketParseError, Result};
use crate::net::raw::ip::{Ipv4PacketBody, Ipv4PacketHeader};

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
    fn code(&self) -> u8 {
        match self {
            &IcmpPacketType::Echo => ICMP_TYPE_ECHO,
            &IcmpPacketType::EchoReply => ICMP_TYPE_ECHO_REPLY,
            &IcmpPacketType::Unknown(pt) => pt,
        }
    }
}

impl From<u8> for IcmpPacketType {
    fn from(code: u8) -> IcmpPacketType {
        match code {
            ICMP_TYPE_ECHO => IcmpPacketType::Echo,
            ICMP_TYPE_ECHO_REPLY => IcmpPacketType::EchoReply,
            pt => IcmpPacketType::Unknown(pt),
        }
    }
}

/// ICMP packet.
pub struct IcmpPacket {
    icmp_type: IcmpPacketType,
    code: u8,
    rest: u32,
    body: Box<[u8]>,
}

impl IcmpPacket {
    /// Create a new echo request.
    pub fn echo_request(id: u16, seq: u16, payload: &[u8]) -> IcmpPacket {
        let id = id as u32;
        let seq = seq as u32;

        IcmpPacket {
            icmp_type: IcmpPacketType::Echo,
            code: 0,
            rest: (id << 16) | seq,
            body: payload.to_vec().into_boxed_slice(),
        }
    }

    /// Create a new echo request without payload.
    pub fn empty_echo_request(id: u16, seq: u16) -> IcmpPacket {
        IcmpPacket::echo_request(id, seq, &[])
    }

    /// Parse an ICMP packet from given data.
    pub fn parse(data: &[u8]) -> Result<IcmpPacket> {
        let size = mem::size_of::<RawIcmpPacketHeader>();

        if data.len() < size {
            Err(PacketParseError::from(
                "unable to parse ICMP packet, not enough data",
            ))
        } else {
            let ptr = data.as_ptr();
            let ptr = ptr as *const RawIcmpPacketHeader;

            let rh = unsafe { &*ptr };

            let body = &data[size..];

            let res = IcmpPacket {
                icmp_type: IcmpPacketType::from(rh.icmp_type),
                code: rh.code,
                rest: u32::from_be(rh.rest),
                body: body.to_vec().into_boxed_slice(),
            };

            Ok(res)
        }
    }

    /// Get raw ICMP packet header.
    fn raw_header(&self) -> RawIcmpPacketHeader {
        let checksum = self.checksum();

        RawIcmpPacketHeader {
            icmp_type: self.icmp_type.code(),
            code: self.code,
            checksum: checksum.to_be(),
            rest: self.rest.to_be(),
        }
    }

    /// Get packet checksum.
    fn checksum(&self) -> u16 {
        let icmp_type = self.icmp_type.code() as u16;
        let icmp_code = self.code as u16;

        let payload = self.body.as_ref();

        let mut sum = ((icmp_type << 8) | icmp_code) as u32;

        sum = sum.wrapping_add(self.rest >> 16);
        sum = sum.wrapping_add(self.rest & 0xff);
        sum = sum.wrapping_add(raw::utils::sum_slice(payload));

        raw::utils::sum_to_checksum(sum)
    }
}

impl Ipv4PacketBody for IcmpPacket {
    fn serialize(&self, _: &Ipv4PacketHeader, w: &mut dyn Write) -> io::Result<()> {
        let raw_header = self.raw_header();

        let payload = self.body.as_ref();

        w.write_all(utils::as_bytes(&raw_header))?;
        w.write_all(payload)?;

        Ok(())
    }

    fn len(&self, _: &Ipv4PacketHeader) -> usize {
        let payload = self.body.as_ref();

        mem::size_of::<RawIcmpPacketHeader>() + payload.len()
    }
}

/// Raw ICMP packet header.
#[repr(packed)]
#[allow(dead_code)]
struct RawIcmpPacketHeader {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    rest: u32,
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
    use super::*;

    use std::net::Ipv4Addr;

    use bytes::Bytes;

    use crate::net::raw::pcap;

    use crate::net::raw::devices::EthernetDevice;
    use crate::net::raw::ether::packet::EtherPacket;
    use crate::net::raw::ether::MacAddr;
    use crate::net::raw::ip::Ipv4Packet;
    use crate::net::raw::pcap::Scanner;
    use crate::net::raw::utils::Serialize;

    use crate::net::utils::Ipv4AddrEx;

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
            IcmpScanner::new(device).scan()
        }

        /// Create a new scanner instance.
        fn new(device: &EthernetDevice) -> IcmpScanner {
            let mask = device.netmask.as_u32();
            let addr = device.ip_addr.as_u32();
            let network = addr & mask;

            IcmpScanner {
                device: device.clone(),
                scanner: Scanner::new(&device.name),
                mask: mask,
                network: network,
            }
        }

        /// Scan a given device and return list of all active hosts.
        fn scan(&mut self) -> pcap::Result<Vec<(MacAddr, Ipv4Addr)>> {
            let bcast = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
            let hsrc = self.device.mac_addr;
            let psrc = self.device.ip_addr;
            let mask = self.device.netmask.as_u32();
            let addr = self.device.ip_addr.as_u32();

            let end = addr | !mask;

            let mut current = (addr & mask) + 1;

            let mut buffer = Vec::new();

            let mut generator = move || {
                if current < end {
                    let icmp_id = (current >> 16) as u16;
                    let icmp_seq = (current & 0xff) as u16;

                    let pdst = Ipv4Addr::from(current);

                    let icmpp = IcmpPacket::empty_echo_request(icmp_id, icmp_seq);
                    let ipp = Ipv4Packet::icmp(psrc, pdst, 64, icmpp);
                    let pkt = EtherPacket::ipv4(hsrc, bcast, ipp);

                    buffer.clear();

                    pkt.serialize(&mut buffer).unwrap();

                    current += 1;

                    let pkt = Bytes::from(buffer.as_slice());

                    Some(pkt)
                } else {
                    None
                }
            };

            let filter = format!(
                "icmp and icmp[icmptype] = icmp-echoreply \
                 and ip dst {}",
                self.device.ip_addr
            );
            let packets = self.scanner.sr(&filter, &mut generator, 2000)?;

            let mut hosts = Vec::new();

            for ep in packets {
                let eh = ep.header();

                if let Some(ip) = ep.body::<Ipv4Packet>() {
                    let iph = ip.header();

                    let sha = eh.src;
                    let spa = iph.src;

                    let nwa = spa.as_u32() & self.mask;

                    if nwa == self.network {
                        hosts.push((sha, spa));
                    }
                }
            }

            Ok(hosts)
        }
    }
}
