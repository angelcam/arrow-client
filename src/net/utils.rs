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

//! Common networking utils.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use utils::RuntimeError;

/// Get socket address from a given argument.
pub fn get_socket_address<T>(s: T) -> Result<SocketAddr, RuntimeError>
    where T: ToSocketAddrs {
    s.to_socket_addrs()
        .ok()
        .ok_or(RuntimeError::from("unable get socket address"))?
        .next()
        .ok_or(RuntimeError::from("unable get socket address"))
}

/// IpAddr extension.
pub trait IpAddrEx {
    /// Get left-aligned byte representation of the IP address.
    fn bytes(&self) -> [u8; 16];

    /// Get IP address version.
    fn version(&self) -> u8;
}

impl IpAddrEx for IpAddr {
    fn bytes(&self) -> [u8; 16] {
        match self {
            &IpAddr::V4(ref ip_addr) => ip_addr.bytes(),
            &IpAddr::V6(ref ip_addr) => ip_addr.bytes()
        }
    }

    fn version(&self) -> u8 {
        match self {
            &IpAddr::V4(ref ip_addr) => ip_addr.version(),
            &IpAddr::V6(ref ip_addr) => ip_addr.version()
        }
    }
}

impl IpAddrEx for Ipv4Addr {
    fn bytes(&self) -> [u8; 16] {
        let octets  = self.octets();
        let mut res = [0u8; 16];

        for i in 0..octets.len() {
            res[i] = octets[i];
        }

        res
    }

    fn version(&self) -> u8 {
        4
    }
}

impl IpAddrEx for Ipv6Addr {
    fn bytes(&self) -> [u8; 16] {
        let segments = self.segments();
        let mut res  = [0u8; 16];

        for i in 0..segments.len() {
            let segment = segments[i];
            let j       = i << 1;
            res[j]      = (segment >> 8) as u8;
            res[j + 1]  = (segment & 0xff) as u8;
        }

        res
    }

    fn version(&self) -> u8 {
        6
    }
}
