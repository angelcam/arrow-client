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

pub mod logger;

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::net::raw::ether::MacAddr;

/// Get current UNIX timestamp in UTC.
pub fn get_utc_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|err| err.duration())
        .unwrap_or_else(|d| -(d.as_secs() as i64))
}

/// Generate a fake MAC address from a given prefix and IP address.
///
/// Note: It is used in case we do not know the device MAC address (e.g. for
/// services passed as command line arguments).
pub fn get_fake_mac(prefix: u16, addr: IpAddr) -> MacAddr {
    match addr {
        IpAddr::V4(addr) => get_fake_mac_from_ipv4(prefix, addr),
        IpAddr::V6(addr) => get_fake_mac_from_ipv6(prefix, addr),
    }
}

/// Generate a fake MAC address from a given prefix and IPv4 address.
pub fn get_fake_mac_from_ipv4(prefix: u16, addr: Ipv4Addr) -> MacAddr {
    let a = ((prefix >> 8) & 0xff) as u8;
    let b = (prefix & 0xff) as u8;

    let octets = addr.octets();

    MacAddr::new(a, b, octets[0], octets[1], octets[2], octets[3])
}

/// Generate a fake MAC address from a given prefix and IPv6 address.
pub fn get_fake_mac_from_ipv6(prefix: u16, addr: Ipv6Addr) -> MacAddr {
    let segments = addr.segments();

    let e0 = ((prefix >> 8) & 0xff) as u8;
    let e1 = (prefix & 0xff) as u8;
    let e2 = ((segments[6] >> 8) & 0xff) as u8;
    let e3 = (segments[6] & 0xff) as u8;
    let e4 = ((segments[7] >> 8) & 0xff) as u8;
    let e5 = (segments[7] & 0xff) as u8;

    MacAddr::new(e0, e1, e2, e3, e4, e5)
}
