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

#[cfg(feature = "discovery")]
pub mod packet;

use std::{
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    str::FromStr,
};

/// MacAddr parse error.
#[derive(Debug, Clone)]
pub struct AddrParseError {
    msg: String,
}

impl AddrParseError {
    /// Create a new error.
    fn new<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self {
            msg: msg.to_string(),
        }
    }
}

impl std::error::Error for AddrParseError {}

impl Display for AddrParseError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

/// MAC address type.
#[derive(Debug, Copy, Clone, Eq)]
pub struct MacAddr {
    bytes: [u8; 6],
}

impl MacAddr {
    pub const ZERO: Self = Self::zero();

    /// Create a new MAC address with all octets set to zero.
    pub const fn zero() -> Self {
        Self { bytes: [0; 6] }
    }

    /// Create a new MAC address.
    pub const fn new(e0: u8, e1: u8, e2: u8, e3: u8, e4: u8, e5: u8) -> Self {
        Self {
            bytes: [e0, e1, e2, e3, e4, e5],
        }
    }

    /// Get address octets.
    pub fn octets(self) -> [u8; 6] {
        self.bytes
    }

    /// Crete address from slice.
    pub fn from_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 6);
        Self::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
    }
}

impl PartialEq for MacAddr {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.eq(&other.bytes)
    }
}

impl Hash for MacAddr {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        // We need the hash to be stable regardless of the system pointer
        // width. Using u32 to represent the slice length is safe here because
        // the MAC address is always 6 bytes long.
        //
        // NOTE: Even though the slice length is not necessary here, we cannot
        // remove it without introducing a breaking change.
        state.write_u32(6);
        state.write(&self.bytes);
    }
}

impl Display for MacAddr {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
            self.bytes[4],
            self.bytes[5]
        ))
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(bytes: [u8; 6]) -> Self {
        Self { bytes }
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(addr: MacAddr) -> Self {
        addr.bytes
    }
}

impl FromStr for MacAddr {
    type Err = AddrParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let octets = s
            .split(':')
            .map(|x| {
                u8::from_str_radix(x, 16).map_err(|_| {
                    AddrParseError::new("unable to parse a MAC address, invalid octet")
                })
            })
            .collect::<Vec<_>>();

        if octets.len() == 6 {
            Ok(Self::new(
                octets[0].clone()?,
                octets[1].clone()?,
                octets[2].clone()?,
                octets[3].clone()?,
                octets[4].clone()?,
                octets[5].clone()?,
            ))
        } else {
            Err(AddrParseError::new(
                "unable to parse a MAC address, invalid number of octets",
            ))
        }
    }
}
