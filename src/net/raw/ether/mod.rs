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

#[cfg(feature = "discovery")]
pub mod packet;

use std::fmt;
use std::result;

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

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

impl Error for AddrParseError {}

impl Display for AddrParseError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

/// MAC address type.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct MacAddr {
    bytes: [u8; 6],
}

impl MacAddr {
    /// Create a new MAC address with all octets set to zero.
    pub fn zero() -> Self {
        Self { bytes: [0; 6] }
    }

    /// Create a new MAC address.
    pub fn new(e0: u8, e1: u8, e2: u8, e3: u8, e4: u8, e5: u8) -> Self {
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

impl Display for MacAddr {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
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

impl FromStr for MacAddr {
    type Err = AddrParseError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        let octets = s
            .split(':')
            .map(|x| {
                u8::from_str_radix(x, 16).or_else(|_| {
                    Err(AddrParseError::new(
                        "unable to parse a MAC address, invalid octet",
                    ))
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
