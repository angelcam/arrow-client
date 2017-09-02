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

use std::str::FromStr;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// MacAddr parse error.
#[derive(Debug, Clone)]
pub struct AddrParseError {
    msg: String,
}

impl Error for AddrParseError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for AddrParseError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(self.description())
    }
}

impl<'a> From<&'a str> for AddrParseError {
    fn from(msg: &'a str) -> AddrParseError {
        AddrParseError { msg: msg.to_string() }
    }
}

/// MAC address type.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct MacAddr {
    bytes: [u8; 6],
}

impl MacAddr {
    /// Create a new MAC address with all octets set to zero.
    pub fn zero() -> MacAddr {
        MacAddr { bytes: [0; 6] }
    }

    /// Create a new MAC address.
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> MacAddr {
        MacAddr { bytes: [a, b, c, d, e, f] }
    }

    /// Get address octets.
    pub fn octets(&self) -> [u8; 6] {
        self.bytes
    }

    /// Crete address from slice.
    pub fn from_slice(bytes: &[u8]) -> MacAddr {
        assert_eq!(bytes.len(), 6);
        MacAddr::new(bytes[0], bytes[1], bytes[2],
                     bytes[3], bytes[4], bytes[5])
    }
}

impl Display for MacAddr {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.bytes[0], self.bytes[1], self.bytes[2],
            self.bytes[3], self.bytes[4], self.bytes[5]))
    }
}

impl FromStr for MacAddr {
    type Err = AddrParseError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        let octets = s.split(':')
            .map(|x| u8::from_str_radix(x, 16)
                .or(Err(AddrParseError::from("unable to parse a MAC address, invalid octet"))))
            .collect::<Vec<_>>();
        if octets.len() == 6 {
            Ok(MacAddr::new(
                try!(octets[0].clone()),
                try!(octets[1].clone()),
                try!(octets[2].clone()),
                try!(octets[3].clone()),
                try!(octets[4].clone()),
                try!(octets[5].clone())))
        } else {
            Err(AddrParseError::from("unable to parse a MAC address, invalid number of octets"))
        }
    }
}
