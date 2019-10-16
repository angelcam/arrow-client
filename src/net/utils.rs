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

use std::mem;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use futures;

use futures::{Async, Future};

use crate::runtime;

use crate::utils::RuntimeError;

/// Get socket address from a given argument.
pub fn get_socket_address<T>(s: T) -> Result<SocketAddr, RuntimeError>
where
    T: ToSocketAddrs,
{
    s.to_socket_addrs()
        .ok()
        .ok_or_else(|| RuntimeError::from("unable to get socket address"))?
        .next()
        .ok_or_else(|| RuntimeError::from("unable to get socket address"))
}

/// Asynchronously get socket address from a given argument.
pub fn get_socket_address_async<T>(
    s: T,
) -> impl Future<Item = SocketAddr, Error = RuntimeError> + Send
where
    T: ToSocketAddrs + Clone + Send,
{
    futures::future::poll_fn(move || {
        let s = s.clone();

        let res = runtime::blocking(|| get_socket_address(s));

        match res.unwrap() {
            Async::Ready(Ok(addr)) => Ok(Async::Ready(addr)),
            Async::Ready(Err(err)) => Err(err),
            Async::NotReady => Ok(Async::NotReady),
        }
    })
}

/// Ipv4Addr extension.
pub trait Ipv4AddrEx {
    /// Crete address from slice.
    fn from_slice(bytes: &[u8]) -> Ipv4Addr;

    /// Convert a given IPv4 address into big endian 32-bit unsigned number.
    fn as_u32(&self) -> u32;
}

impl Ipv4AddrEx for Ipv4Addr {
    fn from_slice(bytes: &[u8]) -> Ipv4Addr {
        assert_eq!(bytes.len(), 4);

        #[allow(clippy::cast_ptr_alignment)]
        let ptr = bytes.as_ptr() as *const u32;
        let addr = unsafe { u32::from_be(*ptr) };

        Self::from(addr)
    }

    fn as_u32(&self) -> u32 {
        let octets = self.octets();

        let nr: u32 = unsafe { mem::transmute(octets) };

        nr.to_be()
    }
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
        match &self {
            Self::V4(ref ip_addr) => ip_addr.bytes(),
            Self::V6(ref ip_addr) => ip_addr.bytes(),
        }
    }

    fn version(&self) -> u8 {
        match &self {
            Self::V4(ref ip_addr) => ip_addr.version(),
            Self::V6(ref ip_addr) => ip_addr.version(),
        }
    }
}

impl IpAddrEx for Ipv4Addr {
    fn bytes(&self) -> [u8; 16] {
        let octets = self.octets();
        let mut res = [0_u8; 16];

        res[0..octets.len()].clone_from_slice(&octets[..]);

        res
    }

    fn version(&self) -> u8 {
        4
    }
}

impl IpAddrEx for Ipv6Addr {
    fn bytes(&self) -> [u8; 16] {
        let segments = self.segments();
        let mut res = [0_u8; 16];

        for (i, segment) in segments.iter().enumerate() {
            let j = i << 1;
            res[j] = (segment >> 8) as u8;
            res[j + 1] = (segment & 0xff) as u8;
        }

        res
    }

    fn version(&self) -> u8 {
        6
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic]
    fn test_slice_to_ipv4addr_1() {
        let buffer = [0_u8; 3];
        Ipv4Addr::from_slice(&buffer);
    }

    #[test]
    fn test_slice_to_ipv4addr_2() {
        let buffer = [192, 168, 2, 3];
        let addr = Ipv4Addr::from_slice(&buffer);

        assert_eq!(buffer, addr.octets());
    }

    #[test]
    fn test_ipv4addr_to_u32() {
        let addr = Ipv4Addr::new(192, 168, 2, 5);
        assert_eq!(0xc0a8_0205, addr.as_u32());
    }
}
