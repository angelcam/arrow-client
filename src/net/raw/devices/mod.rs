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

//! Ethernet device definitions.

use std::{
    net::{IpAddr, Ipv4Addr},
    os::raw::{c_char, c_void},
};

use crate::{net::raw::ether::MacAddr, utils};

#[allow(non_camel_case_types)]
type net_device = *mut c_void;

#[link(name = "net_devices")]
unsafe extern "C" {
    unsafe fn net_find_devices() -> net_device;
    unsafe fn net_free_device_list(dev: net_device) -> c_void;
    unsafe fn net_get_name(dev: net_device) -> *const c_char;
    unsafe fn net_get_ipv4_address(dev: net_device) -> *const c_char;
    unsafe fn net_get_ipv4_netmask(dev: net_device) -> *const c_char;
    unsafe fn net_get_mac_address(dev: net_device) -> *const c_char;
    unsafe fn net_get_next_device(dev: net_device) -> net_device;
    unsafe fn net_get_mac_addr_size() -> usize;
    unsafe fn net_get_ipv4_addr_size() -> usize;
}

/// Network interface.
#[derive(Clone, Debug)]
pub struct EthernetDevice {
    pub(crate) name: String,
    pub(crate) mac_addr: MacAddr,
    pub(crate) ip_addr: Ipv4Addr,
    pub(crate) netmask: Ipv4Addr,
}

impl EthernetDevice {
    /// List all configured IPv4 network interfaces.
    pub fn list() -> Vec<Self> {
        let mut result = Vec::new();

        unsafe {
            let devices = net_find_devices();

            let mut device = devices;

            while !device.is_null() {
                result.push(Self::new(device));
                device = net_get_next_device(device);
            }

            net_free_device_list(devices);
        }

        result
    }

    /// Create a new network interface instance from its raw counterpart.
    unsafe fn new(dev: net_device) -> Self {
        unsafe {
            Self {
                name: get_name(dev),
                mac_addr: get_mac_addr(dev),
                ip_addr: get_ipv4_addr(dev),
                netmask: get_ipv4_mask(dev),
            }
        }
    }

    /// Get the name of the interface.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the MAC address.
    #[inline]
    pub fn mac(&self) -> MacAddr {
        self.mac_addr
    }

    /// Get the IP address.
    #[inline]
    pub fn ip(&self) -> IpAddr {
        self.ip_addr.into()
    }

    /// Get the network mask.
    #[inline]
    pub fn mask(&self) -> IpAddr {
        self.netmask.into()
    }
}

/// Get device name.
unsafe fn get_name(dev: net_device) -> String {
    unsafe { utils::cstr_to_string(net_get_name(dev) as *const _) }
}

/// Get device MAC address.
unsafe fn get_mac_addr(dev: net_device) -> MacAddr {
    unsafe {
        let addr = net_get_mac_address(dev) as *const c_void;
        let bytes = ptr_to_bytes(addr, net_get_mac_addr_size());

        MacAddr::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
    }
}

/// Get device IPv4 address.
unsafe fn get_ipv4_addr(dev: net_device) -> Ipv4Addr {
    unsafe {
        let addr = net_get_ipv4_address(dev) as *const c_void;
        let bytes = ptr_to_bytes(addr, net_get_ipv4_addr_size());

        Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

/// Get device IPv4 mask.
unsafe fn get_ipv4_mask(dev: net_device) -> Ipv4Addr {
    unsafe {
        let addr = net_get_ipv4_netmask(dev) as *const c_void;
        let bytes = ptr_to_bytes(addr, net_get_ipv4_addr_size());

        Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

unsafe fn ptr_to_bytes<'a>(ptr: *const c_void, len: usize) -> &'a [u8] {
    unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }
}
