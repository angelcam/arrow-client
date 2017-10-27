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

//! Ethernet device definitions.

use std::slice;

use std::net::Ipv4Addr;

use utils;

use net::raw::ether::MacAddr;

use libc::{c_char, c_void, size_t};

#[allow(non_camel_case_types)]
type net_device = *mut c_void;

#[link(name = "net_devices")]
extern "C" {
    fn net_find_devices() -> net_device;
    fn net_free_device_list(dev: net_device) -> c_void;
    fn net_get_name(dev: net_device) -> *const c_char;
    fn net_get_ipv4_address(dev: net_device) -> *const c_char;
    fn net_get_ipv4_netmask(dev: net_device) -> *const c_char;
    fn net_get_mac_address(dev: net_device) -> *const c_char;
    fn net_get_next_device(dev: net_device) -> net_device;
    fn net_get_mac_addr_size() -> size_t;
    fn net_get_ipv4_addr_size() -> size_t;
}

/// Ethernet device.
#[derive(Clone, Debug)]
pub struct EthernetDevice {
    pub name:     String,
    pub mac_addr: MacAddr,
    pub ip_addr:  Ipv4Addr,
    pub netmask:  Ipv4Addr,
}

impl EthernetDevice {
    /// List all configured IPv4 network devices.
    pub fn list() -> Vec<EthernetDevice> {
        let mut result = Vec::new();

        unsafe {
            let devices = net_find_devices();

            let mut device = devices.clone();

            while !device.is_null() {
                result.push(EthernetDevice::new(device));
                device = net_get_next_device(device);
            }

            net_free_device_list(devices);
        }

        result
    }

    /// Create a new ethernet device instance from its raw counterpart.
    unsafe fn new(dev: net_device) -> EthernetDevice {
        EthernetDevice {
            name:     get_name(dev),
            mac_addr: get_mac_addr(dev),
            ip_addr:  get_ipv4_addr(dev),
            netmask:  get_ipv4_mask(dev)
        }
    }
}

/// Get device name.
unsafe fn get_name(dev: net_device) -> String {
    utils::cstr_to_string(net_get_name(dev) as *const i8)
}

/// Get device MAC address.
unsafe fn get_mac_addr(dev: net_device) -> MacAddr {
    let addr  = net_get_mac_address(dev) as *const c_void;
    let bytes = ptr_to_bytes(addr, net_get_mac_addr_size() as usize);

    MacAddr::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
}

/// Get device IPv4 address.
unsafe fn get_ipv4_addr(dev: net_device) -> Ipv4Addr {
    let addr  = net_get_ipv4_address(dev) as *const c_void;
    let bytes = ptr_to_bytes(addr, net_get_ipv4_addr_size() as usize);

    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Get device IPv4 mask.
unsafe fn get_ipv4_mask(dev: net_device) -> Ipv4Addr {
    let addr  = net_get_ipv4_netmask(dev) as *const c_void;
    let bytes = ptr_to_bytes(addr, net_get_ipv4_addr_size() as usize);

    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

unsafe fn ptr_to_bytes<'a>(ptr: *const c_void, len: usize) -> &'a [u8] {
    slice::from_raw_parts(ptr as *const u8, len)
}
