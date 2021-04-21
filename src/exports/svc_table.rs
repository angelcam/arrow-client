// Copyright 2019 Angelcam, Inc.
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

#![allow(clippy::missing_safety_doc)]

use std::ptr;
use std::slice;

use std::ffi::CString;
use std::net::IpAddr;
use std::os::raw::c_char;

use crate::net::raw::ether::MacAddr;
use crate::net::utils::IpAddrEx;
use crate::svc_table::Service;

/// Helper struct.
pub struct NativeServiceTable {
    services: Vec<NativeService>,
}

impl<T> From<T> for NativeServiceTable
where
    T: IntoIterator<Item = (u16, Service)>,
{
    fn from(table: T) -> Self {
        let services = table
            .into_iter()
            .filter_map(|(id, svc)| {
                if svc.is_control() {
                    None
                } else {
                    Some(NativeService::new(id, &svc))
                }
            })
            .collect();

        Self { services }
    }
}

/// Helper struct.
pub struct NativeService {
    service_id: u16,
    service_type: u16,
    mac_address: MacAddr,
    ip_address: IpAddr,
    port: u16,
    path: Option<CString>,
}

impl NativeService {
    fn new(id: u16, service: &Service) -> Self {
        let path = service
            .path()
            .map(|s| CString::new(s.to_string()))
            .transpose()
            .unwrap();

        Self {
            service_id: id,
            service_type: service.service_type().code(),
            mac_address: service.mac().unwrap(),
            ip_address: service.ip_address().unwrap(),
            port: service.port().unwrap(),
            path,
        }
    }
}

/// Free the service table.
#[no_mangle]
pub unsafe extern "C" fn ac__service_table__free(table: *mut NativeServiceTable) {
    Box::from_raw(table);
}

/// Get number of services in the table.
#[no_mangle]
pub unsafe extern "C" fn ac__service_table__get_service_count(
    table: *const NativeServiceTable,
) -> usize {
    (*table).services.len() as _
}

/// Get service at a given index.
#[no_mangle]
pub unsafe extern "C" fn ac__service_table__get_service(
    table: *const NativeServiceTable,
    index: usize,
) -> *const NativeService {
    let table = &*table;

    &table.services[index as usize]
}

/// Get service ID.
#[no_mangle]
pub unsafe extern "C" fn ac__service__get_id(service: *const NativeService) -> u16 {
    (*service).service_id
}

/// Get service type.
#[no_mangle]
pub unsafe extern "C" fn ac__service__get_type(service: *const NativeService) -> u16 {
    (*service).service_type
}

/// Get service MAC address. The given buffer must have enough space to store at least 6 bytes.
#[no_mangle]
pub unsafe extern "C" fn ac__service__get_mac_address(
    service: *const NativeService,
    buffer: *mut u8,
) {
    let mac = (*service).mac_address.octets();
    let buffer = slice::from_raw_parts_mut(buffer, mac.len());

    buffer.copy_from_slice(&mac);
}

/// Get version of the service IP address.
#[no_mangle]
pub unsafe extern "C" fn ac__service__get_ip_version(service: *const NativeService) -> u8 {
    (*service).ip_address.version()
}

/// Get service IP address. The given buffer must have enough space to store at least 4 bytes for
/// IPv4 address or 16 bytes for IPv6 address. Version of the IP address is returned.
#[no_mangle]
pub unsafe extern "C" fn ac__service__get_ip_address(
    service: *const NativeService,
    buffer: *mut u8,
) -> u8 {
    let addr = (*service).ip_address;

    match addr {
        IpAddr::V4(addr) => {
            let addr = addr.octets();
            let buffer = slice::from_raw_parts_mut(buffer, addr.len());

            buffer.copy_from_slice(&addr);
        }
        IpAddr::V6(addr) => {
            let addr = addr.octets();
            let buffer = slice::from_raw_parts_mut(buffer, addr.len());

            buffer.copy_from_slice(&addr);
        }
    }

    addr.version()
}

/// Get service port.
#[no_mangle]
pub unsafe extern "C" fn ac__service__get_port(service: *const NativeService) -> u16 {
    (*service).port
}

/// Get service path/endpoint (may be NULL).
#[no_mangle]
pub unsafe extern "C" fn ac__service__get_path(service: *const NativeService) -> *const c_char {
    if let Some(path) = (*service).path.as_ref() {
        path.as_ptr() as _
    } else {
        ptr::null()
    }
}
