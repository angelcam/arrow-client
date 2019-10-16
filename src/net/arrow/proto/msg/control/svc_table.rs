// Copyright 2017 click2stream, Inc.
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

use std::mem;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use bytes::BytesMut;

use crate::utils;

use crate::net::arrow::proto::codec::Encode;
use crate::net::arrow::proto::msg::MessageBody;
use crate::net::raw::ether::MacAddr;
use crate::net::utils::IpAddrEx;
use crate::svc_table::{BoxServiceTable, Service, ServiceIdentifier, ServiceTable};

/// Service Table element header.
#[repr(packed)]
struct ElementHeader {
    svc_id: u16,
    svc_type: u16,
    mac_addr: [u8; 6],
    ip_version: u8,
    ip_addr: [u8; 16],
    port: u16,
}

impl<'a> From<&'a Element> for ElementHeader {
    fn from(element: &'a Element) -> Self {
        let service_type = element.service.service_type();

        let null_maddress = MacAddr::new(0, 0, 0, 0, 0, 0);
        let null_saddress = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));

        let maddress = element.service.mac().unwrap_or(null_maddress);
        let saddress = element.service.address().unwrap_or(null_saddress);
        let iaddress = saddress.ip();

        Self {
            svc_id: element.id,
            svc_type: service_type.code(),
            mac_addr: maddress.octets(),
            ip_version: iaddress.version(),
            ip_addr: iaddress.bytes(),
            port: saddress.port(),
        }
    }
}

impl Encode for ElementHeader {
    fn encode(&self, buf: &mut BytesMut) {
        let be_header = Self {
            svc_id: self.svc_id.to_be(),
            svc_type: self.svc_type.to_be(),
            mac_addr: self.mac_addr,
            ip_version: self.ip_version,
            ip_addr: self.ip_addr,
            port: self.port.to_be(),
        };

        buf.extend_from_slice(utils::as_bytes(&be_header))
    }
}

/// Simple service table element.
#[derive(Clone)]
struct Element {
    id: u16,
    service: Service,
}

impl Element {
    /// Create a new element for the simple service table.
    fn new(id: u16, service: Service) -> Self {
        Self { id, service }
    }
}

impl Encode for Element {
    fn encode(&self, buf: &mut BytesMut) {
        ElementHeader::from(self).encode(buf);

        let path = self.service.path().unwrap_or("");

        buf.extend_from_slice(path.as_bytes());
        buf.extend_from_slice(&[0]);
    }
}

impl MessageBody for Element {
    fn len(&self) -> usize {
        let plen = self.service.path().unwrap_or("").as_bytes().len() + 1;

        mem::size_of::<ElementHeader>() + plen
    }
}

/// Simple service table implementation.
#[derive(Clone)]
pub struct SimpleServiceTable {
    map: HashMap<u16, Element>,
}

impl<I> From<I> for SimpleServiceTable
where
    I: IntoIterator<Item = (u16, Service)>,
{
    fn from(services: I) -> Self {
        let mut map = HashMap::new();

        for (id, service) in services {
            map.insert(id, Element::new(id, service));
        }

        Self { map }
    }
}

impl ServiceTable for SimpleServiceTable {
    fn get(&self, id: u16) -> Option<Service> {
        if id == 0 {
            return Some(Service::control());
        }

        if let Some(elem) = self.map.get(&id) {
            Some(elem.service.clone())
        } else {
            None
        }
    }

    fn get_id(&self, identifier: &ServiceIdentifier) -> Option<u16> {
        if identifier.is_control() {
            return Some(0);
        }

        for elem in self.map.values() {
            if *identifier == elem.service.to_service_identifier() {
                return Some(elem.id);
            }
        }

        None
    }

    fn boxed(self) -> BoxServiceTable {
        Box::new(self)
    }
}

impl Encode for SimpleServiceTable {
    fn encode(&self, buf: &mut BytesMut) {
        for elem in self.map.values() {
            elem.encode(buf);
        }

        Element::new(0, Service::control()).encode(buf)
    }
}

impl MessageBody for SimpleServiceTable {
    fn len(&self) -> usize {
        let mut len = 0;

        for elem in self.map.values() {
            len += elem.len();
        }

        let control = Element::new(0, Service::control());

        len + control.len()
    }
}
