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

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use utils;

use net::arrow::proto::Encode;
use net::arrow::proto::buffer::OutputBuffer;
use net::arrow::proto::msg::MessageBody;
use net::raw::ether::MacAddr;
use net::utils::IpAddrEx;

const SVC_TYPE_CONTROL_PROTOCOL: u16 = 0x0000;
const SVC_TYPE_RTSP:             u16 = 0x0001;
const SVC_TYPE_LOCKED_RTSP:      u16 = 0x0002;
const SVC_TYPE_UNKNOWN_RTSP:     u16 = 0x0003;
const SVC_TYPE_UNSUPPORTED_RTSP: u16 = 0x0004;
const SVC_TYPE_HTTP:             u16 = 0x0005;
const SVC_TYPE_MJPEG:            u16 = 0x0006;
const SVC_TYPE_LOCKED_MJPEG:     u16 = 0x0007;
const SVC_TYPE_TCP:              u16 = 0xffff;

/// Service type.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub enum ServiceType {
    /// Control Protocol service.
    ControlProtocol,
    /// Remote RTSP service.
    RTSP,
    /// Remote RTSP service requiring authentication.
    LockedRTSP,
    /// Remote RTSP service without any known path.
    UnknownRTSP,
    /// Remote RTSP service without any supported stream.
    UnsupportedRTSP,
    /// Remote HTTP service.
    HTTP,
    /// Remote MJPEG service.
    MJPEG,
    /// Remote MJPEG service requiring authentication.
    LockedMJPEG,
    /// General purpose TCP service.
    TCP,
}

impl ServiceType {
    fn code(&self) -> u16 {
        match self {
            &ServiceType::ControlProtocol => SVC_TYPE_CONTROL_PROTOCOL,
            &ServiceType::RTSP            => SVC_TYPE_RTSP,
            &ServiceType::LockedRTSP      => SVC_TYPE_LOCKED_RTSP,
            &ServiceType::UnknownRTSP     => SVC_TYPE_UNKNOWN_RTSP,
            &ServiceType::UnsupportedRTSP => SVC_TYPE_UNSUPPORTED_RTSP,
            &ServiceType::HTTP            => SVC_TYPE_HTTP,
            &ServiceType::MJPEG           => SVC_TYPE_MJPEG,
            &ServiceType::LockedMJPEG     => SVC_TYPE_LOCKED_MJPEG,
            &ServiceType::TCP             => SVC_TYPE_TCP,
        }
    }
}

/// Service Table item header.
#[repr(packed)]
struct ServiceHeader {
    svc_id:     u16,
    svc_type:   u16,
    mac_addr:   [u8; 6],
    ip_version: u8,
    ip_addr:    [u8; 16],
    port:       u16,
}

impl<'a> From<&'a Service> for ServiceHeader {
    fn from(service: &'a Service) -> ServiceHeader {
        let service_type = service.service_type();

        let null_maddress = MacAddr::new(0, 0, 0, 0, 0, 0);
        let null_saddress = SocketAddr::V4(
            SocketAddrV4::new(
                Ipv4Addr::new(0, 0, 0, 0), 0));

        let maddress = service.mac()
            .unwrap_or(&null_maddress);
        let saddress = service.address()
            .unwrap_or(&null_saddress);
        let iaddress = saddress.ip();

        ServiceHeader {
            svc_id:     service.id(),
            svc_type:   service_type.code(),
            mac_addr:   maddress.octets(),
            ip_version: iaddress.version(),
            ip_addr:    iaddress.bytes(),
            port:       saddress.port(),
        }
    }
}

impl Encode for ServiceHeader {
    fn encode(&self, buf: &mut OutputBuffer) {
        let be_header = ServiceHeader {
            svc_id:     self.svc_id.to_be(),
            svc_type:   self.svc_type.to_be(),
            mac_addr:   self.mac_addr,
            ip_version: self.ip_version,
            ip_addr:    self.ip_addr,
            port:       self.port.to_be(),
        };

        buf.append(utils::as_bytes(&be_header))
    }
}

/// Arrow service.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Service {
    svc_type: ServiceType,
    id:       u16,
    mac:      Option<MacAddr>,
    address:  Option<SocketAddr>,
    path:     Option<String>,
}

impl Service {
    /// Create a new Control Protocol service.
    pub fn control() -> Service {
        Service {
            svc_type: ServiceType::ControlProtocol,
            id:       0,
            mac:      None,
            address:  None,
            path:     None,
        }
    }

    /// Create a new RTSP service.
    pub fn rtsp(id: u16, mac: MacAddr, address: SocketAddr, path: String) -> Service {
        Service {
            svc_type: ServiceType::RTSP,
            id:       id,
            mac:      Some(mac),
            address:  Some(address),
            path:     Some(path),
        }
    }

    /// Create a new Locked RTSP service.
    pub fn locked_rtsp(id: u16, mac: MacAddr, address: SocketAddr, path: Option<String>) -> Service {
        Service {
            svc_type: ServiceType::LockedRTSP,
            id:       id,
            mac:      Some(mac),
            address:  Some(address),
            path:     path,
        }
    }

    /// Create a new Unknown RTSP service.
    pub fn unknown_rtsp(id: u16, mac: MacAddr, address: SocketAddr) -> Service {
        Service {
            svc_type: ServiceType::UnknownRTSP,
            id:       id,
            mac:      Some(mac),
            address:  Some(address),
            path:     None,
        }
    }

    /// Create a new Unsupported RTSP service.
    pub fn unsupported_rtsp(id: u16, mac: MacAddr, address: SocketAddr, path: String) -> Service {
        Service {
            svc_type: ServiceType::RTSP,
            id:       id,
            mac:      Some(mac),
            address:  Some(address),
            path:     Some(path),
        }
    }

    /// Create a new HTTP service.
    pub fn http(id: u16, mac: MacAddr, address: SocketAddr) -> Service {
        Service {
            svc_type: ServiceType::HTTP,
            id:       id,
            mac:      Some(mac),
            address:  Some(address),
            path:     None,
        }
    }

    /// Create a new MJPEG service.
    pub fn mjpeg(id: u16, mac: MacAddr, address: SocketAddr, path: String) -> Service {
        Service {
            svc_type: ServiceType::MJPEG,
            id:       id,
            mac:      Some(mac),
            address:  Some(address),
            path:     Some(path),
        }
    }

    /// Create a new Locked MJPEG service.
    pub fn locked_mjpeg(id: u16, mac: MacAddr, address: SocketAddr, path: Option<String>) -> Service {
        Service {
            svc_type: ServiceType::LockedMJPEG,
            id:       id,
            mac:      Some(mac),
            address:  Some(address),
            path:     path,
        }
    }

    /// Create a new TCP service.
    pub fn tcp(id: u16, mac: MacAddr, address: SocketAddr) -> Service {
        Service {
            svc_type: ServiceType::TCP,
            id:       id,
            mac:      Some(mac),
            address:  Some(address),
            path:     None,
        }
    }

    /// Get service type.
    pub fn service_type(&self) -> ServiceType {
        self.svc_type
    }

    /// Get service ID.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Get service MAC address.
    pub fn mac(&self) -> Option<&MacAddr> {
        self.mac.as_ref()
    }

    /// Get service IP address and port.
    pub fn address(&self) -> Option<&SocketAddr> {
        self.address.as_ref()
    }

    /// Get service path.
    pub fn path(&self) -> Option<&str> {
        self.path.as_ref()
            .map(|v| v as &str)
    }
}

impl Encode for Service {
    fn encode(&self, buf: &mut OutputBuffer) {
        ServiceHeader::from(self)
            .encode(buf);

        let path = self.path()
            .unwrap_or("");

        buf.append(path.as_bytes());
        buf.append(&[0]);
    }
}

impl MessageBody for Service {
    fn len(&self) -> usize {
        let plen = self.path()
            .unwrap_or("")
            .as_bytes()
            .len() + 1;

        mem::size_of::<ServiceHeader>() + plen
    }
}

/// Arrow Control Protocol service table.
pub struct ServiceTable {
    services: Vec<Service>,
}

impl ServiceTable {
    /// Create a new service table.
    pub fn new() -> ServiceTable {
        ServiceTable {
            services: Vec::new()
        }
    }

    /// Add a given service.
    pub fn add(&mut self, service: Service) {
        self.services.push(service)
    }
}

impl Encode for ServiceTable {
    fn encode(&self, buf: &mut OutputBuffer) {
        for svc in &self.services {
            svc.encode(buf);
        }

        Service::control()
            .encode(buf)
    }
}

impl MessageBody for ServiceTable {
    fn len(&self) -> usize {
        let mut len = 0;

        for svc in &self.services {
            len += svc.len();
        }

        let control = Service::control();

        len + control.len()
    }
}
