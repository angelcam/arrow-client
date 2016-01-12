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

//! Service table definitions.

use std::io;
use std::mem;

use std::io::Write;
use std::str::FromStr;
use std::error::Error;
use std::collections::HashSet;
use std::net::{ToSocketAddrs, SocketAddr, SocketAddrV4, Ipv4Addr, Ipv6Addr};

use utils;

use utils::Serialize;
use utils::config::ConfigError;
use net::raw::ether::MacAddr;
use net::arrow::protocol::control::ControlMessageBody;

use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

const SVC_TYPE_CONTROL_PROTOCOL: u16 = 0x0000;
const SVC_TYPE_RTSP:             u16 = 0x0001;
const SVC_TYPE_LOCKED_RTSP:      u16 = 0x0002;
const SVC_TYPE_UNKNOWN_RTSP:     u16 = 0x0003;

/// Service Table item header.
#[derive(Debug, Copy, Clone)]
#[repr(packed)]
struct ServiceHeader {
    svc_id:     u16,
    svc_type:   u16,
    mac_addr:   [u8; 6],
    ip_version: u8,
    ip_addr:    [u8; 16],
    port:       u16,
}

impl ServiceHeader {
    /// Create a new item header.
    fn new(
        svc_id: u16, 
        svc_type: u16, 
        haddr: &MacAddr, 
        saddr: &SocketAddr) -> ServiceHeader {
        let ip_version = match saddr {
            &SocketAddr::V4(_) => 4,
            &SocketAddr::V6(_) => 6
        };
        
        let ip_bytes   = match saddr {
            &SocketAddr::V4(ref addr) => Self::ipv4_bytes(addr.ip()),
            &SocketAddr::V6(ref addr) => Self::ipv6_bytes(addr.ip())
        };
        
        ServiceHeader {
            svc_id:     svc_id,
            svc_type:   svc_type,
            mac_addr:   haddr.octets(),
            ip_version: ip_version,
            ip_addr:    ip_bytes,
            port:       saddr.port(),
        }
    }
    
    /// Get IPv6 bytes.
    fn ipv6_bytes(addr: &Ipv6Addr) -> [u8; 16] {
        let segments = addr.segments();
        let mut res  = [0u8; 16];
        
        for i in 0..segments.len() {
            let segment = segments[i];
            let j       = i << 1;
            res[j]      = (segment >> 8) as u8;
            res[j + 1]  = (segment & 0xff) as u8;
        }
        
        res
    }
    
    /// Get IPv4 bytes left-aligned and padded to 16 bytes.
    fn ipv4_bytes(addr: &Ipv4Addr) -> [u8; 16] {
        let octets  = addr.octets();
        let mut res = [0u8; 16];
        
        for i in 0..octets.len() {
            res[i] = octets[i];
        }
        
        res
    }
}

impl Serialize for ServiceHeader {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let be_header = ServiceHeader {
            svc_id:     self.svc_id.to_be(),
            svc_type:   self.svc_type.to_be(),
            mac_addr:   self.mac_addr,
            ip_version: self.ip_version,
            ip_addr:    self.ip_addr,
            port:       self.port.to_be(),
        };
        
        w.write_all(utils::as_bytes(&be_header))
    }
}

/// Service Table item.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Service {
    /// Control Protocol service.
    ControlProtocol,
    /// Remote RTSP service (mac, addr, path).
    RTSP(MacAddr, SocketAddr, String),
    /// Remote RTSP service requiring authorization (mac, addr).
    LockedRTSP(MacAddr, SocketAddr),
    /// Remote RTSP service without any known path.
    UnknownRTSP(MacAddr, SocketAddr),
}

impl Service {
    /// Get service type ID.
    pub fn type_id(&self) -> u16 {
        match self {
            &Service::ControlProtocol   => SVC_TYPE_CONTROL_PROTOCOL,
            &Service::RTSP(_, _, _)     => SVC_TYPE_RTSP,
            &Service::LockedRTSP(_, _)  => SVC_TYPE_LOCKED_RTSP,
            &Service::UnknownRTSP(_, _) => SVC_TYPE_UNKNOWN_RTSP
        }
    }
    
    /// Get service MAC address (in case it is not the Control Protocol svc).
    pub fn mac(&self) -> Option<&MacAddr> {
        match self {
            &Service::ControlProtocol          => None,
            &Service::RTSP(ref addr, _, _)     => Some(addr),
            &Service::LockedRTSP(ref addr, _)  => Some(addr),
            &Service::UnknownRTSP(ref addr, _) => Some(addr)
        }
    }
    
    /// Get service address (in case it is not the Control Protocol svc).
    pub fn address(&self) -> Option<&SocketAddr> {
        match self {
            &Service::ControlProtocol          => None,
            &Service::RTSP(_, ref addr, _)     => Some(addr),
            &Service::LockedRTSP(_, ref addr)  => Some(addr),
            &Service::UnknownRTSP(_, ref addr) => Some(addr)
        }
    }
    
    /// Get service path (valid only for certain types of services),
    pub fn path(&self) -> Option<&str> {
        match self {
            &Service::RTSP(_, _, ref path) => Some(path),
            _ => None
        }
    }
    
    /// Serialize this Service Table item in-place.
    fn serialize<W: Write>(&self, w: &mut W, id: u16) -> io::Result<()> {
        let dhaddr = MacAddr::new(0, 0, 0, 0, 0, 0);
        let dsaddr = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(0, 0, 0, 0), 0));
        
        let haddr = self.mac()
            .unwrap_or(&dhaddr);
        let saddr = self.address()
            .unwrap_or(&dsaddr);
        
        let header = ServiceHeader::new(id, self.type_id(), haddr, saddr);
        
        try!(header.serialize(w));
        
        if let Some(path) = self.path() {
            try!(w.write_all(path.as_bytes()));
        }
        
        w.write_all(&[0u8])
    }
    
    /// Get size of this Service Table item in bytes.
    fn len(&self) -> usize {
        let path_bytes = match self.path() {
            Some(path) => path.as_bytes(),
            None       => &[] as &[u8]
        };
        
        mem::size_of::<ServiceHeader>() + path_bytes.len() + 1
    }
}

/// JSON mapping for a service.
#[derive(Debug, Clone, RustcDecodable, RustcEncodable)]
struct JsonService {
    svc_type: u16,
    mac:      String,
    address:  String,
    path:     String,
}

impl JsonService {
    /// Create a new JsonService instance.
    fn new(
        svc_type: u16, 
        mac: String, 
        address: String, 
        path: String) -> JsonService {
        JsonService {
            svc_type: svc_type,
            mac:      mac,
            address:  address,
            path:     path
        }
    }
    
    /// Transform this service description into a service object.
    fn into_service(self) -> Result<Service, ConfigError> {
        match self.svc_type {
            SVC_TYPE_CONTROL_PROTOCOL => Ok(Service::ControlProtocol),
            SVC_TYPE_RTSP => Ok(Service::RTSP(
                try!(MacAddr::from_str(&self.mac)), 
                try!(parse_socket_addr(&self.address)), self.path)),
            SVC_TYPE_LOCKED_RTSP => Ok(Service::LockedRTSP(
                try!(MacAddr::from_str(&self.mac)), 
                try!(parse_socket_addr(&self.address)))),
            SVC_TYPE_UNKNOWN_RTSP => Ok(Service::UnknownRTSP(
                try!(MacAddr::from_str(&self.mac)),
                try!(parse_socket_addr(&self.address)))),
            _ => Err(ConfigError::from("unknown service type"))
        }
    }
}

impl<'a> From<&'a Service> for JsonService {
    fn from(svc: &Service) -> JsonService {
        let mac = svc.mac()
            .map_or(String::new(), |mac| format!("{}", mac));
        let address = svc.address()
            .map_or(String::new(), |addr| format!("{}", addr));
        let path = svc.path()
            .map_or(String::new(), |path| path.to_string());
        
        JsonService::new(svc.type_id(), mac, address, path)
    }
}

/// Service Table.
#[derive(Debug, Clone)]
pub struct ServiceTable {
    services: Vec<Service>,
    set:      HashSet<Service>,
}

impl ServiceTable {
    /// Create a new Service Table containing only a single Control Protocol 
    /// service.
    pub fn new() -> ServiceTable {
        ServiceTable {
            services: Vec::new(),
            set:      HashSet::new()
        }
    }
    
    /// Check if there is a given service in the table.
    pub fn contains(&self, svc: &Service) -> bool {
        match svc {
            &Service::ControlProtocol => true,
            svc => self.set.contains(svc)
        }
    }
    
    /// Get service according to its ID.
    pub fn get(&self, id: u16) -> Option<Service> {
        if id == 0 {
            Some(Service::ControlProtocol)
        } else {
            match self.services.get((id - 1) as usize) {
                Some(svc) => Some(svc.clone()),
                None => None
            }
        }
    }
    
    /// Add a given service into the table in case it is not already there and 
    /// return the service ID, otherwise return None.
    pub fn add(&mut self, svc: Service) -> Option<u16> {
        if self.contains(&svc) {
            None
        } else {
            self.services.push(svc.clone());
            self.set.insert(svc);
            Some(self.services.len() as u16)
        }
    }
    
    /// Get vector of remote services in this configuration (i.e. without the 
    /// implicit Control Protocol service).
    ///
    /// The result is a vector of pairs. The first element is service ID, 
    /// the second element is the service itself.
    pub fn services(&self) -> Vec<(u16, Service)> {
        let mut res = Vec::new();
        for i in 0..self.services.len() {
            let svc = &self.services[i];
            let id  = i + 1;
            res.push((id as u16, svc.clone()));
        }
        
        res
    }
}

impl Serialize for ServiceTable {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for i in 0..self.services.len() {
            let svc = &self.services[i];
            let id  = i + 1;
            try!(svc.serialize(w, id as u16));
        }
        
        let cp_svc = Service::ControlProtocol;
        
        cp_svc.serialize(w, 0)
    }
}

impl ControlMessageBody for ServiceTable {
    fn len(&self) -> usize {
        let cp_svc = Service::ControlProtocol;
        cp_svc.len() + self.services.iter()
            .fold(0, |sum, svc| sum + svc.len())
    }
}

impl Decodable for ServiceTable {
    fn decode<D: Decoder>(d: &mut D) -> Result<ServiceTable, D::Error> {
        let table = try!(JsonServiceTable::decode(d));
        match table.into_service_table() {
            Err(err)  => Err(d.error(err.description())),
            Ok(table) => Ok(table)
        }
    }
}

impl Encodable for ServiceTable {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let mut table = JsonServiceTable::new();
        for svc in &self.services {
            table.add(JsonService::from(svc));
        }
        
        table.encode(s)
    }
}

/// JSON mapping for the ServiceTable.
#[derive(Debug, Clone, RustcDecodable, RustcEncodable)]
struct JsonServiceTable {
    services: Vec<JsonService>,
}

impl JsonServiceTable {
    /// Create a new JsonServiceTable instance.
    fn new() -> JsonServiceTable {
        JsonServiceTable {
            services: Vec::new()
        }
    }
    
    /// Add a new configuration entry.
    fn add(&mut self, svc: JsonService) -> &mut Self {
        self.services.push(svc);
        self
    }
    
    /// Transform this service table representation into a real service table.
    fn into_service_table(self) -> Result<ServiceTable, ConfigError> {
        let mut res = ServiceTable::new();
        for svc in self.services {
            res.add(try!(svc.into_service()));
        }
        
        Ok(res)
    }
}

/// Parse a socket address.
fn parse_socket_addr(addr: &str) -> Result<SocketAddr, ConfigError> {
    try!(addr.to_socket_addrs())
        .next()
        .ok_or(ConfigError::from("no socket address given"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::Serialize;
    use rustc_serialize::json;
    use net::utils::WriteBuffer;
    use net::raw::ether::MacAddr;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use net::arrow::protocol::control::ControlMessageBody;
    
    #[test]
    fn test_service_table() {
        let mac  = MacAddr::new(0, 0, 0, 0, 0, 0);
        let addr = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 2, 3, 4), 5));
        let rtsp = Service::RTSP(
            mac.clone(), addr.clone(), "/foo".to_string());
        let lrtsp = Service::LockedRTSP(
            mac.clone(), addr.clone());
        let mut table = ServiceTable::new();
        
        assert!(table.contains(&Service::ControlProtocol));
        assert!(!table.contains(&rtsp));
        assert!(!table.contains(&lrtsp));
        
        assert_eq!(table.add(rtsp.clone()), Some(1));
        assert_eq!(table.add(lrtsp.clone()), Some(2));
        
        assert!(table.contains(&rtsp));
        assert!(table.contains(&lrtsp));
    }
    
    #[test]
    fn test_service_table_serialization() {
        let data = [
            0, 1, 0, 1, 
                0, 0, 0, 0, 0, 0, 
                4, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 
                47, 102, 111, 111, 0, 
            0, 2, 0, 2, 
                0, 0, 0, 0, 0, 0, 
                4, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 
                0, 
            0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 
                4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0];
        
        let mac  = MacAddr::new(0, 0, 0, 0, 0, 0);
        let addr = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 2, 3, 4), 5));
        let rtsp = Service::RTSP(
            mac.clone(), addr.clone(), "/foo".to_string());
        let lrtsp = Service::LockedRTSP(
            mac.clone(), addr.clone());
        let mut table = ServiceTable::new();
        
        table.add(rtsp);
        table.add(lrtsp);
        
        let mut buf = WriteBuffer::new(0);
        
        table.serialize(&mut buf).unwrap();
        
        let data_bytes: &[u8] = &data;
        
        assert_eq!(data_bytes, buf.as_bytes());
    }
    
    #[test]
    fn test_service_table_json_serialization() {
        let mac  = MacAddr::new(0, 0, 0, 0, 0, 0);
        let addr = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 2, 3, 4), 5));
        let rtsp = Service::RTSP(
            mac.clone(), addr.clone(), "/foo".to_string());
        let lrtsp = Service::LockedRTSP(
            mac.clone(), addr.clone());
        let mut table = ServiceTable::new();
        
        table.add(rtsp.clone());
        table.add(lrtsp.clone());
        
        let json  = json::encode(&table).unwrap();
        let table = json::decode::<ServiceTable>(&json).unwrap();
        
        assert!(table.contains(&rtsp));
        assert!(table.contains(&lrtsp));
        assert!(table.contains(&Service::ControlProtocol));
        
        let services = table.services();
        
        assert_eq!(services.len(), 2);
    }
}
