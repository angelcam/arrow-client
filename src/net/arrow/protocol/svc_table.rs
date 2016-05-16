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
use std::fmt;
use std::result;

use std::io::Write;
use std::str::FromStr;
use std::error::Error;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::{ToSocketAddrs, SocketAddr, SocketAddrV4, Ipv4Addr};

use utils;

use utils::Serialize;
use utils::config::ConfigError;
use net::utils::IpAddrEx;
use net::raw::ether::MacAddr;
use net::arrow::protocol::control::ControlMessageBody;

use time;

use rustc_serialize::json;

use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

const SVC_TYPE_CONTROL_PROTOCOL: u16 = 0x0000;
const SVC_TYPE_RTSP:             u16 = 0x0001;
const SVC_TYPE_LOCKED_RTSP:      u16 = 0x0002;
const SVC_TYPE_UNKNOWN_RTSP:     u16 = 0x0003;
const SVC_TYPE_UNSUPPORTED_RTSP: u16 = 0x0004;
const SVC_TYPE_HTTP:             u16 = 0x0005;
const SVC_TYPE_MJPEG:            u16 = 0x0006;
const SVC_TYPE_LOCKED_MJPEG:     u16 = 0x0007;
const SVC_TYPE_TCP:              u16 = 0xffff;

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
        let ip_addr = saddr.ip();
        
        ServiceHeader {
            svc_id:     svc_id,
            svc_type:   svc_type,
            mac_addr:   haddr.octets(),
            ip_version: ip_addr.version(),
            ip_addr:    ip_addr.bytes(),
            port:       saddr.port(),
        }
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
    /// Remote RTSP service without any known path (mac, addr).
    UnknownRTSP(MacAddr, SocketAddr),
    /// Remote RTSP service without any supported stream (mac, addr, path).
    UnsupportedRTSP(MacAddr, SocketAddr, String),
    /// Remote HTTP service (mac, addr).
    HTTP(MacAddr, SocketAddr),
    /// Remote MJPEG service (mac, addr, path).
    MJPEG(MacAddr, SocketAddr, String),
    /// Remote MJPEG service requiring authorization (mac, addr).
    LockedMJPEG(MacAddr, SocketAddr),
    /// General purpose TCP service (mac, addr).
    TCP(MacAddr, SocketAddr),
}

impl Service {
    /// Get service type ID.
    pub fn type_id(&self) -> u16 {
        match self {
            &Service::ControlProtocol          => SVC_TYPE_CONTROL_PROTOCOL,
            &Service::RTSP(_, _, _)            => SVC_TYPE_RTSP,
            &Service::LockedRTSP(_, _)         => SVC_TYPE_LOCKED_RTSP,
            &Service::UnknownRTSP(_, _)        => SVC_TYPE_UNKNOWN_RTSP,
            &Service::UnsupportedRTSP(_, _, _) => SVC_TYPE_UNSUPPORTED_RTSP,
            &Service::HTTP(_, _)               => SVC_TYPE_HTTP,
            &Service::MJPEG(_, _, _)           => SVC_TYPE_MJPEG,
            &Service::LockedMJPEG(_, _)        => SVC_TYPE_LOCKED_MJPEG,
            &Service::TCP(_, _)                => SVC_TYPE_TCP
        }
    }
    
    /// Get service MAC address (in case it is not the Control Protocol svc).
    pub fn mac(&self) -> Option<&MacAddr> {
        match self {
            &Service::ControlProtocol                 => None,
            &Service::RTSP(ref addr, _, _)            => Some(addr),
            &Service::LockedRTSP(ref addr, _)         => Some(addr),
            &Service::UnknownRTSP(ref addr, _)        => Some(addr),
            &Service::UnsupportedRTSP(ref addr, _, _) => Some(addr),
            &Service::HTTP(ref addr, _)               => Some(addr),
            &Service::MJPEG(ref addr, _, _)           => Some(addr),
            &Service::LockedMJPEG(ref addr, _)        => Some(addr),
            &Service::TCP(ref addr, _)                => Some(addr)
        }
    }
    
    /// Get service address (in case it is not the Control Protocol svc).
    pub fn address(&self) -> Option<&SocketAddr> {
        match self {
            &Service::ControlProtocol                 => None,
            &Service::RTSP(_, ref addr, _)            => Some(addr),
            &Service::LockedRTSP(_, ref addr)         => Some(addr),
            &Service::UnknownRTSP(_, ref addr)        => Some(addr),
            &Service::UnsupportedRTSP(_, ref addr, _) => Some(addr),
            &Service::HTTP(_, ref addr)               => Some(addr),
            &Service::MJPEG(_, ref addr, _)           => Some(addr),
            &Service::LockedMJPEG(_, ref addr)        => Some(addr),
            &Service::TCP(_, ref addr)                => Some(addr)
        }
    }
    
    /// Get service path (valid only for certain types of services),
    pub fn path(&self) -> Option<&str> {
        match self {
            &Service::RTSP(_, _, ref path)            => Some(path),
            &Service::UnsupportedRTSP(_, _, ref path) => Some(path),
            &Service::MJPEG(_, _, ref path)           => Some(path),
            _ => None
        }
    }
    
    /// Serialize this Service Table item in-place.
    pub fn serialize<W: Write>(&self, w: &mut W, id: u16) -> io::Result<()> {
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
    pub fn len(&self) -> usize {
        let path_bytes = match self.path() {
            Some(path) => path.as_bytes(),
            None       => &[] as &[u8]
        };
        
        mem::size_of::<ServiceHeader>() + path_bytes.len() + 1
    }
}

/// JSON mapping for a service table element.
#[derive(Debug, Clone, RustcDecodable, RustcEncodable)]
struct JsonService {
    svc_type:   u16,
    mac:        String,
    address:    String,
    path:       String,
    static_svc: Option<bool>,
    last_seen:  Option<i64>,
    active:     Option<bool>,
}

impl JsonService {
    /// Transform this service description into a service table element.
    fn into_service_table_element(
        self) -> Result<ServiceTableElement, ConfigError> {
        let svc = match self.svc_type {
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
            SVC_TYPE_UNSUPPORTED_RTSP => Ok(Service::UnsupportedRTSP(
                try!(MacAddr::from_str(&self.mac)),
                try!(parse_socket_addr(&self.address)), self.path)),
            SVC_TYPE_HTTP => Ok(Service::HTTP(
                try!(MacAddr::from_str(&self.mac)),
                try!(parse_socket_addr(&self.address)))),
            SVC_TYPE_MJPEG => Ok(Service::MJPEG(
                try!(MacAddr::from_str(&self.mac)),
                try!(parse_socket_addr(&self.address)), self.path)),
            SVC_TYPE_LOCKED_MJPEG => Ok(Service::LockedMJPEG(
                try!(MacAddr::from_str(&self.mac)),
                try!(parse_socket_addr(&self.address)))),
            SVC_TYPE_TCP => Ok(Service::TCP(
                try!(MacAddr::from_str(&self.mac)),
                try!(parse_socket_addr(&self.address)))),
            _ => Err(ConfigError::from("unknown service type"))
        };
        
        let static_svc = self.static_svc.unwrap_or(false);
        let last_seen  = self.last_seen.unwrap_or(get_utc_timestamp());
        let active     = self.active.unwrap_or(true);
        
        let elem = ServiceTableElement {
            service_id:     0,
            service:        try!(svc),
            static_service: static_svc,
            last_seen:      last_seen,
            active:         active
        };
        
        Ok(elem)
    }
}

impl<'a> From<&'a ServiceTableElement> for JsonService {
    fn from(elem: &ServiceTableElement) -> JsonService {
        let svc = &elem.service;
        let mac = svc.mac()
            .map_or(String::new(), |mac| format!("{}", mac));
        let address = svc.address()
            .map_or(String::new(), |addr| format!("{}", addr));
        let path = svc.path()
            .map_or(String::new(), |path| path.to_string());
        
        JsonService {
            svc_type:   svc.type_id(),
            mac:        mac,
            address:    address,
            path:       path,
            static_svc: Some(elem.static_service),
            last_seen:  Some(elem.last_seen),
            active:     Some(elem.active)
        }
    }
}

/// Service table key (svc_type, mac_addr, port, path).
type ServiceTableKey = (u16, Option<MacAddr>, Option<u16>, Option<String>);

/// Get service table key for a given service.
fn get_service_table_key(svc: &Service) -> ServiceTableKey {
    let type_id  = svc.type_id();
    let mac_addr = svc.mac()
        .map(|ma| *ma);
    let port = svc.address()
        .map(|sa| sa.port());
    let path = svc.path()
        .map(|p| p.to_string());
    
    (type_id, mac_addr, port, path)
}

const ACTIVE_THRESHOLD: u32 = 1200;

/// Get current UNIX timestamp in UTC.
fn get_utc_timestamp() -> i64 {
    time::now_utc()
        .to_timespec()
        .sec
}

/// Service table element.
#[derive(Debug, Clone)]
struct ServiceTableElement {
    /// Service ID.
    service_id:     u16,
    /// Service.
    service:        Service,
    /// Flag indicating a manually added service.
    static_service: bool,
    /// UNIX timestamp (in UTC) of the last discovery event.
    last_seen:      i64,
    /// Active flag. (Note: We need this flag because the service table 
    /// serialization must remain idempotent between flag updates.)
    active:         bool,
}

impl ServiceTableElement {
    /// Update the active flag.
    fn update_active_flag(&mut self, timestamp: i64) -> bool {
        let old_value = self.active;
        self.active = self.static_service ||
            (self.last_seen + ACTIVE_THRESHOLD as i64) >= timestamp;
        self.active != old_value
    }
}

/// Service Table.
#[derive(Debug, Clone)]
pub struct ServiceTable {
    services: Vec<ServiceTableElement>,
    map:      HashMap<ServiceTableKey, usize>,
}

impl ServiceTable {
    /// Create a new Service Table containing only a single Control Protocol 
    /// service.
    pub fn new() -> ServiceTable {
        ServiceTable {
            services: Vec::new(),
            map:      HashMap::new()
        }
    }
    
    /// Check if there is a given service in the table.
    pub fn contains(&self, svc: &Service) -> bool {
        match svc {
            &Service::ControlProtocol => true,
            svc => self.map.contains_key(&get_service_table_key(svc))
        }
    }
    
    /// Get service according to its ID.
    pub fn get(&self, id: u16) -> Option<Service> {
        if id == 0 {
            Some(Service::ControlProtocol)
        } else {
            match self.services.get((id - 1) as usize) {
                Some(elem) => Some(elem.service.clone()),
                None       => None
            }
        }
    }
    
    /// Get ID of a given service.
    pub fn get_id(&self, svc: &Service) -> Option<u16> {
        match svc {
            &Service::ControlProtocol => Some(0),
            svc => self.map.get(&get_service_table_key(svc))
                        .map(|id| *id as u16)
        }
    }
    
    /// Add a given element into the table and assign it its service ID.
    fn add_element(&mut self, mut elem: ServiceTableElement) {
        let key = get_service_table_key(&elem.service);
        if !self.map.contains_key(&key) {
            elem.service_id = (self.services.len() + 1) as u16;
            self.map.insert(key, self.services.len());
            self.services.push(elem);
        }
    }
    
    /// Add a given service into the table in case it is not already there and 
    /// return the service ID, otherwise return None. The last_seen timestamp 
    /// will be set to the current time in both cases.
    pub fn add(&mut self, svc: Service) -> Option<u16> {
        self.add_internal(false, svc)
    }
    
    /// Add a given static service (i.e. manually added) into the table in case 
    /// it is not already there and return the service ID, otherwise return 
    /// None.
    pub fn add_static(&mut self, svc: Service) -> Option<u16> {
        self.add_internal(true, svc)
    }
    
    /// Add a given service into the table in case it is not already there and 
    /// return the service ID, otherwise return None. The last_seen timestamp 
    /// will be set to the current time in both cases.
    fn add_internal(&mut self, static_svc: bool, svc: Service) -> Option<u16> {
        let key   = get_service_table_key(&svc);
        let index = self.map.get(&key)
            .map(|index| *index);
        
        if svc == Service::ControlProtocol {
            None
        } else if let Some(index) = index {
            let elem = &mut self.services[index];
            
            elem.last_seen = get_utc_timestamp();
            elem.service   = svc;
            
            None
        } else {
            let svc_id = (self.services.len() + 1) as u16;
            let elem   = ServiceTableElement {
                service_id:     svc_id,
                service:        svc,
                static_service: static_svc,
                last_seen:      get_utc_timestamp(),
                active:         true
            };
            
            self.map.insert(key, self.services.len());
            self.services.push(elem);
            
            Some(svc_id)
        }
    }
    
    /// Update active flags of all services.
    pub fn update_active_services(&mut self) -> bool {
        let timestamp = get_utc_timestamp();
        self.services.iter_mut()
            .fold(false, |acc, elem| elem.update_active_flag(timestamp) || acc)
    }
    
    /// Get all active services.
    ///
    /// Only static services or services with the last_seen timestamp from the 
    /// interval [now - ACTIVE_THRESHOLD, now] are considered active.
    pub fn active_services(&self) -> Vec<Service> {
        let mut res = vec![Service::ControlProtocol];
        for elem in &self.services {
            if elem.active {
                res.push(elem.service.clone());
            }
        }
        
        res
    }
}

impl Serialize for ServiceTable {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for elem in &self.services {
            if elem.active {
                try!(elem.service.serialize(w, elem.service_id));
            }
        }
        
        let cp_svc = Service::ControlProtocol;
        
        cp_svc.serialize(w, 0)
    }
}

impl ControlMessageBody for ServiceTable {
    fn len(&self) -> usize {
        let cp_svc = Service::ControlProtocol;
        cp_svc.len() + self.services.iter()
            .filter(|elem| elem.active)
            .fold(0, |sum, elem| sum + elem.service.len())
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
        for elem in &self.services {
            table.add(JsonService::from(elem));
        }
        
        table.encode(s)
    }
}

impl Display for ServiceTable {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        let content = try!(json::encode(self)
            .or(Err(fmt::Error)));
        f.write_str(&content)
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
            let elem = try!(svc.into_service_table_element());
            res.add_element(elem);
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
        
        assert_eq!(table.services.len(), 2);
    }
}
