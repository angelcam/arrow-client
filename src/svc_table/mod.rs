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

pub mod service;

use std;
use std::fmt;

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use json::JsonValue;

use time;

use net::raw::ether::MacAddr;

use utils::json::{FromJson, ParseError, ToJson};

pub use self::service::{
    Service,
    ServiceIdentifier,
    ServiceType,

    SVC_TYPE_CONTROL_PROTOCOL,
    SVC_TYPE_RTSP,
    SVC_TYPE_LOCKED_RTSP,
    SVC_TYPE_UNKNOWN_RTSP,
    SVC_TYPE_UNSUPPORTED_RTSP,
    SVC_TYPE_HTTP,
    SVC_TYPE_MJPEG,
    SVC_TYPE_LOCKED_MJPEG,
    SVC_TYPE_TCP,
};

const ACTIVE_THRESHOLD: i64 = 1200;

/// Get current UNIX timestamp in UTC.
fn get_utc_timestamp() -> i64 {
    time::now_utc()
        .to_timespec()
        .sec
}

/// Common trait for service table implementations.
pub trait ServiceTable {
    /// Get service with a given ID.
    fn get(&self, id: u16) -> Option<Service>;

    /// Get service ID for a given ServiceIdentifier.
    fn get_id(&self, identifier: &ServiceIdentifier) -> Option<u16>;

    /// Convert this service table into a trait object.
    fn boxed(self) -> BoxServiceTable;
}

/// Type alias for boxed service table.
pub type BoxServiceTable = Box<ServiceTable>;

impl ServiceTable for Box<ServiceTable> {
    fn get(&self, id: u16) -> Option<Service> {
        self.as_ref()
            .get(id)
    }

    fn get_id(&self, identifier: &ServiceIdentifier) -> Option<u16> {
        self.as_ref()
            .get_id(identifier)
    }

    fn boxed(self) -> BoxServiceTable {
        self
    }
}

/// Service table element.
#[derive(Clone)]
struct ServiceTableElement {
    /// Service.
    service:        Service,
    /// Flag indicating a manually added service.
    static_service: bool,
    /// Flag indicating static service visibility.
    enabled:        bool,
    /// UNIX timestamp (in UTC) of the last discovery event.
    last_seen:      i64,
    /// Active flag.
    active:         bool,
}

impl ServiceTableElement {
    /// Create a new service table element.
    fn new(svc: Service, static_svc: bool, enabled: bool) -> ServiceTableElement {
        ServiceTableElement {
            service:        svc,
            static_service: static_svc,
            enabled:        enabled,
            last_seen:      get_utc_timestamp(),
            active:         true,
        }
    }

    /// Check if the element should be visible.
    fn is_visible(&self) -> bool {
        if self.static_service {
            self.enabled
        } else {
            self.active
        }
    }

    /// Update the internal service, the enabled flag and the last_seen timestamp.
    fn update(&mut self, svc: Service, enabled: bool) {
        self.service   = svc;
        self.enabled   = enabled;
        self.last_seen = get_utc_timestamp();
    }

    /// Update the active flag and return true if visibility was changed.
    fn update_active_flag(&mut self, timestamp: i64) {
        self.active = (self.last_seen + ACTIVE_THRESHOLD) >= timestamp;
    }

    /// Get service for this element.
    fn to_service(&self) -> Service {
        self.service.clone()
    }
}

impl ToJson for ServiceTableElement {
    fn to_json(&self) -> JsonValue {
        let default_mac = MacAddr::zero();
        let default_address = SocketAddr::V4(
            SocketAddrV4::new(
                Ipv4Addr::new(0, 0, 0, 0),
                0));

        let svc_type = self.service.service_type();

        let mac = self.service.mac()
            .unwrap_or(default_mac);
        let address = self.service.address()
            .unwrap_or(default_address);
        let path = self.service.path()
            .unwrap_or("");

        object!{
            "svc_type" => svc_type.code(),
            "mac" => format!("{}", mac),
            "address" => format!("{}", address),
            "path" => path,
            "static_svc" => self.static_service,
            "last_seen" => self.last_seen,
            "active" => self.active
        }
    }
}

impl FromJson for ServiceTableElement {
    fn from_json(value: JsonValue) -> Result<Self, ParseError> {
        let service;

        if let JsonValue::Object(svc) = value {
            service = svc;
        } else {
            return Err(ParseError::from("JSON object expected"));
        }

        let svc_type = service.get("svc_type")
            .and_then(|v| v.as_u16())
            .ok_or(ParseError::from("missing field \"svc_type\""))?;
        let mac = service.get("mac")
            .and_then(|v| v.as_str())
            .ok_or(ParseError::from("missing field \"mac\""))?;
        let address = service.get("address")
            .and_then(|v| v.as_str())
            .ok_or(ParseError::from("missing field \"address\""))?;
        let path = service.get("path")
            .and_then(|v| v.as_str())
            .ok_or(ParseError::from("missing field \"path\""))?;

        let epath = String::new();
        let opath;

        if path.len() > 0 {
            opath = Some(path.to_string());
        } else {
            opath = None;
        }

        let mac = mac.parse()
            .map_err(|_| ParseError::from("unable to parse MAC address"));
        let address = address.parse()
            .map_err(|_| ParseError::from("unable to parse socket address"));

        let svc = match svc_type {
            SVC_TYPE_CONTROL_PROTOCOL => Ok(Service::control()),
            SVC_TYPE_RTSP => Ok(Service::rtsp(
                mac?,
                address?,
                opath.unwrap_or(epath),
            )),
            SVC_TYPE_LOCKED_RTSP => Ok(Service::locked_rtsp(
                mac?,
                address?,
                opath,
            )),
            SVC_TYPE_UNKNOWN_RTSP => Ok(Service::unknown_rtsp(
                mac?,
                address?,
            )),
            SVC_TYPE_UNSUPPORTED_RTSP => Ok(Service::unsupported_rtsp(
                mac?,
                address?,
                opath.unwrap_or(epath),
            )),
            SVC_TYPE_HTTP => Ok(Service::http(
                mac?,
                address?,
            )),
            SVC_TYPE_MJPEG => Ok(Service::mjpeg(
                mac?,
                address?,
                opath.unwrap_or(epath),
            )),
            SVC_TYPE_LOCKED_MJPEG => Ok(Service::locked_mjpeg(
                mac?,
                address?,
                opath,
            )),
            SVC_TYPE_TCP => Ok(Service::tcp(
                mac?,
                address?,
            )),
            _ => Err(ParseError::from("unknown service type"))
        };

        let static_svc = service.get("static_svc")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let last_seen = service.get("last_seen")
            .and_then(|v| v.as_i64())
            .unwrap_or(get_utc_timestamp());
        let active = service.get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let elem = ServiceTableElement {
            service:        svc?,
            static_service: static_svc,
            last_seen:      last_seen,
            active:         active,
            enabled:        false,
        };

        Ok(elem)
    }
}

/// Service table internal data.
#[derive(Clone)]
struct ServiceTableData {
    map:      HashMap<ServiceIdentifier, usize>,
    services: Vec<ServiceTableElement>,
    version:  usize,
}

impl ServiceTableData {
    /// Create a new instance of ServiceTableData.
    fn new() -> ServiceTableData {
        ServiceTableData {
            map:      HashMap::new(),
            services: Vec::new(),
            version:  0,
        }
    }

    /// Get version of the service table.
    fn version(&self) -> usize {
        self.version
    }

    /// Get visible service for a given ID.
    fn get(&self, id: u16) -> Option<Service> {
        if id == 0 {
            Some(Service::control())
        } else if let Some(ref elem) = self.services.get((id - 1) as usize) {
            if elem.is_visible() {
                Some(elem.to_service())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get service ID for a given ServiceIdentifier or None if there is no such service or
    /// the given service is invisible.
    fn get_id(&self, identifier: &ServiceIdentifier) -> Option<u16> {
        if identifier.is_control() {
            Some(0)
        } else if let Some(index) = self.map.get(identifier) {
            let elem = self.services.get(*index)
                .expect("broken service table");

            if elem.is_visible() {
                Some((index + 1) as u16)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get visible services.
    fn visible(&self) -> ServiceTableIterator {
        let visible = self.services.iter()
            .enumerate()
            .filter(|&(_, elem)| elem.is_visible());

        ServiceTableIterator::new(visible)
    }

    /// Update a given table element and return its ID.
    fn update_element(&mut self, index: usize, svc: Service, enabled: bool) -> u16 {
        let elem = self.services.get_mut(index)
            .expect("broken service table");

        let svc_change  = elem.service != svc;
        let old_visible = elem.is_visible();

        elem.update(svc, enabled);

        let new_visible = elem.is_visible();

        if old_visible != new_visible || (new_visible && svc_change) {
            self.version += 1;
        }

        (index + 1) as u16
    }

    /// Insert a new element into the table and return its ID.
    fn insert_element(&mut self, svc: Service, static_svc: bool, enabled: bool) -> u16 {
        let id = self.services.len() as u16 + 1;

        let key = svc.to_service_identifier();

        assert!(!self.map.contains_key(&key));

        let elem = ServiceTableElement::new(svc, static_svc, enabled);

        if elem.is_visible() {
            self.version += 1;
        }

        self.map.insert(key, self.services.len());
        self.services.push(elem);

        id
    }

    /// Update service table with a given service and return ID of the service.
    fn update(&mut self, svc: Service, static_svc: bool, enabled: bool) -> u16 {
        let key = svc.to_service_identifier();

        let index = self.map.get(&key)
            .map(|index| *index);

        if svc.is_control() {
            0
        } else if let Some(index) = index {
            self.update_element(index, svc, enabled)
        } else {
            self.insert_element(svc, static_svc, enabled)
        }
    }

    /// Update active flags of all services.
    fn update_active_services(&mut self) {
        let timestamp = get_utc_timestamp();

        for elem in &mut self.services {
            let visible = elem.is_visible();
            elem.update_active_flag(timestamp);
            if visible != elem.is_visible() {
                self.version += 1;
            }
        }
    }
}

impl ToJson for ServiceTableData {
    fn to_json(&self) -> JsonValue {
        let services = self.services.iter()
            .map(|elem| elem.to_json())
            .collect::<Vec<_>>();

        object!{
            "services" => services
        }
    }
}

impl FromJson for ServiceTableData {
    fn from_json(value: JsonValue) -> Result<Self, ParseError> {
        let mut res = ServiceTableData {
            services: Vec::new(),
            map:      HashMap::new(),
            version:  0,
        };

        let mut table;

        if let JsonValue::Object(t) = value {
            table = t;
        } else {
            return Err(ParseError::from("JSON object expected"));
        }

        let tmp = table.remove("services")
            .ok_or(ParseError::from("missing field \"mac\""))?;

        let services;

        if let JsonValue::Array(svcs) = tmp {
            services = svcs;
        } else {
            return Err(ParseError::from("JSON array expected"));
        }

        for service in services {
            let index = res.services.len();
            let elem = ServiceTableElement::from_json(service)?;
            let key = elem.service.to_service_identifier();

            res.services.push(elem);
            res.map.insert(key, index);
        }

        Ok(res)
    }
}

impl Display for ServiceTableData {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_json())
    }
}

/// Service table iterator.
pub struct ServiceTableIterator {
    elements: std::vec::IntoIter<(u16, Service)>,
}

impl ServiceTableIterator {
    /// Create a new service table iterator.
    fn new<'a, I>(elements: I) -> ServiceTableIterator
        where I: IntoIterator<Item=(usize, &'a ServiceTableElement)> {
        let elements = elements.into_iter()
            .map(|(index, elem)| {
                (index as u16 + 1, elem.to_service())
            })
            .collect::<Vec<_>>();

        ServiceTableIterator {
            elements: elements.into_iter(),
        }
    }
}

impl Iterator for ServiceTableIterator {
    type Item = (u16, Service);

    fn next(&mut self) -> Option<Self::Item> {
        self.elements.next()
    }
}

/// Service table implementation that can be shared across multiple threads.
pub struct SharedServiceTable {
    data: Arc<Mutex<ServiceTableData>>,
}

impl SharedServiceTable {
    /// Create a new shared service table.
    pub fn new() -> SharedServiceTable {
        SharedServiceTable {
            data: Arc::new(Mutex::new(ServiceTableData::new())),
        }
    }

    /// Get version of the service table.
    pub fn version(&self) -> usize {
        self.data.lock()
            .unwrap()
            .version()
    }

    /// Add a given service into the table and return its ID.
    pub fn add(&mut self, svc: Service) -> u16 {
        self.data.lock()
            .unwrap()
            .update(svc, false, true)
    }

    /// Add a given static service into the table and return its ID.
    pub fn add_static(&mut self, svc: Service) -> u16 {
        self.data.lock()
            .unwrap()
            .update(svc, true, true)
    }

    /// Update active flags of all services.
    pub fn update_active_services(&mut self) {
        self.data.lock()
            .unwrap()
            .update_active_services()
    }

    /// Get read-only reference to this table.
    pub fn get_ref(&self) -> SharedServiceTableRef {
        SharedServiceTableRef {
            data: self.data.clone()
        }
    }
}

impl Clone for SharedServiceTable {
    fn clone(&self) -> SharedServiceTable {
        let cloned = self.data.lock()
            .unwrap()
            .clone();

        SharedServiceTable {
            data: Arc::new(Mutex::new(cloned)),
        }
    }
}

impl ServiceTable for SharedServiceTable {
    fn get(&self, id: u16) -> Option<Service> {
        self.data.lock()
            .unwrap()
            .get(id)
    }

    fn get_id(&self, identifier: &ServiceIdentifier) -> Option<u16> {
        self.data.lock()
            .unwrap()
            .get_id(identifier)
    }

    fn boxed(self) -> BoxServiceTable {
        Box::new(self)
    }
}

impl Display for SharedServiceTable {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        self.data.lock()
            .unwrap()
            .fmt(f)
    }
}

impl ToJson for SharedServiceTable {
    fn to_json(&self) -> JsonValue {
        self.data.lock()
            .unwrap()
            .to_json()
    }
}

impl FromJson for SharedServiceTable {
    fn from_json(value: JsonValue) -> Result<Self, ParseError> {
        let data = ServiceTableData::from_json(value)?;

        let res = SharedServiceTable {
            data: Arc::new(Mutex::new(data)),
        };

        Ok(res)
    }
}

/// Service table implementation that can be shared across multiple threads.
#[derive(Clone)]
pub struct SharedServiceTableRef {
    data: Arc<Mutex<ServiceTableData>>,
}

impl SharedServiceTableRef {
    /// Get version of the service table.
    pub fn version(&self) -> usize {
        self.data.lock()
            .unwrap()
            .version()
    }

    /// Get visible services.
    pub fn visible(&self) -> ServiceTableIterator {
        self.data.lock()
            .unwrap()
            .visible()
    }
}

impl ServiceTable for SharedServiceTableRef {
    fn get(&self, id: u16) -> Option<Service> {
        self.data.lock()
            .unwrap()
            .get(id)
    }

    fn get_id(&self, identifier: &ServiceIdentifier) -> Option<u16> {
        self.data.lock()
            .unwrap()
            .get_id(identifier)
    }

    fn boxed(self) -> BoxServiceTable {
        Box::new(self)
    }
}

impl ToJson for SharedServiceTableRef {
    fn to_json(&self) -> JsonValue {
        self.data.lock()
            .unwrap()
            .to_json()
    }
}

impl Display for SharedServiceTableRef {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        self.data.lock()
            .unwrap()
            .fmt(f)
    }
}

#[cfg(test)]
#[test]
fn test_visible_services_iterator() {
    let mut table = ServiceTableData::new();

    let mac = MacAddr::zero();
    let ip = Ipv4Addr::new(0, 0, 0, 0);
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, 0));

    let svc_1 = Service::rtsp(mac, addr, "/1".to_string());
    let svc_2 = Service::rtsp(mac, addr, "/2".to_string());
    let svc_3 = Service::rtsp(mac, addr, "/3".to_string());

    table.update(svc_1.clone(), true, true);
    table.update(svc_2.clone(), true, false);
    table.update(svc_3.clone(), true, true);

    let visible = table.visible()
        .collect::<Vec<_>>();

    assert_eq!(visible, vec![
        (1, svc_1),
        (3, svc_3),
    ]);
}
