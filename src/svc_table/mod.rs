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

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use time;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error;

use config::ConfigError;

use net::raw::ether::MacAddr;

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

    /// Check if the element should be visible.
    fn is_visible(&self) -> bool {
        if self.static_service {
            self.enabled
        } else {
            self.active
        }
    }

    /// Check if this element is equal to a given service (except service ID and IP address).
    fn equals(&self, svc: &Service) -> bool {
        self.service.service_type() == svc.service_type()
            && self.service.mac() == svc.mac()
            && self.service.port() == svc.port()
            && self.service.path() == svc.path()
    }

    /// Check if this element is equal to a given service (except service ID).
    fn equals_exact(&self, svc: &Service) -> bool {
        self.equals(svc) && self.service.address() == svc.address()
    }
}

/// Service table internal data.
#[derive(Clone)]
struct ServiceTableData {
    map:      HashMap<ServiceIdentifier, usize>,
    services: Vec<ServiceTableElement>,
}

impl ServiceTableData {
    /// Create a new instance of ServiceTableData.
    fn new() -> ServiceTableData {
        ServiceTableData {
            map:      HashMap::new(),
            services: Vec::new(),
        }
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

    /// Update a given table element and return its ID.
    fn update_element(
        &mut self,
        index: usize,
        svc: Service,
        enabled: bool) -> u16 {
        if let Some(elem) = self.services.get_mut(index) {
            elem.update(svc, enabled);
        } else {
            panic!("given service table element does not exist");
        }

        (index + 1) as u16
    }

    /// Insert a new element into the table and return its ID.
    fn insert_element(&mut self, svc: Service, static_svc: bool, enabled: bool) -> u16 {
        let id  = (self.services.len() + 1) as u16;
        let key = svc.to_service_identifier();

        assert!(!self.map.contains_key(&key));

        let elem = ServiceTableElement::new(svc, static_svc, enabled);

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

    /// Update active flags of all services and return number of services
    /// with changed visibility.
    fn update_active_services(&mut self) -> usize {
        let timestamp = get_utc_timestamp();

        let mut changed = 0;

        for elem in &mut self.services {
            let visible = elem.is_visible();
            elem.update_active_flag(timestamp);
            if visible != elem.is_visible() {
                changed += 1;
            }
        }

        changed
    }

    /// Check if there is already a given service in the table.
    fn contains(&self, svc: &Service) -> bool {
        if svc.is_control() {
            return true
        }

        let key = svc.to_service_identifier();

        self.map.contains_key(&key)
    }

    /// Check if there is already a given service in the table and all service fields
    /// are equal to the given one.
    fn contains_exact(&self, svc: &Service) -> bool {
        if svc.is_control() {
            return true
        }

        let key = svc.to_service_identifier();

        let index = self.map.get(&key)
            .map(|index| *index);

        if let Some(index) = index {
            if let Some(elem) = self.services.get(index) {
                elem.equals_exact(svc)
            } else {
                panic!("given service table element does not exist");
            }
        } else {
            false
        }
    }

    /// Get service table iterator.
    fn iter(&self) -> ServiceTableIterator {
        ServiceTableIterator::new(&self.services)
    }
}

impl Serialize for ServiceTableData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
        SerdeServiceTable::from(&self.services)
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServiceTableData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
        let table = SerdeServiceTable::deserialize(deserializer)?;

        let mut res = ServiceTableData {
            services: Vec::new(),
            map:      HashMap::new(),
        };

        for svc in table.services {
            let index = res.services.len();
            let elem = svc.into_service_table_element()
                .map_err(|err| D::Error::custom(format!("{}", err)))?;
            let key = elem.service.to_service_identifier();

            res.services.push(elem);
            res.map.insert(key, index);
        }

        Ok(res)
    }
}

/// Service table iterator.
pub struct ServiceTableIterator {
    elements: std::vec::IntoIter<(u16, Service)>,
}

impl ServiceTableIterator {
    /// Create a new service table iterator.
    fn new(elements: &[ServiceTableElement]) -> ServiceTableIterator {
        let mut res = Vec::new();

        for ref element in elements {
            let id = res.len() as u16 + 1;
            
            res.push((
                id,
                element.to_service(),
            ));
        }

        ServiceTableIterator {
            elements: res.into_iter(),
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

    /// Update active flags of all services and return number of services
    /// with changed visibility.
    pub fn update_active_services(&mut self) -> usize {
        self.data.lock()
            .unwrap()
            .update_active_services()
    }

    /// Check if there is already a given service.
    pub fn contains(&self, svc: &Service) -> bool {
        self.data.lock()
            .unwrap()
            .contains(svc)
    }

    /// Check if there is already a given service.
    pub fn contains_exact(&self, svc: &Service) -> bool {
        self.data.lock()
            .unwrap()
            .contains_exact(svc)
    }

    /// Get service table iterator.
    pub fn iter(&self) -> ServiceTableIterator {
        self.data.lock()
            .unwrap()
            .iter()
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

    fn boxed(self) -> BoxServiceTable {
        Box::new(self)
    }
}

impl Serialize for SharedServiceTable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
        self.data.lock()
            .unwrap()
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SharedServiceTable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
        let data = ServiceTableData::deserialize(deserializer)?;

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
    /// Get service table iterator.
    pub fn iter(&self) -> ServiceTableIterator {
        self.data.lock()
            .unwrap()
            .iter()
    }
}

impl ServiceTable for SharedServiceTableRef {
    fn get(&self, id: u16) -> Option<Service> {
        self.data.lock()
            .unwrap()
            .get(id)
    }

    fn boxed(self) -> BoxServiceTable {
        Box::new(self)
    }
}

/// Helper struct for service table element serialization/deserialization.
#[derive(Serialize, Deserialize)]
struct SerdeService {
    svc_type:   u16,
    mac:        String,
    address:    String,
    path:       String,
    static_svc: Option<bool>,
    last_seen:  Option<i64>,
    active:     Option<bool>,
}

impl SerdeService {
    /// Convert this object into a ServiceTableElement.
    fn into_service_table_element(self) -> Result<ServiceTableElement, ConfigError> {
        let epath = String::new();
        let opath;

        if self.path.len() > 0 {
            opath = Some(self.path);
        } else {
            opath = None;
        }

        let svc = match self.svc_type {
            SVC_TYPE_CONTROL_PROTOCOL => Ok(Service::control()),
            SVC_TYPE_RTSP => Ok(Service::rtsp(
                self.mac.parse()?,
                self.address.parse()?,
                opath.unwrap_or(epath),
            )),
            SVC_TYPE_LOCKED_RTSP => Ok(Service::locked_rtsp(
                self.mac.parse()?,
                self.address.parse()?,
                opath,
            )),
            SVC_TYPE_UNKNOWN_RTSP => Ok(Service::unknown_rtsp(
                self.mac.parse()?,
                self.address.parse()?,
            )),
            SVC_TYPE_UNSUPPORTED_RTSP => Ok(Service::unsupported_rtsp(
                self.mac.parse()?,
                self.address.parse()?,
                opath.unwrap_or(epath),
            )),
            SVC_TYPE_HTTP => Ok(Service::http(
                self.mac.parse()?,
                self.address.parse()?,
            )),
            SVC_TYPE_MJPEG => Ok(Service::mjpeg(
                self.mac.parse()?,
                self.address.parse()?,
                opath.unwrap_or(epath),
            )),
            SVC_TYPE_LOCKED_MJPEG => Ok(Service::locked_mjpeg(
                self.mac.parse()?,
                self.address.parse()?,
                opath,
            )),
            SVC_TYPE_TCP => Ok(Service::tcp(
                self.mac.parse()?,
                self.address.parse()?,
            )),
            _ => Err(ConfigError::from("unknown service type"))
        };

        let static_svc = self.static_svc.unwrap_or(false);
        let last_seen  = self.last_seen.unwrap_or(get_utc_timestamp());
        let active     = self.active.unwrap_or(true);

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

impl<'a> From<&'a ServiceTableElement> for SerdeService {
    fn from(elem: &'a ServiceTableElement) -> SerdeService {
        let default_mac = MacAddr::zero();
        let default_address = SocketAddr::V4(
            SocketAddrV4::new(
                Ipv4Addr::new(0, 0, 0, 0),
                0));

        let svc_type = elem.service.service_type();

        let mac = elem.service.mac()
            .unwrap_or(default_mac);
        let address = elem.service.address()
            .unwrap_or(default_address);
        let path = elem.service.path()
            .unwrap_or("");

        SerdeService {
            svc_type:   svc_type.code(),
            mac:        format!("{}", mac),
            address:    format!("{}", address),
            path:       path.to_string(),
            static_svc: Some(elem.static_service),
            last_seen:  Some(elem.last_seen),
            active:     Some(elem.active),
        }
    }
}

/// Helper struct for service table serialization/deserialization.
#[derive(Serialize, Deserialize)]
struct SerdeServiceTable {
    services: Vec<SerdeService>,
}

impl<'a, I> From<I> for SerdeServiceTable
    where I: IntoIterator<Item=&'a ServiceTableElement> {
    fn from(services: I) -> SerdeServiceTable {
        let services = services.into_iter()
            .map(|svc| SerdeService::from(svc))
            .collect::<_>();

        SerdeServiceTable {
            services: services,
        }
    }
}
