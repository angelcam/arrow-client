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

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use time;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error;

use net::arrow::proto::{
    BoxServiceTable,
    Service,
    ServiceTable,
    ServiceType,
    SimpleServiceTable,

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
use net::raw::ether::MacAddr;

use utils::config::ConfigError;

const ACTIVE_THRESHOLD: i64 = 1200;

/// Get current UNIX timestamp in UTC.
fn get_utc_timestamp() -> i64 {
    time::now_utc()
        .to_timespec()
        .sec
}

/// Helper struct for service table keys.
#[derive(Eq, PartialEq, Hash)]
struct ServiceTableKey {
    svc_type: ServiceType,
    mac_addr: Option<MacAddr>,
    port:     Option<u16>,
    path:     Option<String>,
}

impl<'a> From<&'a Service> for ServiceTableKey {
    fn from(svc: &'a Service) -> ServiceTableKey {
        let mac  = svc.mac();
        let addr = svc.address();
        let path = svc.path();

        ServiceTableKey {
            svc_type: svc.service_type(),
            mac_addr: mac.map(|mac| mac.clone()),
            port:     addr.map(|addr| addr.port()),
            path:     path.map(|path| path.to_string()),
        }
    }
}

/// Service table element.
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
        let id = self.service.id();

        self.service   = Service::new(id, svc);
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
}

/// Service table internal data.
struct ServiceTableData {
    map:      HashMap<ServiceTableKey, usize>,
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
        let key = ServiceTableKey::from(&svc);

        assert!(!self.map.contains_key(&key));

        let elem = ServiceTableElement::new(
            Service::new(id, svc),
            static_svc,
            enabled);

        self.map.insert(key, self.services.len());
        self.services.push(elem);

        id
    }

    /// Update service table with a given service and return ID of the service.
    fn update(&mut self, svc: Service, static_svc: bool, enabled: bool) -> u16 {
        let key = ServiceTableKey::from(&svc);

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

    /// Get SimpleServiceTable consisting of all visible services.
    fn to_simple_table(&self) -> SimpleServiceTable {
        let iter = self.services.iter()
            .filter(|elem| elem.is_visible())
            .map(|elem| elem.to_service());

        SimpleServiceTable::from(iter)
    }
}

impl Serialize for ServiceTableData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
        SerdeServiceTable::from(&self.services)
            .serialize(serializer)
    }
}

impl Deserialize for ServiceTableData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer {
        let table = SerdeServiceTable::deserialize(deserializer)?;

        let mut res = ServiceTableData {
            services: Vec::new(),
            map:      HashMap::new(),
        };

        for svc in table.services {
            let index = res.services.len();
            let elem = svc.into_service_table_element((index + 1) as u16)
                .map_err(|err| D::Error::custom(format!("{}", err)))?;
            let key = ServiceTableKey::from(&elem.service);

            res.services.push(elem);
            res.map.insert(key, index);
        }

        Ok(res)
    }
}

/// Service table implementation that can be shared across multiple threads.
#[derive(Clone)]
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

    /// Get SimpleServiceTable consisting of all visible services.
    pub fn to_simple_table(&self) -> SimpleServiceTable {
        self.data.lock()
            .unwrap()
            .to_simple_table()
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

impl Deserialize for SharedServiceTable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer {
        let data = ServiceTableData::deserialize(deserializer)?;

        let res = SharedServiceTable {
            data: Arc::new(Mutex::new(data)),
        };

        Ok(res)
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
    fn into_service_table_element(
        self,
        id: u16) -> Result<ServiceTableElement, ConfigError> {
        let epath = String::new();
        let opath;

        if self.path.len() > 0 {
            opath = Some(self.path);
        } else {
            opath = None;
        }

        let svc = match self.svc_type {
            SVC_TYPE_CONTROL_PROTOCOL => Ok(Service::control()),
            SVC_TYPE_RTSP => Ok(Service::rtsp(id,
                self.mac.parse()?, self.address.parse()?,
                opath.unwrap_or(epath))),
            SVC_TYPE_LOCKED_RTSP => Ok(Service::locked_rtsp(id,
                self.mac.parse()?, self.address.parse()?,
                opath)),
            SVC_TYPE_UNKNOWN_RTSP => Ok(Service::unknown_rtsp(id,
                self.mac.parse()?, self.address.parse()?)),
            SVC_TYPE_UNSUPPORTED_RTSP => Ok(Service::unsupported_rtsp(id,
                self.mac.parse()?, self.address.parse()?,
                opath.unwrap_or(epath))),
            SVC_TYPE_HTTP => Ok(Service::http(id,
                self.mac.parse()?, self.address.parse()?)),
            SVC_TYPE_MJPEG => Ok(Service::mjpeg(id,
                self.mac.parse()?, self.address.parse()?,
                opath.unwrap_or(epath))),
            SVC_TYPE_LOCKED_MJPEG => Ok(Service::locked_mjpeg(id,
                self.mac.parse()?, self.address.parse()?,
                opath)),
            SVC_TYPE_TCP => Ok(Service::tcp(id,
                self.mac.parse()?, self.address.parse()?)),
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
            .unwrap_or(&default_mac);
        let address = elem.service.address()
            .unwrap_or(&default_address);
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
