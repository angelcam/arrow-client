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

use std::fmt;

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use json::JsonValue;

use crate::net::raw::ether::MacAddr;
use crate::utils::json::{FromJson, ParseError, ToJson};

pub use self::service::{
    Service, ServiceIdentifier, ServiceType, SVC_TYPE_CONTROL_PROTOCOL, SVC_TYPE_HTTP,
    SVC_TYPE_LOCKED_MJPEG, SVC_TYPE_LOCKED_RTSP, SVC_TYPE_MJPEG, SVC_TYPE_RTSP, SVC_TYPE_TCP,
    SVC_TYPE_UNKNOWN_RTSP, SVC_TYPE_UNSUPPORTED_RTSP,
};

const ACTIVE_THRESHOLD: i64 = 1200;

/// Stable implementation of the Hasher trait.
struct StableHasher {
    data: Vec<u8>,
}

impl StableHasher {
    /// Create a new instance of StableHasher with a given capacity of the
    /// internal data buffer.
    fn new(capacity: usize) -> StableHasher {
        StableHasher {
            data: Vec::with_capacity(capacity),
        }
    }
}

impl Hasher for StableHasher {
    fn finish(&self) -> u64 {
        farmhash::fingerprint64(&self.data)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes)
    }
}

/// Compute an u64 hash for a given hashable object using a stable hasher.
fn stable_hash<T: Hash>(val: &T) -> u64 {
    let mut hasher = StableHasher::new(512);

    val.hash(&mut hasher);

    hasher.finish()
}

/// Get current UNIX timestamp in UTC.
fn get_utc_timestamp() -> i64 {
    time::now_utc().to_timespec().sec
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
pub type BoxServiceTable = Box<dyn ServiceTable + Send + Sync>;

impl ServiceTable for Box<dyn ServiceTable + Send + Sync> {
    fn get(&self, id: u16) -> Option<Service> {
        self.as_ref().get(id)
    }

    fn get_id(&self, identifier: &ServiceIdentifier) -> Option<u16> {
        self.as_ref().get_id(identifier)
    }

    fn boxed(self) -> BoxServiceTable {
        self
    }
}

/// Service table element.
#[derive(Clone)]
struct ServiceTableElement {
    /// Service ID.
    id: u16,
    /// Service.
    service: Service,
    /// Flag indicating a manually added service.
    static_service: bool,
    /// Flag indicating static service visibility.
    enabled: bool,
    /// UNIX timestamp (in UTC) of the last discovery event.
    last_seen: i64,
    /// Active flag.
    active: bool,
}

impl ServiceTableElement {
    /// Create a new Control Protocol service table element.
    fn control() -> Self {
        Self::new(0, Service::control(), true, true)
    }

    /// Create a new service table element.
    fn new(id: u16, svc: Service, static_svc: bool, enabled: bool) -> Self {
        Self {
            id,
            service: svc,
            static_service: static_svc,
            enabled,
            last_seen: get_utc_timestamp(),
            active: true,
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
        self.service = svc;
        self.enabled = enabled;
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
        let default_address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));

        let svc_type = self.service.service_type();

        let mac = self.service.mac().unwrap_or(default_mac);
        let address = self.service.address().unwrap_or(default_address);
        let path = self.service.path().unwrap_or("");

        object! {
            "id" => self.id,
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
            return Err(ParseError::new("JSON object expected"));
        }

        let svc_type = service
            .get("svc_type")
            .and_then(|v| v.as_u16())
            .ok_or_else(|| ParseError::new("missing field \"svc_type\""))?;
        let mac = service
            .get("mac")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ParseError::new("missing field \"mac\""))?;
        let address = service
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ParseError::new("missing field \"address\""))?;
        let path = service
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ParseError::new("missing field \"path\""))?;

        let epath = String::new();

        let opath = if path.is_empty() {
            None
        } else {
            Some(path.to_string())
        };

        let mac = mac
            .parse()
            .map_err(|_| ParseError::new("unable to parse MAC address"));
        let address = address
            .parse()
            .map_err(|_| ParseError::new("unable to parse socket address"));

        let svc = match svc_type {
            SVC_TYPE_CONTROL_PROTOCOL => Ok(Service::control()),
            SVC_TYPE_RTSP => Ok(Service::rtsp(mac?, address?, opath.unwrap_or(epath))),
            SVC_TYPE_LOCKED_RTSP => Ok(Service::locked_rtsp(mac?, address?, opath)),
            SVC_TYPE_UNKNOWN_RTSP => Ok(Service::unknown_rtsp(mac?, address?)),
            SVC_TYPE_UNSUPPORTED_RTSP => Ok(Service::unsupported_rtsp(
                mac?,
                address?,
                opath.unwrap_or(epath),
            )),
            SVC_TYPE_HTTP => Ok(Service::http(mac?, address?)),
            SVC_TYPE_MJPEG => Ok(Service::mjpeg(mac?, address?, opath.unwrap_or(epath))),
            SVC_TYPE_LOCKED_MJPEG => Ok(Service::locked_mjpeg(mac?, address?, opath)),
            SVC_TYPE_TCP => Ok(Service::tcp(mac?, address?)),
            _ => Err(ParseError::new("unknown service type")),
        };

        let id = service.get("id").and_then(|v| v.as_u16()).unwrap_or(0);
        let static_svc = service
            .get("static_svc")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let last_seen = service
            .get("last_seen")
            .and_then(|v| v.as_i64())
            .unwrap_or_else(get_utc_timestamp);
        let active = service
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let elem = Self {
            id,
            service: svc?,
            static_service: static_svc,
            last_seen,
            active,
            enabled: false,
        };

        Ok(elem)
    }
}

/// Service table internal data.
#[derive(Clone)]
struct ServiceTableData {
    identifier_map: HashMap<ServiceIdentifier, u16>,
    service_map: HashMap<u16, ServiceTableElement>,
    version: usize,
}

impl ServiceTableData {
    /// Create a new instance of ServiceTableData.
    fn new() -> Self {
        let elem = ServiceTableElement::control();

        let mut identifier_map = HashMap::new();
        let mut service_map = HashMap::new();

        identifier_map.insert(elem.service.to_service_identifier(), elem.id);

        service_map.insert(elem.id, elem);

        Self {
            identifier_map,
            service_map,
            version: 0,
        }
    }

    /// Get version of the service table.
    fn version(&self) -> usize {
        self.version
    }

    /// Get visible service for a given ID.
    fn get(&self, id: u16) -> Option<Service> {
        if let Some(elem) = self.service_map.get(&id) {
            if elem.is_visible() || elem.service.is_control() {
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
        if let Some(id) = self.identifier_map.get(identifier) {
            let elem = self.service_map.get(id).expect("broken service table");

            if elem.is_visible() || elem.service.is_control() {
                Some(*id)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get visible services.
    fn visible(&self) -> ServiceTableIterator {
        let visible = self
            .service_map
            .values()
            .filter(|elem| elem.is_visible() && !elem.service.is_control());

        ServiceTableIterator::new(visible)
    }

    /// Insert a new element into the table and return its ID.
    fn add_service(&mut self, svc: Service, static_svc: bool, enabled: bool) -> u16 {
        let key = svc.to_service_identifier();
        let id = stable_hash(&key) as u16;

        assert!(!self.identifier_map.contains_key(&key));

        let elem = ServiceTableElement::new(id, svc, static_svc, enabled);

        if elem.is_visible() {
            self.version += 1;
        }

        self.add_element(elem)
    }

    /// Add a given service table element into the table and return its ID.
    fn add_element(&mut self, mut elem: ServiceTableElement) -> u16 {
        let mut current_id = elem.id;

        while self.service_map.contains_key(&current_id) {
            current_id = current_id.wrapping_add(1);

            if current_id == elem.id {
                panic!("service table is full");
            }
        }

        elem.id = current_id;

        self.identifier_map
            .insert(elem.service.to_service_identifier(), current_id);

        self.service_map.insert(current_id, elem);

        current_id
    }

    /// Update a given table element and return its ID.
    fn update_element(&mut self, id: u16, svc: Service, enabled: bool) -> u16 {
        let elem = self.service_map.get_mut(&id).expect("broken service table");

        let svc_change = elem.service != svc;
        let old_visible = elem.is_visible();

        elem.update(svc, enabled);

        let new_visible = elem.is_visible();

        if old_visible != new_visible || (new_visible && svc_change) {
            self.version += 1;
        }

        id
    }

    /// Update service table with a given service and return ID of the service.
    fn update(&mut self, svc: Service, static_svc: bool, enabled: bool) -> u16 {
        let key = svc.to_service_identifier();

        let id = self.identifier_map.get(&key).copied();

        if let Some(id) = id {
            self.update_element(id, svc, enabled)
        } else {
            self.add_service(svc, static_svc, enabled)
        }
    }

    /// Update active flags of all services.
    fn update_active_services(&mut self) {
        let timestamp = get_utc_timestamp();

        for elem in self.service_map.values_mut() {
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
        let services = self
            .service_map
            .values()
            .filter(|elem| !elem.service.is_control())
            .map(|elem| elem.to_json())
            .collect::<Vec<_>>();

        object! {
            "services" => services
        }
    }
}

impl FromJson for ServiceTableData {
    fn from_json(value: JsonValue) -> Result<Self, ParseError> {
        let mut res = Self::new();

        let mut table;

        if let JsonValue::Object(t) = value {
            table = t;
        } else {
            return Err(ParseError::new("JSON object expected"));
        }

        let tmp = table
            .remove("services")
            .ok_or_else(|| ParseError::new("missing field \"services\""))?;

        let services;

        if let JsonValue::Array(svcs) = tmp {
            services = svcs.into_iter();
        } else {
            return Err(ParseError::new("JSON array expected"));
        }

        for (index, service) in services.enumerate() {
            let use_array_index = !service.has_key("id");

            let mut elem = ServiceTableElement::from_json(service)?;

            if use_array_index {
                elem.id = (index + 1) as u16;
            }

            res.add_element(elem);
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
    fn new<'a, I>(elements: I) -> Self
    where
        I: IntoIterator<Item = &'a ServiceTableElement>,
    {
        let elements = elements
            .into_iter()
            .map(|elem| (elem.id, elem.to_service()))
            .collect::<Vec<_>>();

        Self {
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

impl Default for SharedServiceTable {
    fn default() -> Self {
        Self {
            data: Arc::new(Mutex::new(ServiceTableData::new())),
        }
    }
}

impl SharedServiceTable {
    /// Create a new shared service table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get version of the service table.
    pub fn version(&self) -> usize {
        self.data.lock().unwrap().version()
    }

    /// Add a given service into the table and return its ID.
    pub fn add(&mut self, svc: Service) -> u16 {
        self.data.lock().unwrap().update(svc, false, true)
    }

    /// Add a given static service into the table and return its ID.
    pub fn add_static(&mut self, svc: Service) -> u16 {
        self.data.lock().unwrap().update(svc, true, true)
    }

    /// Update active flags of all services.
    pub fn update_active_services(&mut self) {
        self.data.lock().unwrap().update_active_services()
    }

    /// Get read-only reference to this table.
    pub fn get_ref(&self) -> SharedServiceTableRef {
        SharedServiceTableRef {
            data: self.data.clone(),
        }
    }
}

impl Clone for SharedServiceTable {
    fn clone(&self) -> Self {
        let cloned = self.data.lock().unwrap().clone();

        Self {
            data: Arc::new(Mutex::new(cloned)),
        }
    }
}

impl ServiceTable for SharedServiceTable {
    fn get(&self, id: u16) -> Option<Service> {
        self.data.lock().unwrap().get(id)
    }

    fn get_id(&self, identifier: &ServiceIdentifier) -> Option<u16> {
        self.data.lock().unwrap().get_id(identifier)
    }

    fn boxed(self) -> BoxServiceTable {
        Box::new(self)
    }
}

impl Display for SharedServiceTable {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        self.data.lock().unwrap().fmt(f)
    }
}

impl ToJson for SharedServiceTable {
    fn to_json(&self) -> JsonValue {
        self.data.lock().unwrap().to_json()
    }
}

impl FromJson for SharedServiceTable {
    fn from_json(value: JsonValue) -> Result<Self, ParseError> {
        let data = ServiceTableData::from_json(value)?;

        let res = Self {
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
        self.data.lock().unwrap().version()
    }

    /// Get visible services.
    pub fn visible(&self) -> ServiceTableIterator {
        self.data.lock().unwrap().visible()
    }
}

impl ServiceTable for SharedServiceTableRef {
    fn get(&self, id: u16) -> Option<Service> {
        self.data.lock().unwrap().get(id)
    }

    fn get_id(&self, identifier: &ServiceIdentifier) -> Option<u16> {
        self.data.lock().unwrap().get_id(identifier)
    }

    fn boxed(self) -> BoxServiceTable {
        Box::new(self)
    }
}

impl ToJson for SharedServiceTableRef {
    fn to_json(&self) -> JsonValue {
        self.data.lock().unwrap().to_json()
    }
}

impl Display for SharedServiceTableRef {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        self.data.lock().unwrap().fmt(f)
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
    table.update(svc_2, true, false);
    table.update(svc_3.clone(), true, true);

    let mut visible = table.visible().collect::<Vec<_>>();

    visible.sort_by_key(|&(id, _)| id);

    let mut expected = vec![(41839, svc_1), (26230, svc_3)];

    expected.sort_by_key(|&(id, _)| id);

    assert_eq!(visible, expected);
}

#[cfg(test)]
#[test]
fn test_deserialization_and_initialization() {
    let json = object! {
        "services" => array![
            object!{
                "svc_type" => 1,
                "mac" => "00:00:00:00:00:00",
                "address" => "0.0.0.0:0",
                "path" => "/1",
                "static_svc" => true,
                "last_seen" => 123,
                "active" => true
            },
            object!{
                "svc_type" => 1,
                "mac" => "00:00:00:00:00:00",
                "address" => "0.0.0.0:0",
                "path" => "/2",
                "static_svc" => true,
                "last_seen" => 123,
                "active" => true
            },
            object!{
                "svc_type" => 1,
                "mac" => "00:00:00:00:00:00",
                "address" => "0.0.0.0:0",
                "path" => "/3",
                "static_svc" => false,
                "last_seen" => 123,
                "active" => true
            },
            object!{
                "id" => 10000,
                "svc_type" => 1,
                "mac" => "00:00:00:00:00:00",
                "address" => "0.0.0.0:0",
                "path" => "/4",
                "static_svc" => false,
                "last_seen" => 123,
                "active" => true
            }
        ]
    };

    let mut table = SharedServiceTable::from_json(json).expect("expected valid service table JSON");

    assert_eq!(table.version(), 0);

    let mac = MacAddr::zero();
    let ip = Ipv4Addr::new(0, 0, 0, 0);
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, 0));

    let svc_1 = Service::rtsp(mac, addr, "/1".to_string());
    let svc_2 = Service::rtsp(mac, addr, "/2".to_string());
    let svc_3 = Service::rtsp(mac, addr, "/3".to_string());
    let svc_4 = Service::rtsp(mac, addr, "/4".to_string());
    let svc_5 = Service::rtsp(mac, addr, "/5".to_string());

    let mut visible = table.get_ref().visible().collect::<Vec<_>>();

    visible.sort_by_key(|&(id, _)| id);

    assert_eq!(visible, vec![(3, svc_3.clone()), (10000, svc_4.clone()),]);

    // add the first static service
    table.add_static(svc_1.clone());

    let mut visible = table.get_ref().visible().collect::<Vec<_>>();

    visible.sort_by_key(|&(id, _)| id);

    assert_eq!(
        visible,
        vec![
            (1, svc_1.clone()),
            (3, svc_3.clone()),
            (10000, svc_4.clone()),
        ]
    );

    assert_eq!(table.version(), 1);

    // add the first static service again
    table.add_static(svc_1.clone());

    let mut visible = table.get_ref().visible().collect::<Vec<_>>();

    visible.sort_by_key(|&(id, _)| id);

    assert_eq!(
        visible,
        vec![
            (1, svc_1.clone()),
            (3, svc_3.clone()),
            (10000, svc_4.clone()),
        ]
    );

    assert_eq!(table.version(), 1);

    // add the second static service
    table.add_static(svc_2.clone());

    let mut visible = table.get_ref().visible().collect::<Vec<_>>();

    visible.sort_by_key(|&(id, _)| id);

    assert_eq!(
        visible,
        vec![
            (1, svc_1.clone()),
            (2, svc_2.clone()),
            (3, svc_3.clone()),
            (10000, svc_4.clone()),
        ]
    );

    assert_eq!(table.version(), 2);

    // add a new service
    table.add(svc_5.clone());

    let mut visible = table.get_ref().visible().collect::<Vec<_>>();

    visible.sort_by_key(|&(id, _)| id);

    assert_eq!(
        visible,
        vec![
            (1, svc_1.clone()),
            (2, svc_2.clone()),
            (3, svc_3.clone()),
            (10000, svc_4.clone()),
            (33402, svc_5.clone()),
        ]
    );

    assert_eq!(table.version(), 3);

    // some additional consistency checks
    let mut internal = table.data.lock().unwrap();

    let control = Service::control();
    let key = control.to_service_identifier();

    assert_eq!(internal.get(0), Some(control.clone()));
    assert_eq!(internal.get_id(&key), Some(0));
    assert_eq!(internal.service_map.len(), 6);
    assert_eq!(internal.identifier_map.len(), 6);

    internal.update(control.clone(), true, true);

    assert_eq!(internal.get(0), Some(control));
    assert_eq!(internal.get_id(&key), Some(0));
    assert_eq!(internal.service_map.len(), 6);
    assert_eq!(internal.identifier_map.len(), 6);

    let mut visible = internal.visible().collect::<Vec<_>>();

    visible.sort_by_key(|&(id, _)| id);

    assert_eq!(
        visible,
        vec![
            (1, svc_1.clone()),
            (2, svc_2.clone()),
            (3, svc_3),
            (10000, svc_4),
            (33402, svc_5.clone()),
        ]
    );

    assert_eq!(internal.version(), 3);

    // update the list of active services
    internal.update_active_services();

    let mut visible = internal.visible().collect::<Vec<_>>();

    visible.sort_by_key(|&(id, _)| id);

    assert_eq!(visible, vec![(1, svc_1), (2, svc_2), (33402, svc_5),]);

    assert_eq!(internal.version(), 5);
}
