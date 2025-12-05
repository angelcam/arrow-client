// Copyright 2025 Angelcam, Inc.
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

use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_lite::{Deserialize, Intermediate, Serialize};

use crate::net::raw::ether::MacAddr;

pub use self::service::{
    SVC_TYPE_CONTROL_PROTOCOL, SVC_TYPE_HTTP, SVC_TYPE_LOCKED_MJPEG, SVC_TYPE_LOCKED_RTSP,
    SVC_TYPE_MJPEG, SVC_TYPE_RTSP, SVC_TYPE_TCP, SVC_TYPE_UNKNOWN_RTSP, SVC_TYPE_UNSUPPORTED_RTSP,
    Service, ServiceIdentifier, ServiceType,
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|err| err.duration())
        .unwrap_or_else(|d| -(d.as_secs() as i64))
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

/// Service table internal data.
#[derive(Clone)]
struct ServiceTableData {
    identifier_map: HashMap<ServiceIdentifier, u16>,
    service_map: HashMap<u16, ServiceTableElement>,
    service_table_version: u32,
    visible_set_version: u32,
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
            service_table_version: 0,
            visible_set_version: 0,
        }
    }

    /// Get version of the service table.
    ///
    /// The version is updated whenever a new service is added or an existing
    /// service is changed (e.g. its IP address).
    fn service_table_version(&self) -> u32 {
        self.service_table_version
    }

    /// Get version of the set of visible services.
    ///
    /// The version is updated whenever service visibility changes.
    fn visible_set_version(&self) -> u32 {
        self.visible_set_version
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
            self.visible_set_version = self.visible_set_version.wrapping_add(1);
        }

        self.service_table_version = self.service_table_version.wrapping_add(1);

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

        if svc_change {
            self.service_table_version = self.service_table_version.wrapping_add(1);
        }

        if old_visible != new_visible || (new_visible && svc_change) {
            self.visible_set_version = self.visible_set_version.wrapping_add(1);
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
                self.visible_set_version = self.visible_set_version.wrapping_add(1);
            }
        }
    }
}

impl Deserialize for ServiceTableData {
    fn deserialize(val: &Intermediate) -> Result<Self, serde_lite::Error> {
        let data = ServiceTableDataSerializer::deserialize(val)?;

        let mut res = Self::new();

        data.services
            .into_iter()
            .enumerate()
            .for_each(|(index, svc)| {
                res.add_element(svc.into_service_table_element(index));
            });

        Ok(res)
    }
}

impl Serialize for ServiceTableData {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        let services = self
            .service_map
            .values()
            .filter(|elem| !elem.service.is_control())
            .map(ServiceTableElementSerializer::from)
            .collect::<Vec<_>>();

        let serializer = ServiceTableDataSerializer { services };

        serializer.serialize()
    }
}

impl Display for ServiceTableData {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let s = self
            .serialize()
            .ok()
            .map(|val| serde_json::to_string(&val))
            .and_then(Result::ok)
            .expect("unable to serialize service table");

        f.write_str(&s)
    }
}

/// Service table iterator.
pub struct ServiceTableIterator {
    elements: std::vec::IntoIter<(u16, Service)>,
}

impl ServiceTableIterator {
    /// Create a new service table iterator.
    #[allow(clippy::needless_collect)]
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
    ///
    /// The version is updated whenever a new service is added or an existing
    /// service is changed (e.g. its IP address).
    pub fn service_table_version(&self) -> u32 {
        self.data.lock().unwrap().service_table_version()
    }

    /// Get version of the set of visible services.
    ///
    /// The version is updated whenever service visibility changes.
    pub fn visible_set_version(&self) -> u32 {
        self.data.lock().unwrap().visible_set_version()
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

impl Deserialize for SharedServiceTable {
    fn deserialize(val: &Intermediate) -> Result<Self, serde_lite::Error> {
        let data = ServiceTableData::deserialize(val)?;

        let res = Self {
            data: Arc::new(Mutex::new(data)),
        };

        Ok(res)
    }
}

impl Serialize for SharedServiceTable {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        self.data.lock().unwrap().serialize()
    }
}

/// Service table implementation that can be shared across multiple threads.
#[derive(Clone)]
pub struct SharedServiceTableRef {
    data: Arc<Mutex<ServiceTableData>>,
}

impl SharedServiceTableRef {
    /// Get version of the service table.
    ///
    /// The version is updated whenever a new service is added or an existing
    /// service is changed (e.g. its IP address).
    pub fn service_table_version(&self) -> u32 {
        self.data.lock().unwrap().service_table_version()
    }

    /// Get version of the set of visible services.
    ///
    /// The version is updated whenever service visibility changes.
    pub fn visible_set_version(&self) -> u32 {
        self.data.lock().unwrap().visible_set_version()
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

impl Serialize for SharedServiceTableRef {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        self.data.lock().unwrap().serialize()
    }
}

impl Display for SharedServiceTableRef {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        self.data.lock().unwrap().fmt(f)
    }
}

/// Helper type for serializing/deserializing service table data.
#[derive(Deserialize, Serialize)]
struct ServiceTableDataSerializer {
    services: Vec<ServiceTableElementSerializer>,
}

/// Helper type for serializing/deserializing service table elements.
#[derive(Deserialize, Serialize)]
struct ServiceTableElementSerializer {
    #[serde(default)]
    id: Option<u16>,

    svc_type: ServiceTypeSerializer,
    mac: MacAddrSerializer,
    address: SocketAddrSerializer,
    path: String,

    #[serde(default)]
    static_svc: Option<bool>,

    #[serde(default)]
    last_seen: Option<i64>,

    #[serde(default)]
    active: Option<bool>,
}

impl ServiceTableElementSerializer {
    /// Create the corresponding `ServiceTableElement`.
    fn into_service_table_element(self, index: usize) -> ServiceTableElement {
        let mac = self.mac.into();
        let address = self.address.into();

        let epath = String::new();

        let opath = if self.path.is_empty() {
            None
        } else {
            Some(self.path)
        };

        let service = match ServiceType::from(self.svc_type) {
            ServiceType::ControlProtocol => Service::control(),
            ServiceType::RTSP => Service::rtsp(mac, address, opath.unwrap_or(epath)),
            ServiceType::LockedRTSP => Service::locked_rtsp(mac, address, opath),
            ServiceType::UnknownRTSP => Service::unknown_rtsp(mac, address),
            ServiceType::UnsupportedRTSP => {
                Service::unsupported_rtsp(mac, address, opath.unwrap_or(epath))
            }
            ServiceType::HTTP => Service::http(mac, address),
            ServiceType::MJPEG => Service::mjpeg(mac, address, opath.unwrap_or(epath)),
            ServiceType::LockedMJPEG => Service::locked_mjpeg(mac, address, opath),
            ServiceType::TCP => Service::tcp(mac, address),
        };

        ServiceTableElement {
            id: self.id.unwrap_or((index + 1) as u16),
            service,
            static_service: self.static_svc.unwrap_or(false),
            last_seen: self.last_seen.unwrap_or_else(get_utc_timestamp),
            active: self.active.unwrap_or(true),
            enabled: false,
        }
    }
}

impl From<&ServiceTableElement> for ServiceTableElementSerializer {
    fn from(elem: &ServiceTableElement) -> Self {
        let svc_type = elem.service.service_type();

        let mac = elem.service.mac().unwrap_or(MacAddr::ZERO).into();

        let address = elem
            .service
            .address()
            .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .into();

        let path = elem.service.path().unwrap_or("").into();

        Self {
            id: Some(elem.id),
            svc_type: svc_type.into(),
            mac,
            address,
            path,
            static_svc: Some(elem.static_service),
            last_seen: Some(elem.last_seen),
            active: Some(elem.active),
        }
    }
}

/// Helper type for serializing/deserializing service types.
struct ServiceTypeSerializer {
    inner: ServiceType,
}

impl Serialize for ServiceTypeSerializer {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        Ok(Intermediate::from(self.inner.code()))
    }
}

impl Deserialize for ServiceTypeSerializer {
    fn deserialize(value: &Intermediate) -> Result<Self, serde_lite::Error> {
        let inner = value
            .as_number()
            .map(u16::try_from)
            .and_then(Result::ok)
            .and_then(|code| {
                let res = match code {
                    SVC_TYPE_CONTROL_PROTOCOL => ServiceType::ControlProtocol,
                    SVC_TYPE_RTSP => ServiceType::RTSP,
                    SVC_TYPE_LOCKED_RTSP => ServiceType::LockedRTSP,
                    SVC_TYPE_UNKNOWN_RTSP => ServiceType::UnknownRTSP,
                    SVC_TYPE_UNSUPPORTED_RTSP => ServiceType::UnsupportedRTSP,
                    SVC_TYPE_HTTP => ServiceType::HTTP,
                    SVC_TYPE_MJPEG => ServiceType::MJPEG,
                    SVC_TYPE_LOCKED_MJPEG => ServiceType::LockedMJPEG,
                    SVC_TYPE_TCP => ServiceType::TCP,
                    _ => return None,
                };

                Some(res)
            })
            .ok_or_else(|| serde_lite::Error::invalid_value("service type code"))?;

        let res = Self { inner };

        Ok(res)
    }
}

impl From<ServiceType> for ServiceTypeSerializer {
    fn from(svc_type: ServiceType) -> Self {
        Self { inner: svc_type }
    }
}

impl From<ServiceTypeSerializer> for ServiceType {
    fn from(serializer: ServiceTypeSerializer) -> Self {
        serializer.inner
    }
}

/// Helper type for serializing/deserializing socket addresses.
struct SocketAddrSerializer {
    addr: SocketAddr,
}

impl Deserialize for SocketAddrSerializer {
    fn deserialize(value: &Intermediate) -> Result<Self, serde_lite::Error> {
        let addr = value
            .as_str()
            .map(|s| s.parse())
            .and_then(Result::ok)
            .ok_or_else(|| serde_lite::Error::invalid_value("socket address"))?;

        let res = Self { addr };

        Ok(res)
    }
}

impl Serialize for SocketAddrSerializer {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        Ok(Intermediate::from(self.addr.to_string()))
    }
}

impl From<SocketAddr> for SocketAddrSerializer {
    fn from(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

impl From<SocketAddrSerializer> for SocketAddr {
    fn from(serializer: SocketAddrSerializer) -> Self {
        serializer.addr
    }
}

/// Helper type for serializing/deserializing MAC addresses.
struct MacAddrSerializer {
    addr: MacAddr,
}

impl Deserialize for MacAddrSerializer {
    fn deserialize(value: &Intermediate) -> Result<Self, serde_lite::Error> {
        let addr = value
            .as_str()
            .map(|s| s.parse())
            .and_then(Result::ok)
            .ok_or_else(|| serde_lite::Error::invalid_value("MAC address"))?;

        let res = Self { addr };

        Ok(res)
    }
}

impl Serialize for MacAddrSerializer {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        Ok(Intermediate::from(self.addr.to_string()))
    }
}

impl From<MacAddr> for MacAddrSerializer {
    fn from(addr: MacAddr) -> Self {
        Self { addr }
    }
}

impl From<MacAddrSerializer> for MacAddr {
    fn from(serializer: MacAddrSerializer) -> Self {
        serializer.addr
    }
}

#[cfg(test)]
#[test]
fn test_visible_services_iterator() {
    let mut table = ServiceTableData::new();

    let mac = MacAddr::zero();
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

    let svc_1 = Service::rtsp(mac, addr, "/1".to_string());
    let svc_2 = Service::rtsp(mac, addr, "/2".to_string());
    let svc_3 = Service::rtsp(mac, addr, "/3".to_string());

    table.update(svc_1.clone(), true, true);
    table.update(svc_2, true, false);
    table.update(svc_3.clone(), true, true);

    let mut visible = table.visible().collect::<Vec<_>>();

    visible.sort_by_key(|&(id, _)| id);

    let mut expected = vec![(93, svc_3), (640, svc_1)];

    expected.sort_by_key(|&(id, _)| id);

    assert_eq!(visible, expected);
}

#[cfg(test)]
#[test]
fn test_deserialization_and_initialization() {
    use serde_lite::intermediate;

    let intermediate = intermediate!({
        "services": [
            {
                "svc_type": 1,
                "mac": "00:00:00:00:00:00",
                "address": "0.0.0.0:0",
                "path": "/1",
                "static_svc": true,
                "last_seen": 123,
                "active": true
            },
            {
                "svc_type": 1,
                "mac": "00:00:00:00:00:00",
                "address": "0.0.0.0:0",
                "path": "/2",
                "static_svc": true,
                "last_seen": 123,
                "active": true
            },
            {
                "svc_type": 1,
                "mac": "00:00:00:00:00:00",
                "address": "0.0.0.0:0",
                "path": "/3",
                "static_svc": false,
                "last_seen": 123,
                "active": true
            },
            {
                "id": 10000,
                "svc_type": 1,
                "mac": "00:00:00:00:00:00",
                "address": "0.0.0.0:0",
                "path": "/4",
                "static_svc": false,
                "last_seen": 123,
                "active": true
            }
        ]
    });

    let mut table =
        SharedServiceTable::deserialize(&intermediate).expect("expected valid service table JSON");

    assert_eq!(table.service_table_version(), 0);
    assert_eq!(table.visible_set_version(), 0);

    let mac = MacAddr::zero();
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

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

    assert_eq!(table.service_table_version(), 0);
    assert_eq!(table.visible_set_version(), 1);

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

    assert_eq!(table.service_table_version(), 0);
    assert_eq!(table.visible_set_version(), 1);

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

    assert_eq!(table.service_table_version(), 0);
    assert_eq!(table.visible_set_version(), 2);

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
            (11717, svc_5.clone()),
        ]
    );

    assert_eq!(table.service_table_version(), 1);
    assert_eq!(table.visible_set_version(), 3);

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
            (11717, svc_5.clone()),
        ]
    );

    assert_eq!(internal.service_table_version(), 1);
    assert_eq!(internal.visible_set_version(), 3);

    // update the list of active services
    internal.update_active_services();

    let mut visible = internal.visible().collect::<Vec<_>>();

    visible.sort_by_key(|&(id, _)| id);

    assert_eq!(visible, vec![(1, svc_1), (2, svc_2), (11717, svc_5),]);

    assert_eq!(internal.service_table_version(), 1);
    assert_eq!(internal.visible_set_version(), 5);
}
