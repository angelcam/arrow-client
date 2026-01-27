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

mod hash;
mod serializer;

pub mod service;

use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    sync::{Arc, Mutex, MutexGuard},
};

use serde_lite::{Deserialize, Intermediate, Serialize};

use crate::{net::raw::devices::EthernetDevice, utils::get_utc_timestamp};

use self::serializer::ServiceTableSerializer;

pub use self::service::{
    SVC_TYPE_CONTROL_PROTOCOL, SVC_TYPE_HTTP, SVC_TYPE_LOCKED_MJPEG, SVC_TYPE_LOCKED_RTSP,
    SVC_TYPE_MJPEG, SVC_TYPE_RTSP, SVC_TYPE_TCP, SVC_TYPE_UNKNOWN_RTSP, SVC_TYPE_UNSUPPORTED_RTSP,
    Service, ServiceIdentifier, ServiceType,
};

const ACTIVE_THRESHOLD: i64 = 1200;

/// Service source.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServiceSource {
    /// Service added via command line.
    Static,

    /// Service added via the JSON-RPC API.
    Custom,

    /// Service discovered via network scanning.
    Discovery,
}

/// Service table implementation that can be shared across multiple threads.
pub struct ServiceTable {
    data: Arc<Mutex<ServiceTableData>>,
}

impl Default for ServiceTable {
    fn default() -> Self {
        Self {
            data: Arc::new(Mutex::new(ServiceTableData::new())),
        }
    }
}

impl ServiceTable {
    /// Create a new shared service table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset the service table, keeping only static and custom services.
    pub fn reset(&self) {
        self.data.lock().unwrap().reset();
    }

    /// Lock the service table for exclusive access.
    pub fn lock(&self) -> LockedServiceTable<'_> {
        LockedServiceTable {
            inner: self.data.lock().unwrap(),
        }
    }

    /// Get a read-only handle for this table.
    ///
    /// Use this method instead of `clone` when you need a reference to the
    /// same underlying data. The `clone` method creates a copy of the internal
    /// data.
    pub fn handle(&self) -> ServiceTableHandle {
        ServiceTableHandle {
            data: self.data.clone(),
        }
    }
}

impl Clone for ServiceTable {
    fn clone(&self) -> Self {
        let cloned = self.data.lock().unwrap().clone();

        Self {
            data: Arc::new(Mutex::new(cloned)),
        }
    }
}

impl Display for ServiceTable {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        self.data.lock().unwrap().fmt(f)
    }
}

impl Deserialize for ServiceTable {
    fn deserialize(val: &Intermediate) -> Result<Self, serde_lite::Error> {
        let data = ServiceTableData::deserialize(val)?;

        let res = Self {
            data: Arc::new(Mutex::new(data)),
        };

        Ok(res)
    }
}

impl Serialize for ServiceTable {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        self.data.lock().unwrap().serialize()
    }
}

/// Locked service table instance.
pub struct LockedServiceTable<'a> {
    inner: MutexGuard<'a, ServiceTableData>,
}

impl<'a> LockedServiceTable<'a> {
    /// Get version of the service table.
    ///
    /// The version is updated whenever a new service is added or an existing
    /// service is changed (e.g. its IP address).
    pub fn service_table_version(&self) -> u32 {
        self.inner.service_table_version()
    }

    /// Get version of the set of visible services.
    ///
    /// The version is updated whenever service visibility changes.
    pub fn visible_set_version(&self) -> u32 {
        self.inner.visible_set_version()
    }

    /// Add a given service into the table and return its ID.
    pub fn add(&mut self, svc: Service, source: ServiceSource) -> u16 {
        self.inner.update(svc, source)
    }

    /// Update service availability.
    pub fn update_service_availability(&mut self, local_networks: &[EthernetDevice]) {
        self.inner.update_service_availability(local_networks);
    }

    /// Update service visibility.
    pub fn update_service_visibility(&mut self, now: i64) {
        self.inner.update_service_visibility(now);
    }
}

/// Read-only handle to the service table.
#[derive(Clone)]
pub struct ServiceTableHandle {
    data: Arc<Mutex<ServiceTableData>>,
}

impl ServiceTableHandle {
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

    /// Get service with a given ID.
    pub fn get(&self, id: u16) -> Option<Service> {
        self.data.lock().unwrap().get(id)
    }

    /// Get ID of a given service.
    pub fn get_id(&self, identifier: &ServiceIdentifier) -> Option<u16> {
        self.data.lock().unwrap().get_id(identifier)
    }
}

impl Serialize for ServiceTableHandle {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        self.data.lock().unwrap().serialize()
    }
}

impl Display for ServiceTableHandle {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        self.data.lock().unwrap().fmt(f)
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

    /// Get available service for a given ID.
    fn get(&self, id: u16) -> Option<Service> {
        if let Some(elem) = self.service_map.get(&id) {
            if elem.is_available() || elem.service.is_control() {
                Some(elem.to_service())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get service ID for a given ServiceIdentifier or None if there is no
    /// such service or the given service is not available.
    fn get_id(&self, identifier: &ServiceIdentifier) -> Option<u16> {
        if let Some(id) = self.identifier_map.get(identifier) {
            let elem = self.service_map.get(id).expect("broken service table");

            if elem.is_available() || elem.service.is_control() {
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
    fn add_service(&mut self, svc: Service, source: ServiceSource, visible: bool) -> u16 {
        let key = svc.to_service_identifier();
        let id = hash::stable_hash(&key) as u16;

        assert!(!self.identifier_map.contains_key(&key));

        let elem = ServiceTableElement::new(id, svc, source, visible, true);

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
    fn update_element(&mut self, id: u16, svc: Service, source: ServiceSource) -> u16 {
        // We don't update the control service. It's just a placeholder.
        if id == 0 {
            return id;
        }

        let elem = self.service_map.get_mut(&id).expect("broken service table");

        let svc_change = elem.service != svc;

        let old_visible = elem.is_visible();

        elem.update(svc, source);

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
    fn update(&mut self, svc: Service, source: ServiceSource) -> u16 {
        let key = svc.to_service_identifier();

        let id = self.identifier_map.get(&key).copied();

        if let Some(id) = id {
            self.update_element(id, svc, source)
        } else {
            self.add_service(svc, source, true)
        }
    }

    /// Update service availability.
    fn update_service_availability(&mut self, local_networks: &[EthernetDevice]) {
        for elem in self.service_map.values_mut() {
            let visible = elem.is_visible();

            elem.update_availability(local_networks);

            if visible != elem.is_visible() {
                self.visible_set_version = self.visible_set_version.wrapping_add(1);
            }
        }
    }

    /// Update service visibility.
    fn update_service_visibility(&mut self, now: i64) {
        for elem in self.service_map.values_mut() {
            let visible = elem.is_visible();

            elem.update_visibility(now);

            if visible != elem.is_visible() {
                self.visible_set_version = self.visible_set_version.wrapping_add(1);
            }
        }
    }

    /// Reset the service table, keeping only static and custom services.
    fn reset(&mut self) {
        let mut new = ServiceTableData::new();

        for (_, element) in self.service_map.drain() {
            // the static service is already in the new table and we only
            // want to keep static and custom services
            if element.id != 0 && (element.static_service || element.custom_service) {
                new.add_element(element);
            }
        }

        *self = new;
    }
}

impl Deserialize for ServiceTableData {
    fn deserialize(val: &Intermediate) -> Result<Self, serde_lite::Error> {
        let serializer = ServiceTableSerializer::deserialize(val)?;

        let res = serializer.into();

        Ok(res)
    }
}

impl Serialize for ServiceTableData {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        let services = self
            .service_map
            .values()
            .filter(|elem| !elem.service.is_control());

        let serializer = ServiceTableSerializer::new(services);

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

/// Service table element.
///
/// Note that each service could have been added via multiple sources. We need
/// to track them all to properly manage service visibility and availability.
/// The `static_service` flag is non-persistent. It indicates if the service
/// was added via command line. The remaining flags are persistent and sticky
/// (i.e. once set to true, they remain true). The `static_service` flag is
/// sticky only for the lifetime of the process.
#[derive(Debug, Clone)]
struct ServiceTableElement {
    /// Service ID.
    id: u16,

    /// Service.
    service: Service,

    /// Non-persistent flag indicating that the service was added via command
    /// line.
    static_service: bool,

    /// Flag indicating that the service was discovered via network scanning.
    discovered_service: bool,

    /// Flag indicating that the service was added via the JSON-RPC API.
    custom_service: bool,

    /// UNIX timestamp (in UTC) of the last discovery event.
    last_seen: i64,

    /// Visibility flag.
    visible: bool,

    /// Availability flag.
    ///
    /// Custom services and services discovered via network scanning are
    /// available only if they belong to one of the whitelisted networks.
    /// Static services are available only when present as a command line
    /// argument.
    available: bool,
}

impl ServiceTableElement {
    /// Create a new Control Protocol service table element.
    fn control() -> Self {
        Self {
            id: 0,
            service: Service::control(),
            last_seen: get_utc_timestamp(),
            static_service: false,
            discovered_service: false,
            custom_service: false,
            visible: false,
            available: false,
        }
    }

    /// Create a new service table element.
    fn new(
        id: u16,
        service: Service,
        source: ServiceSource,
        visible: bool,
        available: bool,
    ) -> Self {
        Self {
            id,
            service,
            last_seen: get_utc_timestamp(),
            static_service: source == ServiceSource::Static,
            discovered_service: source == ServiceSource::Discovery,
            custom_service: source == ServiceSource::Custom,
            visible,
            available,
        }
    }

    /// Check if the service should be visible.
    ///
    /// Services that are not visible should not be returned in the visible
    /// set. A service that is not available is also not visible.
    fn is_visible(&self) -> bool {
        self.visible
    }

    /// Check if the service is available.
    ///
    /// Services that are not available must not be used for new connections.
    fn is_available(&self) -> bool {
        self.available
    }

    /// Update the internal service, the service source and the last_seen
    /// timestamp.
    ///
    /// We assume that the service is either static, it was discovered via
    /// network scanning, or it was added via the JSON-RPC API in which case
    /// it has passed the whitelisting check. Therefore, we set the service as
    /// visible and available.
    fn update(&mut self, svc: Service, source: ServiceSource) {
        self.service = svc;
        self.last_seen = get_utc_timestamp();
        self.visible = true;
        self.available = true;

        // the static and custom service flags are sticky
        match source {
            ServiceSource::Static => self.static_service = true,
            ServiceSource::Discovery => self.discovered_service = true,
            ServiceSource::Custom => self.custom_service = true,
        }
    }

    /// Update service availability.
    fn update_availability(&mut self, local_networks: &[EthernetDevice]) {
        // Static services are always available. The remaining services are
        // available only if they belong to one of the accessible local
        // networks.
        self.available = if self.static_service {
            true
        } else if let Some(ip) = self.service.ip_address() {
            local_networks.iter().any(|dev| dev.contains_ip_addr(ip))
        } else {
            false
        };

        // If the service is not available, it cannot be visible.
        if !self.available {
            self.visible = false;
        }
    }

    /// Update service visibility.
    fn update_visibility(&mut self, now: i64) {
        // Static services are always visible. Custom services are visible
        // only if they are available. Discovered services are visible only if
        // they are available and were seen recently.
        self.visible = if self.static_service {
            true
        } else if self.custom_service {
            self.available
        } else if self.discovered_service {
            self.available && ((self.last_seen + ACTIVE_THRESHOLD) >= now)
        } else {
            false
        };
    }

    /// Get service for this element.
    fn to_service(&self) -> Service {
        self.service.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use serde_lite::Deserialize;

    use crate::{
        net::raw::{devices::EthernetDevice, ether::MacAddr},
        utils::get_utc_timestamp,
    };

    use super::{LockedServiceTable, Service, ServiceSource, ServiceTable, ServiceTableData};

    trait ServiceTableTestHelper {
        /// Check that the list of available services matches the given list.
        fn check_available_services(&self, expected: &[(u16, &Service)]);

        /// Check that the list of visible services matches the given list.
        fn check_visible_services(&self, expected: &[(u16, &Service)]);
    }

    impl ServiceTableTestHelper for ServiceTableData {
        fn check_available_services(&self, expected: &[(u16, &Service)]) {
            let available = self
                .service_map
                .values()
                .filter(|elem| elem.is_available() && !elem.service.is_control())
                .map(|elem| (elem.id, elem.to_service()))
                .collect::<Vec<_>>();

            let expected = expected
                .iter()
                .map(|&(id, svc)| (id, svc.clone()))
                .collect::<Vec<_>>();

            check_service_list(&available, &expected);
        }

        fn check_visible_services(&self, expected: &[(u16, &Service)]) {
            let visible = Vec::from_iter(self.visible());

            let expected = expected
                .iter()
                .map(|&(id, svc)| (id, svc.clone()))
                .collect::<Vec<_>>();

            check_service_list(&visible, &expected);
        }
    }

    impl ServiceTableTestHelper for LockedServiceTable<'_> {
        fn check_available_services(&self, expected: &[(u16, &Service)]) {
            self.inner.check_available_services(expected);
        }

        fn check_visible_services(&self, expected: &[(u16, &Service)]) {
            self.inner.check_visible_services(expected);
        }
    }

    fn check_service_list(a: &[(u16, Service)], b: &[(u16, Service)]) {
        let mut a = a.to_vec();

        a.sort_by_key(|&(id, _)| id);

        let mut b = b.to_vec();

        b.sort_by_key(|&(id, _)| id);

        assert_eq!(a.len(), b.len());

        let a = a.iter();
        let b = b.iter();

        for (a, b) in a.zip(b) {
            let (a_id, a_svc) = a;
            let (b_id, b_svc) = b;

            assert_eq!(a_id, b_id);
            assert_eq!(a_svc, b_svc);
        }
    }

    fn create_fake_ethernet_device(name: &str, network: Ipv4Addr) -> EthernetDevice {
        EthernetDevice {
            name: name.to_string(),
            mac_addr: MacAddr::ZERO,
            ip_addr: network,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
        }
    }

    #[test]
    fn test_visible_services_iterator() {
        let mut table = ServiceTableData::new();

        let mac = MacAddr::zero();
        let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

        let svc_1 = Service::rtsp(mac, addr, "/1".to_string());
        let svc_2 = Service::rtsp(mac, addr, "/2".to_string());
        let svc_3 = Service::rtsp(mac, addr, "/3".to_string());

        table.add_service(svc_1.clone(), ServiceSource::Discovery, true);
        table.add_service(svc_2, ServiceSource::Discovery, false);
        table.add_service(svc_3.clone(), ServiceSource::Discovery, true);

        table.check_visible_services(&[
            (93, &svc_3),
            (640, &svc_1),
        ]);
    }

    #[test]
    fn test_old_deserialization_and_initialization() {
        // This will test backward compatibility with old service table JSON
        // representations. The very first format did not even have service
        // IDs. Service IDs were assigned sequentially starting from 1 for
        // each service during deserialization.
        //
        // A more recent format added the service ID field, however, the
        // service flags have been changed since then. We have renamed the
        // `active` flag to `visible` in order to better reflect the semantics.
        // The flag captures service visibility at the time of serialization.
        //
        // The `static_svc` was used to indicate services added via command
        // line. However, this flag should not be persistent, so we treat
        // services with this flag as non-custom and non-discovered and we
        // mark them as invisible after deserialization. They also may not be
        // available if they do not belong to any of the whitelisted networks.
        // They are marked as static, visible and available only if they are
        // added via command line again.

        let json = r#"{
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
        }"#;

        let intermediate = serde_json::from_str(json)
            .expect("invalid JSON");

        let table =
            ServiceTable::deserialize(&intermediate).expect("expected valid service table JSON");

        let mut table = table.lock();

        assert_eq!(table.service_table_version(), 0);
        assert_eq!(table.visible_set_version(), 0);

        let mac = MacAddr::zero();
        let addr_1 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        let addr_2 = SocketAddr::from((Ipv4Addr::new(192, 168, 0, 10), 0));

        let svc_1 = Service::rtsp(mac, addr_1, "/1".to_string());
        let svc_2 = Service::rtsp(mac, addr_1, "/2".to_string());
        let svc_3 = Service::rtsp(mac, addr_1, "/3".to_string());
        let svc_4 = Service::rtsp(mac, addr_1, "/4".to_string());
        let svc_5 = Service::rtsp(mac, addr_1, "/5".to_string());
        let svc_6 = Service::rtsp(mac, addr_2, "/6".to_string());

        // NOTE: The only visible services should be the last two defined in
        //   the JSON above. The first two are static services that should not
        //   be visible until they are explicitly added as static again.
        table.check_visible_services(&[
            (3, &svc_3),
            (10000, &svc_4),
        ]);

        // ... however, all the services should be available at this point.
        table.check_available_services(&[
            (1, &svc_1),
            (2, &svc_2),
            (3, &svc_3),
            (10000, &svc_4),
        ]);

        // add the first static service
        table.add(svc_1.clone(), ServiceSource::Static);

        // NOTE: The first static service should now be visible and it's ID
        //   should be 1 because it didn't come with an explicit ID but it was
        //   the first service in the JSON array.
        table.check_visible_services(&[
            (1, &svc_1),
            (3, &svc_3),
            (10000, &svc_4),
        ]);

        assert_eq!(table.service_table_version(), 0);
        assert_eq!(table.visible_set_version(), 1);

        // add the first static service again
        table.add(svc_1.clone(), ServiceSource::Static);

        // NOTE: No changes are expected here.
        table.check_visible_services(&[
            (1, &svc_1),
            (3, &svc_3),
            (10000, &svc_4),
        ]);

        assert_eq!(table.service_table_version(), 0);
        assert_eq!(table.visible_set_version(), 1);

        // add the second static service
        table.add(svc_2.clone(), ServiceSource::Static);

        table.check_visible_services(&[
            (1, &svc_1),
            (2, &svc_2),
            (3, &svc_3),
            (10000, &svc_4),
        ]);

        assert_eq!(table.service_table_version(), 0);
        assert_eq!(table.visible_set_version(), 2);

        // add new services
        table.add(svc_5.clone(), ServiceSource::Discovery);
        table.add(svc_6.clone(), ServiceSource::Discovery);

        table.check_visible_services(&[
            (1, &svc_1),
            (2, &svc_2),
            (3, &svc_3),
            (10000, &svc_4),
            (11717, &svc_5),
            (63236, &svc_6),
        ]);

        assert_eq!(table.service_table_version(), 2);
        assert_eq!(table.visible_set_version(), 4);

        // additional consistency checks
        let table = &mut *table.inner;

        let control = Service::control();

        let key = control.to_service_identifier();

        assert_eq!(table.get(0), Some(control.clone()));
        assert_eq!(table.get_id(&key), Some(0));
        assert_eq!(table.service_map.len(), 7);
        assert_eq!(table.identifier_map.len(), 7);

        table.update(control.clone(), ServiceSource::Static);

        assert_eq!(table.get(0), Some(control));
        assert_eq!(table.get_id(&key), Some(0));
        assert_eq!(table.service_map.len(), 7);
        assert_eq!(table.identifier_map.len(), 7);

        table.check_visible_services(&[
            (1, &svc_1),
            (2, &svc_2),
            (3, &svc_3),
            (10000, &svc_4),
            (11717, &svc_5),
            (63236, &svc_6),
        ]);

        assert_eq!(table.service_table_version(), 2);
        assert_eq!(table.visible_set_version(), 4);

        // update visible services
        table.update_service_visibility(get_utc_timestamp());

        // NOTE: The first two services are static, so we expect them to remain
        //   visible. The last two services were added recently as
        //   "discovered", so they should also remain visible. The third and
        //   the fourth service should be hidden because they are neither
        //   static nor custom and their `last_seen` timestamp is too old.
        table.check_visible_services(&[
            (1, &svc_1),
            (2, &svc_2),
            (11717, &svc_5),
            (63236, &svc_6),
        ]);

        assert_eq!(table.service_table_version(), 2);
        assert_eq!(table.visible_set_version(), 6);

        let interface = create_fake_ethernet_device("eth0", Ipv4Addr::new(192, 168, 0, 1));

        // update available services
        table.update_service_availability(&[interface]);

        // NOTE: The first two services are static, so we expect them to remain
        //   available. The last service belongs to the `eth0` network so it
        //   should also remain available. The third service should be
        //   unavailable because it isn't static and it doesn't belong to any
        //   of the whitelisted networks.
        table.check_available_services(&[
            (1, &svc_1),
            (2, &svc_2),
            (63236, &svc_6),
        ]);

        // NOTE: The list of visible services should match the list of
        //   available services.
        table.check_visible_services(&[
            (1, &svc_1),
            (2, &svc_2),
            (63236, &svc_6),
        ]);

        assert_eq!(table.service_table_version(), 2);
        assert_eq!(table.visible_set_version(), 7);
    }

    #[test]
    fn test_new_deserialization() {
        let json = r#"{
            "services": [
                {
                    "id": 1001,
                    "svc_type": 1,
                    "mac": "00:00:00:00:00:00",
                    "address": "192.168.1.100:554",
                    "path": "/1",
                    "discovered": false,
                    "custom": false,
                    "last_seen": 1000,
                    "visible": true
                },
                {
                    "id": 1002,
                    "svc_type": 1,
                    "mac": "00:00:00:00:00:00",
                    "address": "192.168.1.100:554",
                    "path": "/2",
                    "discovered": true,
                    "custom": false,
                    "last_seen": 1000,
                    "visible": true
                },
                {
                    "id": 1003,
                    "svc_type": 1,
                    "mac": "00:00:00:00:00:00",
                    "address": "192.168.1.100:554",
                    "path": "/3",
                    "discovered": false,
                    "custom": true,
                    "last_seen": 1000,
                    "visible": true
                },
                {
                    "id": 1004,
                    "svc_type": 1,
                    "mac": "00:00:00:00:00:00",
                    "address": "192.168.1.100:554",
                    "path": "/4",
                    "discovered": true,
                    "custom": true,
                    "last_seen": 1000,
                    "visible": true
                },
                {
                    "id": 1005,
                    "svc_type": 1,
                    "mac": "00:00:00:00:00:00",
                    "address": "192.168.2.100:554",
                    "path": "/5",
                    "discovered": true,
                    "custom": false,
                    "last_seen": 5000,
                    "visible": false
                },
                {
                    "id": 1006,
                    "svc_type": 1,
                    "mac": "00:00:00:00:00:00",
                    "address": "192.168.2.100:554",
                    "path": "/6",
                    "discovered": false,
                    "custom": true,
                    "last_seen": 5000,
                    "visible": false
                },
                {
                    "id": 1007,
                    "svc_type": 1,
                    "mac": "00:00:00:00:00:00",
                    "address": "192.168.2.100:554",
                    "path": "/7",
                    "discovered": true,
                    "custom": true,
                    "last_seen": 5000,
                    "visible": false
                }
            ]
        }"#;

        let intermediate = serde_json::from_str(json)
            .expect("invalid JSON");

        let table =
            ServiceTable::deserialize(&intermediate).expect("expected valid service table JSON");

        let mut table = table.lock();

        assert_eq!(table.service_table_version(), 0);
        assert_eq!(table.visible_set_version(), 0);

        let mac = MacAddr::zero();
        let addr_1 = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 100), 554));
        let addr_2 = SocketAddr::from((Ipv4Addr::new(192, 168, 2, 100), 554));

        let svc_1 = Service::rtsp(mac, addr_1, "/1".to_string());
        let svc_2 = Service::rtsp(mac, addr_1, "/2".to_string());
        let svc_3 = Service::rtsp(mac, addr_1, "/3".to_string());
        let svc_4 = Service::rtsp(mac, addr_1, "/4".to_string());
        let svc_5 = Service::rtsp(mac, addr_2, "/5".to_string());
        let svc_6 = Service::rtsp(mac, addr_2, "/6".to_string());
        let svc_7 = Service::rtsp(mac, addr_2, "/7".to_string());

        // all the service should be available
        table.check_available_services(&[
            (1001, &svc_1),
            (1002, &svc_2),
            (1003, &svc_3),
            (1004, &svc_4),
            (1005, &svc_5),
            (1006, &svc_6),
            (1007, &svc_7),
        ]);

        // 1001 should be hidden because it's neither static, discovered nor
        // custom. 1005 should be also hidden because it's neither static nor
        // custom and its `visible` flag is false.
        table.check_visible_services(&[
            (1002, &svc_2),
            (1003, &svc_3),
            (1004, &svc_4),
            (1006, &svc_6),
            (1007, &svc_7),
        ]);

        table.add(svc_1.clone(), ServiceSource::Static);

        // Now 1001 should be visible because it's been marked as static.
        table.check_visible_services(&[
            (1001, &svc_1),
            (1002, &svc_2),
            (1003, &svc_3),
            (1004, &svc_4),
            (1006, &svc_6),
            (1007, &svc_7),
        ]);

        table.update_service_visibility(6000);

        // All the services should still remain available after the visibility
        // update.
        table.check_available_services(&[
            (1001, &svc_1),
            (1002, &svc_2),
            (1003, &svc_3),
            (1004, &svc_4),
            (1005, &svc_5),
            (1006, &svc_6),
            (1007, &svc_7),
        ]);

        // Only 1002 should be hidden now because it's the only one discovered,
        // non-static and non-custom whose `last_seen`` timestamp is too old.
        table.check_visible_services(&[
            (1001, &svc_1),
            (1003, &svc_3),
            (1004, &svc_4),
            (1005, &svc_5),
            (1006, &svc_6),
            (1007, &svc_7),
        ]);

        let interface = create_fake_ethernet_device("eth0", Ipv4Addr::new(192, 168, 2, 1));

        table.update_service_availability(&[interface]);

        // 1001, 1002 and 1003 should become unavailable because they don't
        // belong to the `eth0` network and they are not static.
        table.check_available_services(&[
            (1001, &svc_1),
            (1005, &svc_5),
            (1006, &svc_6),
            (1007, &svc_7),
        ]);

        // Visibility of the available services should not change.
        table.check_visible_services(&[
            (1001, &svc_1),
            (1005, &svc_5),
            (1006, &svc_6),
            (1007, &svc_7),
        ]);
    }
}
