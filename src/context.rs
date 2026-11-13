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

use std::{
    collections::hash_map::{self, HashMap},
    fmt::{self, Display, Formatter},
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{
    config::{ClientId, ClientKey, Config},
    net::raw::ether::MacAddr,
    scanner::ScanResult,
    svc_table::{Service, ServiceSource, ServiceTableHandle},
    tls::TlsConnector,
};

/// Arrow service connection state.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ConnectionState {
    Connected,
    Disconnected,
    Unauthorized,
}

impl AsRef<str> for ConnectionState {
    fn as_ref(&self) -> &str {
        match &self {
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
            Self::Unauthorized => "unauthorized",
        }
    }
}

impl Display for ConnectionState {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.as_ref())
    }
}

/// Listener for application events.
pub trait ApplicationEventListener {
    /// Report new connection state.
    fn connection_state_changed(&self, _: ConnectionState) {}

    /// Report new network scanner state (`true` means that the network scanner is running).
    fn network_scanner_state_changed(&self, _: bool) {}

    /// Report a service table change.
    fn service_table_changed(&self) {}
}

/// Application context.
#[derive(Clone)]
pub struct ApplicationContext {
    data: Arc<ApplicationContextData>,
}

impl ApplicationContext {
    /// Take a given application config and create a new application context.
    pub fn new(config: Config) -> Self {
        Self {
            data: Arc::new(ApplicationContextData::new(config)),
        }
    }

    /// Get address of the remote Arrow Service.
    pub fn get_arrow_service_address(&self) -> &str {
        self.data.config().get_arrow_service_address()
    }

    /// Get Arrow Client ID.
    pub fn get_client_id(&self) -> ClientId {
        self.data.config().get_client_id()
    }

    /// Get Arrow Client key.
    pub fn get_client_key(&self) -> ClientKey {
        self.data.config().get_client_key()
    }

    /// Get Arrow Client MAC address.
    pub fn get_arrow_mac_address(&self) -> MacAddr {
        self.data.config().get_mac_address()
    }

    /// Get network discovery whitelist.
    pub fn get_discovery_interfaces(&self) -> Arc<Vec<String>> {
        self.data.config().get_discovery_interfaces()
    }

    /// Check if the application is in the diagnostic mode.
    pub fn get_diagnostic_mode(&self) -> bool {
        self.data.config().get_diagnostic_mode()
    }

    /// Check if the gateway mode is enabled.
    pub fn get_gateway_mode(&self) -> bool {
        self.data.config().get_gateway_mode()
    }

    /// Get RTSP paths for the network scanner.
    pub fn get_rtsp_paths(&self) -> Arc<Vec<String>> {
        self.data.config().get_rtsp_paths()
    }

    /// Get MJPEG paths for the network scanner.
    pub fn get_mjpeg_paths(&self) -> Arc<Vec<String>> {
        self.data.config().get_mjpeg_paths()
    }

    /// Get TLS connector for a given server hostname.
    pub fn get_tls_connector(&self) -> TlsConnector {
        self.data.config().get_tls_connector()
    }

    /// Set the state of the network scanner thread.
    pub fn set_scanning(&self, scanning: bool) {
        let mut data = self.data.lock();

        if scanning == data.is_scanning() {
            return;
        }

        data.set_scanning(scanning);

        let listeners = data.get_event_listeners();

        // make sure that we are not holding the mutex
        std::mem::drop(data);

        for listener in &listeners {
            listener.network_scanner_state_changed(scanning);
        }
    }

    /// Check if the network scanner thread is running right now.
    pub fn is_scanning(&self) -> bool {
        self.data.lock().is_scanning()
    }

    /// Get the last scan result.
    pub fn get_scan_result(&self) -> ScanResult {
        self.data.lock().get_scan_result().clone()
    }

    /// Set last scan result.
    pub fn set_scan_result(&mut self, result: ScanResult) {
        self.data.lock().set_scan_result(result)
    }

    /// Get read-only reference to the service table.
    pub fn get_service_table(&self) -> ServiceTableHandle {
        self.data.config().get_service_table()
    }

    /// Check if a given service belongs to one of the gateway networks.
    pub async fn is_available(&self, service: &Service) -> bool {
        self.data.config().is_available(service).await
    }

    /// Add a new service to the service table.
    pub async fn add_service(&self, service: Service, source: ServiceSource) -> u16 {
        let (changed, service_id) = self.data.config().add_service(service, source).await;

        if changed {
            self.on_service_table_change();
        }

        service_id
    }

    /// Update service table. Add all given services into the table and update active services.
    pub async fn update_service_table<I>(&self, services: I, source: ServiceSource)
    where
        I: IntoIterator<Item = Service>,
    {
        if self
            .data
            .config()
            .update_service_table(services, source)
            .await
        {
            self.on_service_table_change();
        }
    }

    /// Remove a given service source from a given service table element.
    pub async fn remove_service_source(&self, id: u16, source: ServiceSource) {
        if self.data.config().remove_service_source(id, source).await {
            self.on_service_table_change();
        }
    }

    /// Update service flags.
    pub async fn update_service_flags(&self) {
        if self.data.config().update_service_flags().await {
            self.on_service_table_change();
        }
    }

    /// Reset service table.
    ///
    /// If `full` is `true`, then all custom and discovered services will be
    /// removed from the service table. Otherwise, only discovered services
    /// will be removed.
    pub async fn reset_service_table(&self, full: bool) {
        self.data.config().reset_service_table(full).await;

        self.on_service_table_change();
    }

    /// Send the service table changed event.
    fn on_service_table_change(&self) {
        let data = self.data.lock();

        let listeners = data.get_event_listeners();

        // make sure that we are not holding the mutex
        std::mem::drop(data);

        for listener in &listeners {
            listener.service_table_changed();
        }
    }

    /// Get connection state.
    pub fn get_connection_state(&self) -> ConnectionState {
        self.data.lock().get_connection_state()
    }

    /// Set connection state.
    pub async fn set_connection_state(&self, state: ConnectionState) {
        {
            let mut data = self.data.lock();

            if state == data.get_connection_state() {
                return;
            }

            data.set_connection_state(state);

            let listeners = data.get_event_listeners();

            // make sure that we are not holding the mutex
            std::mem::drop(data);

            for listener in &listeners {
                listener.connection_state_changed(state);
            }
        }

        self.data.config().update_connection_state(state).await;
    }

    /// Get client extended info.
    pub fn get_extended_info(&self) -> String {
        self.data.config().get_extended_info().to_string()
    }

    /// Add a new event listener.
    pub fn add_event_listener<T>(&self, listener: T) -> u64
    where
        T: 'static + ApplicationEventListener + Send + Sync,
    {
        self.data.lock().add_event_listener(listener)
    }

    /// Remove event listener with a given ID.
    pub fn remove_event_listener(&self, id: u64) {
        self.data.lock().remove_event_listener(id);
    }
}

/// Internal data of the application context.
struct ApplicationContextData {
    config: Config,
    mutable: Mutex<MutableApplicationContextData>,
}

impl ApplicationContextData {
    /// Take a given application config and create application context data.
    fn new(config: Config) -> Self {
        Self {
            config,
            mutable: Mutex::new(MutableApplicationContextData::new()),
        }
    }

    /// Get application config.
    fn config(&self) -> &Config {
        &self.config
    }

    /// Lock the context data for exclusive access.
    fn lock(&self) -> LockedApplicationContextData<'_> {
        LockedApplicationContextData {
            mutable: self.mutable.lock().unwrap(),
        }
    }
}

/// Locked application context data.
struct LockedApplicationContextData<'a> {
    mutable: MutexGuard<'a, MutableApplicationContextData>,
}

impl Deref for LockedApplicationContextData<'_> {
    type Target = MutableApplicationContextData;

    fn deref(&self) -> &Self::Target {
        &self.mutable
    }
}

impl DerefMut for LockedApplicationContextData<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mutable
    }
}

/// Mutable application context data.
struct MutableApplicationContextData {
    scanning: bool,
    scan_result: ScanResult,
    connection_state: ConnectionState,
    event_listeners: HashMap<u64, Arc<dyn ApplicationEventListener + Send + Sync>>,
    next_event_listener_id: u64,
}

impl MutableApplicationContextData {
    /// Create new context data.
    fn new() -> Self {
        Self {
            scanning: false,
            scan_result: ScanResult::new(),
            connection_state: ConnectionState::Disconnected,
            event_listeners: HashMap::new(),
            next_event_listener_id: 0,
        }
    }

    /// Set the state of the network scanner thread.
    fn set_scanning(&mut self, scanning: bool) {
        self.scanning = scanning;
    }

    /// Check if the network scanner thread is running right now.
    fn is_scanning(&self) -> bool {
        self.scanning
    }

    /// Get the last scan result.
    fn get_scan_result(&self) -> &ScanResult {
        &self.scan_result
    }

    /// Set last scan result.
    fn set_scan_result(&mut self, result: ScanResult) {
        self.scan_result = result;
    }

    /// Get connection state.
    fn get_connection_state(&self) -> ConnectionState {
        self.connection_state
    }

    /// Set connection state.
    fn set_connection_state(&mut self, state: ConnectionState) {
        self.connection_state = state;
    }

    /// Add a new event listener.
    fn add_event_listener<T>(&mut self, listener: T) -> u64
    where
        T: 'static + ApplicationEventListener + Send + Sync,
    {
        for _ in 0..u64::MAX {
            let id = self.next_event_listener_id;

            self.next_event_listener_id = self.next_event_listener_id.wrapping_add(1);

            if let hash_map::Entry::Vacant(entry) = self.event_listeners.entry(id) {
                entry.insert(Arc::new(listener));

                return id;
            }
        }

        panic!("no available listener ID")
    }

    /// Remove event listener with a given ID.
    fn remove_event_listener(&mut self, id: u64) {
        self.event_listeners.remove(&id);
    }

    /// Get all event listeners.
    fn get_event_listeners(&self) -> Vec<Arc<dyn ApplicationEventListener + Send + Sync>> {
        self.event_listeners.values().cloned().collect()
    }
}
