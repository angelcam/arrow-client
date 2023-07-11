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

use std::fmt;

use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};

use uuid::Uuid;

use crate::config::Config;
use crate::net::raw::ether::MacAddr;
use crate::net::tls::TlsConnector;
use crate::scanner::ScanResult;
use crate::svc_table::{Service, SharedServiceTableRef};
use crate::utils::logger::BoxLogger;
use crate::utils::RuntimeError;

/// Arrow service connection state.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ConnectionState {
    Connected,
    Disconnected,
    Unauthorized,
}

impl ConnectionState {
    /// Get string representation of the state.
    fn as_str(&self) -> &str {
        match &self {
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
            Self::Unauthorized => "unauthorized",
        }
    }
}

impl Display for ConnectionState {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.as_str())
    }
}

/// Listener for application events.
pub trait ApplicationEventListener {
    /// Report new connection state.
    fn connection_state_changed(&mut self, _: ConnectionState) {}

    /// Report new network scanner state (`true` means that the network scanner is running).
    fn network_scanner_state_changed(&mut self, _: bool) {}
}

/// Internal data of the application context.
struct ApplicationContextData {
    logger: BoxLogger,
    config: Config,
    scanning: bool,
    scan_result: ScanResult,
    connection_state: ConnectionState,
    event_listeners: Vec<Box<dyn ApplicationEventListener + Send>>,
}

impl ApplicationContextData {
    /// Take a given application config and create application context data.
    fn new(config: Config) -> Self {
        Self {
            logger: config.get_logger(),
            config,
            scanning: false,
            scan_result: ScanResult::new(),
            connection_state: ConnectionState::Disconnected,
            event_listeners: Vec::new(),
        }
    }

    /// Get application config.
    fn get_config(&self) -> &Config {
        &self.config
    }

    /// Get application config.
    fn get_config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    /// Get application logger.
    fn get_logger(&self) -> BoxLogger {
        self.logger.clone()
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
    fn get_scan_result(&self) -> ScanResult {
        self.scan_result.clone()
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

        self.config.update_connection_state(state);
    }

    /// Add a new event listener.
    fn add_event_listener<T>(&mut self, listener: T)
    where
        T: 'static + ApplicationEventListener + Send,
    {
        self.event_listeners.push(Box::new(listener));
    }

    /// Add all given event listeners.
    fn add_event_listeners(
        &mut self,
        mut listeners: Vec<Box<dyn ApplicationEventListener + Send>>,
    ) {
        for listener in self.event_listeners.drain(..) {
            listeners.push(listener);
        }

        self.event_listeners = listeners;
    }

    /// Get all event listeners.
    fn take_event_listeners(&mut self) -> Vec<Box<dyn ApplicationEventListener + Send>> {
        std::mem::take(&mut self.event_listeners)
    }
}

/// Application context.
#[derive(Clone)]
pub struct ApplicationContext {
    data: Arc<Mutex<ApplicationContextData>>,
}

impl ApplicationContext {
    /// Take a given application config and create a new application context.
    pub fn new(config: Config) -> Self {
        Self {
            data: Arc::new(Mutex::new(ApplicationContextData::new(config))),
        }
    }

    /// Get address of the remote Arrow Service.
    pub fn get_arrow_service_address(&self) -> String {
        self.data
            .lock()
            .unwrap()
            .get_config()
            .get_arrow_service_address()
            .to_string()
    }

    /// Get Arrow Client UUID.
    pub fn get_arrow_uuid(&self) -> Uuid {
        self.data.lock().unwrap().get_config().get_uuid()
    }

    /// Get Arrow Client password.
    pub fn get_arrow_password(&self) -> Uuid {
        self.data.lock().unwrap().get_config().get_password()
    }

    /// Get Arrow Client MAC address.
    pub fn get_arrow_mac_address(&self) -> MacAddr {
        self.data.lock().unwrap().get_config().get_mac_address()
    }

    /// Get network discovery settings.
    pub fn get_discovery(&self) -> bool {
        self.data.lock().unwrap().get_config().get_discovery()
    }

    /// Get network discovery whitelist.
    pub fn get_discovery_whitelist(&self) -> Arc<HashSet<String>> {
        self.data
            .lock()
            .unwrap()
            .get_config()
            .get_discovery_whitelist()
    }

    /// Check if the application is in the diagnostic mode.
    pub fn get_diagnostic_mode(&self) -> bool {
        self.data.lock().unwrap().get_config().get_diagnostic_mode()
    }

    /// Check if the gateway mode is enabled.
    pub fn get_gateway_mode(&self) -> bool {
        self.data.lock().unwrap().get_config().get_gateway_mode()
    }

    /// Get RTSP paths for the network scanner.
    pub fn get_rtsp_paths(&self) -> Arc<Vec<String>> {
        self.data.lock().unwrap().get_config().get_rtsp_paths()
    }

    /// Get MJPEG paths for the network scanner.
    pub fn get_mjpeg_paths(&self) -> Arc<Vec<String>> {
        self.data.lock().unwrap().get_config().get_mjpeg_paths()
    }

    /// Get application logger.
    pub fn get_logger(&self) -> BoxLogger {
        self.data.lock().unwrap().get_logger()
    }

    /// Get TLS connector for a given server hostname.
    pub fn get_tls_connector(&self) -> Result<TlsConnector, RuntimeError> {
        self.data
            .lock()
            .unwrap()
            .get_config_mut()
            .get_tls_connector()
    }

    /// Set the state of the network scanner thread.
    pub fn set_scanning(&mut self, scanning: bool) {
        let mut data = self.data.lock().unwrap();

        if scanning == data.is_scanning() {
            return;
        }

        data.set_scanning(scanning);

        let mut listeners = data.take_event_listeners();

        // make sure that we are not holding the mutex
        std::mem::drop(data);

        for listener in &mut listeners {
            listener.network_scanner_state_changed(scanning);
        }

        self.data.lock().unwrap().add_event_listeners(listeners);
    }

    /// Check if the network scanner thread is running right now.
    pub fn is_scanning(&self) -> bool {
        self.data.lock().unwrap().is_scanning()
    }

    /// Get the last scan result.
    pub fn get_scan_result(&self) -> ScanResult {
        self.data.lock().unwrap().get_scan_result()
    }

    /// Set last scan result.
    pub fn set_scan_result(&mut self, result: ScanResult) {
        self.data.lock().unwrap().set_scan_result(result)
    }

    /// Get read-only reference to the service table.
    pub fn get_service_table(&self) -> SharedServiceTableRef {
        self.data.lock().unwrap().get_config().get_service_table()
    }

    /// Update service table. Add all given services into the table and update active services.
    pub fn update_service_table<I>(&mut self, services: I)
    where
        I: IntoIterator<Item = Service>,
    {
        self.data
            .lock()
            .unwrap()
            .get_config_mut()
            .update_service_table(services)
    }

    /// Reset service table.
    pub fn reset_service_table(&mut self) {
        self.data
            .lock()
            .unwrap()
            .get_config_mut()
            .reset_service_table()
    }

    /// Get connection state.
    pub fn get_connection_state(&self) -> ConnectionState {
        self.data.lock().unwrap().get_connection_state()
    }

    /// Set connection state.
    pub fn set_connection_state(&mut self, state: ConnectionState) {
        let mut data = self.data.lock().unwrap();

        if state == data.get_connection_state() {
            return;
        }

        data.set_connection_state(state);

        let mut listeners = data.take_event_listeners();

        // make sure that we are not holding the mutex
        std::mem::drop(data);

        for listener in &mut listeners {
            listener.connection_state_changed(state);
        }

        self.data.lock().unwrap().add_event_listeners(listeners);
    }

    /// Get client extended info.
    pub fn get_extended_info(&self) -> String {
        self.data
            .lock()
            .unwrap()
            .get_config()
            .get_extended_info()
            .dump()
    }

    /// Add a new event listener.
    pub fn add_event_listener<T>(&mut self, listener: T)
    where
        T: 'static + ApplicationEventListener + Send,
    {
        self.data.lock().unwrap().add_event_listener(listener)
    }
}
