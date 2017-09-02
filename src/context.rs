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
use std::io;

use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};

use config::ApplicationConfig;

use svc_table::{Service, SharedServiceTableRef};

use net::raw::ether::MacAddr;

use scanner::ScanResult;

use timer::Timer;

use utils;

use utils::RuntimeError;

use utils::logger::{BoxedLogger, Severity};

use native_tls::TlsConnector;

use uuid::Uuid;

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
        match self {
            &ConnectionState::Connected    => "connected",
            &ConnectionState::Disconnected => "disconnected",
            &ConnectionState::Unauthorized => "unauthorized",
        }
    }
}

impl Display for ConnectionState {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.as_str())
    }
}

/// Internal data of the application context.
struct ApplicationContextData {
    logger:      BoxedLogger,
    timer:       Timer,
    config:      ApplicationConfig,
    scanning:    bool,
    scan_result: ScanResult,
    conn_state:  ConnectionState,
}

impl ApplicationContextData {
    /// Take a given application config and create application context data.
    fn new(config: ApplicationConfig) -> ApplicationContextData {
        let timer = Timer::new(config.get_logger());

        ApplicationContextData {
            logger:      config.get_logger(),
            timer:       timer,
            config:      config,
            scanning:    false,
            scan_result: ScanResult::new(),
            conn_state:  ConnectionState::Disconnected,
        }
    }

    /// Get address of the remote Arrow Service.
    pub fn get_arrow_service_address(&self) -> String {
        self.config.get_arrow_service_address()
            .to_string()
    }

    /// Get current version of the configuration.
    fn get_config_version(&self) -> usize {
        self.config.get_version()
    }

    /// Get Arrow Client UUID.
    fn get_arrow_uuid(&self) -> Uuid {
        self.config.get_uuid()
    }

    /// Get Arrow Client password.
    fn get_arrow_password(&self) -> Uuid {
        self.config.get_password()
    }

    /// Get Arrow Client MAC address.
    fn get_arrow_mac_address(&self) -> MacAddr {
        self.config.get_mac_address()
    }

    /// Get network discovery settings.
    pub fn get_discovery(&self) -> bool {
        self.config.get_discovery()
    }

    /// Check if the application is in the diagnostic mode.
    fn get_diagnostic_mode(&self) -> bool {
        self.config.get_diagnostic_mode()
    }

    /// Get path to a file containing RTSP paths for the network scanner.
    fn get_rtsp_paths_file(&self) -> String {
        self.config.get_rtsp_paths_file()
            .to_string()
    }

    /// Get path to a file containing MJPEG paths for the network scanner.
    fn get_mjpeg_paths_file(&self) -> String {
        self.config.get_mjpeg_paths_file()
            .to_string()
    }

    /// Get application logger.
    fn get_logger(&self) -> BoxedLogger {
        self.logger.clone()
    }

    /// Get application-wide instance of the Timer.
    fn get_timer(&self) -> Timer {
        self.timer.clone()
    }

    /// Get TLS connector.
    fn get_tls_connector(&self) -> Result<TlsConnector, RuntimeError> {
        self.config.get_tls_connector()
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

    /// Get read-only reference to the service table.
    fn get_service_table(&self) -> SharedServiceTableRef {
        self.config.get_service_table()
    }

    /// Update service table. Add all given services into the table and update active services.
    pub fn update_service_table<I>(&mut self, services: I)
        where I: IntoIterator<Item=Service> {
        self.config.update_service_table(services)
    }

    /// Reset service table.
    fn reset_service_table(&mut self) {
        self.config.reset_service_table()
    }

    /// Set connection state.
    fn set_connection_state(&mut self, state: ConnectionState) {
        self.conn_state = state;

        let res = self.save_connection_state();

        utils::result_or_log(
            &mut self.logger,
            Severity::WARN,
            "unable to save current connection state",
            res);
    }

    /// Save connection state into the file.
    fn save_connection_state(&self) -> Result<(), io::Error> {
        let mut file = File::create(self.config.get_connection_state_file())?;

        writeln!(&mut file, "{}", self.conn_state)?;

        Ok(())
    }
}

/// Application context.
#[derive(Clone)]
pub struct ApplicationContext {
    data: Arc<Mutex<ApplicationContextData>>,
}

impl ApplicationContext {
    /// Take a given application config and create a new application context.
    pub fn new(config: ApplicationConfig) -> ApplicationContext {
        ApplicationContext {
            data: Arc::new(Mutex::new(ApplicationContextData::new(config)))
        }
    }

    /// Get address of the remote Arrow Service.
    pub fn get_arrow_service_address(&self) -> String {
        self.data.lock()
            .unwrap()
            .get_arrow_service_address()
    }

    /// Get current version of the configuration.
    pub fn get_config_version(&self) -> usize {
        self.data.lock()
            .unwrap()
            .get_config_version()
    }

    /// Get Arrow Client UUID.
    pub fn get_arrow_uuid(&self) -> Uuid {
        self.data.lock()
            .unwrap()
            .get_arrow_uuid()
    }

    /// Get Arrow Client password.
    pub fn get_arrow_password(&self) -> Uuid {
        self.data.lock()
            .unwrap()
            .get_arrow_password()
    }

    /// Get Arrow Client MAC address.
    pub fn get_arrow_mac_address(&self) -> MacAddr {
        self.data.lock()
            .unwrap()
            .get_arrow_mac_address()
    }

    /// Get network discovery settings.
    pub fn get_discovery(&self) -> bool {
        self.data.lock()
            .unwrap()
            .get_discovery()
    }

    /// Check if the application is in the diagnostic mode.
    pub fn get_diagnostic_mode(&self) -> bool {
        self.data.lock()
            .unwrap()
            .get_diagnostic_mode()
    }

    /// Get path to a file containing RTSP paths for the network scanner.
    pub fn get_rtsp_paths_file(&self) -> String {
        self.data.lock()
            .unwrap()
            .get_rtsp_paths_file()
    }

    /// Get path to a file containing MJPEG paths for the network scanner.
    pub fn get_mjpeg_paths_file(&self) -> String {
        self.data.lock()
            .unwrap()
            .get_mjpeg_paths_file()
    }

    /// Get application logger.
    pub fn get_logger(&self) -> BoxedLogger {
        self.data.lock()
            .unwrap()
            .get_logger()
    }

    /// Get application-wide instance of the Timer.
    pub fn get_timer(&self) -> Timer {
        self.data.lock()
            .unwrap()
            .get_timer()
    }

    /// Get TLS connector.
    pub fn get_tls_connector(&self) -> Result<TlsConnector, RuntimeError> {
        self.data.lock()
            .unwrap()
            .get_tls_connector()
    }

    /// Set the state of the network scanner thread.
    pub fn set_scanning(&mut self, scanning: bool) {
        self.data.lock()
            .unwrap()
            .set_scanning(scanning)
    }

    /// Check if the network scanner thread is running right now.
    pub fn is_scanning(&self) -> bool {
        self.data.lock()
            .unwrap()
            .is_scanning()
    }

    /// Get the last scan result.
    pub fn get_scan_result(&self) -> ScanResult {
        self.data.lock()
            .unwrap()
            .get_scan_result()
    }

    /// Set last scan result.
    pub fn set_scan_result(&mut self, result: ScanResult) {
        self.data.lock()
            .unwrap()
            .set_scan_result(result)
    }

    /// Get read-only reference to the service table.
    pub fn get_service_table(&self) -> SharedServiceTableRef {
        self.data.lock()
            .unwrap()
            .get_service_table()
    }

    /// Update service table. Add all given services into the table and update active services.
    pub fn update_service_table<I>(&mut self, services: I)
        where I: IntoIterator<Item=Service> {
        self.data.lock()
            .unwrap()
            .update_service_table(services)
    }

    /// Reset service table.
    pub fn reset_service_table(&mut self) {
        self.data.lock()
            .unwrap()
            .reset_service_table()
    }

    /// Set connection state.
    pub fn set_connection_state(&mut self, state: ConnectionState) {
        self.data.lock()
            .unwrap()
            .set_connection_state(state)
    }
}
