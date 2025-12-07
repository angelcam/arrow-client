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
    fmt::{self, Display, Write},
    io,
    iter::FromIterator,
    path::{Path, PathBuf},
    process,
    sync::Arc,
};

use argh::FromArgs;
use log::{LevelFilter, Log};
use serde_lite::{Deserialize, Intermediate, Serialize};
use tokio_native_tls::TlsConnector;
use ttpkit_url::Url;
use uuid::Uuid;

use crate::{
    context::ConnectionState,
    error::Error,
    storage::{DefaultStorage, Storage},
    svc_table::{LockedServiceTable, ServiceSource, ServiceTable, ServiceTableHandle},
    utils::{
        get_fake_mac,
        logger::{FileLogger, StderrLogger},
    },
};

#[cfg(not(target_os = "windows"))]
use crate::utils::logger::Syslog;

pub use crate::{
    net::raw::{
        devices::EthernetDevice as NetworkInterface,
        ether::{AddrParseError, MacAddr},
    },
    svc_table::{Service, ServiceType},
};

/*const EXIT_CODE_USAGE:         i32 = 1;
const EXIT_CODE_NETWORK_ERROR: i32 = 2;
const EXIT_CODE_CONFIG_ERROR:  i32 = 3;
const EXIT_CODE_SSL_ERROR:     i32 = 4;
const EXIT_CODE_CERT_ERROR:    i32 = 5;*/

/// Arrow Client configuration file.
const CONFIG_FILE: &str = "/etc/arrow/config.json";

/// Arrow Client configuration file skeleton.
const CONFIG_FILE_SKELETON: &str = "/etc/arrow/config-skel.json";

/// Arrow Client connection state file.
const STATE_FILE: &str = "/var/lib/arrow/state";

/// A file containing RTSP paths tested on service discovery (one path per
/// line).
#[cfg(feature = "discovery")]
const RTSP_PATHS_FILE: &str = "/etc/arrow/rtsp-paths";

/// A file containing MJPEG paths tested on service discovery (one path per
/// line).
#[cfg(feature = "discovery")]
const MJPEG_PATHS_FILE: &str = "/etc/arrow/mjpeg-paths";

/// Default port number for connecting to an Arrow Service.
const DEFAULT_ARROW_SERVICE_PORT: u16 = 8900;

/// Arrow Client ID.
pub type ClientId = Uuid;

/// Arrow Client secret key.
pub type ClientKey = [u8; 16];

/// Builder for the Arrow client configuration.
pub struct ConfigBuilder {
    arrow_mac: Option<MacAddr>,
    services: Vec<Service>,
    flash_friendly: bool,
    diagnostic_mode: bool,
    gateway_interfaces: Vec<String>,
    discovery_interfaces: Vec<String>,
    device_category: Option<String>,
    device_type: Option<String>,
    device_vendor: Option<String>,
}

impl ConfigBuilder {
    /// Create a new configuration builder.
    fn new() -> Self {
        Self {
            arrow_mac: None,
            services: Vec::new(),
            flash_friendly: false,
            diagnostic_mode: false,
            gateway_interfaces: Vec::new(),
            discovery_interfaces: Vec::new(),
            device_category: None,
            device_type: None,
            device_vendor: None,
        }
    }

    /// Set MAC address.
    ///
    /// The MAC address can be used as a client identifier in the pairing
    /// process.
    pub fn mac_address(&mut self, mac_addr: Option<MacAddr>) -> &mut Self {
        self.arrow_mac = mac_addr;
        self
    }

    /// Add a given static service.
    pub fn add_service(&mut self, service: Service) -> &mut Self {
        self.services.push(service);
        self
    }

    /// Set a collection of static services.
    pub fn services<I>(&mut self, services: I) -> &mut Self
    where
        I: IntoIterator<Item = Service>,
    {
        self.services = Vec::from_iter(services);
        self
    }

    /// Enable/disable the flash-friendly mode.
    ///
    /// This will limit the number of writes into the configuration file. It is
    /// useful for embedded deployments with service discovery where it is
    /// desirable for the configuration file to be in a persistent storage.
    ///
    /// If enabled, the application will write into the configuration file only
    /// if a new service is discovered or if an existing service changes its
    /// IP address. There will be no writes if an existing service changes its
    /// visibility.
    pub fn flash_friendly(&mut self, enabled: bool) -> &mut Self {
        self.flash_friendly = enabled;
        self
    }

    /// Set diagnostic mode.
    pub fn diagnostic_mode(&mut self, enabled: bool) -> &mut Self {
        self.diagnostic_mode = enabled;
        self
    }

    /// Enable the gateway mode on given network interfaces.
    ///
    /// Services belonging to all local networks associated with the interfaces
    /// will be accessible to the Arrow Client. Note that even if no gateway
    /// interfaces are set, the client can still access services provided via
    /// the `services` method.
    pub fn gateway_interfaces<I>(&mut self, interfaces: I) -> &mut Self
    where
        I: IntoIterator<Item = String>,
    {
        self.gateway_interfaces = Vec::from_iter(interfaces);
        self
    }

    /// Enable automatic service discovery on given network interfaces.
    ///
    /// This also enables the gateway mode for these interfaces.
    pub fn discovery_interfaces<I>(&mut self, interfaces: I) -> &mut Self
    where
        I: IntoIterator<Item = String>,
    {
        self.discovery_interfaces = Vec::from_iter(interfaces);
        self
    }

    /// Set device category.
    pub fn device_category<T>(&mut self, device_category: T) -> &mut Self
    where
        T: ToString,
    {
        self.device_category = Some(device_category.to_string());
        self
    }

    /// Set device type.
    pub fn device_type<T>(&mut self, device_type: T) -> &mut Self
    where
        T: ToString,
    {
        self.device_type = Some(device_type.to_string());
        self
    }

    /// Set device vendor.
    pub fn device_vendor<T>(&mut self, device_vendor: T) -> &mut Self
    where
        T: ToString,
    {
        self.device_vendor = Some(device_vendor.to_string());
        self
    }

    /// Build the configuration.
    pub fn build<S, T>(mut self, mut storage: S, arrow_service_address: T) -> Result<Config, Error>
    where
        S: 'static + Storage + Send,
        T: ToString,
    {
        let config = storage.load_configuration().map_err(|err| {
            Error::from_static_msg_and_cause("unable to load client configuration", err)
        })?;

        let mac = self
            .arrow_mac
            .map(Ok)
            .unwrap_or_else(get_first_mac)
            .map_err(|_| {
                Error::from_static_msg("unable to get any network interface MAC address")
            })?;

        let tls_connector = create_tls_connector(&mut storage).map_err(|err| {
            Error::from_static_msg_and_cause("unable to create TLS connector: {}", err)
        })?;

        let rtsp_paths = storage
            .load_rtsp_paths()
            .inspect_err(|err| warn!("unable to load RTSP paths ({err})"))
            .unwrap_or_default();

        let mjpeg_paths = storage
            .load_mjpeg_paths()
            .inspect_err(|err| warn!("unable to load MJPEG paths ({err})"))
            .unwrap_or_default();

        self.gateway_interfaces
            .extend(self.discovery_interfaces.clone());
        self.gateway_interfaces.sort_unstable();
        self.gateway_interfaces.dedup();

        self.discovery_interfaces.sort_unstable();
        self.discovery_interfaces.dedup();

        let mut config = Config {
            version: config.version,
            uuid: config.uuid.into(),
            passwd: config.passwd.into(),
            arrow_mac: mac,
            arrow_svc_addr: arrow_service_address.to_string(),
            diagnostic_mode: self.diagnostic_mode,
            gateway_interfaces: Arc::new(self.gateway_interfaces),
            discovery_interfaces: Arc::new(self.discovery_interfaces),
            rtsp_paths: Arc::new(rtsp_paths),
            mjpeg_paths: Arc::new(mjpeg_paths),
            default_svc_table: config.svc_table.clone(),
            svc_table: config.svc_table,
            storage: Box::new(storage),
            tls_connector,
            flash_friendly: self.flash_friendly,
            device_category: self.device_category,
            device_type: self.device_type,
            device_vendor: self.device_vendor,
        };

        {
            let mut svc_table = config.svc_table.lock();
            let mut default_svc_table = config.default_svc_table.lock();

            for svc in self.services {
                svc_table.add(svc.clone(), ServiceSource::Static);
                default_svc_table.add(svc, ServiceSource::Static);
            }
        }

        config.update_service_availability();

        config.save().map_err(Error::from_other)?;

        Ok(config)
    }
}

/// Client identification that can be publicly available.
#[doc(hidden)]
#[derive(Serialize)]
pub struct PublicIdentity {
    uuid: UuidSerializer,
}

/// Persistent part of application configuration.
#[derive(Deserialize, Serialize)]
pub struct PersistentConfig {
    uuid: UuidSerializer,
    passwd: UuidSerializer,
    version: usize,
    svc_table: ServiceTable,
}

impl PersistentConfig {
    /// Create a new instance of persistent configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get client public identity.
    #[doc(hidden)]
    pub fn to_identity(&self) -> PublicIdentity {
        PublicIdentity { uuid: self.uuid }
    }

    /// Create a configuration skeleton from this persistent config.
    #[doc(hidden)]
    pub fn to_skeleton(&self) -> Self {
        Self {
            uuid: self.uuid,
            passwd: self.passwd,
            version: 0,
            svc_table: ServiceTable::new(),
        }
    }
}

impl Default for PersistentConfig {
    fn default() -> Self {
        Self {
            uuid: UuidSerializer::from(Uuid::new_v4()),
            passwd: UuidSerializer::from(Uuid::new_v4()),
            version: 0,
            svc_table: ServiceTable::new(),
        }
    }
}

/// Arrow client configuration.
pub struct Config {
    version: usize,
    uuid: ClientId,
    passwd: ClientKey,
    arrow_mac: MacAddr,
    arrow_svc_addr: String,
    diagnostic_mode: bool,
    gateway_interfaces: Arc<Vec<String>>,
    discovery_interfaces: Arc<Vec<String>>,
    rtsp_paths: Arc<Vec<String>>,
    mjpeg_paths: Arc<Vec<String>>,
    svc_table: ServiceTable,
    default_svc_table: ServiceTable,
    storage: Box<dyn Storage + Send>,
    tls_connector: TlsConnector,
    flash_friendly: bool,
    device_category: Option<String>,
    device_type: Option<String>,
    device_vendor: Option<String>,
}

impl Config {
    /// Get a new client configuration builder.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }

    /// Create a new application configuration.
    ///
    /// The method reads all command line arguments and loads the configuration
    /// file.
    pub fn from_args() -> Result<Self, Error> {
        argh::from_env::<ConfigParser>().into_config()
    }

    /// Get address of the remote Arrow Service.
    #[doc(hidden)]
    pub fn get_arrow_service_address(&self) -> &str {
        &self.arrow_svc_addr
    }

    /// Get Arrow Client ID.
    #[doc(hidden)]
    pub fn get_client_id(&self) -> ClientId {
        self.uuid
    }

    /// Get Arrow Client key.
    #[doc(hidden)]
    pub fn get_client_key(&self) -> ClientKey {
        self.passwd
    }

    /// Get Arrow Client MAC address.
    #[doc(hidden)]
    pub fn get_mac_address(&self) -> MacAddr {
        self.arrow_mac
    }

    /// Get network discovery whitelist.
    #[doc(hidden)]
    pub fn get_discovery_interfaces(&self) -> Arc<Vec<String>> {
        self.discovery_interfaces.clone()
    }

    /// Check if the application is in the diagnostic mode.
    #[doc(hidden)]
    pub fn get_diagnostic_mode(&self) -> bool {
        self.diagnostic_mode
    }

    /// Check if the client can be used as a gateway.
    #[doc(hidden)]
    pub fn get_gateway_mode(&self) -> bool {
        !self.gateway_interfaces.is_empty()
    }

    /// Get RTSP paths for the network scanner.
    #[doc(hidden)]
    pub fn get_rtsp_paths(&self) -> Arc<Vec<String>> {
        self.rtsp_paths.clone()
    }

    /// Get MJPEG paths for the network scanner.
    #[doc(hidden)]
    pub fn get_mjpeg_paths(&self) -> Arc<Vec<String>> {
        self.mjpeg_paths.clone()
    }

    /// Get TLS connector.
    #[doc(hidden)]
    pub fn get_tls_connector(&self) -> TlsConnector {
        self.tls_connector.clone()
    }

    /// Get read-only reference to the shared service table.
    #[doc(hidden)]
    pub fn get_service_table(&self) -> ServiceTableHandle {
        self.svc_table.handle()
    }

    /// Reset the service table.
    #[doc(hidden)]
    pub fn reset_service_table(&mut self) {
        self.svc_table = self.default_svc_table.clone();

        self.version += 1;

        if let Err(err) = self.save() {
            warn!("{err}");
        }
    }

    /// Add a new service to the service table.
    #[doc(hidden)]
    pub fn add_service(&mut self, service: Service, source: ServiceSource) -> u16 {
        self.update_service_table_internal(|svc_table| svc_table.add(service, source))
    }

    /// Update service table.
    ///
    /// Add all given services into the table and update visible and available
    /// services.
    #[doc(hidden)]
    pub fn update_service_table<I>(&mut self, services: I, source: ServiceSource)
    where
        I: IntoIterator<Item = Service>,
    {
        self.update_service_table_internal(|svc_table| {
            for svc in services {
                svc_table.add(svc, source);
            }
        });
    }

    /// Update service availability based on the current network state.
    #[doc(hidden)]
    pub fn update_service_availability(&self) {
        self.svc_table
            .lock()
            .update_service_availability(&self.get_whitelisted_network_interfaces());
    }

    /// Update connection state.
    #[doc(hidden)]
    pub fn update_connection_state(&mut self, state: ConnectionState) {
        if let Err(err) = self.storage.save_connection_state(state) {
            debug!("unable to save current connection state ({err})");
        }
    }

    /// Get client extended info.
    #[doc(hidden)]
    pub fn get_extended_info(&self) -> ExtendedInfo {
        ExtendedInfo {
            client: ExtendedClientInfo::new(),
            device: ExtendedDeviceInfo {
                category: self.device_category.clone(),
                device_type: self.device_type.clone(),
                vendor: self.device_vendor.clone(),
            },
        }
    }

    /// Save the current configuration.
    fn save(&mut self) -> Result<(), io::Error> {
        let config = self.to_persistent_config();

        self.storage
            .save_configuration(&config)
            .map_err(|err| io::Error::other(format!("unable to save client configuration: {err}")))
    }

    /// Create persistent configuration.
    fn to_persistent_config(&self) -> PersistentConfig {
        PersistentConfig {
            uuid: self.uuid.into(),
            passwd: self.passwd.into(),
            version: self.version,
            svc_table: self.svc_table.clone(),
        }
    }

    /// Update service table.
    fn update_service_table_internal<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut LockedServiceTable) -> R,
    {
        let interface_whitelist = self.get_whitelisted_network_interfaces();

        let (res, save) = {
            let mut svc_table = self.svc_table.lock();

            let old_st_version = svc_table.service_table_version();
            let old_vs_version = svc_table.visible_set_version();

            let res = f(&mut svc_table);

            svc_table.update_service_availability(&interface_whitelist);
            svc_table.update_service_visibility(crate::utils::get_utc_timestamp());

            let new_st_version = svc_table.service_table_version();
            let new_vs_version = svc_table.visible_set_version();

            let save = old_st_version != new_st_version
                || (!self.flash_friendly && old_vs_version != new_vs_version);

            (res, save)
        };

        if save {
            self.version += 1;

            if let Err(err) = self.save() {
                warn!("{err}");
            }
        }

        res
    }

    /// Get whitelisted network interfaces.
    fn get_whitelisted_network_interfaces(&self) -> Vec<NetworkInterface> {
        NetworkInterface::list()
            .into_iter()
            .filter(|iface| {
                self.gateway_interfaces
                    .binary_search_by_key(&iface.name(), String::as_str)
                    .is_ok()
            })
            .collect::<Vec<_>>()
    }
}

/// Arrow Client configuration parser.
#[derive(FromArgs)]
#[argh(help_triggers("-h", "--help"))]
struct ConfigParser {
    /// address of the Angelcam Arrow Service ("host[:port]" format expected)
    #[argh(positional)]
    arrow_service: String,

    /// path to a CA certificate for Arrow Service identity verification; in
    /// case the path is a directory, it's scanned recursively for all files
    /// with the following extensions: *.der, *.cer, *.crr, *.pem
    #[argh(option, short = 'c')]
    ca_certificate: Vec<PathBuf>,

    /// ethernet interface used for client identification (the first configured
    /// network interface is used by default)
    #[argh(option, short = 'i')]
    default_interface: Option<String>,

    /// enable the gateway mode on a given network interface (services
    /// belonging to all local networks associated with the interface will be
    /// accessible to the Arrow Client)
    #[argh(option, short = 'G')]
    gateway_interface: Vec<String>,

    /// enable automatic service discovery on a given network interface (this
    /// also enables the gateway mode on the interface)
    #[cfg(feature = "discovery")]
    #[argh(option, short = 'D')]
    discovery_interface: Vec<String>,

    /// add a given RTSP service URL
    #[argh(option, short = 'R')]
    rtsp_service: Vec<String>,

    /// add a given MJPEG service URL
    #[argh(option, short = 'M')]
    mjpeg_service: Vec<String>,

    /// add a given HTTP service ("host:port" format expected)
    #[argh(option, short = 'H')]
    http_service: Vec<String>,

    /// add a given TCP service ("host:port" format expected)
    #[argh(option, short = 'T')]
    tcp_service: Vec<String>,

    /// enable debug logs
    #[argh(switch, short = 'v')]
    verbose: bool,

    /// alternative path to the client configuration file (default value:
    /// /etc/arrow/config.json)
    #[argh(option, default = "String::from(CONFIG_FILE)")]
    config_file: String,

    /// the client will use this file as a backup for its credentials (default
    /// value: /etc/arrow/config-skel.json)
    #[argh(option, default = "String::from(CONFIG_FILE_SKELETON)")]
    config_file_skel: String,

    /// a file that will contain only the public part of the client
    /// identification (i.e. there will be no secret in the file)
    #[argh(option)]
    identity_file: Option<String>,

    /// alternative path to a file for saving the client connection state
    /// (default value: /var/lib/arrow/state)
    #[argh(option, default = "String::from(STATE_FILE)")]
    conn_state_file: String,

    /// limit the number of writes into the configuration file (useful for
    /// embedded device deployments with service discovery)
    #[argh(switch)]
    flash_friendly: bool,

    /// start the client in the diagnostic mode (i.e. the client will try to
    /// connect to a given Arrow Service and it will report success as its
    /// exit code; note: the "access denied" response from the server is also
    /// considered as a success)
    #[argh(switch)]
    diagnostic_mode: bool,

    /// send log messages into stderr instead of syslog
    #[argh(switch)]
    log_stderr: bool,

    /// send log messages into stderr instead of syslog and use colored
    /// messages
    #[argh(switch)]
    log_stderr_pretty: bool,

    /// send log messages into a given file instead of syslog
    #[argh(option)]
    log_file: Option<String>,

    /// size limit for the log file (in bytes; default value: 10240)
    #[argh(option, default = "10240")]
    log_file_size: usize,

    /// number of backup files (i.e. rotations) for the log file (default
    /// value: 1)
    #[argh(option, default = "1")]
    log_file_rotations: usize,

    /// alternative path to a file containing a list of RTSP paths used for
    /// service discovery (default value: /etc/arrow/rtsp-paths)
    #[cfg(feature = "discovery")]
    #[argh(option, default = "String::from(RTSP_PATHS_FILE)")]
    rtsp_paths: String,

    /// alternative path to a file containing a list of MJPEG paths used for
    /// service discovery (default value: /etc/arrow/mjpeg-paths)
    #[cfg(feature = "discovery")]
    #[argh(option, default = "String::from(MJPEG_PATHS_FILE)")]
    mjpeg_paths: String,

    /// use a given lock file to make sure that there is only one instance of
    /// the process running; the file will contain also the PID of the process
    #[argh(option)]
    lock_file: Option<String>,

    /// type of a device running the client (informational)
    #[argh(option)]
    device_type: Option<String>,

    /// device vendor (informational)
    #[argh(option)]
    device_vendor: Option<String>,

    /// device category (informational)
    #[argh(option)]
    device_category: Option<String>,

    /// print the version information and exit
    #[argh(switch)]
    version: bool,
}

impl ConfigParser {
    /// Build the client configuration from the parsed command line arguments.
    fn into_config(self) -> Result<Config, Error> {
        if self.version {
            version();
        }

        // because of the lock file, we need to create the storage builder
        // before creating the logger
        let mut storage_builder =
            DefaultStorage::builder(&self.config_file, self.lock_file.as_ref())
                .map_err(Error::from_other)?;

        self.init_logger()?;

        let arrow_mac = self.get_arrow_mac()?;
        let services = self.collect_services()?;

        storage_builder
            .config_skeleton_file(Some(self.config_file_skel))
            .connection_state_file(Some(self.conn_state_file))
            .identity_file(self.identity_file)
            .ca_certificates(self.ca_certificate);

        #[cfg(feature = "discovery")]
        storage_builder
            .rtsp_paths_file(Some(self.rtsp_paths))
            .mjpeg_paths_file(Some(self.mjpeg_paths));

        let storage = storage_builder.build();

        let mut config_builder = Config::builder();

        config_builder
            .mac_address(arrow_mac)
            .services(services)
            .diagnostic_mode(self.diagnostic_mode)
            .flash_friendly(self.flash_friendly)
            .gateway_interfaces(self.gateway_interface);

        #[cfg(feature = "discovery")]
        config_builder.discovery_interfaces(self.discovery_interface);

        if let Some(c) = self.device_category {
            config_builder.device_category(c);
        }

        if let Some(t) = self.device_type {
            config_builder.device_type(t);
        }

        if let Some(v) = self.device_vendor {
            config_builder.device_vendor(v);
        }

        let mut arrow_service = self.arrow_service;

        // add the default port number if the given address has no port
        if arrow_service.ends_with(']') || !arrow_service.contains(':') {
            let _ = write!(arrow_service, ":{}", DEFAULT_ARROW_SERVICE_PORT);
        }

        config_builder.build(storage, arrow_service)
    }

    /// Initialize the application logger.
    fn init_logger(&self) -> Result<(), Error> {
        let logger: Box<dyn Log> = if let Some(file) = self.log_file.as_deref() {
            let logger = FileLogger::new(file, self.log_file_size, self.log_file_rotations)
                .map_err(|err| {
                    Error::from_msg_and_cause(
                        format!("unable to open the given log file: \"{file}\""),
                        err,
                    )
                })?;

            Box::new(logger)
        } else if self.log_stderr || self.log_stderr_pretty || cfg!(target_os = "windows") {
            Box::new(StderrLogger::new(self.log_stderr_pretty))
        } else {
            Box::new(Syslog::new())
        };

        log::set_boxed_logger(logger).expect("unable to configure application logger");

        let max_log_level = if self.verbose {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        };

        log::set_max_level(max_log_level);

        Ok(())
    }

    /// Collect services passed via command line arguments.
    fn collect_services(&self) -> Result<Vec<Service>, Error> {
        let mut services = Vec::new();

        for url in &self.rtsp_service {
            services.push(parse_rtsp_url(url)?);
        }

        for url in &self.mjpeg_service {
            services.push(parse_mjpeg_url(url)?);
        }

        for addr in &self.http_service {
            let addr = crate::net::utils::get_socket_address(addr.as_str()).map_err(|_| {
                Error::from_msg(format!("unable to resolve socket address: {addr}"))
            })?;

            let mac = get_fake_mac(0xffff, addr.ip());

            services.push(Service::http(mac, addr));
        }

        for addr in &self.tcp_service {
            let addr = crate::net::utils::get_socket_address(addr.as_str()).map_err(|_| {
                Error::from_msg(format!("unable to resolve socket address: {addr}"))
            })?;

            let mac = get_fake_mac(0xffff, addr.ip());

            services.push(Service::tcp(mac, addr));
        }

        Ok(services)
    }

    /// Get the Arrow Client MAC address.
    fn get_arrow_mac(&self) -> Result<Option<MacAddr>, Error> {
        self.default_interface.as_deref().map(get_mac).transpose()
    }
}

/// Get MAC address of the first configured ethernet device.
fn get_first_mac() -> Result<MacAddr, Error> {
    NetworkInterface::list()
        .into_iter()
        .next()
        .map(|dev| dev.mac())
        .ok_or_else(|| Error::from_static_msg("there is no configured ethernet device"))
}

/// Get MAC address of a given network interface.
fn get_mac(iface: &str) -> Result<MacAddr, Error> {
    NetworkInterface::list()
        .into_iter()
        .find(|dev| dev.name() == iface)
        .map(|dev| dev.mac())
        .ok_or_else(|| Error::from_msg(format!("there is no such ethernet device: {iface}")))
}

/// Parse a given RTSP URL and return an RTSP service, a LockedRTSP service or an error.
fn parse_rtsp_url(url: &str) -> Result<Service, Error> {
    let url = url
        .parse::<Url>()
        .map_err(|_| Error::from_msg(format!("invalid RTSP URL given: {url}")))?;

    let scheme = url.scheme();

    if !scheme.eq_ignore_ascii_case("rtsp") {
        return Err(Error::from_msg(format!("invalid RTSP URL given: {url}")));
    }

    let host = url.host();
    let port = url.port().unwrap_or(554);

    let socket_addr = crate::net::utils::get_socket_address((host, port)).map_err(|_| {
        Error::from_msg(format!(
            "unable to resolve RTSP service address: {host}:{port}"
        ))
    })?;

    let mac = get_fake_mac(0xffff, socket_addr.ip());

    let mut path = url.path().to_string();

    if let Some(query) = url.query() {
        path = format!("{}?{}", path, query);
    }

    // NOTE: we do not want to probe the service here as it might not be available on app startup
    match url.username() {
        Some(_) => Ok(Service::locked_rtsp(mac, socket_addr, Some(path))),
        None => Ok(Service::rtsp(mac, socket_addr, path)),
    }
}

/// Parse a given HTTP URL and return an MJPEG service, a LockedMJPEG service or an error.
fn parse_mjpeg_url(url: &str) -> Result<Service, Error> {
    let url = url
        .parse::<Url>()
        .map_err(|_| Error::from_msg(format!("invalid HTTP URL given: {url}")))?;

    let scheme = url.scheme();

    if !scheme.eq_ignore_ascii_case("http") {
        return Err(Error::from_msg(format!("invalid HTTP URL given: {url}")));
    }

    let host = url.host();
    let port = url.port().unwrap_or(80);

    let socket_addr = crate::net::utils::get_socket_address((host, port)).map_err(|_| {
        Error::from_msg(format!(
            "unable to resolve HTTP service address: {host}:{port}"
        ))
    })?;

    let mac = get_fake_mac(0xffff, socket_addr.ip());

    let mut path = url.path().to_string();

    if let Some(query) = url.query() {
        path = format!("{}?{}", path, query);
    }

    // NOTE: we do not want to probe the service here as it might not be available on app startup
    match url.username() {
        Some(_) => Ok(Service::locked_mjpeg(mac, socket_addr, Some(path))),
        None => Ok(Service::mjpeg(mac, socket_addr, path)),
    }
}

/// Print usage and exit the process with a given exit code.
#[doc(hidden)]
pub fn usage(exit_code: i32) -> ! {
    let cmd = app_name();

    let err = ConfigParser::from_args(&[&cmd], &["--help"]).err().unwrap();

    println!("{}", err.output);

    process::exit(exit_code);
}

/// Print version information and exit the process.
#[doc(hidden)]
pub fn version() -> ! {
    println!(
        "{} ({} v{})",
        app_name(),
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    process::exit(0);
}

/// Get the application name.
fn app_name() -> String {
    std::env::args()
        .next()
        .and_then(|path| {
            PathBuf::from(path)
                .file_name()
                .map(Path::new)
                .map(|p| p.display())
                .map(|p| p.to_string())
        })
        .unwrap_or_else(|| String::from(env!("CARGO_PKG_NAME")))
}

/// UUID wrapper for serialization and deserialization.
#[derive(Copy, Clone)]
struct UuidSerializer {
    inner: Uuid,
}

impl Deserialize for UuidSerializer {
    fn deserialize(value: &Intermediate) -> Result<Self, serde_lite::Error> {
        let inner = value
            .as_str()
            .map(|v| v.parse())
            .and_then(Result::ok)
            .ok_or_else(|| serde_lite::Error::invalid_value("UUID"))?;

        let res = Self { inner };

        Ok(res)
    }
}

impl Serialize for UuidSerializer {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        Ok(Intermediate::from(format!(
            "{}",
            self.inner.as_hyphenated()
        )))
    }
}

impl From<[u8; 16]> for UuidSerializer {
    fn from(bytes: [u8; 16]) -> Self {
        Self::from(Uuid::from_bytes(bytes))
    }
}

impl From<Uuid> for UuidSerializer {
    fn from(uuid: Uuid) -> Self {
        Self { inner: uuid }
    }
}

impl From<UuidSerializer> for [u8; 16] {
    fn from(serializer: UuidSerializer) -> Self {
        serializer.inner.into_bytes()
    }
}

impl From<UuidSerializer> for Uuid {
    fn from(serializer: UuidSerializer) -> Self {
        serializer.inner
    }
}

/// Extended client and device information.
#[derive(Serialize)]
pub struct ExtendedInfo {
    client: ExtendedClientInfo,
    device: ExtendedDeviceInfo,
}

impl Display for ExtendedInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self
            .serialize()
            .ok()
            .map(|val| serde_json::to_string(&val))
            .and_then(Result::ok)
            .expect("unable to serialize extended info");

        f.write_str(&s)
    }
}

/// Extended client information.
#[derive(Serialize)]
struct ExtendedClientInfo {
    id: &'static str,
    version: &'static str,
    vendor: &'static str,
}

impl ExtendedClientInfo {
    /// Create a new instance of extended client info.
    const fn new() -> Self {
        Self {
            id: "arrow-client",
            version: env!("CARGO_PKG_VERSION"),
            vendor: "angelcam",
        }
    }
}

/// Extended device information.
#[derive(Serialize)]
struct ExtendedDeviceInfo {
    category: Option<String>,

    #[serde(rename = "type")]
    device_type: Option<String>,

    vendor: Option<String>,
}

/// Create a TLS connector with loaded CA certificates.
fn create_tls_connector<S>(storage: &mut S) -> Result<TlsConnector, Error>
where
    S: Storage,
{
    use tokio_native_tls::native_tls::Protocol;

    let mut builder = tokio_native_tls::native_tls::TlsConnector::builder();

    builder
        .min_protocol_version(Some(Protocol::Tlsv12))
        .disable_built_in_roots(true);

    storage
        .load_ca_certificates(&mut builder)
        .map_err(Error::from_other)?;

    let connector = builder.build().map_err(Error::from_other)?;

    Ok(connector.into())
}
