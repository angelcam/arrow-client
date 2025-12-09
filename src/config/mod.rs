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

mod parser;
mod utils;

use std::{
    fmt::{self, Display},
    io,
    iter::FromIterator,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use argh::FromArgs;
use serde_lite::{Deserialize, Intermediate, Serialize};
use uuid::Uuid;

use crate::{
    context::ConnectionState,
    error::Error,
    storage::Storage,
    svc_table::{LockedServiceTable, ServiceSource, ServiceTable, ServiceTableHandle},
    tls::TlsConnector,
};

use self::{parser::ConfigParser, utils::NetworkInterfacesCache};

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
    pub async fn build<S, T>(
        mut self,
        mut storage: S,
        arrow_service_address: T,
    ) -> Result<Config, Error>
    where
        S: Storage + Send + Sync + 'static,
        T: ToString,
    {
        let config = storage.load_configuration().await.map_err(|err| {
            Error::from_static_msg_and_cause("unable to load client configuration", err)
        })?;

        let network_interfaces = NetworkInterfacesCache::new();

        let interfaces = network_interfaces.get_interfaces().await;

        let mac = self
            .arrow_mac
            .map(Ok)
            .unwrap_or_else(|| get_first_mac(&interfaces))
            .map_err(|_| {
                Error::from_static_msg("unable to get any network interface MAC address")
            })?;

        let tls_connector = create_tls_connector(&mut storage).await.map_err(|err| {
            Error::from_static_msg_and_cause("unable to create TLS connector: {}", err)
        })?;

        let rtsp_paths = if self.discovery_interfaces.is_empty() {
            Vec::new()
        } else {
            storage
                .load_rtsp_paths()
                .await
                .inspect_err(|err| warn!("unable to load RTSP paths ({err})"))
                .unwrap_or_default()
        };

        let mjpeg_paths = if self.discovery_interfaces.is_empty() {
            Vec::new()
        } else {
            storage
                .load_mjpeg_paths()
                .await
                .inspect_err(|err| warn!("unable to load MJPEG paths ({err})"))
                .unwrap_or_default()
        };

        self.gateway_interfaces
            .extend(self.discovery_interfaces.clone());

        self.gateway_interfaces.sort_unstable();
        self.gateway_interfaces.dedup();

        self.discovery_interfaces.sort_unstable();
        self.discovery_interfaces.dedup();

        let config = Config {
            version: AtomicUsize::new(config.version),
            uuid: config.uuid.into(),
            passwd: config.passwd.into(),
            arrow_mac: mac,
            arrow_svc_addr: arrow_service_address.to_string(),
            diagnostic_mode: self.diagnostic_mode,
            network_interfaces,
            gateway_interfaces: Arc::new(self.gateway_interfaces),
            discovery_interfaces: Arc::new(self.discovery_interfaces),
            rtsp_paths: Arc::new(rtsp_paths),
            mjpeg_paths: Arc::new(mjpeg_paths),
            svc_table: config.svc_table,
            storage: Box::new(storage),
            tls_connector,
            flash_friendly: self.flash_friendly,
            device_category: self.device_category,
            device_type: self.device_type,
            device_vendor: self.device_vendor,
        };

        let whitelisted_networks = config.get_whitelisted_network_interfaces().await;

        {
            let mut svc_table = config.svc_table.lock();

            for svc in self.services {
                svc_table.add(svc, ServiceSource::Static);
            }

            svc_table.update_service_availability(&whitelisted_networks);
        }

        config.save().await.map_err(Error::from_other)?;

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
    version: AtomicUsize,
    uuid: ClientId,
    passwd: ClientKey,
    arrow_mac: MacAddr,
    arrow_svc_addr: String,
    diagnostic_mode: bool,
    network_interfaces: NetworkInterfacesCache,
    gateway_interfaces: Arc<Vec<String>>,
    discovery_interfaces: Arc<Vec<String>>,
    rtsp_paths: Arc<Vec<String>>,
    mjpeg_paths: Arc<Vec<String>>,
    svc_table: ServiceTable,
    storage: Box<dyn StorageObject + Send + Sync>,
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
    pub async fn from_args() -> Result<Self, Error> {
        argh::from_env::<ConfigParser>().into_config().await
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
    pub async fn reset_service_table(&self) {
        self.svc_table.reset();

        self.version.fetch_add(1, Ordering::AcqRel);

        if let Err(err) = self.save().await {
            warn!("{err}");
        }
    }

    /// Check if a given service belongs to one of the gateway networks.
    #[doc(hidden)]
    pub async fn is_available(&self, service: &Service) -> bool {
        let Some(ip) = service.ip_address() else {
            return false;
        };

        self.get_whitelisted_network_interfaces()
            .await
            .into_iter()
            .any(|iface| iface.contains_ip_addr(ip))
    }

    /// Add a new service to the service table.
    #[doc(hidden)]
    pub async fn add_service(&self, service: Service, source: ServiceSource) -> u16 {
        self.update_service_table_internal(|svc_table| svc_table.add(service, source))
            .await
    }

    /// Update service table.
    ///
    /// Add all given services into the table and update visible and available
    /// services.
    #[doc(hidden)]
    pub async fn update_service_table<I>(&self, services: I, source: ServiceSource)
    where
        I: IntoIterator<Item = Service>,
    {
        self.update_service_table_internal(|svc_table| {
            for svc in services {
                svc_table.add(svc, source);
            }
        })
        .await;
    }

    /// Update the availability and visibility flags of all services.
    #[doc(hidden)]
    pub async fn update_service_flags(&self) {
        self.update_service_table_internal(|_| {}).await;
    }

    /// Update connection state.
    #[doc(hidden)]
    pub async fn update_connection_state(&self, state: ConnectionState) {
        if let Err(err) = self.storage.save_connection_state(state).await {
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

    /// Update service table.
    async fn update_service_table_internal<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut LockedServiceTable) -> R,
    {
        let interface_whitelist = self.get_whitelisted_network_interfaces().await;

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
            self.version.fetch_add(1, Ordering::AcqRel);

            if let Err(err) = self.save().await {
                warn!("{err}");
            }
        }

        res
    }

    /// Get whitelisted network interfaces.
    async fn get_whitelisted_network_interfaces(&self) -> Vec<NetworkInterface> {
        self.network_interfaces
            .get_interfaces()
            .await
            .iter()
            .filter(|iface| {
                self.gateway_interfaces
                    .binary_search_by_key(&iface.name(), String::as_str)
                    .is_ok()
            })
            .cloned()
            .collect::<Vec<_>>()
    }

    /// Save the current configuration.
    async fn save(&self) -> io::Result<()> {
        let config = self.to_persistent_config();

        self.storage
            .save_configuration(&config)
            .await
            .map_err(|err| io::Error::other(format!("unable to save client configuration: {err}")))
    }

    /// Create persistent configuration.
    fn to_persistent_config(&self) -> PersistentConfig {
        PersistentConfig {
            uuid: self.uuid.into(),
            passwd: self.passwd.into(),
            version: self.version.load(Ordering::Acquire),
            svc_table: self.svc_table.clone(),
        }
    }
}

/// Get MAC address of the first configured ethernet device.
fn get_first_mac(interfaces: &[NetworkInterface]) -> Result<MacAddr, Error> {
    interfaces
        .iter()
        .next()
        .map(|dev| dev.mac())
        .ok_or_else(|| Error::from_static_msg("there is no configured ethernet device"))
}

/// Get MAC address of a given network interface.
fn get_mac(interfaces: &[NetworkInterface], iface: &str) -> Result<MacAddr, Error> {
    interfaces
        .iter()
        .find(|dev| dev.name() == iface)
        .map(|dev| dev.mac())
        .ok_or_else(|| Error::from_msg(format!("there is no such ethernet device: {iface}")))
}

/// Print usage and exit the process with a given exit code.
#[doc(hidden)]
pub fn usage(exit_code: i32) -> ! {
    let cmd = app_name();

    let err = ConfigParser::from_args(&[&cmd], &["--help"]).err().unwrap();

    println!("{}", err.output);

    std::process::exit(exit_code);
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

    std::process::exit(0);
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
async fn create_tls_connector<S>(storage: &mut S) -> Result<TlsConnector, Error>
where
    S: Storage,
{
    let mut builder = TlsConnector::builder()?;

    storage
        .load_ca_certificates(&mut builder)
        .await
        .map_err(Error::from_other)?;

    builder.build()
}

/// Helper type.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Helper trait.
trait StorageObject {
    /// Save the configuration.
    fn save_configuration<'a>(
        &'a self,
        config: &'a PersistentConfig,
    ) -> BoxFuture<'a, io::Result<()>>;

    /// Save the connection state.
    fn save_connection_state(&self, _: ConnectionState) -> BoxFuture<'_, io::Result<()>>;
}

impl<T> StorageObject for T
where
    T: Storage,
{
    fn save_configuration<'a>(
        &'a self,
        config: &'a PersistentConfig,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(self.save_configuration(config))
    }

    fn save_connection_state(&self, state: ConnectionState) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(self.save_connection_state(state))
    }
}
