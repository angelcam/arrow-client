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

use std;

use std::fmt;
use std::io;
use std::process;
use std::str;

use std::collections::HashSet;
use std::env::Args;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::iter::FromIterator;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use json;

use json::JsonValue;

use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode};

use uuid::Uuid;

use crate::net;
use crate::utils;

use crate::context::ConnectionState;
use crate::net::raw::devices::EthernetDevice;
use crate::net::tls::TlsConnector;
use crate::net::url::Url;
use crate::storage::{DefaultStorage, Storage};
use crate::svc_table::{SharedServiceTable, SharedServiceTableRef};
use crate::utils::logger::file::FileLogger;
use crate::utils::logger::stderr::StderrLogger;

#[cfg(not(target_os = "windows"))]
use crate::utils::logger::syslog::Syslog;

use crate::utils::logger::{BoxLogger, DummyLogger, Logger, Severity};
use crate::utils::RuntimeError;

pub use crate::net::raw::ether::{AddrParseError, MacAddr};
pub use crate::svc_table::{Service, ServiceType};
pub use crate::utils::json::{FromJson, ParseError, ToJson};

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
const RTSP_PATHS_FILE: &str = "/etc/arrow/rtsp-paths";

/// A file containing MJPEG paths tested on service discovery (one path per
/// line).
const MJPEG_PATHS_FILE: &str = "/etc/arrow/mjpeg-paths";

/// Default port number for connecting to an Arrow Service.
const DEFAULT_ARROW_SERVICE_PORT: u16 = 8900;

/// List of cipher that can be used for TLS connections to Arrow services.
const SSL_CIPHER_LIST: &str = "HIGH:!aNULL:!kRSA:!PSK:!MD5:!RC4";

/// Arrow configuration loading/parsing/saving error.
#[derive(Debug, Clone)]
pub struct ConfigError {
    msg: String,
}

impl ConfigError {
    /// Create a new error.
    fn new<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self {
            msg: msg.to_string(),
        }
    }
}

impl Error for ConfigError {}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

/// Builder for the Arrow client configuration.
pub struct ConfigBuilder {
    logger: Option<BoxLogger>,
    arrow_mac: Option<MacAddr>,
    services: Vec<Service>,
    diagnostic_mode: bool,
    discovery: bool,
    discovery_whitelist: HashSet<String>,
    verbose: bool,
}

impl ConfigBuilder {
    /// Create a new configuration builder.
    fn new() -> Self {
        Self {
            logger: None,
            arrow_mac: None,
            services: Vec::new(),
            diagnostic_mode: false,
            discovery: false,
            discovery_whitelist: HashSet::new(),
            verbose: false,
        }
    }

    /// Set logger.
    pub fn logger(&mut self, logger: BoxLogger) -> &mut Self {
        self.logger = Some(logger);
        self
    }

    /// Set MAC address. (The MAC address can be used as a client identifier in the pairing
    /// process).
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

    /// Set diagnostic mode.
    pub fn diagnostic_mode(&mut self, enabled: bool) -> &mut Self {
        self.diagnostic_mode = enabled;
        self
    }

    /// Enable/disable automatic service discovery.
    pub fn discovery(&mut self, enabled: bool) -> &mut Self {
        self.discovery = enabled;
        self
    }

    /// Set a given discovery whitelist (i.e. a set of network interfaces which
    /// can be used for automatic service discovery).
    pub fn discovery_whitelist<I>(&mut self, whitelist: I) -> &mut Self
    where
        I: IntoIterator<Item = String>,
    {
        self.discovery_whitelist = HashSet::from_iter(whitelist);
        self
    }

    /// Enable/disable verbose logging.
    pub fn verbose(&mut self, enabled: bool) -> &mut Self {
        self.verbose = enabled;
        self
    }

    /// Build the configuration.
    pub fn build<S, T>(
        self,
        mut storage: S,
        arrow_service_address: T,
    ) -> Result<Config, ConfigError>
    where
        S: 'static + Storage + Send,
        T: ToString,
    {
        let mut logger = self
            .logger
            .unwrap_or_else(|| BoxLogger::new(DummyLogger::default()));

        let config = storage.load_configuration().map_err(|err| {
            ConfigError::new(format!("unable to load client configuration: {}", err))
        })?;

        let mac = self
            .arrow_mac
            .map(Ok)
            .unwrap_or_else(get_first_mac)
            .map_err(|_| ConfigError::new("unable to get any network interface MAC address"))?;

        let rtsp_paths = utils::result_or_log(
            &mut logger,
            Severity::WARN,
            "unable to load RTSP paths",
            storage.load_rtsp_paths(),
        );

        let mjpeg_paths = utils::result_or_log(
            &mut logger,
            Severity::WARN,
            "unable to load MJPEG paths",
            storage.load_mjpeg_paths(),
        );

        let mut config = Config {
            version: config.version,
            uuid: config.uuid,
            passwd: config.passwd,
            arrow_mac: mac,
            arrow_svc_addr: arrow_service_address.to_string(),
            diagnostic_mode: self.diagnostic_mode,
            discovery: self.discovery,
            discovery_whitelist: Arc::new(self.discovery_whitelist),
            rtsp_paths: Arc::new(rtsp_paths.unwrap_or_default()),
            mjpeg_paths: Arc::new(mjpeg_paths.unwrap_or_default()),
            default_svc_table: config.svc_table.clone(),
            svc_table: config.svc_table,
            logger,
            storage: Box::new(storage),
        };

        if self.verbose {
            config.logger.set_level(Severity::DEBUG);
        }

        for svc in self.services {
            config.svc_table.add_static(svc.clone());
            config.default_svc_table.add_static(svc);
        }

        config.save().map_err(ConfigError::new)?;

        Ok(config)
    }
}

/// Type of the logger backend that should be used.
enum LoggerType {
    #[cfg(not(target_os = "windows"))]
    Syslog,

    Stderr,
    StderrPretty,
    FileLogger,
}

impl Default for LoggerType {
    #[cfg(not(target_os = "windows"))]
    fn default() -> Self {
        Self::Syslog
    }

    #[cfg(target_os = "windows")]
    fn default() -> Self {
        Self::Stderr
    }
}

/// Builder for application configuration.
struct ConfigParser {
    arrow_mac: Option<MacAddr>,
    arrow_svc_addr: String,
    ca_certificates: Vec<PathBuf>,
    services: Vec<Service>,
    logger_type: LoggerType,
    config_file: PathBuf,
    config_file_skel: PathBuf,
    identity_file: Option<PathBuf>,
    state_file: PathBuf,
    rtsp_paths_file: PathBuf,
    mjpeg_paths_file: PathBuf,
    log_file: PathBuf,
    discovery: bool,
    discovery_whitelist: Vec<String>,
    verbose: bool,
    diagnostic_mode: bool,
    log_file_size: usize,
    log_file_rotations: usize,
    lock_file: Option<PathBuf>,
}

impl ConfigParser {
    /// Create a new application configuration builder.
    fn new() -> Self {
        Self {
            arrow_mac: None,
            arrow_svc_addr: String::new(),
            ca_certificates: Vec::new(),
            services: Vec::new(),
            logger_type: LoggerType::default(),
            config_file: PathBuf::from(CONFIG_FILE),
            config_file_skel: PathBuf::from(CONFIG_FILE_SKELETON),
            identity_file: None,
            state_file: PathBuf::from(STATE_FILE),
            rtsp_paths_file: PathBuf::from(RTSP_PATHS_FILE),
            mjpeg_paths_file: PathBuf::from(MJPEG_PATHS_FILE),
            log_file: PathBuf::new(),
            discovery: false,
            discovery_whitelist: Vec::new(),
            verbose: false,
            diagnostic_mode: false,
            log_file_size: 10 * 1024,
            log_file_rotations: 1,
            lock_file: None,
        }
    }

    /// Create a new logger.
    fn create_logger(&self) -> Result<BoxLogger, ConfigError> {
        let logger = match self.logger_type {
            #[cfg(not(target_os = "windows"))]
            LoggerType::Syslog => BoxLogger::new(Syslog::new()),

            LoggerType::Stderr => BoxLogger::new(StderrLogger::new(false)),
            LoggerType::StderrPretty => BoxLogger::new(StderrLogger::new(true)),
            LoggerType::FileLogger => {
                FileLogger::new(&self.log_file, self.log_file_size, self.log_file_rotations)
                    .map(BoxLogger::new)
                    .map_err(|_| {
                        ConfigError::new(format!(
                            "unable to open the given log file: \"{}\"",
                            self.log_file.to_string_lossy()
                        ))
                    })?
            }
        };

        Ok(logger)
    }

    /// Build application configuration.
    fn build(self) -> Result<Config, ConfigError> {
        // because of the lock file, we need to create the storage builder before creating the
        // logger
        let mut storage_builder =
            DefaultStorage::builder(&self.config_file, self.lock_file.as_ref())
                .map_err(ConfigError::new)?;

        let logger = self.create_logger()?;

        storage_builder
            .logger(logger.clone())
            .config_skeleton_file(Some(self.config_file_skel))
            .connection_state_file(Some(self.state_file))
            .identity_file(self.identity_file)
            .rtsp_paths_file(Some(self.rtsp_paths_file))
            .mjpeg_paths_file(Some(self.mjpeg_paths_file))
            .ca_certificates(self.ca_certificates);

        let storage = storage_builder.build();

        let mut config_builder = Config::builder();

        config_builder
            .logger(logger)
            .mac_address(self.arrow_mac)
            .services(self.services)
            .diagnostic_mode(self.diagnostic_mode)
            .discovery(self.discovery)
            .discovery_whitelist(self.discovery_whitelist)
            .verbose(self.verbose);

        let config = config_builder.build(storage, self.arrow_svc_addr)?;

        Ok(config)
    }

    /// Parse given command line arguments.
    fn parse(mut self, mut args: Args) -> Result<Self, ConfigError> {
        // skip the application name
        args.next();

        self.arrow_service_address(&mut args)?;

        while let Some(ref arg) = args.next() {
            match arg as &str {
                "-c" => self.ca_certificates(&mut args)?,
                "-d" => self.discovery()?,
                "-D" => self.discovery_whitelist(&mut args)?,
                "-i" => self.interface(&mut args)?,
                "-r" => self.rtsp_service(&mut args)?,
                "-m" => self.mjpeg_service(&mut args)?,
                "-h" => self.http_service(&mut args)?,
                "-t" => self.tcp_service(&mut args)?,
                "-v" => self.verbose(),

                "--diagnostic-mode" => self.diagnostic_mode(),
                "--log-stderr" => self.log_stderr(),
                "--log-stderr-pretty" => self.log_stderr_pretty(),

                arg => {
                    if arg.starts_with("--config-file=") {
                        self.config_file(arg);
                    } else if arg.starts_with("--config-file-skel=") {
                        self.config_file_skel(arg);
                    } else if arg.starts_with("--conn-state-file=") {
                        self.conn_state_file(arg);
                    } else if arg.starts_with("--identity-file=") {
                        self.identity_file(arg);
                    } else if arg.starts_with("--rtsp-paths=") {
                        self.rtsp_paths(arg)?;
                    } else if arg.starts_with("--mjpeg-paths=") {
                        self.mjpeg_paths(arg)?;
                    } else if arg.starts_with("--log-file=") {
                        self.log_file(arg)?;
                    } else if arg.starts_with("--log-file-size=") {
                        self.log_file_size(arg)?;
                    } else if arg.starts_with("--log-file-rotations=") {
                        self.log_file_rotations(arg)?;
                    } else if arg.starts_with("--lock-file=") {
                        self.lock_file(arg)?
                    } else {
                        return Err(ConfigError::new(format!("unknown argument: \"{}\"", arg)));
                    }
                }
            }
        }

        Ok(self)
    }

    /// Process the Arrow Service address argument.
    fn arrow_service_address(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let addr = args
            .next()
            .ok_or_else(|| ConfigError::new("missing Angelcam Arrow Service address"))?;

        // add the default port number if the given address has no port
        if addr.ends_with(']') || !addr.contains(':') {
            self.arrow_svc_addr = format!("{}:{}", addr, DEFAULT_ARROW_SERVICE_PORT);
        } else {
            self.arrow_svc_addr = addr;
        }

        Ok(())
    }

    /// Process the CA certificate argument.
    fn ca_certificates(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let path = args
            .next()
            .ok_or_else(|| ConfigError::new("CA certificate path expected"))?;

        self.ca_certificates.push(path.into());

        Ok(())
    }

    /// Process the discovery argument.
    fn discovery(&mut self) -> Result<(), ConfigError> {
        if !cfg!(feature = "discovery") {
            return Err(ConfigError::new("unknown argument: \"-d\""));
        }

        self.discovery = true;

        Ok(())
    }

    /// Process the discovery argument.
    fn discovery_whitelist(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        if !cfg!(feature = "discovery") {
            return Err(ConfigError::new("unknown argument: \"-D\""));
        }

        let iface = args
            .next()
            .ok_or_else(|| ConfigError::new("network interface name expected"))?;

        self.discovery_whitelist.push(iface);
        self.discovery = true;

        Ok(())
    }

    /// Process the interface argument.
    fn interface(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let iface = args
            .next()
            .ok_or_else(|| ConfigError::new("network interface name expected"))?;

        self.arrow_mac = Some(get_mac(&iface)?);

        Ok(())
    }

    /// Process the RTSP service argument.
    fn rtsp_service(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let url = args
            .next()
            .ok_or_else(|| ConfigError::new("RTSP URL expected"))?;

        let service = parse_rtsp_url(&url)?;

        self.services.push(service);

        Ok(())
    }

    /// Process the MJPEG service argument.
    fn mjpeg_service(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let url = args
            .next()
            .ok_or_else(|| ConfigError::new("HTTP URL expected"))?;

        let service = parse_mjpeg_url(&url)?;

        self.services.push(service);

        Ok(())
    }

    /// Process the HTTP service argument.
    fn http_service(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let addr = args
            .next()
            .ok_or_else(|| ConfigError::new("TCP socket address expected"))?;

        let addr = net::utils::get_socket_address(addr.as_str())
            .map_err(|_| ConfigError::new(format!("unable to resolve socket address: {}", addr)))?;

        let mac = get_fake_mac(0xffff, &addr);

        self.services.push(Service::http(mac, addr));

        Ok(())
    }

    /// Process the TCP service argument.
    fn tcp_service(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let addr = args
            .next()
            .ok_or_else(|| ConfigError::new("TCP socket address expected"))?;

        let addr = net::utils::get_socket_address(addr.as_str())
            .map_err(|_| ConfigError::new(format!("unable to resolve socket address: {}", addr)))?;

        let mac = get_fake_mac(0xffff, &addr);

        self.services.push(Service::tcp(mac, addr));

        Ok(())
    }

    /// Process the verbose argument.
    fn verbose(&mut self) {
        self.verbose = true;
    }

    /// Process the diagnostic mode argument.
    fn diagnostic_mode(&mut self) {
        self.diagnostic_mode = true;
    }

    /// Process the log-stderr argument.
    fn log_stderr(&mut self) {
        self.logger_type = LoggerType::Stderr;
    }

    /// Process the log-stderr-pretty argument.
    fn log_stderr_pretty(&mut self) {
        self.logger_type = LoggerType::StderrPretty;
    }

    /// Process the log-file argument.
    fn log_file(&mut self, arg: &str) -> Result<(), ConfigError> {
        self.logger_type = LoggerType::FileLogger;

        // skip "--log-file=" length
        let log_file = &arg[11..];

        self.log_file = log_file.into();

        Ok(())
    }

    /// Process the log-file-size argument.
    fn log_file_size(&mut self, arg: &str) -> Result<(), ConfigError> {
        // skip "--log-file-size=" length
        let size = &arg[16..];

        self.log_file_size = size.parse().map_err(|_| {
            ConfigError::new(format!("invalid value given for {}, number expeced", arg))
        })?;

        Ok(())
    }

    /// Process the log-file-rotations argument.
    fn log_file_rotations(&mut self, arg: &str) -> Result<(), ConfigError> {
        // skip "--log-file-rotations=" length
        let rotations = &arg[21..];

        self.log_file_rotations = rotations.parse().map_err(|_| {
            ConfigError::new(format!("invalid value given for {}, number expeced", arg))
        })?;

        Ok(())
    }

    /// Process the config-file argument.
    fn config_file(&mut self, arg: &str) {
        // skip "--config-file=" length
        self.config_file = PathBuf::from(&arg[14..])
    }

    /// Process the config-file-skel argument.
    fn config_file_skel(&mut self, arg: &str) {
        // skip "--config-file-skel=" length
        self.config_file_skel = PathBuf::from(&arg[19..])
    }

    /// Process the identity-file argument.
    fn identity_file(&mut self, arg: &str) {
        // skip "--identity-file=" length
        self.identity_file = Some(PathBuf::from(&arg[16..]))
    }

    /// Process the conn-state-file argument.
    fn conn_state_file(&mut self, arg: &str) {
        // skip "--conn-state-file=" length
        self.state_file = PathBuf::from(&arg[18..])
    }

    /// Process the rtsp-paths argument.
    fn rtsp_paths(&mut self, arg: &str) -> Result<(), ConfigError> {
        if !cfg!(feature = "discovery") {
            return Err(ConfigError::new("unknown argument: \"--rtsp-paths\""));
        }

        // skip "--rtsp-paths=" length
        let rtsp_paths_file = &arg[13..];

        self.rtsp_paths_file = rtsp_paths_file.into();

        Ok(())
    }

    /// Process the mjpeg-paths argument.
    fn mjpeg_paths(&mut self, arg: &str) -> Result<(), ConfigError> {
        if !cfg!(feature = "discovery") {
            return Err(ConfigError::new("unknown argument: \"--mjpeg-paths\""));
        }

        // skip "--mjpeg-paths=" length
        let mjpeg_paths_file = &arg[14..];

        self.mjpeg_paths_file = mjpeg_paths_file.into();

        Ok(())
    }

    /// Process the lock-file argument.
    fn lock_file(&mut self, arg: &str) -> Result<(), ConfigError> {
        // skip "--lock-file=" length
        let lock_file = &arg[12..];

        self.lock_file = Some(lock_file.into());

        Ok(())
    }
}

/// Client identification that can be publicly available.
#[doc(hidden)]
pub struct PublicIdentity {
    uuid: Uuid,
}

impl ToJson for PublicIdentity {
    fn to_json(&self) -> JsonValue {
        object! {
            "uuid" => format!("{}", self.uuid.to_hyphenated_ref())
        }
    }
}

/// Persistent part of application configuration.
pub struct PersistentConfig {
    uuid: Uuid,
    passwd: Uuid,
    version: usize,
    svc_table: SharedServiceTable,
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
            svc_table: SharedServiceTable::new(),
        }
    }
}

impl Default for PersistentConfig {
    fn default() -> Self {
        Self {
            uuid: Uuid::new_v4(),
            passwd: Uuid::new_v4(),
            version: 0,
            svc_table: SharedServiceTable::new(),
        }
    }
}

impl ToJson for PersistentConfig {
    fn to_json(&self) -> JsonValue {
        object! {
            "uuid" => format!("{}", self.uuid.to_hyphenated_ref()),
            "passwd" => format!("{}", self.passwd.to_hyphenated_ref()),
            "version" => self.version,
            "svc_table" => self.svc_table.to_json()
        }
    }
}

impl FromJson for PersistentConfig {
    fn from_json(value: JsonValue) -> Result<Self, ParseError> {
        let mut config;

        if let JsonValue::Object(cfg) = value {
            config = cfg;
        } else {
            return Err(ParseError::new("JSON object expected"));
        }

        let svc_table = config
            .remove("svc_table")
            .ok_or_else(|| ParseError::new("missing field \"svc_table\""))?;

        let svc_table = SharedServiceTable::from_json(svc_table)
            .map_err(|err| ParseError::new(format!("unable to parse service table: {}", err)))?;

        let uuid = config
            .get("uuid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ParseError::new("missing field \"uuid\""))?;
        let passwd = config
            .get("passwd")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ParseError::new("missing field \"passwd\""))?;
        let version = config
            .get("version")
            .and_then(|v| v.as_usize())
            .ok_or_else(|| ParseError::new("missing field \"version\""))?;

        let uuid = Uuid::from_str(uuid).map_err(|_| ParseError::new("unable to parse UUID"))?;
        let passwd = Uuid::from_str(passwd).map_err(|_| ParseError::new("unable to parse UUID"))?;

        let res = Self {
            uuid,
            passwd,
            version,
            svc_table,
        };

        Ok(res)
    }
}

/// Arrow client configuration.
pub struct Config {
    version: usize,
    uuid: Uuid,
    passwd: Uuid,
    arrow_mac: MacAddr,
    arrow_svc_addr: String,
    diagnostic_mode: bool,
    discovery: bool,
    discovery_whitelist: Arc<HashSet<String>>,
    rtsp_paths: Arc<Vec<String>>,
    mjpeg_paths: Arc<Vec<String>>,
    svc_table: SharedServiceTable,
    default_svc_table: SharedServiceTable,
    logger: BoxLogger,
    storage: Box<dyn Storage + Send>,
}

impl Config {
    /// Get a new client configuration builder.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }

    /// Create a new application configuration. The methods reads all command line arguments and
    /// loads the configuration file.
    pub fn from_args(args: Args) -> Result<Self, ConfigError> {
        ConfigParser::new().parse(args)?.build()
    }

    /// Get address of the remote Arrow Service.
    #[doc(hidden)]
    pub fn get_arrow_service_address(&self) -> &str {
        &self.arrow_svc_addr
    }

    /// Get Arrow Client UUID.
    #[doc(hidden)]
    pub fn get_uuid(&self) -> Uuid {
        self.uuid
    }

    /// Get Arrow Client password.
    #[doc(hidden)]
    pub fn get_password(&self) -> Uuid {
        self.passwd
    }

    /// Get Arrow Client MAC address.
    #[doc(hidden)]
    pub fn get_mac_address(&self) -> MacAddr {
        self.arrow_mac
    }

    /// Get network discovery settings.
    #[doc(hidden)]
    pub fn get_discovery(&self) -> bool {
        self.discovery
    }

    /// Get network discovery whitelist.
    #[doc(hidden)]
    pub fn get_discovery_whitelist(&self) -> Arc<HashSet<String>> {
        self.discovery_whitelist.clone()
    }

    /// Check if the application is in the diagnostic mode.
    #[doc(hidden)]
    pub fn get_diagnostic_mode(&self) -> bool {
        self.diagnostic_mode
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

    /// Get logger.
    #[doc(hidden)]
    pub fn get_logger(&self) -> BoxLogger {
        self.logger.clone()
    }

    /// Get TLS connector for a given server hostname.
    #[doc(hidden)]
    pub fn get_tls_connector(&mut self) -> Result<TlsConnector, RuntimeError> {
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|err| {
            RuntimeError::new(format!(
                "unable to create a TLS connection builder: {}",
                err
            ))
        })?;

        let mut options = builder.options();

        options.insert(SslOptions::NO_COMPRESSION);
        options.insert(SslOptions::NO_SSLV2);
        options.insert(SslOptions::NO_SSLV3);
        options.insert(SslOptions::NO_TLSV1);
        options.insert(SslOptions::NO_TLSV1_1);

        builder.set_options(options);

        builder.set_verify(SslVerifyMode::PEER);
        builder
            .set_cipher_list(SSL_CIPHER_LIST)
            .map_err(|err| RuntimeError::new(format!("unable to set TLS cipher list: {}", err)))?;

        self.storage
            .load_ca_certificates(&mut builder)
            .map_err(RuntimeError::new)?;

        let connector = TlsConnector::from(builder.build());

        Ok(connector)
    }

    /// Get read-only reference to the shared service table.
    #[doc(hidden)]
    pub fn get_service_table(&self) -> SharedServiceTableRef {
        self.svc_table.get_ref()
    }

    /// Reset the service table.
    #[doc(hidden)]
    pub fn reset_service_table(&mut self) {
        self.svc_table = self.default_svc_table.clone();

        self.version += 1;

        if let Err(err) = self.save() {
            log_warn!(&mut self.logger, "{}", err);
        }
    }

    /// Update service table. Add all given services into the table and update active services.
    #[doc(hidden)]
    pub fn update_service_table<I>(&mut self, services: I)
    where
        I: IntoIterator<Item = Service>,
    {
        let old_version = self.svc_table.version();

        for svc in services {
            self.svc_table.add(svc);
        }

        self.svc_table.update_active_services();

        if old_version == self.svc_table.version() {
            return;
        }

        self.version += 1;

        if let Err(err) = self.save() {
            log_warn!(&mut self.logger, "{}", err);
        }
    }

    /// Update connection state.
    #[doc(hidden)]
    pub fn update_connection_state(&mut self, state: ConnectionState) {
        utils::result_or_log(
            &mut self.logger,
            Severity::DEBUG,
            "unable to save current connection state",
            self.storage.save_connection_state(state),
        );
    }

    /// Save the current configuration.
    fn save(&mut self) -> Result<(), io::Error> {
        let config = self.to_persistent_config();

        self.storage.save_configuration(&config).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("unable to save client configuration: {}", err),
            )
        })
    }

    /// Create persistent configuration.
    fn to_persistent_config(&self) -> PersistentConfig {
        PersistentConfig {
            uuid: self.uuid,
            passwd: self.passwd,
            version: self.version,
            svc_table: self.svc_table.clone(),
        }
    }
}

/// Get MAC address of the first configured ethernet device.
fn get_first_mac() -> Result<MacAddr, ConfigError> {
    EthernetDevice::list()
        .into_iter()
        .next()
        .map(|dev| dev.mac_addr)
        .ok_or_else(|| ConfigError::new("there is no configured ethernet device"))
}

/// Get MAC address of a given network interface.
fn get_mac(iface: &str) -> Result<MacAddr, ConfigError> {
    EthernetDevice::list()
        .into_iter()
        .find(|dev| dev.name == iface)
        .map(|dev| dev.mac_addr)
        .ok_or_else(|| ConfigError::new(format!("there is no such ethernet device: {}", iface)))
}

/// Generate a fake MAC address from a given prefix and socket address.
///
/// Note: It is used in case we do not know the device MAC address (e.g. for
/// services passed as command line arguments).
fn get_fake_mac(prefix: u16, addr: &SocketAddr) -> MacAddr {
    match &addr {
        SocketAddr::V4(ref addr) => get_fake_mac_from_ipv4(prefix, addr),
        SocketAddr::V6(ref addr) => get_fake_mac_from_ipv6(prefix, addr),
    }
}

fn get_fake_mac_from_ipv4(prefix: u16, addr: &SocketAddrV4) -> MacAddr {
    let a = ((prefix >> 8) & 0xff) as u8;
    let b = (prefix & 0xff) as u8;

    let addr = addr.ip();
    let octets = addr.octets();

    MacAddr::new(a, b, octets[0], octets[1], octets[2], octets[3])
}

fn get_fake_mac_from_ipv6(prefix: u16, addr: &SocketAddrV6) -> MacAddr {
    let addr = addr.ip();
    let segments = addr.segments();

    let e0 = ((prefix >> 8) & 0xff) as u8;
    let e1 = (prefix & 0xff) as u8;
    let e2 = ((segments[6] >> 8) & 0xff) as u8;
    let e3 = (segments[6] & 0xff) as u8;
    let e4 = ((segments[7] >> 8) & 0xff) as u8;
    let e5 = (segments[7] & 0xff) as u8;

    MacAddr::new(e0, e1, e2, e3, e4, e5)
}

/// Parse a given RTSP URL and return an RTSP service, a LockedRTSP service or an error.
fn parse_rtsp_url(url: &str) -> Result<Service, ConfigError> {
    let url = url
        .parse::<Url>()
        .map_err(|_| ConfigError::new(format!("invalid RTSP URL given: {}", url)))?;

    let scheme = url.scheme();

    if !scheme.eq_ignore_ascii_case("rtsp") {
        return Err(ConfigError::new(format!("invalid RTSP URL given: {}", url)));
    }

    let host = url.host();
    let port = url.port().unwrap_or(554);

    let socket_addr = net::utils::get_socket_address((host, port)).map_err(|_| {
        ConfigError::new(format!(
            "unable to resolve RTSP service address: {}:{}",
            host, port
        ))
    })?;

    let mac = get_fake_mac(0xffff, &socket_addr);

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
fn parse_mjpeg_url(url: &str) -> Result<Service, ConfigError> {
    let url = url
        .parse::<Url>()
        .map_err(|_| ConfigError::new(format!("invalid HTTP URL given: {}", url)))?;

    let scheme = url.scheme();

    if !scheme.eq_ignore_ascii_case("http") {
        return Err(ConfigError::new(format!("invalid HTTP URL given: {}", url)));
    }

    let host = url.host();
    let port = url.port().unwrap_or(80);

    let socket_addr = net::utils::get_socket_address((host, port)).map_err(|_| {
        ConfigError::new(format!(
            "unable to resolve HTTP service address: {}:{}",
            host, port
        ))
    })?;

    let mac = get_fake_mac(0xffff, &socket_addr);

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
    println!("USAGE: arrow-client arr-host[:arr-port] [OPTIONS]\n");
    println!("    arr-host  Angelcam Arrow Service host");
    println!("    arr-port  Angelcam Arrow Service port\n");
    println!("OPTIONS:\n");
    println!("    -i iface  ethernet interface used for client identification (the first");
    println!("              configured network interface is used by default)");
    println!("    -c path   path to a CA certificate for Arrow Service identity verification;");
    println!("              in case the path is a directory, it's scanned recursively for");
    println!("              all files with the following extensions:\n");
    println!("              .der");
    println!("              .cer");
    println!("              .crr");
    println!("              .pem\n");
    if cfg!(feature = "discovery") {
        println!("    -d        automatic service discovery");
        println!("    -D iface  limit automatic service discovery only on a given network");
        println!("              interface (implies -d; can be used multiple times)");
    }
    println!("    -r URL    add a given RTSP service");
    println!("    -m URL    add a given MJPEG service");
    println!("    -h addr   add a given HTTP service (addr must be in the \"host:port\"");
    println!("              format)");
    println!("    -t addr   add a given TCP service (addr must be in the \"host:port\"");
    println!("              format)");
    println!("    -v        enable debug logs\n");
    println!("    --config-file=path  alternative path to the client configuration file");
    println!("                        (default value: /etc/arrow/config.json)");
    println!("    --config-file-skel=path  the client will use this file as a backup for");
    println!("                        its credentials (default value:");
    println!("                        /etc/arrow/config-skel.json)");
    println!("    --identity-file=path  a file that will contain only the public part of");
    println!("                        the client identification (i.e. there will be no");
    println!("                        secret in the file)");
    println!("    --conn-state-file=path  alternative path to the client connection state");
    println!("                        file (default value: /var/lib/arrow/state)");
    println!("    --diagnostic-mode   start the client in diagnostic mode (i.e. the client");
    println!("                        will try to connect to a given Arrow Service and it");
    println!("                        will report success as its exit code; note: the");
    println!("                        \"access denied\" response from the server is also");
    println!("                        considered as a success)");
    println!("    --log-stderr        send log messages into stderr instead of syslog");
    println!("    --log-stderr-pretty  send log messages into stderr instead of syslog and");
    println!("                        use colored messages");
    println!("    --log-file=path     send log messages into a given file instead of syslog");
    println!("    --log-file-size=n   size limit for the log file (in bytes; default value:");
    println!("                        10240)");
    println!("    --log-file-rotations=n  number of backup files (i.e. rotations) for the");
    println!("                        log file (default value: 1)");
    if cfg!(feature = "discovery") {
        println!("    --rtsp-paths=path   alternative path to a file containing list of RTSP");
        println!("                        paths used on service discovery (default value:");
        println!("                        /etc/arrow/rtsp-paths)");
        println!("    --mjpeg-paths=path  alternative path to a file containing list of MJPEG");
        println!("                        paths used on service discovery (default value:");
        println!("                        /etc/arrow/mjpeg-paths)");
    }
    println!("    --lock-file=path    make sure that there is only one instance of the");
    println!("                        process running; the file will contain also PID of the");
    println!("                        process");
    println!();

    process::exit(exit_code);
}
