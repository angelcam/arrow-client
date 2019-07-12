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
use std::process;
use std::str;

use std::env::Args;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::Path;
use std::str::FromStr;

use fs2::FileExt;

use json;

use json::JsonValue;

use openssl::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslOptions, SslVerifyMode};

use uuid::Uuid;

use crate::net;
use crate::utils;
use crate::utils::logger;

use crate::net::raw::devices::EthernetDevice;
use crate::net::raw::ether::MacAddr;
use crate::net::tls::TlsConnector;
use crate::net::url::Url;
use crate::svc_table::{Service, SharedServiceTable, SharedServiceTableRef};
use crate::utils::json::{FromJson, ParseError, ToJson};
use crate::utils::logger::{BoxLogger, Logger, Severity};
use crate::utils::RuntimeError;

/*const EXIT_CODE_USAGE:         i32 = 1;
const EXIT_CODE_NETWORK_ERROR: i32 = 2;
const EXIT_CODE_CONFIG_ERROR:  i32 = 3;
const EXIT_CODE_SSL_ERROR:     i32 = 4;
const EXIT_CODE_CERT_ERROR:    i32 = 5;*/

/// Arrow Client configuration file.
const CONFIG_FILE: &'static str = "/etc/arrow/config.json";

/// Arrow Client configuration file skeleton.
const CONFIG_FILE_SKELETON: &'static str = "/etc/arrow/config-skel.json";

/// Arrow Client connection state file.
const STATE_FILE: &'static str = "/var/lib/arrow/state";

/// A file containing RTSP paths tested on service discovery (one path per
/// line).
const RTSP_PATHS_FILE: &'static str = "/etc/arrow/rtsp-paths";

/// A file containing MJPEG paths tested on service discovery (one path per
/// line).
const MJPEG_PATHS_FILE: &'static str = "/etc/arrow/mjpeg-paths";

/// Default port number for connecting to an Arrow Service.
const DEFAULT_ARROW_SERVICE_PORT: u16 = 8900;

/// List of cipher that can be used for TLS connections to Arrow services.
const SSL_CIPHER_LIST: &'static str = "HIGH:!aNULL:!kRSA:!PSK:!MD5:!RC4";

/// Arrow configuration loading/parsing/saving error.
#[derive(Debug, Clone)]
pub struct ConfigError {
    msg: String,
}

impl Error for ConfigError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str(self.description())
    }
}

impl From<String> for ConfigError {
    fn from(msg: String) -> ConfigError {
        ConfigError { msg: msg }
    }
}

impl<'a> From<&'a str> for ConfigError {
    fn from(msg: &'a str) -> ConfigError {
        ConfigError::from(msg.to_string())
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> ConfigError {
        ConfigError::from(format!("{}", err))
    }
}

impl From<utils::json::ParseError> for ConfigError {
    fn from(err: utils::json::ParseError) -> ConfigError {
        ConfigError::from(format!("{}", err))
    }
}

impl From<std::net::AddrParseError> for ConfigError {
    fn from(err: std::net::AddrParseError) -> ConfigError {
        ConfigError::from(format!("{}", err))
    }
}

impl From<net::raw::ether::AddrParseError> for ConfigError {
    fn from(err: net::raw::ether::AddrParseError) -> ConfigError {
        ConfigError::from(format!("{}", err))
    }
}

/// Type of the logger backend that should be used.
enum LoggerType {
    Syslog,
    Stderr,
    StderrPretty,
    FileLogger,
}

/// Builder for application configuration.
struct ApplicationConfigBuilder {
    arrow_mac: MacAddr,
    arrow_svc_addr: String,
    ca_certificates: Vec<String>,
    services: Vec<Service>,
    logger_type: LoggerType,
    config_file: String,
    config_file_skel: String,
    identity_file: Option<String>,
    state_file: String,
    rtsp_paths_file: String,
    mjpeg_paths_file: String,
    log_file: String,
    discovery: bool,
    verbose: bool,
    diagnostic_mode: bool,
    log_file_size: usize,
    log_file_rotations: usize,
    lock_file: Option<String>,
}

impl ApplicationConfigBuilder {
    /// Create a new application configuration builder.
    fn new() -> Result<ApplicationConfigBuilder, ConfigError> {
        let default_mac_addr = get_first_mac()
            .map_err(|_| ConfigError::from("unable to get any network interface MAC address"))?;

        let builder = ApplicationConfigBuilder {
            arrow_mac: default_mac_addr,
            arrow_svc_addr: String::new(),
            ca_certificates: Vec::new(),
            services: Vec::new(),
            logger_type: LoggerType::Syslog,
            config_file: CONFIG_FILE.to_string(),
            config_file_skel: CONFIG_FILE_SKELETON.to_string(),
            identity_file: None,
            state_file: STATE_FILE.to_string(),
            rtsp_paths_file: RTSP_PATHS_FILE.to_string(),
            mjpeg_paths_file: MJPEG_PATHS_FILE.to_string(),
            log_file: String::new(),
            discovery: false,
            verbose: false,
            diagnostic_mode: false,
            log_file_size: 10 * 1024,
            log_file_rotations: 1,
            lock_file: None,
        };

        Ok(builder)
    }

    /// Create a lock file (if specified).
    fn create_lock_file(&self) -> Result<Option<File>, ConfigError> {
        self.lock_file
            .as_ref()
            .map(|lock_file| {
                File::create(lock_file)
                    .and_then(|mut lock_file| {
                        lock_file.try_lock_exclusive()?;
                        lock_file.write_fmt(format_args!("{}\n", process::id()))?;
                        lock_file.flush()?;
                        lock_file.sync_all()?;

                        Ok(lock_file)
                    })
                    .map_err(|_| {
                        ConfigError::from(format!(
                            "unable to acquire an exclusive lock on \"{}\"",
                            lock_file
                        ))
                    })
            })
            .transpose()
    }

    /// Create a new logger.
    fn create_logger(&self) -> Result<BoxLogger, ConfigError> {
        let logger = match self.logger_type {
            LoggerType::Syslog => BoxLogger::new(logger::syslog::new()),
            LoggerType::Stderr => BoxLogger::new(logger::stderr::new()),
            LoggerType::StderrPretty => BoxLogger::new(logger::stderr::new_pretty()),
            LoggerType::FileLogger => {
                logger::file::new(&self.log_file, self.log_file_size, self.log_file_rotations)
                    .map(|logger| BoxLogger::new(logger))
                    .map_err(|_| {
                        ConfigError::from(format!(
                            "unable to open the given log file: \"{}\"",
                            self.log_file
                        ))
                    })?
            }
        };

        Ok(logger)
    }

    /// Build application configuration.
    fn build(self) -> Result<ApplicationConfig, ConfigError> {
        let lock_file = self.create_lock_file()?;

        let mut logger = self.create_logger()?;

        // read config skeleton
        let config_skeleton = utils::result_or_log(
            &mut logger,
            Severity::WARN,
            format!(
                "unable to read configuration file skeleton\"{}\"",
                self.config_file_skel
            ),
            PersistentConfig::load(&self.config_file_skel),
        );

        // read config
        let config = utils::result_or_log(
            &mut logger,
            Severity::WARN,
            format!("unable to read configuration file \"{}\"", self.config_file),
            PersistentConfig::load(&self.config_file),
        );

        let config_skeleton_exists = config_skeleton.is_some();

        // get the persistent config, if there is no config, use the skeleton,
        // if there is no skeleton, create a new config
        let config = config
            .or(config_skeleton)
            .unwrap_or(PersistentConfig::new());

        // if there is no skeleton, create one from the config
        if !config_skeleton_exists {
            let config_skeleton = config.to_skeleton();

            log_info!(
                &mut logger,
                "creating configuration file skeleton \"{}\"",
                self.config_file_skel
            );

            utils::result_or_log(
                &mut logger,
                Severity::WARN,
                format!(
                    "unable to create configuration file skeleton \"{}\"",
                    self.config_file_skel
                ),
                config_skeleton.save(&self.config_file_skel),
            );
        }

        // create identity file
        if let Some(identity_file) = self.identity_file {
            let identity = config.to_identity();

            utils::result_or_log(
                &mut logger,
                Severity::WARN,
                format!("unable to create identity file \"{}\"", identity_file),
                identity.save(&identity_file),
            );
        }

        let mut config = ApplicationConfig {
            version: config.version,
            uuid: config.uuid,
            passwd: config.passwd,
            arrow_mac: self.arrow_mac,
            arrow_svc_addr: self.arrow_svc_addr,
            ca_certificates: self.ca_certificates,
            config_file: self.config_file,
            state_file: self.state_file,
            rtsp_paths_file: self.rtsp_paths_file,
            mjpeg_paths_file: self.mjpeg_paths_file,
            diagnostic_mode: self.diagnostic_mode,
            discovery: self.discovery,
            default_svc_table: config.svc_table.clone(),
            svc_table: config.svc_table,
            logger: logger,
            _lock_file: lock_file,
        };

        if self.verbose {
            config.logger.set_level(Severity::DEBUG);
        }

        for svc in self.services {
            config.svc_table.add_static(svc.clone());
            config.default_svc_table.add_static(svc);
        }

        config.save().map_err(|_| {
            ConfigError::from(format!(
                "unable to save configuration file \"{}\"",
                &config.config_file
            ))
        })?;

        Ok(config)
    }

    /// Parse given command line arguments.
    fn parse(mut self, mut args: Args) -> Result<ApplicationConfigBuilder, ConfigError> {
        // skip the application name
        args.next();

        self.arrow_service_address(&mut args)?;

        while let Some(ref arg) = args.next() {
            match arg as &str {
                "-c" => self.ca_certificates(&mut args)?,
                "-d" => self.discovery()?,
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
                        return Err(ConfigError::from(format!("unknown argument: \"{}\"", arg)));
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
            .ok_or(ConfigError::from("missing Angelcam Arrow Service address"))?;

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
            .ok_or(ConfigError::from("CA certificate path expected"))?;

        self.ca_certificates.push(path);

        Ok(())
    }

    /// Process the discovery argument.
    fn discovery(&mut self) -> Result<(), ConfigError> {
        if !cfg!(feature = "discovery") {
            return Err(ConfigError::from("unknown argument: \"-d\""));
        }

        self.discovery = true;

        Ok(())
    }

    /// Process the interface argument.
    fn interface(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let iface = args
            .next()
            .ok_or(ConfigError::from("network interface name expected"))?;

        self.arrow_mac = get_mac(&iface)?;

        Ok(())
    }

    /// Process the RTSP service argument.
    fn rtsp_service(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let url = args.next().ok_or(ConfigError::from("RTSP URL expected"))?;

        let service = parse_rtsp_url(&url)?;

        self.services.push(service);

        Ok(())
    }

    /// Process the MJPEG service argument.
    fn mjpeg_service(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let url = args.next().ok_or(ConfigError::from("HTTP URL expected"))?;

        let service = parse_mjpeg_url(&url)?;

        self.services.push(service);

        Ok(())
    }

    /// Process the HTTP service argument.
    fn http_service(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let addr = args
            .next()
            .ok_or(ConfigError::from("TCP socket address expected"))?;

        let addr = net::utils::get_socket_address(addr.as_str()).map_err(|_| {
            ConfigError::from(format!("unable to resolve socket address: {}", addr))
        })?;

        let mac = get_fake_mac(0xffff, &addr);

        self.services.push(Service::http(mac, addr));

        Ok(())
    }

    /// Process the TCP service argument.
    fn tcp_service(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let addr = args
            .next()
            .ok_or(ConfigError::from("TCP socket address expected"))?;

        let addr = net::utils::get_socket_address(addr.as_str()).map_err(|_| {
            ConfigError::from(format!("unable to resolve socket address: {}", addr))
        })?;

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

        self.log_file = log_file.to_string();

        Ok(())
    }

    /// Process the log-file-size argument.
    fn log_file_size(&mut self, arg: &str) -> Result<(), ConfigError> {
        // skip "--log-file-size=" length
        let size = &arg[16..];

        self.log_file_size = size.parse().map_err(|_| {
            ConfigError::from(format!("invalid value given for {}, number expeced", arg))
        })?;

        Ok(())
    }

    /// Process the log-file-rotations argument.
    fn log_file_rotations(&mut self, arg: &str) -> Result<(), ConfigError> {
        // skip "--log-file-rotations=" length
        let rotations = &arg[21..];

        self.log_file_rotations = rotations.parse().map_err(|_| {
            ConfigError::from(format!("invalid value given for {}, number expeced", arg))
        })?;

        Ok(())
    }

    /// Process the config-file argument.
    fn config_file(&mut self, arg: &str) {
        // skip "--config-file=" length
        self.config_file = arg[14..].to_string()
    }

    /// Process the config-file-skel argument.
    fn config_file_skel(&mut self, arg: &str) {
        // skip "--config-file-skel=" length
        self.config_file_skel = arg[19..].to_string()
    }

    /// Process the identity-file argument.
    fn identity_file(&mut self, arg: &str) {
        // skip "--identity-file=" length
        self.identity_file = Some(arg[16..].to_string())
    }

    /// Process the conn-state-file argument.
    fn conn_state_file(&mut self, arg: &str) {
        // skip "--conn-state-file=" length
        self.state_file = arg[18..].to_string()
    }

    /// Process the rtsp-paths argument.
    fn rtsp_paths(&mut self, arg: &str) -> Result<(), ConfigError> {
        if !cfg!(feature = "discovery") {
            return Err(ConfigError::from("unknown argument: \"--rtsp-paths\""));
        }

        // skip "--rtsp-paths=" length
        let rtsp_paths_file = &arg[13..];

        self.rtsp_paths_file = rtsp_paths_file.to_string();

        Ok(())
    }

    /// Process the mjpeg-paths argument.
    fn mjpeg_paths(&mut self, arg: &str) -> Result<(), ConfigError> {
        if !cfg!(feature = "discovery") {
            return Err(ConfigError::from("unknown argument: \"--mjpeg-paths\""));
        }

        // skip "--mjpeg-paths=" length
        let mjpeg_paths_file = &arg[14..];

        self.mjpeg_paths_file = mjpeg_paths_file.to_string();

        Ok(())
    }

    /// Process the lock-file argument.
    fn lock_file(&mut self, arg: &str) -> Result<(), ConfigError> {
        // skip "--lock-file=" length
        let lock_file = &arg[12..];

        self.lock_file = Some(lock_file.to_string());

        Ok(())
    }
}

/// Client identification that can be publicly available.
struct PublicIdentity {
    uuid: Uuid,
}

impl PublicIdentity {
    /// Save identity into a given file.
    fn save(&self, path: &str) -> Result<(), ConfigError> {
        let mut file = File::create(path)?;

        self.to_json().write(&mut file)?;

        Ok(())
    }
}

impl ToJson for PublicIdentity {
    fn to_json(&self) -> JsonValue {
        object! {
            "uuid" => format!("{}", self.uuid.to_hyphenated_ref())
        }
    }
}

/// Persistent part of application configuration.
struct PersistentConfig {
    uuid: Uuid,
    passwd: Uuid,
    version: usize,
    svc_table: SharedServiceTable,
}

impl PersistentConfig {
    /// Create a new instance of persistent configuration.
    fn new() -> PersistentConfig {
        PersistentConfig {
            uuid: Uuid::new_v4(),
            passwd: Uuid::new_v4(),
            version: 0,
            svc_table: SharedServiceTable::new(),
        }
    }

    /// Load configuration from a given file.
    fn load(path: &str) -> Result<PersistentConfig, ConfigError> {
        let mut file = File::open(path)?;
        let mut data = String::new();

        file.read_to_string(&mut data)?;

        let object = json::parse(&data).map_err(|err| {
            utils::json::ParseError::from(format!("unable to parse configuration: {}", err))
        })?;

        let config = PersistentConfig::from_json(object)?;

        Ok(config)
    }

    /// Get client public identity.
    fn to_identity(&self) -> PublicIdentity {
        PublicIdentity { uuid: self.uuid }
    }

    /// Create a configuration skeleton from this persistent config.
    fn to_skeleton(&self) -> PersistentConfig {
        PersistentConfig {
            uuid: self.uuid.clone(),
            passwd: self.passwd.clone(),
            version: 0,
            svc_table: SharedServiceTable::new(),
        }
    }

    /// Save configuration into a given file.
    fn save(&self, path: &str) -> Result<(), ConfigError> {
        let mut file = File::create(path)?;

        self.to_json().write(&mut file)?;

        Ok(())
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
            return Err(ParseError::from("JSON object expected"));
        }

        let svc_table = config
            .remove("svc_table")
            .ok_or(ParseError::from("missing field \"svc_table\""))?;

        let svc_table = SharedServiceTable::from_json(svc_table)
            .map_err(|err| ParseError::from(format!("unable to parse service table: {}", err)))?;

        let uuid = config
            .get("uuid")
            .and_then(|v| v.as_str())
            .ok_or(ParseError::from("missing field \"uuid\""))?;
        let passwd = config
            .get("passwd")
            .and_then(|v| v.as_str())
            .ok_or(ParseError::from("missing field \"passwd\""))?;
        let version = config
            .get("version")
            .and_then(|v| v.as_usize())
            .ok_or(ParseError::from("missing field \"version\""))?;

        let uuid = Uuid::from_str(uuid).map_err(|_| ParseError::from("unable to parse UUID"))?;
        let passwd =
            Uuid::from_str(passwd).map_err(|_| ParseError::from("unable to parse UUID"))?;

        let res = PersistentConfig {
            uuid: uuid,
            passwd: passwd,
            version: version,
            svc_table: svc_table,
        };

        Ok(res)
    }
}

/// Struct holding application configuration loaded from a configuration file and passed as
/// command line arguments.
pub struct ApplicationConfig {
    version: usize,
    uuid: Uuid,
    passwd: Uuid,
    arrow_mac: MacAddr,
    arrow_svc_addr: String,
    ca_certificates: Vec<String>,
    config_file: String,
    state_file: String,
    rtsp_paths_file: String,
    mjpeg_paths_file: String,
    diagnostic_mode: bool,
    discovery: bool,
    svc_table: SharedServiceTable,
    default_svc_table: SharedServiceTable,
    logger: BoxLogger,
    _lock_file: Option<File>,
}

impl ApplicationConfig {
    /// Create a new application configuration. The methods reads all command line arguments and
    /// loads the configuration file.
    pub fn create() -> Result<ApplicationConfig, ConfigError> {
        ApplicationConfigBuilder::new()?
            .parse(std::env::args())?
            .build()
    }

    /// Get address of the remote Arrow Service.
    pub fn get_arrow_service_address(&self) -> &str {
        &self.arrow_svc_addr
    }

    /// Get Arrow Client UUID.
    pub fn get_uuid(&self) -> Uuid {
        self.uuid
    }

    /// Get Arrow Client password.
    pub fn get_password(&self) -> Uuid {
        self.passwd
    }

    /// Get Arrow Client MAC address.
    pub fn get_mac_address(&self) -> MacAddr {
        self.arrow_mac
    }

    /// Get network discovery settings.
    pub fn get_discovery(&self) -> bool {
        self.discovery
    }

    /// Check if the application is in the diagnostic mode.
    pub fn get_diagnostic_mode(&self) -> bool {
        self.diagnostic_mode
    }

    /// Get connection state file.
    pub fn get_connection_state_file(&self) -> &str {
        &self.state_file
    }

    /// Get path to a file containing RTSP paths for the network scanner.
    pub fn get_rtsp_paths_file(&self) -> &str {
        &self.rtsp_paths_file
    }

    /// Get path to a file containing MJPEG paths for the network scanner.
    pub fn get_mjpeg_paths_file(&self) -> &str {
        &self.mjpeg_paths_file
    }

    /// Get logger.
    pub fn get_logger(&self) -> BoxLogger {
        self.logger.clone()
    }

    /// Get TLS connector for a given server hostname.
    pub fn get_tls_connector(&self) -> Result<TlsConnector, RuntimeError> {
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|err| {
            RuntimeError::from(format!(
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
            .map_err(|err| RuntimeError::from(format!("unable to set TLS cipher list: {}", err)))?;

        for ca_cert in &self.ca_certificates {
            builder.load_ca_certificates(&ca_cert)?;
        }

        let connector = TlsConnector::from(builder.build());

        Ok(connector)
    }

    /// Get read-only reference to the shared service table.
    pub fn get_service_table(&self) -> SharedServiceTableRef {
        self.svc_table.get_ref()
    }

    /// Reset the service table.
    pub fn reset_service_table(&mut self) {
        self.svc_table = self.default_svc_table.clone();

        self.version += 1;

        let res = self.save();

        utils::result_or_log(
            &mut self.logger,
            Severity::WARN,
            format!("unable to save config file \"{}\"", self.config_file),
            res,
        );
    }

    /// Update service table. Add all given services into the table and update active services.
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

        let res = self.save();

        utils::result_or_log(
            &mut self.logger,
            Severity::WARN,
            format!("unable to save config file \"{}\"", self.config_file),
            res,
        );
    }

    /// Save the current configuration into the configuration file.
    fn save(&self) -> Result<(), ConfigError> {
        self.to_persistent_config().save(&self.config_file)
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
        .ok_or(ConfigError::from("there is no configured ethernet device"))
}

/// Get MAC address of a given network interface.
fn get_mac(iface: &str) -> Result<MacAddr, ConfigError> {
    EthernetDevice::list()
        .into_iter()
        .find(|dev| dev.name == iface)
        .map(|dev| dev.mac_addr)
        .ok_or(ConfigError::from(format!(
            "there is no such ethernet device: {}",
            iface
        )))
}

/// Simple extension to the SslContextBuilder.
trait SslConnectorBuilderExt {
    /// Load all CA certificates from a given path.
    fn load_ca_certificates<P: AsRef<Path>>(&mut self, path: P) -> Result<(), RuntimeError>;
}

impl SslConnectorBuilderExt for SslConnectorBuilder {
    fn load_ca_certificates<P: AsRef<Path>>(&mut self, path: P) -> Result<(), RuntimeError> {
        let path = path.as_ref();

        if path.is_dir() {
            let dir = path
                .read_dir()
                .map_err(|err| RuntimeError::from(format!("{}", err)))?;

            for entry in dir {
                let path = entry
                    .map_err(|err| RuntimeError::from(format!("{}", err)))?
                    .path();

                self.load_ca_certificates(&path)?;
            }
        } else if is_cert_file(&path) {
            self.set_ca_file(&path)
                .map_err(|err| RuntimeError::from(format!("{}", err)))?;
        }

        Ok(())
    }
}

/// Check if a given file is a certificate file.
fn is_cert_file<P: AsRef<Path>>(path: P) -> bool {
    let path = path.as_ref();

    if let Some(ext) = path.extension() {
        let ext = ext.to_string_lossy();

        match &ext.to_ascii_lowercase() as &str {
            "der" => true,
            "cer" => true,
            "crt" => true,
            "pem" => true,
            _ => false,
        }
    } else {
        false
    }
}

/// Generate a fake MAC address from a given prefix and socket address.
///
/// Note: It is used in case we do not know the device MAC address (e.g. for
/// services passed as command line arguments).
fn get_fake_mac(prefix: u16, addr: &SocketAddr) -> MacAddr {
    match addr {
        &SocketAddr::V4(ref addr) => get_fake_mac_from_ipv4(prefix, addr),
        &SocketAddr::V6(ref addr) => get_fake_mac_from_ipv6(prefix, addr),
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

    let a = ((prefix >> 8) & 0xff) as u8;
    let b = (prefix & 0xff) as u8;
    let c = ((segments[6] >> 8) & 0xff) as u8;
    let d = (segments[6] & 0xff) as u8;
    let e = ((segments[7] >> 8) & 0xff) as u8;
    let f = (segments[7] & 0xff) as u8;

    MacAddr::new(a, b, c, d, e, f)
}

/// Parse a given RTSP URL and return an RTSP service, a LockedRTSP service or an error.
fn parse_rtsp_url(url: &str) -> Result<Service, ConfigError> {
    let url = url
        .parse::<Url>()
        .map_err(|_| ConfigError::from(format!("invalid RTSP URL given: {}", url)))?;

    let scheme = url.scheme();

    if !scheme.eq_ignore_ascii_case("rtsp") {
        return Err(ConfigError::from(format!(
            "invalid RTSP URL given: {}",
            url
        )));
    }

    let host = url.host();
    let port = url.port().unwrap_or(554);

    let socket_addr = net::utils::get_socket_address((host, port)).map_err(|_| {
        ConfigError::from(format!(
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
        .map_err(|_| ConfigError::from(format!("invalid HTTP URL given: {}", url)))?;

    let scheme = url.scheme();

    if !scheme.eq_ignore_ascii_case("http") {
        return Err(ConfigError::from(format!(
            "invalid HTTP URL given: {}",
            url
        )));
    }

    let host = url.host();
    let port = url.port().unwrap_or(80);

    let socket_addr = net::utils::get_socket_address((host, port)).map_err(|_| {
        ConfigError::from(format!(
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
