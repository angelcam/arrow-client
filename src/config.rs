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

use std::env::Args;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::Path;
use std::str::FromStr;

use net;

use net::arrow::proto::Service;
use net::raw::ether::MacAddr;
use net::raw::devices::EthernetDevice;

use svc_table::{SharedServiceTable, SharedServiceTableRef};

use utils;

use utils::RuntimeError;

use utils::logger;

use utils::logger::{BoxedLogger, Logger, Severity};

use native_tls::{Protocol, TlsConnector};
use native_tls::backend::openssl::TlsConnectorBuilderExt;

use openssl::ssl::{
    SSL_OP_NO_COMPRESSION,

    SslContextBuilder,
};

use regex::Regex;

use serde_json;

use uuid::Uuid;

/*const EXIT_CODE_USAGE:         i32 = 1;
const EXIT_CODE_NETWORK_ERROR: i32 = 2;
const EXIT_CODE_CONFIG_ERROR:  i32 = 3;
const EXIT_CODE_SSL_ERROR:     i32 = 4;
const EXIT_CODE_CERT_ERROR:    i32 = 5;*/

/// Arrow Client configuration file.
const CONFIG_FILE: &'static str = "/etc/arrow/config.json";

/// Arrow Client connection state file.
const STATE_FILE: &'static str = "/var/lib/arrow/state";

/// A file containing RTSP paths tested on service discovery (one path per
/// line).
const RTSP_PATHS_FILE: &'static str = "/etc/arrow/rtsp-paths";

/// A file containing MJPEG paths tested on service discovery (one path per
/// line).
const MJPEG_PATHS_FILE: &'static str = "/etc/arrow/mjpeg-paths";


/// List of TLS protocols that can be used for connections to Arrow services.
const SSL_METHODS: &'static [Protocol] = &[
    Protocol::Tlsv12
];

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

impl From<serde_json::Error> for ConfigError {
    fn from(err: serde_json::Error) -> ConfigError {
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
    arrow_mac:          MacAddr,
    arrow_svc_addr:     String,
    ca_certificates:    Vec<String>,
    services:           Vec<Service>,
    logger_type:        LoggerType,
    config_file:        String,
    state_file:         String,
    rtsp_paths_file:    String,
    mjpeg_paths_file:   String,
    log_file:           String,
    discovery:          bool,
    verbose:            bool,
    diagnostic_mode:    bool,
    log_file_size:      usize,
    log_file_rotations: usize,
}

impl ApplicationConfigBuilder {
    /// Create a new application configuration builder.
    fn new() -> Result<ApplicationConfigBuilder, ConfigError> {
        let default_mac_addr = get_first_mac()
            .map_err(|_| ConfigError::from("unable to get any network interface MAC address"))?;

        let builder = ApplicationConfigBuilder {
            arrow_mac:          default_mac_addr,
            arrow_svc_addr:     String::new(),
            ca_certificates:    Vec::new(),
            services:           Vec::new(),
            logger_type:        LoggerType::Syslog,
            config_file:        CONFIG_FILE.to_string(),
            state_file:         STATE_FILE.to_string(),
            rtsp_paths_file:    RTSP_PATHS_FILE.to_string(),
            mjpeg_paths_file:   MJPEG_PATHS_FILE.to_string(),
            log_file:           String::new(),
            discovery:          false,
            verbose:            false,
            diagnostic_mode:    false,
            log_file_size:      10 * 1024,
            log_file_rotations: 1,
        };

        Ok(builder)
    }

    /// Build application configuration.
    fn build(self) -> Result<ApplicationConfig, ConfigError> {
        let mut logger = match self.logger_type {
            LoggerType::Syslog       => BoxedLogger::new(logger::syslog::new()),
            LoggerType::Stderr       => BoxedLogger::new(logger::stderr::new()),
            LoggerType::StderrPretty => BoxedLogger::new(logger::stderr::new_pretty()),
            LoggerType::FileLogger   => BoxedLogger::new(
                logger::file::new(
                        &self.log_file,
                        self.log_file_size,
                        self.log_file_rotations)
                    .map_err(|_| ConfigError::from(
                        format!("unable to open the given log file: \"{}\"", self.log_file)
                    ))?
            ),
        };

        let config = utils::result_or_log(
                &mut logger,
                Severity::WARN,
                format!("unable to read config file \"{}\", creating a new one", self.config_file),
                PersistentConfig::load(&self.config_file))
            .unwrap_or(PersistentConfig::new());

        let mut config = ApplicationConfig {
            version:           config.version,
            uuid:              config.uuid,
            passwd:            config.passwd,
            arrow_mac:         self.arrow_mac,
            arrow_svc_addr:    self.arrow_svc_addr,
            ca_certificates:   self.ca_certificates,
            config_file:       self.config_file,
            state_file:        self.state_file,
            rtsp_paths_file:   self.rtsp_paths_file,
            mjpeg_paths_file:  self.mjpeg_paths_file,
            diagnostic_mode:   self.diagnostic_mode,
            discovery:         self.discovery,
            default_svc_table: config.svc_table.clone(),
            svc_table:         config.svc_table,
            logger:            logger,
        };

        if self.verbose {
            config.logger.set_level(Severity::DEBUG);
        }

        for svc in self.services {
            config.svc_table.add_static(svc.clone());
            config.default_svc_table.add_static(svc);
        }

        config.save()
            .map_err(|_| ConfigError::from(
                format!("unable to save config file \"{}\"", &config.config_file)
            ))?;

        Ok(config)
    }

    /// Parse given command line arguments.
    fn parse(mut self, mut args: Args) -> Result<ApplicationConfigBuilder, ConfigError> {
        // skip the application name
        args.next();

        self.arrow_svc_addr = args.next()
            .ok_or(ConfigError::from("missing Angelcam Arrow Service address"))?;

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

                "--diagnostic-mode"   => self.diagnostic_mode(),
                "--log-stderr"        => self.log_stderr(),
                "--log-stderr-pretty" => self.log_stderr_pretty(),

                arg => {
                    if arg.starts_with("--config-file=") {
                        self.config_file(arg);
                    } else if arg.starts_with("--conn-state-file=") {
                        self.conn_state_file(arg);
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
                    } else {
                        return Err(ConfigError::from(
                            format!("unknown argument: \"{}\"", arg)
                        ));
                    }
                }
            }
        }

        Ok(self)
    }

    /// Process the CA certificate argument.
    fn ca_certificates(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let path = args.next()
            .ok_or(ConfigError::from("CA certificate path expected"))?;

        self.ca_certificates.push(path);

        Ok(())
    }

    /// Process the discovery argument.
    fn discovery(&mut self) -> Result<(), ConfigError> {
        if ! cfg!(feature = "discovery") {
            return Err(ConfigError::from("unknown argument: \"-d\""))
        }

        self.discovery = true;

        Ok(())
    }

    /// Process the interface argument.
    fn interface(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let iface = args.next()
            .ok_or(ConfigError::from("network interface name expected"))?;

        self.arrow_mac = get_mac(&iface)?;

        Ok(())
    }

    /// Process the RTSP service argument.
    fn rtsp_service(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let url = args.next()
            .ok_or(ConfigError::from("RTSP URL expected"))?;

        let service = parse_rtsp_url(&url)?;

        self.services.push(service);

        Ok(())
    }

    /// Process the MJPEG service argument.
    fn mjpeg_service(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let url = args.next()
            .ok_or(ConfigError::from("HTTP URL expected"))?;

        let service = parse_mjpeg_url(&url)?;

        self.services.push(service);

        Ok(())
    }

    /// Process the HTTP service argument.
    fn http_service(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let addr = args.next()
            .ok_or(ConfigError::from("TCP socket address expected"))?;

        let addr = net::utils::get_socket_address(addr.as_str())
            .map_err(|_| ConfigError::from(
                format!("unable to resolve socket address: {}", addr)
            ))?;

        let mac = get_fake_mac(0xffff, &addr);

        self.services.push(
            Service::http(0, mac, addr));

        Ok(())
    }

    /// Process the TCP service argument.
    fn tcp_service(&mut self, args: &mut Args) -> Result<(), ConfigError> {
        let addr = args.next()
            .ok_or(ConfigError::from("TCP socket address expected"))?;

        let addr = net::utils::get_socket_address(addr.as_str())
            .map_err(|_| ConfigError::from(
                format!("unable to resolve socket address: {}", addr)
            ))?;

        let mac = get_fake_mac(0xffff, &addr);

        self.services.push(
            Service::tcp(0, mac, addr));

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

        let re = Regex::new(r"^--log-file=(.*)$")
            .unwrap();

        self.log_file = re.captures(arg)
            .unwrap()
            .at(1)
            .unwrap()
            .to_string();

        Ok(())
    }

    /// Process the log-file-size argument.
    fn log_file_size(&mut self, arg: &str) -> Result<(), ConfigError> {
        let re = Regex::new(r"^--log-file-size=(\d+)$")
            .unwrap();

        self.log_file_size = re.captures(arg)
            .ok_or(ConfigError::from(
                format!("invalid value given for {}, number expeced", arg)
            ))?
            .at(1)
            .unwrap()
            .parse()
            .unwrap();

        Ok(())
    }

    /// Process the log-file-rotations argument.
    fn log_file_rotations(&mut self, arg: &str) -> Result<(), ConfigError> {
        let re = Regex::new(r"^--log-file-rotations=(\d+)$")
            .unwrap();

        self.log_file_size = re.captures(arg)
            .ok_or(ConfigError::from(
                format!("invalid value given for {}, number expeced", arg)
            ))?
            .at(1)
            .unwrap()
            .parse()
            .unwrap();

        Ok(())
    }

    /// Process the config-file argument.
    fn config_file(&mut self, arg: &str) {
        let re = Regex::new(r"^--config-file=(.*)$")
            .unwrap();

        self.config_file = re.captures(arg)
            .unwrap()
            .at(1)
            .unwrap()
            .to_string();
    }

    /// Process the conn-state-file argument.
    fn conn_state_file(&mut self, arg: &str) {
        let re = Regex::new(r"^--conn-state-file=(.*)$")
            .unwrap();

        self.state_file = re.captures(arg)
            .unwrap()
            .at(1)
            .unwrap()
            .to_string();
    }

    /// Process the rtsp-paths argument.
    fn rtsp_paths(&mut self, arg: &str) -> Result<(), ConfigError> {
        if ! cfg!(feature = "discovery") {
            return Err(ConfigError::from("unknown argument: \"--rtsp-paths\""))
        }

        let re = Regex::new(r"^--rtsp-paths=(.*)$")
            .unwrap();

        self.rtsp_paths_file = re.captures(arg)
            .unwrap()
            .at(1)
            .unwrap()
            .to_string();

        Ok(())
    }

    /// Process the mjpeg-paths argument.
    fn mjpeg_paths(&mut self, arg: &str) -> Result<(), ConfigError> {
        if ! cfg!(feature = "discovery") {
            return Err(ConfigError::from("unknown argument: \"--mjpeg-paths\""))
        }

        let re = Regex::new(r"^--mjpeg-paths=(.*)$")
            .unwrap();

        self.mjpeg_paths_file = re.captures(arg)
            .unwrap()
            .at(1)
            .unwrap()
            .to_string();

        Ok(())
    }
}

/// Persistent part of application configuration.
#[derive(Deserialize, Serialize)]
struct PersistentConfig {
    uuid:      Uuid,
    passwd:    Uuid,
    version:   usize,
    svc_table: SharedServiceTable,
}

impl PersistentConfig {
    /// Create a new instance of persistent configuration.
    fn new() -> PersistentConfig {
        PersistentConfig {
            uuid:      Uuid::new_v4(),
            passwd:    Uuid::new_v4(),
            version:   0,
            svc_table: SharedServiceTable::new(),
        }
    }

    /// Load configuration from a given file.
    fn load(path: &str) -> Result<PersistentConfig, ConfigError> {
        let file   = File::open(path)?;
        let config = serde_json::from_reader(file)?;

        Ok(config)
    }

    /// Save configuration into a given file.
    fn save(&self, path: &str) -> Result<(), ConfigError> {
        let mut file = File::create(path)?;

        serde_json::to_writer(&mut file, self)?;

        Ok(())
    }
}

/// Struct holding application configuration loaded from a configuration file and passed as
/// command line arguments.
pub struct ApplicationConfig {
    version:           usize,
    uuid:              Uuid,
    passwd:            Uuid,
    arrow_mac:         MacAddr,
    arrow_svc_addr:    String,
    ca_certificates:   Vec<String>,
    config_file:       String,
    state_file:        String,
    rtsp_paths_file:   String,
    mjpeg_paths_file:  String,
    diagnostic_mode:   bool,
    discovery:         bool,
    svc_table:         SharedServiceTable,
    default_svc_table: SharedServiceTable,
    logger:            BoxedLogger,
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

    /// Get version of the configuration.
    pub fn get_version(&self) -> usize {
        self.version
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
    pub fn get_logger(&self) -> BoxedLogger {
        self.logger.clone()
    }

    /// Get TLS connector.
    pub fn get_tls_connector(&self) -> Result<TlsConnector, RuntimeError> {
        let mut builder = TlsConnector::builder()
            .map_err(|err| RuntimeError::from(
                format!("unable to create a TLS connection builder: {}", err)
            ))?;

        builder.supported_protocols(SSL_METHODS)
            .map_err(|err| RuntimeError::from(
                format!("unable to set supported TLS protocols: {}", err)
            ))?;

        {
            let ssl_ctx_builder = builder.builder_mut()
                .builder_mut();

            ssl_ctx_builder.set_verify_depth(4);
            ssl_ctx_builder.set_options(SSL_OP_NO_COMPRESSION);
            ssl_ctx_builder.set_cipher_list(SSL_CIPHER_LIST)
                .map_err(|err| RuntimeError::from(
                    format!("unable to set TLS cipher list: {}", err)
                ))?;

            for ca_cert in &self.ca_certificates {
                ssl_ctx_builder.load_ca_certificates(ca_cert)?;
            }
        }

        builder.build()
            .map_err(|err| RuntimeError::from(
                format!("unable to create a TLS connector: {}", err)
            ))
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
            res);
    }

    /// Update the service table with given services.
    pub fn update_services<I>(&mut self, services: I)
        where I: IntoIterator<Item=Service> {
        let mut changed = false;

        for svc in services {
            if !self.svc_table.contains_exact(&svc) {
                changed = true;
            }

            self.svc_table.add(svc);
        }

        if !changed {
            return
        }

        self.version += 1;

        let res = self.save();

        utils::result_or_log(
            &mut self.logger,
            Severity::WARN,
            format!("unable to save config file \"{}\"", self.config_file),
            res);
    }

    /// Save the current configuration into the configuration file.
    fn save(&self) -> Result<(), ConfigError> {
        self.to_persistent_config()
            .save(&self.config_file)
    }

    /// Create persistent configuration.
    fn to_persistent_config(&self) -> PersistentConfig {
        PersistentConfig {
            uuid:      self.uuid,
            passwd:    self.passwd,
            version:   self.version,
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
        .ok_or(ConfigError::from(format!("there is no such ethernet device: {}", iface)))
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
    let a = ((prefix >> 8)  & 0xff) as u8;
    let b = ( prefix        & 0xff) as u8;

    let addr   = addr.ip();
    let octets = addr.octets();

    MacAddr::new(a, b,
        octets[0],
        octets[1],
        octets[2],
        octets[3])
}

fn get_fake_mac_from_ipv6(prefix: u16, addr: &SocketAddrV6) -> MacAddr {
    let addr     = addr.ip();
    let segments = addr.segments();

    let a = ((prefix      >> 8)  & 0xff) as u8;
    let b = ( prefix             & 0xff) as u8;
    let c = ((segments[6] >> 8)  & 0xff) as u8;
    let d = ( segments[6]        & 0xff) as u8;
    let e = ((segments[7] >> 8)  & 0xff) as u8;
    let f = ( segments[7]        & 0xff) as u8;

    MacAddr::new(a, b, c, d, e, f)
}

/// Parse a given RTSP URL and return an RTSP service, a LockedRTSP service or an error.
fn parse_rtsp_url(url: &str) -> Result<Service, ConfigError> {
    let res = r"^rtsp://([^/]+@)?([^/@:]+|\[[0-9a-fA-F:.]+\])(:(\d+))?(/.*)?$";
    let re  = Regex::new(res).unwrap();

    if let Some(caps) = re.captures(url) {
        let host = caps.at(2).unwrap();
        let path = caps.at(5).unwrap();
        let port = caps.at(4)
            .map(|p| u16::from_str(p))
            .unwrap_or(Ok(554))
            .unwrap();

        let socket_addr = net::utils::get_socket_address((host, port))
            .map_err(|_| ConfigError::from(
                format!("unable to resolve RTSP service address: {}:{}", host, port)
            ))?;

        let mac = get_fake_mac(0xffff, &socket_addr);

        // NOTE: we do not want to probe the service here as it might not be
        // available on app startup
        match caps.at(1) {
            Some(_) => Ok(Service::locked_rtsp(0, mac, socket_addr, None)),
            None    => Ok(Service::rtsp(0, mac, socket_addr, path.to_string()))
        }
    } else {
        Err(ConfigError::from(format!("invalid RTSP URL given: {}", url)))
    }
}

/// Parse a given HTTP URL and return an MJPEG service, a LockedMJPEG service or an error.
fn parse_mjpeg_url(url: &str) -> Result<Service, ConfigError> {
    let res = r"^http://([^/]+@)?([^/@:]+|\[[0-9a-fA-F:.]+\])(:(\d+))?(/.*)?$";
    let re  = Regex::new(res).unwrap();

    if let Some(caps) = re.captures(url) {
        let host = caps.at(2).unwrap();
        let path = caps.at(5).unwrap();
        let port = caps.at(4)
            .map(|p| u16::from_str(p))
            .unwrap_or(Ok(80))
            .unwrap();

        let socket_addr = net::utils::get_socket_address((host, port))
            .map_err(|_| ConfigError::from(
                format!("unable to resolve HTTP service address: {}:{}", host, port)
            ))?;

        let mac = get_fake_mac(0xffff, &socket_addr);

        // NOTE: we do not want to probe the service here as it might not be
        // available on app startup
        match caps.at(1) {
            Some(_) => Ok(Service::locked_mjpeg(0, mac, socket_addr, None)),
            None    => Ok(Service::mjpeg(0, mac, socket_addr, path.to_string()))
        }
    } else {
        Err(ConfigError::from(format!("invalid HTTP URL given: {}", url)))
    }
}

/// Check if a given file is a certificate file.
fn is_cert_file<P: AsRef<Path>>(path: P) -> bool {
    let path = path.as_ref();

    if let Some(ext) = path.extension() {
        let ext = ext.to_string_lossy();

        match &ext.to_lowercase() as &str {
            "der" => true,
            "cer" => true,
            "crt" => true,
            "pem" => true,
            _ => false
        }
    } else {
        false
    }
}

/// Simple extension to the SslContextBuilder.
trait SslContextBuilderExt {
    /// Load all CA certificates from a given path.
    fn load_ca_certificates<P: AsRef<Path>>(&mut self, path: P) -> Result<(), RuntimeError>;
}

impl SslContextBuilderExt for SslContextBuilder {
    fn load_ca_certificates<P: AsRef<Path>>(&mut self, path: P) -> Result<(), RuntimeError> {
        let path = path.as_ref();

        if path.is_dir() {
            let dir = path.read_dir()
                .map_err(|err| RuntimeError::from(format!("{}", err)))?;

            for entry in dir {
                let entry = entry.map_err(|err| RuntimeError::from(format!("{}", err)))?;

                let path = entry.path();

                if path.is_dir() || is_cert_file(&path) {
                    self.load_ca_certificates(&path)?;
                }
            }

            Ok(())
        } else {
            self.set_ca_file(&path)
                .map_err(|err| RuntimeError::from(format!("{}", err)))
        }
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
        println!("                        /etc/arrow/mjpeg-paths)\n");
    } else {
        println!("");
    }
    process::exit(exit_code);
}
