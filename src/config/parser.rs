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

use std::{fmt::Write, path::PathBuf};

use argh::FromArgs;
use log::{LevelFilter, Log};
use ttpkit_url::Url;

use crate::{
    error::Error,
    net::raw::{devices::EthernetDevice as NetworkInterface, ether::MacAddr},
    storage::DefaultStorage,
    svc_table::Service,
    utils::{
        get_fake_mac,
        logger::{FileLogger, StderrLogger},
    },
};

#[cfg(not(target_os = "windows"))]
use crate::utils::logger::Syslog;

use super::{CONFIG_FILE, CONFIG_FILE_SKELETON, Config, DEFAULT_ARROW_SERVICE_PORT, STATE_FILE};

#[cfg(feature = "discovery")]
use super::{MJPEG_PATHS_FILE, RTSP_PATHS_FILE};

/// Arrow Client configuration parser.
#[derive(FromArgs)]
#[argh(help_triggers("-h", "--help"))]
pub struct ConfigParser {
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
    pub async fn into_config(self) -> Result<Config, Error> {
        if self.version {
            super::version();
        }

        // because of the lock file, we need to create the storage builder
        // before creating the logger
        let mut storage_builder =
            DefaultStorage::builder(&self.config_file, self.lock_file.as_ref())
                .await
                .map_err(Error::from_other)?;

        self.init_logger()?;

        let interfaces = NetworkInterface::list().await;

        let arrow_mac = self.get_arrow_mac(&interfaces)?;
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

        config_builder.build(storage, arrow_service).await
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
    fn get_arrow_mac(&self, interfaces: &[NetworkInterface]) -> Result<Option<MacAddr>, Error> {
        self.default_interface
            .as_deref()
            .map(|name| super::get_mac(interfaces, name))
            .transpose()
    }
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
