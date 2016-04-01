// Copyright 2015 click2stream, Inc.
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

//! Arrow Client definitions.

extern crate mio;
extern crate libc;
extern crate regex;
extern crate openssl;
extern crate time;
extern crate uuid;
extern crate rustc_serialize;

#[macro_use]
pub mod utils;

pub mod net;

use std::io;
use std::env;
use std::process;
use std::thread;

use std::fs::File;
use std::env::Args;
use std::fmt::Debug;
use std::error::Error;
use std::str::FromStr;
use std::path::Path;
use std::time::Duration;
use std::thread::JoinHandle;
use std::io::{BufWriter, Write};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

use utils::logger;
use utils::logger::{LoggerWrapper, DummyLogger};

use utils::{Shared, RuntimeError};
use utils::logger::{Logger, Severity};
use utils::config::{ArrowConfig, AppContext};

#[cfg(feature = "discovery")]
use net::discovery;

use net::raw::ether::MacAddr;
use net::raw::devices::EthernetDevice;
use net::arrow::error::{ArrowError, ErrorKind};
use net::arrow::{ArrowClient, Sender, Command};
use net::arrow::protocol::{Service, ServiceTable};

use openssl::nid::Nid;
use openssl::ssl::error::SslError;
use openssl::x509::X509StoreContext;
use openssl::ssl::{SslContext, SslMethod};
use openssl::ssl::{SSL_VERIFY_PEER, SSL_OP_NO_COMPRESSION};

use mio::{EventLoop, Handler, NotifyError};

use regex::Regex;

/// Network scan period.
const NETWORK_SCAN_PERIOD: f64 = 300.0;

/// Connectionn retry timeout.
const RETRY_TIMEOUT:       f64 = 60.0;

const CONN_STATE_CONNECTED:    &'static str = "connected";
const CONN_STATE_UNAUTHORIZED: &'static str = "unauthorized";
const CONN_STATE_DISCONNECTED: &'static str = "disconnected";

/// Arrow Client configuration file.
static CONFIG_FILE: &'static str = "/etc/arrow/config.json";

/// Arrow Client connection state file.
static STATE_FILE: &'static str = "/var/lib/arrow/state";

/// Get socket address from a given argument.
fn get_socket_address<T>(s: T) -> Result<SocketAddr, RuntimeError>
    where T: ToSocketAddrs {
    let mut addrs = try!(s.to_socket_addrs()
        .or(Err(RuntimeError::from("unable get socket address"))));
    
    match addrs.next() {
        Some(addr) => Ok(addr),
        _          => Err(RuntimeError::from("unable get socket address"))
    }
}

/// Get MAC address of the first configured ethernet device.
fn get_first_mac() -> Result<MacAddr, RuntimeError> {
    EthernetDevice::list()
        .into_iter()
        .next()
        .map(|dev| dev.mac_addr)
        .ok_or(RuntimeError::from("there is no configured ethernet device"))
}

/// Get MAC address of a given network interface.
fn get_mac(iface: &str) -> Result<MacAddr, RuntimeError> {
    EthernetDevice::list()
        .into_iter()
        .find(|dev| dev.name == iface)
        .map(|dev| dev.mac_addr)
        .ok_or(RuntimeError::from("there is no such ethernet device"))
}

/// Unwrap a given result (if possible) or print the error message and exit 
/// the process printing application usage.
fn result_or_usage<T, E>(res: Result<T, E>) -> T 
    where E: Error + Debug {
    match res {
        Ok(res)  => res,
        Err(err) => {
            println!("ERROR: {}\n", err);
            usage(1);
        }
    }
}

/// Generate a fake MAC address from a given prefix and socket address.
///
/// Note: It is used in case we do not know the device MAC address (e.g. for 
/// services passed as command line arguments).
fn get_fake_mac_address(prefix: u16, addr: &SocketAddr) -> MacAddr {
    match addr {
        &SocketAddr::V4(ref addr) => get_fake_mac_address_v4(prefix, addr),
        &SocketAddr::V6(ref addr) => get_fake_mac_address_v6(prefix, addr),
    }
}

fn get_fake_mac_address_v4(prefix: u16, addr: &SocketAddrV4) -> MacAddr {
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

fn get_fake_mac_address_v6(prefix: u16, addr: &SocketAddrV6) -> MacAddr {
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

/// Parse a given RTSP URL and return Service::RTSP, Service::LockedRTSP or 
/// an error.
fn parse_rtsp_url(url: &str) -> Result<Service, RuntimeError> {
    let res = r"^rtsp://([^/]+@)?([^/@:]+|\[[0-9a-fA-F:.]+\])(:(\d+))?(/.*)?$";
    let re  = Regex::new(res).unwrap();
    
    if let Some(caps) = re.captures(url) {
        let host = caps.at(2).unwrap();
        let path = caps.at(5).unwrap();
        let port = match caps.at(4) {
            Some(port_str) => u16::from_str(port_str).unwrap(),
            _ => 554
        };
        
        let socket_addr = try!(get_socket_address((host, port))
            .or(Err(RuntimeError::from(
                "unable to resolve RTSP service address"))));
        
        let mac = get_fake_mac_address(0xffff, &socket_addr);
        
        // note: we do not want to probe the service here as it might not be 
        // available on app startup
        match caps.at(1) {
            Some(_) => Ok(Service::LockedRTSP(mac, socket_addr)),
            None    => Ok(Service::RTSP(mac, socket_addr, path.to_string()))
        }
    } else {
        Err(RuntimeError::from("invalid RTSP URL given"))
    }
}

/// Print usage and exit the process with a given exit code.
fn usage(exit_code: i32) -> ! {
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
    println!("    -h addr   add a given HTTP service (addr must be in the \"host:port\"");
    println!("              format)");
    println!("    -t addr   add a given TCP service (addr must be in the \"host:port\"");
    println!("              format)");
    println!("    -v        enable debug logs\n");
    println!("    --diagnostic-mode   start the client in diagnostic mode (i.e. the client");
    println!("                        will try to connect to a given Arrow Service and it");
    println!("                        will report success as its exit code; note: the");
    println!("                        \"access denied\" response from the server is also");
    println!("                        considered as a success)");
    println!("    --log-stderr        send log messages into stderr instead of syslog");
    println!("    --log-stderr-pretty send log messages into stderr instead of syslog and use");
    println!("                        colored messages\n");
    process::exit(exit_code);
}

/// Initialize SSL context. 
fn init_ssl(
    method: SslMethod, 
    cipher_list: &str) -> Result<SslContext, SslError> {
    let mut ssl_context = try!(SslContext::new(method));
    try!(ssl_context.set_cipher_list(cipher_list));
    ssl_context.set_options(SSL_OP_NO_COMPRESSION);
    ssl_context.set_verify(SSL_VERIFY_PEER, None);
    ssl_context.set_verify_depth(4);
    Ok(ssl_context)
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

/// Load all certificate files conained within a given directory structure.
fn load_ca_certificate_dir<P>(
    ssl_context: &mut SslContext, 
    path: P) -> Result<(), RuntimeError> 
    where P: AsRef<Path> {
    let path = path.as_ref();
    let dir  = try!(path.read_dir()
        .map_err(|err| RuntimeError::from(format!("{}", err))));
    
    for entry in dir {
        let entry = try!(entry.map_err(|err|
            RuntimeError::from(format!("{}", err))));
        
        let path = entry.path();
        
        if path.is_dir() {
            try!(load_ca_certificate_dir(ssl_context, &path));
        } else if is_cert_file(&path) {
            try!(ssl_context.set_CA_file(&path)
                .map_err(|err| RuntimeError::from(format!("{}", err))));
        }
    }
    
    Ok(())
}

/// Load CA certificates from a given path.
fn load_ca_certificates<P>(
    ssl_context: &mut SslContext, 
    path: P) -> Result<(), RuntimeError>
    where P: AsRef<Path> {
    let path = path.as_ref();
    if path.is_dir() {
        load_ca_certificate_dir(ssl_context, path)
    } else {
        ssl_context.set_CA_file(path)
            .map_err(|err| RuntimeError::from(format!("{}", err)))
    }
}

/// Data passed to the openssl_verify_callback().
#[derive(Debug, Clone)]
struct VerifyCallbackData {
    /// Current hostname.
    cur_hostname: String,
}

impl VerifyCallbackData {
    /// Create new verify callback data.
    fn new(address: &str) -> VerifyCallbackData {
        VerifyCallbackData {
            cur_hostname: get_hostname(address)
        }
    }
    
    /// Set current address.
    fn set_cur_address(&mut self, address: &str) {
        self.cur_hostname = get_hostname(address)
    }
    
    /// Get current hostname.
    fn get_cur_hostname(&self) -> &str {
        &self.cur_hostname
    }
}

/// Get hostname from a given address.
fn get_hostname(address: &str) -> String {
    Regex::new(r"^([^:]+)(:(\d+))?$")
        .unwrap()
        .captures(address)
        .and_then(|cap| cap.at(1))
        .unwrap_or(address)
        .to_string()
}

/// Verify callback.
fn openssl_verify_callback(
    preverify_ok: bool, 
    x509_ctx: &X509StoreContext, 
    data: &Shared<VerifyCallbackData>) -> bool {
    let data = data.lock()
        .unwrap();
    
    preverify_ok && validate_hostname(x509_ctx, data.get_cur_hostname())
}

/// Validate a given hostname using peer certificate. This function returns 
/// true if there is no CN record or the CN record matches with the given 
/// hostname. False is returned if there is no certificate or the hostname does 
/// not match.
fn validate_hostname(x509_ctx: &X509StoreContext, hostname: &str) -> bool {
    if let Some(cert) = x509_ctx.get_current_cert() {
        let subject_name = cert.subject_name();
        if let Some(cn) = subject_name.text_by_nid(Nid::CN) {
            let re = "^".to_string()
                + &cn.replace(r".", r"\.")
                    .replace(r"*", r"\S+")
                + "$";
            if let Ok(re) = Regex::new(&re) {
                re.is_match(hostname)
            } else {
                false
            }
        } else {
            true
        }
    } else {
        false
    }
}

/// Spawn a new Arrow Client thread.
fn spawn_arrow_thread<L: 'static + Logger + Clone + Send>(
    logger: L, 
    ssl_context: SslContext,
    cmd_sender: CommandSender,
    addr: &str,
    arrow_mac: &MacAddr,
    app_context: &Shared<AppContext>) {
    let addr        = addr.to_string();
    let arrow_mac   = arrow_mac.clone();
    let app_context = app_context.clone();
    
    thread::spawn(move || arrow_thread(logger, ssl_context, cmd_sender, 
        &addr, &arrow_mac, app_context));
}

/// Arrow Client main thread.
///
/// This function ensures maintaining connection with a remote Arrow Service.
fn arrow_thread<L: Logger + Clone, Q: Sender<Command> + Clone>(
    mut logger: L,
    mut ssl_context: SslContext,
    cmd_sender: Q,
    addr: &str,
    arrow_mac: &MacAddr,
    app_context: Shared<AppContext>) {
    let diagnostic_mode = app_context.lock()
        .unwrap()
        .diagnostic_mode;
    
    let t = time::precise_time_s();
    
    let mut unauthorized_timeout = t + 1200.0;
    let mut cur_addr = addr.to_string();
    let mut last_attempt;
    
    let verify_data = Shared::new(VerifyCallbackData::new(&cur_addr));
    
    ssl_context.set_verify_with_data(
        SSL_VERIFY_PEER,
        openssl_verify_callback,
        verify_data.clone());
    
    loop {
        log_info!(logger, "connecting to remote Arrow Service {}", cur_addr);
        
        let lgr = logger.clone();
        let ctx = app_context.clone();
        
        last_attempt = time::precise_time_s();
        
        utils::result_or_log(&mut logger, Severity::INFO,
            "unable to save current connection state", 
            save_connection_state(CONN_STATE_CONNECTED));
        
        let res = connect(lgr, &ssl_context, cmd_sender.clone(), 
            &cur_addr, arrow_mac, ctx);
        
        unauthorized_timeout = get_unauthorized_timeout(&res, 
            last_attempt,
            unauthorized_timeout);
        
        if diagnostic_mode {
            diagnose_connection_result(&res);
        }
        
        match res {
            Ok(addr) => cur_addr = addr,
            Err(err) => {
                log_warn!(logger, "{}", err.description());
                
                let res = match err.kind() {
                    ErrorKind::Unauthorized => 
                         save_connection_state(CONN_STATE_UNAUTHORIZED),
                    _ => save_connection_state(CONN_STATE_DISCONNECTED)
                };
                
                utils::result_or_log(&mut logger, Severity::INFO,
                    "unable to save current connection state", res);
                
                let t = get_next_retry_timeout(err,
                    last_attempt,
                    unauthorized_timeout);
                
                if t > 0.5 {
                    log_info!(logger, "retrying in {:.3} seconds", t);
                    thread::sleep(Duration::from_millis((t * 1000.0) as u64));
                }
                
                cur_addr = addr.to_string();
            }
        }
        
        verify_data.lock()
            .unwrap()
            .set_cur_address(&cur_addr);
    }
}

/// Save current connection state.
fn save_connection_state(state: &str) -> Result<(), io::Error> {
    let file = try!(File::create(STATE_FILE));
    let mut bwriter = BufWriter::new(file);
    
    try!(bwriter.write(state.as_bytes()));
    try!(bwriter.write(b"\n"));
    
    Ok(())
}

/// Get new timeout for the unauthorized state.
fn get_unauthorized_timeout(
    connection_result:       &Result<String, ArrowError>,
    last_connection_attempt: f64,
    current_timeout:         f64) -> f64 {
    let t = time::precise_time_s();
    match connection_result {
        // We know the client is authorized, we can update the timeout.
        &Ok(_)        => t + 1200.0,
        &Err(ref err) => match err.kind() {
            // We don't update the timeout in case the client is unauthorized.
            ErrorKind::Unauthorized => current_timeout,
            // We don't know if the client is authorized but we assume it is 
            // if the last connection was longer than RETRY_TIMEOUT seconds.
            _ => if (last_connection_attempt + RETRY_TIMEOUT) < t {
                t + 1200.0
            } else {
                current_timeout
            }
        }
    }
}

/// Get next reconnect timeout for the Arrow Client thread.
fn get_next_retry_timeout(
    connection_error:        ArrowError,
    last_connection_attempt: f64,
    unauthorized_timeout:    f64) -> f64 {
    let t = time::precise_time_s();
    match connection_error.kind() {
        // the client is not authorized to access the service yet; check the 
        // unauthorized state timeout
        ErrorKind::Unauthorized => match unauthorized_timeout {
            // retry every 10 seconds in the first 10 minutes since the first 
            // "unauthorized" response
            timeout if t < (timeout - 600.0) => 10.0,
            // retry every 30 seconds after the first 10 minutes since the 
            // first "unauthorized" response
            timeout if t < timeout => 30.0,
            // retry in 10 hours after the first 20 minutes since the first 
            // "unauthorized" response
            _ => 36000.0
        },
        // set a very long retry timeout if the version of the Arrow Protocol 
        // is not supported by either side
        ErrorKind::UnsupportedProtocolVersion => 36000.0,
        // in all other cases
        _ => RETRY_TIMEOUT + last_connection_attempt - time::precise_time_s()
    }
}

/// Diagnose a given connection result and exit with exit code 0 if the 
/// connection was successful or the server responded with UNAUTHORIZED, 
/// otherwise exit with exit code 1.
fn diagnose_connection_result(
    connection_result: &Result<String, ArrowError>) -> ! {
    match connection_result {
        &Ok(_)        => process::exit(0),
        &Err(ref err) => match err.kind() {
            ErrorKind::Unauthorized => process::exit(0),
            _ => process::exit(1)
        }
    }
}

/// Connect to a given Arrow Service.
fn connect<L: Logger + Clone, Q: Sender<Command>>(
    logger: L,
    ssl_context: &SslContext,
    cmd_sender: Q,
    addr: &str,
    arrow_mac: &MacAddr,
    app_context: Shared<AppContext>) -> Result<String, ArrowError> {
    let addr = try!(get_socket_address(addr)
        .or(Err(ArrowError::connection_error(format!(
            "failed to lookup Arrow Service {} address information", addr)))));
    
    match ArrowClient::new(logger, ssl_context, cmd_sender, 
        &addr, arrow_mac, app_context) {
        Err(err) => Err(ArrowError::connection_error(format!(
            "unable to connect to remote Arrow Service {} ({})", 
            addr, err.description()))),
        Ok(mut client) => client.event_loop()
    }
}

#[cfg(feature = "discovery")]
/// Run device discovery and update a given service table.
fn network_scanner_thread<L: Logger + Clone>(
    mut logger: L, 
    app_context: Shared<AppContext>) {
    log_info!(logger, "looking for local services...");
    let services = utils::result_or_log(&mut logger, Severity::WARN, 
        "network scanner error", discovery::find_rtsp_streams());
    
    if let Some(services) = services {
        let mut app_context = app_context.lock()
            .unwrap();
        let config = &mut app_context.config;
        let count  = services.len();
        
        for svc in services {
            config.add(svc);
        }
        
        config.update_active_services();
        
        log_info!(logger, "{} services found, current service table: {}", 
            count, config.service_table());
    }
}

#[cfg(not(feature = "discovery"))]
/// Dummy scanner.
fn network_scanner_thread<L>(_: L, _: Shared<AppContext>) {
}

/// Periodical event types.
#[derive(Debug, Copy, Clone)]
enum TimerEvent {
    ScanNetwork
}

/// Arrow Command wrapper/extender.
#[derive(Debug, Copy, Clone)]
enum CommandWrapper {
    Wrapped(Command),
    ScanCompleted
}

/// Command channel.
#[derive(Debug, Clone)]
struct CommandSender {
    sender: mio::Sender<CommandWrapper>,
}

impl CommandSender {
    /// Crate a new channel for sending Arrow Commands.
    fn new(sender: mio::Sender<CommandWrapper>) -> CommandSender {
        CommandSender {
            sender: sender
        }
    }
}

impl Sender<Command> for CommandSender {
    fn send(&self, cmd: Command) -> Result<(), Command> {
        match self.sender.send(CommandWrapper::Wrapped(cmd)) {
            Ok(_)    => Ok(()),
            Err(err) => match err {
                NotifyError::Closed(None) => Ok(()),
                _ => Err(cmd)
            }
        }
    }
}

/// Arrow command handler.
struct CommandHandler<L: Logger> {
    logger:            L,
    default_svc_table: ServiceTable,
    active_services:   Vec<Service>,
    app_context:       Shared<AppContext>,
    scanner:           Option<JoinHandle<()>>,
    last_scan:         f64,
}

impl<L: 'static + Logger + Clone + Send> CommandHandler<L> {
    /// Create a new Arrow Command handler.
    fn new(
        logger: L, 
        default_svc_table: ServiceTable,
        app_context: Shared<AppContext>) -> CommandHandler<L> {
        let now = time::precise_time_s();
        let active_services = {
            let app_context = app_context.lock()
                .unwrap();
            app_context.config.active_services()
        };
        
        CommandHandler {
            logger:            logger,
            default_svc_table: default_svc_table,
            active_services:   active_services,
            app_context:       app_context,
            scanner:           None,
            last_scan:         now - NETWORK_SCAN_PERIOD
        }
    }
    
    /// Scan the local network for new services and schedule the next network 
    /// scanning event.
    fn periodical_network_scan(&mut self, event_loop: &mut EventLoop<Self>) {
        let now     = time::precise_time_s();
        let elapsed = now - self.last_scan;
        let delta   = NETWORK_SCAN_PERIOD - elapsed;
        
        let timeout = if delta <= 0.0 {
            self.scan_network(event_loop);
            NETWORK_SCAN_PERIOD
        } else {
            delta
        };
        
        event_loop.timeout(
                TimerEvent::ScanNetwork,
                Duration::from_millis((timeout * 1000.0) as u64))
            .unwrap();
    }
    
    /// Spawn a new network scanner thread (if it is not already running) and 
    /// save its join handle.
    fn scan_network(&mut self, event_loop: &mut EventLoop<Self>) {
        let mut app_context = self.app_context.lock()
            .unwrap();
        
        // check if the discovery is enabled and if there is another scanner 
        // running
        if app_context.discovery && self.scanner.is_none() {
            self.last_scan = time::precise_time_s();
            
            app_context.scanning = true;
            
            let logger      = self.logger.clone();
            let app_context = self.app_context.clone();
            let sender      = event_loop.channel();
            let handle      = thread::spawn(move || {
                network_scanner_thread(logger, app_context);
                sender.send(CommandWrapper::ScanCompleted)
                    .unwrap();
            });
            
            self.scanner = Some(handle);
        }
    }
    
    /// Called upon network scanner thread completion.
    fn scan_completed(&mut self) {
        let res = match self.scanner.take() {
            Some(handle) => handle.join(),
            _ => Ok(()),
        };
        
        let mut app_context = self.app_context.lock()
            .unwrap();
        
        {
            let config          = &mut app_context.config;
            let active_services = config.active_services();
            if self.active_services != active_services {
                self.active_services = active_services;
                config.bump_version();
            }
            
            utils::result_or_log(&mut self.logger, Severity::WARN, 
                format!("unable to save config file \"{}\"", CONFIG_FILE), 
                config.save(CONFIG_FILE));
        }
        
        app_context.scanning = false;
        
        if res.is_err() {
            log_warn!(self.logger, "network scanner thread panicked");
        }
    }
    
    /// Reinitialize the shared config with the default service table.
    fn reset_svc_table(&mut self) {
        let mut app_context = self.app_context.lock()
            .unwrap();
        let config = &mut app_context.config;
        let table  = &self.default_svc_table;
        
        config.reinit(table.clone());
        config.bump_version();
        
        utils::result_or_log(&mut self.logger, Severity::WARN, 
            format!("unable to save config file \"{}\"", CONFIG_FILE), 
            config.save(CONFIG_FILE));
    }
}

impl<L: 'static + Logger + Clone + Send> Handler for CommandHandler<L> {
    type Timeout = TimerEvent;
    type Message = CommandWrapper;
    
    fn timeout(
        &mut self, 
        event_loop: &mut EventLoop<Self>, 
        event: TimerEvent) {
        match event {
            TimerEvent::ScanNetwork => self.periodical_network_scan(event_loop)
        }
    }
    
    fn notify(
        &mut self, 
        event_loop: &mut EventLoop<Self>, 
        cmd: CommandWrapper) {
        match cmd {
            CommandWrapper::ScanCompleted  => self.scan_completed(),
            CommandWrapper::Wrapped(cmd)   => match cmd {
                Command::ResetServiceTable => self.reset_svc_table(),
                Command::ScanNetwork       => self.scan_network(event_loop)
            }
        }
    }
}

const EXIT_CODE_USAGE:         i32 = 1;
const EXIT_CODE_NETWORK_ERROR: i32 = 2;
const EXIT_CODE_CONFIG_ERROR:  i32 = 3;
const EXIT_CODE_SSL_ERROR:     i32 = 4;
const EXIT_CODE_CERT_ERROR:    i32 = 5;

/// Type of the logger backend that should be used.
enum LoggerType {
    Syslog,
    Stderr,
    StderrPretty,
}

/// Helper struct for application configuration.
struct AppConfiguration {
    logger:            LoggerWrapper,
    logger_type:       LoggerType,
    ssl_context:       SslContext,
    app_context:       AppContext,
    default_svc_table: ServiceTable,
    arrow_svc_addr:    String,
    arrow_mac:         MacAddr,
}

impl AppConfiguration {
    /// Initialize application configuration.
    fn init() -> AppConfiguration {
        let ssl_context = utils::result_or_error(
            init_ssl(SslMethod::Tlsv1_2, "HIGH:!aNULL:!kRSA:!PSK:!MD5:!RC4"),
            EXIT_CODE_SSL_ERROR,
            "unable to set up SSL context");
        let config = ArrowConfig::load(CONFIG_FILE)
            .unwrap_or(ArrowConfig::new());
        let default_mac_addr = utils::result_or_error(
            get_first_mac(),
            EXIT_CODE_NETWORK_ERROR, 
            "unable to get any network interface MAC address");
        
        let mut config = AppConfiguration {
            logger:            LoggerWrapper::new(DummyLogger::new()),
            logger_type:       LoggerType::Syslog,
            ssl_context:       ssl_context,
            app_context:       AppContext::new(config),
            default_svc_table: ServiceTable::new(),
            arrow_svc_addr:    String::new(),
            arrow_mac:         default_mac_addr,
        };
        
        config.parse_cmd_args(&mut env::args());
        
        let level = config.logger.get_level();
        
        config.logger = match config.logger_type {
            LoggerType::Syslog       => LoggerWrapper::new(logger::syslog::new()),
            LoggerType::Stderr       => LoggerWrapper::new(logger::stderr::new()),
            LoggerType::StderrPretty => LoggerWrapper::new(logger::stderr::new_pretty()),
        };
        
        config.logger.set_level(level);
        
        config
    }
    
    /// Parse given command line arguments.
    fn parse_cmd_args(&mut self, args: &mut Args) {
        // skip the application name
        args.next();
        
        if let Some(arrow_svc_addr) = args.next() {
            self.arrow_svc_addr = arrow_svc_addr;
        } else {
            usage(EXIT_CODE_USAGE);
        }
        
        while let Some(ref arg) = args.next() {
            match arg as &str {
                "-c" => self.ca_certificates(args),
                "-d" => self.discovery(),
                "-i" => self.interface(args),
                "-r" => self.rtsp_service(args),
                "-h" => self.http_service(args),
                "-t" => self.tcp_service(args),
                "-v" => self.verbose(),
                
                "--diagnostic-mode"   => self.diagnostic_mode(),
                "--log-stderr"        => self.log_stderr(),
                "--log-stderr-pretty" => self.log_stderr_pretty(),
                
                arg => {
                    println!("unknown argument: {}\n", arg);
                    usage(EXIT_CODE_USAGE);
                }
            }
        }
    }
    
    /// Get next argument from a given list.
    fn next_argument(&mut self, args: &mut Args, emsg: &str) -> String {
        let arg = args.next()
            .ok_or(RuntimeError::from(emsg));
        
        result_or_usage(arg)
    }
    
    /// Process the CA certificate argument.
    fn ca_certificates(&mut self, args: &mut Args) {
        let path = self.next_argument(args, "CA certificate path expected");
        
        utils::result_or_error(load_ca_certificates(
            &mut self.ssl_context, &path),
            EXIT_CODE_CERT_ERROR,
            format!("unable to load certificate(s) from \"{}\"", &path));
    }
    
    /// Process the discovery argument.
    fn discovery(&mut self) {
        if cfg!(feature = "discovery") {
            self.app_context.discovery = true;
        }
    }
    
    /// Process the interface argument.
    fn interface(&mut self, args: &mut Args) {
        let iface = self.next_argument(args, "network interface name expected");
        
        self.arrow_mac = utils::result_or_error(
            get_mac(&iface),
            EXIT_CODE_NETWORK_ERROR, 
            "no such network interface");
    }
    
    /// Process the RTSP service argument.
    fn rtsp_service(&mut self, args: &mut Args) {
        let url = self.next_argument(args, "URL expected");
        
        let service = parse_rtsp_url(&url);
        let service = result_or_usage(service);
        
        self.app_context.config.add_static(service.clone());
        self.default_svc_table.add_static(service);
    }
    
    /// Process the HTTP service argument.
    fn http_service(&mut self, args: &mut Args) {
        let addr = self.next_argument(args, "TCP socket address expected");
        
        let addr = get_socket_address(&addr as &str);
        let addr = result_or_usage(addr);
        
        let mac = get_fake_mac_address(0xffff, &addr);
        
        let service = Service::HTTP(mac, addr);
        
        self.app_context.config.add_static(service.clone());
        self.default_svc_table.add_static(service);
    }
    
    /// Process the TCP service argument.
    fn tcp_service(&mut self, args: &mut Args) {
        let addr = self.next_argument(args, "TCP socket address expected");
        
        let addr = get_socket_address(&addr as &str);
        let addr = result_or_usage(addr);
        
        let mac = get_fake_mac_address(0xffff, &addr);
        
        let service = Service::TCP(mac, addr);
        
        self.app_context.config.add_static(service.clone());
        self.default_svc_table.add_static(service);
    }
    
    /// Process the verbose argument.
    fn verbose(&mut self) {
        self.logger.set_level(Severity::DEBUG);
    }
    
    /// Process the diagnostic mode argument.
    fn diagnostic_mode(&mut self) {
        self.app_context.diagnostic_mode = true;
    }
    
    /// Process the log-stderr argument.
    fn log_stderr(&mut self) {
        self.logger_type = LoggerType::Stderr;
    }
    
    /// Process the log-stderr-pretty argument.
    fn log_stderr_pretty(&mut self) {
        self.logger_type = LoggerType::StderrPretty;
    }
}

/// Arrow Client main function.
fn main() {
    let mut app_config = AppConfiguration::init();
    
    let app_context = app_config.app_context;
    
    utils::result_or_error(app_context.config.save(CONFIG_FILE),
        EXIT_CODE_CONFIG_ERROR, 
        format!("unable to save config file \"{}\"", CONFIG_FILE));
    
    log_info!(&mut app_config.logger, 
        "application started (uuid: {}, mac: {})", 
        app_context.config.uuid_string(), app_config.arrow_mac);
    
    let app_context = Shared::new(app_context);
    
    let mut event_loop = EventLoop::new()
        .unwrap();
    
    let mut cmd_handler = CommandHandler::new(
        app_config.logger.clone(),
        app_config.default_svc_table,
        app_context.clone());
    
    let cmd_sender = CommandSender::new(event_loop.channel());
    
    spawn_arrow_thread(
        app_config.logger,
        app_config.ssl_context, 
        cmd_sender, 
        &app_config.arrow_svc_addr,
        &app_config.arrow_mac,
        &app_context);
    
    event_loop.timeout(
            TimerEvent::ScanNetwork,
            Duration::new(0, 0))
        .unwrap();
    
    event_loop.run(&mut cmd_handler)
        .unwrap();
}
