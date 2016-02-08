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

use std::env;
use std::process;
use std::thread;

use std::sync::Arc;
use std::fmt::Debug;
use std::error::Error;
use std::str::FromStr;
use std::path::Path;
use std::time::Duration;
use std::thread::JoinHandle;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

use utils::logger::syslog;

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

use openssl::ssl::error::SslError;
use openssl::ssl::{IntoSsl, SslContext, SslMethod};
use openssl::ssl::{SSL_VERIFY_PEER, SSL_OP_NO_COMPRESSION};

use mio::{EventLoop, Handler, NotifyError};

use regex::Regex;

/// Network scan period.
const NETWORK_SCAN_PERIOD: u64 = 300000;

/// Connectionn retry timeout.
const RETRY_TIMEOUT:       f64 = 60.0;

/// Arrow Client configuration file.
static CONFIG_FILE: &'static str = "/etc/arrow/config.json";

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
    let mut devices = EthernetDevice::list()
        .into_iter();
    
    match devices.next() {
        Some(dev) => Ok(dev.mac_addr),
        None => Err(RuntimeError::from("there is no configured ethernet device"))
    }
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
    println!("    -r URL    local RTSP service URL");
    println!("    -v        enable debug logs\n");
    println!("    --diagnostic-mode   start the client in diagnostic mode (i.e. the client");
    println!("                        will try to connect to a given Arrow Service and it");
    println!("                        will report succecc as its exit code; note: the");
    println!("                        \"access denied\" response from the server is also");
    println!("                        considered as a successes)\n");
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
fn load_ca_certificate_dir<L, P>(
    logger: &mut L, 
    ssl_context: &mut SslContext, 
    path: P) -> Result<(), RuntimeError> 
    where L: Logger,
          P: AsRef<Path> {
    let path = path.as_ref();
    let dir  = try!(path.read_dir()
        .map_err(|err| RuntimeError::from(format!("{}", err))));
    
    for entry in dir {
        let entry = try!(entry.map_err(|err|
            RuntimeError::from(format!("{}", err))));
        
        let path = entry.path();
        
        if path.is_dir() {
            try!(load_ca_certificate_dir(logger, ssl_context, &path));
        } else if is_cert_file(&path) {
            utils::result_or_log(logger, Severity::WARN, 
                format!("unable to load certificate file \"{}\"", 
                    path.to_string_lossy()),
                ssl_context.set_CA_file(&path));
        }
    }
    
    Ok(())
}

/// Load CA certificates from a given path.
fn load_ca_certificates<L, P>(
    logger: &mut L, 
    ssl_context: &mut SslContext, 
    path: P) -> Result<(), RuntimeError>
    where L: Logger,
          P: AsRef<Path> {
    let path = path.as_ref();
    if path.is_dir() {
        load_ca_certificate_dir(logger, ssl_context, path)
    } else {
        ssl_context.set_CA_file(path)
            .map_err(|err| RuntimeError::from(format!("{}", err)))
    }
}

// TODO: add server hostname verification as soon as it supported by the Rust 
// openssl wrapper

/*// Validate a given hostname using peer certificate. An error is returned 
/// if there is no peer certificate or the CN record does not match. No 
/// error is returned if there is no CN record.
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
}*/

/// Spawn a new Arrow Client thread.
fn spawn_arrow_thread<L: 'static + Logger + Clone + Send>(
    logger: L, 
    ssl_context: Arc<SslContext>,
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
    ssl_context: Arc<SslContext>,
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
    
    loop {
        log_info!(logger, "connecting to remote Arrow Service {}", cur_addr);
        
        let lgr = logger.clone();
        let ctx = app_context.clone();
        
        last_attempt = time::precise_time_s();
        
        let res = connect(lgr, &*ssl_context, cmd_sender.clone(), 
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
    }
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
fn connect<L: Logger + Clone, S: IntoSsl, Q: Sender<Command>>(
    logger: L,
    s: S,
    cmd_sender: Q,
    addr: &str,
    arrow_mac: &MacAddr,
    app_context: Shared<AppContext>) -> Result<String, ArrowError> {
    let addr = try!(get_socket_address(addr)
        .or(Err(ArrowError::connection_error(format!(
            "failed to lookup Arrow Service {} address information", addr)))));
    
    match ArrowClient::new(logger, s, cmd_sender, 
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
    last_scan:         u64,
}

impl<L: 'static + Logger + Clone + Send> CommandHandler<L> {
    /// Create a new Arrow Command handler.
    fn new(
        logger: L, 
        default_svc_table: ServiceTable,
        app_context: Shared<AppContext>) -> CommandHandler<L> {
        let now = time::precise_time_ns() / 1000000;
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
        let now     = time::precise_time_ns() / 1000000;
        let elapsed = (now - self.last_scan) as i64;
        let period  = NETWORK_SCAN_PERIOD as i64;
        let delta   = period - elapsed;
        
        if delta <= 0 {
            self.scan_network(event_loop);
            event_loop.timeout(
                    TimerEvent::ScanNetwork,
                    Duration::from_millis(NETWORK_SCAN_PERIOD))
                .unwrap();
        } else {
            event_loop.timeout(
                    TimerEvent::ScanNetwork,
                    Duration::from_millis(delta as u64))
                .unwrap();
        }
    }
    
    /// Spawn a new network scanner thread (if it is not already running) and 
    /// save its join handle.
    fn scan_network(&mut self, event_loop: &mut EventLoop<Self>) {
        let mut app_context = self.app_context.lock()
            .unwrap();
        
        // check if the discovery is enabled and if there is another scanner 
        // running
        if app_context.discovery && self.scanner.is_none() {
            self.last_scan = time::precise_time_ns() / 1000000;
            
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

/// Arrow Client main function.
fn main() {
    let mut logger = syslog::new();
    let args       = env::args()
        .collect::<Vec<_>>();
    
    if args.len() < 2 {
        usage(1);
    } else {
        let arrow_mac = utils::result_or_error(get_first_mac(), 2, 
            "unable to get any network interface MAC address");
        
        let arrow_addr = &args[1];
        
        let mut i = 2;
        
        let config = ArrowConfig::load(CONFIG_FILE)
            .unwrap_or(ArrowConfig::new());
        
        let mut default_svc_table = ServiceTable::new();
        let mut ssl_context       = utils::result_or_error(init_ssl(
            SslMethod::Tlsv1_2, "HIGH:!aNULL:!kRSA:!PSK:!MD5:!RC4"), 4,
            "unable to set up SSL context");
        let mut app_context       = AppContext::new(config);
        
        while i < args.len() {
            match &args[i] as &str {
                "-c" => {
                    utils::result_or_error(load_ca_certificates(
                        &mut logger, &mut ssl_context, &args[i + 1]), 5,
                        format!("unable to load certificate(s) from \"{}\"", 
                            &args[i + 1]));
                    i += 1;
                },
                "-d" if cfg!(feature = "discovery") => {
                    app_context.discovery = true;
                },
                "-r" => {
                    let service = parse_rtsp_url(&args[i + 1]);
                    let service = result_or_usage(service);
                    app_context.config.add_static(service.clone());
                    default_svc_table.add_static(service);
                    i += 1;
                },
                "-v" => {
                    logger.set_level(Severity::DEBUG);
                },
                "--diagnostic-mode" => {
                    app_context.diagnostic_mode = true;
                },
                _ => {
                    println!("unknown argument: {}\n", &args[i]);
                    usage(1);
                }
            }
            
            i += 1;
        }
        
        utils::result_or_error(app_context.config.save(CONFIG_FILE), 3, 
            format!("unable to save config file \"{}\"", CONFIG_FILE));
        
        log_info!(logger, "application started (uuid: {}, mac: {})", 
            app_context.config.uuid_string(), arrow_mac);
        
        let ssl_context = Arc::new(ssl_context);
        let app_context = Shared::new(app_context);
        
        let mut event_loop = EventLoop::new()
            .unwrap();
        
        let mut cmd_handler = CommandHandler::new(
            logger.clone(),
            default_svc_table,
            app_context.clone());
        
        let cmd_sender = CommandSender::new(event_loop.channel());
        
        spawn_arrow_thread(logger, ssl_context, cmd_sender, 
            arrow_addr, &arrow_mac, &app_context);
        
        event_loop.timeout(
                TimerEvent::ScanNetwork,
                Duration::new(0, 0))
            .unwrap();
        
        event_loop.run(&mut cmd_handler)
            .unwrap();
    }
}
