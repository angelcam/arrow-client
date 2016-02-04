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

use openssl::x509::X509FileType;
use openssl::ssl::error::SslError;
use openssl::ssl::{IntoSsl, SslContext, SslMethod};

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
    println!("USAGE: arrow-client arr-host[:arr-port] ca-cert [OPTIONS]\n");
    println!("    arr-host  Angelcam Arrow Service host");
    println!("    arr-port  Angelcam Arrow Service port\n");
    println!("    ca-cert   CA certificate in PEM format for Arrow Service identity");
    println!("              verification\n");
    println!("OPTIONS:\n");
    if cfg!(feature = "discovery") {
        println!("    -d        automatic service discovery");
    }
    println!("    -r URL    local RTSP service URL");
    println!("    -v        enable debug logs\n");
    process::exit(exit_code);
}

/// Initialize SSL context. 
fn init_ssl(ca_file: &str) -> Result<SslContext, SslError> {
    let mut ssl_context = try!(SslContext::new(SslMethod::Tlsv1_2));
    try!(ssl_context.set_certificate_file(ca_file, X509FileType::PEM));
    try!(ssl_context.set_cipher_list("HIGH:!aNULL:!kRSA:!PSK:!MD5:!RC4"));
    Ok(ssl_context)
}

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
    let mut unauthorized_timeout = None;
    let mut cur_addr = addr.to_string();
    let mut last_attempt;
    
    loop {
        log_info!(logger, "connecting to remote Arrow Service {}", cur_addr);
        
        let lgr = logger.clone();
        let ctx = app_context.clone();
        
        last_attempt = time::precise_time_s();
        
        let res = match connect(lgr, &*ssl_context, cmd_sender.clone(), 
            &cur_addr, arrow_mac, ctx) {
            Ok(addr) => Ok(addr),
            Err(err) => {
                log_warn!(&mut logger, "{}", err.description());
                let t = time::precise_time_s();
                match err.kind() {
                    // the client is not authorized to access the service yet;
                    // check the authorization timeout
                    ErrorKind::Unauthorized => match unauthorized_timeout {
                        // retry every 10 seconds in the first 10 minutes since 
                        // the first "unauthorized" response
                        Some(timeout) if t < (timeout - 600.0) => Err(10.0),
                        // retry every 30 seconds after the first 10 minutes 
                        // since the first "unauthorized" response
                        Some(timeout) if t < timeout => Err(30.0),
                        // retry in 10 hours after the first 20 minutes since
                        // the first "unauthorized" response
                        Some(_) => Err(36000.0),
                        // no timeout has been set yet
                        None => {
                            // set the timeout to 20 minutes from now
                            unauthorized_timeout = Some(t + 1200.0);
                            // retry in 10 seconds
                            Err(10.0)
                        }
                    },
                    // we don't know if the client is authorized...
                    err => {
                        // ... but we assume it is if the last connection was 
                        // longer than RETRY_TIMEOUT seconds
                        if (last_attempt + RETRY_TIMEOUT) < t {
                            unauthorized_timeout = None;
                        }
                        // check the error
                        match err {
                            // set a very long retry timeout if the version of 
                            // the Arrow Protocol is not supported by either 
                            // side
                            ErrorKind::UnsupportedProtocolVersion => Err(36000.0),
                            // in all other cases
                            _ => Err(RETRY_TIMEOUT + last_attempt - t),
                        }
                    }
                }
            }
        };
        
        match res {
            Ok(addr) => cur_addr = addr,
            Err(t) => {
                if t > 0.5 {
                    log_info!(logger, "retrying in {:.3} seconds", t);
                    thread::sleep(Duration::from_millis((t * 1000.0) as u64));
                }
                
                cur_addr = addr.to_string();
            }
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
    discovery:         bool,
}

impl<L: 'static + Logger + Clone + Send> CommandHandler<L> {
    /// Create a new Arrow Command handler.
    fn new(
        logger: L, 
        default_svc_table: ServiceTable,
        app_context: Shared<AppContext>, 
        discovery: bool) -> CommandHandler<L> {
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
            last_scan:         now - NETWORK_SCAN_PERIOD,
            discovery:         discovery
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
        // check if the discovery is enabled and if there is another scanner 
        // running
        if self.discovery && self.scanner.is_none() {
            self.last_scan = time::precise_time_ns() / 1000000;
            
            let mut app_context = self.app_context.lock()
                .unwrap();
            
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
    
    if args.len() < 3 {
        usage(1);
    } else {
        let arrow_mac = utils::result_or_error(get_first_mac(), 2, 
            "unable to get any network interface MAC address");
        
        let arrow_addr = &args[1];
        let ca_file    = &args[2];
        
        let mut discovery = false;
        
        let mut i = 3;
        
        let mut config = ArrowConfig::load(CONFIG_FILE)
            .unwrap_or(ArrowConfig::new());
        
        let mut default_svc_table = ServiceTable::new();
        
        while i < args.len() {
            match &args[i] as &str {
                "-d" if cfg!(feature = "discovery") => { discovery = true; },
                "-r" => {
                    let service = parse_rtsp_url(&args[i + 1]);
                    let service = result_or_usage(service);
                    config.add_static(service.clone());
                    default_svc_table.add_static(service);
                    i += 1;
                },
                "-v" => { logger.set_level(Severity::DEBUG); },
                _    => {
                    println!("unknown argument: {}\n", &args[i]);
                    usage(1);
                }
            }
            
            i += 1;
        }
        
        utils::result_or_error(config.save(CONFIG_FILE), 3, 
            format!("unable to save config file \"{}\"", CONFIG_FILE));
        
        let ssl_context = Arc::new(
            utils::result_or_error(init_ssl(ca_file), 4, 
                format!("unable to load CA certificate \"{}\"", ca_file)));
        
        log_info!(logger, "application started (uuid: {}, mac: {})", 
            config.uuid_string(), arrow_mac);
        
        let app_context = Shared::new(AppContext::new(config));
        
        let mut event_loop = EventLoop::new()
            .unwrap();
        
        let mut cmd_handler = CommandHandler::new(
            logger.clone(),
            default_svc_table,
            app_context.clone(),
            discovery);
        
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
