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
mod utils;

pub mod net;

use std::env;
use std::process;
use std::thread;

use std::sync::Arc;
use std::fmt::Debug;
use std::error::Error;
use std::str::FromStr;
use std::thread::JoinHandle;
use std::net::{SocketAddr, ToSocketAddrs};

use utils::logger::syslog;

use utils::{Shared, RuntimeError};
use utils::logger::{Logger, Severity};
use utils::config::{ArrowConfig, AppContext};

#[cfg(feature = "discovery")]
use net::discovery;

use net::raw::ether::MacAddr;
use net::raw::devices::EthernetDevice;
use net::arrow::error::ArrowError;
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
            println!("ERROR: {}\n", err.description());
            usage(1);
        }
    }
}

/// Parse a given RTSP URL and return Service::RTSP, Service::LockedRTSP or 
/// an error.
fn parse_rtsp_url(url: &str) -> Result<Service, RuntimeError> {
    let res = r"^rtsp://([^/]+@)?([^/@:]+|\[[0-9a-fA-F:.]+\])(:(\d+))?(/.*)?$";
    let re  = Regex::new(res).unwrap();
    
    if let Some(caps) = re.captures(url) {
        // we don't care about the actual MAC address
        let mac  = MacAddr::new(0, 0, 0, 0, 0, 0);
        let host = caps.at(2).unwrap();
        let path = caps.at(5).unwrap();
        let port = match caps.at(4) {
            Some(port_str) => u16::from_str(port_str).unwrap(),
            _ => 554
        };
        
        let socket_addr = try!(get_socket_address((host, port))
            .or(Err(RuntimeError::from(
                "unable to resolve RTSP service address"))));
        
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
    let mut last_error = time::precise_time_s();
    let mut cur_addr   = addr.to_string();
    
    loop {
        log_info!(logger, &format!("connecting to remote Arrow Service {}", cur_addr));
        
        let lgr = logger.clone();
        let ctx = app_context.clone();
        
        let res = match utils::result_or_log(&mut logger, Severity::WARN,
            connect(lgr, &*ssl_context, cmd_sender.clone(), 
                &cur_addr, arrow_mac, ctx)) {
            Some(addr) => Ok(addr),
            None => Err(time::precise_time_s())
        };
        
        match res {
            Ok(addr) => cur_addr = addr,
            Err(t) => {
                if (last_error + RETRY_TIMEOUT - 0.5) > t {
                    let retry = RETRY_TIMEOUT + last_error - t;
                    log_info!(logger, &format!("retrying in {:.3} seconds", retry));
                    thread::sleep_ms((retry * 1000.0) as u32);
                }
                
                cur_addr   = addr.to_string();
                last_error = t;
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
        .or(Err(ArrowError::from(format!("failed to lookup Arrow Service {} address information", addr)))));
    
    match ArrowClient::new(logger, s, cmd_sender, 
        &addr, arrow_mac, app_context) {
        Err(err) => Err(ArrowError::from(format!("unable to connect to remote Arrow Service {} ({})", addr, err.description()))),
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
        discovery::find_rtsp_streams());
    
    if let Some(services) = services {
        let mut app_context = app_context.lock()
            .unwrap();
        let config = &mut app_context.config;
        let count  = services.len();
        
        let bump = services.into_iter()
            .fold(false, |b, svc| {
                config.add(svc)
                    .is_some() | b
            });
        
        if bump {
            config.bump_version();
        }
        
        log_info!(logger, &format!("{} services found, current service table: {}", count, config));
        utils::result_or_log(&mut logger, Severity::WARN, 
            config.save(CONFIG_FILE));
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
    app_context:       Shared<AppContext>,
    scanner:           Option<JoinHandle<()>>,
    discovery:         bool,
}

impl<L: 'static + Logger + Clone + Send> CommandHandler<L> {
    /// Create a new Arrow Command handler.
    fn new(
        logger: L, 
        default_svc_table: ServiceTable,
        app_context: Shared<AppContext>, 
        discovery: bool) -> CommandHandler<L> {
        CommandHandler {
            logger:            logger,
            default_svc_table: default_svc_table,
            app_context:       app_context,
            scanner:           None,
            discovery:         discovery
        }
    }
    
    /// Scan the local network for new services and schedule the next network 
    /// scanning event.
    fn periodical_network_scan(&mut self, event_loop: &mut EventLoop<Self>) {
        self.scan_network(event_loop);
        
        event_loop.timeout_ms(TimerEvent::ScanNetwork, NETWORK_SCAN_PERIOD)
            .unwrap();
    }
    
    /// Spawn a new network scanner thread (if it is not already running) and 
    /// save its join handle.
    fn scan_network(&mut self, event_loop: &mut EventLoop<Self>) {
        // check if the discovery is enabled and if there is another scanner 
        // running
        if self.discovery && self.scanner.is_none() {
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
        let arrow_mac  = utils::result_or_error(get_first_mac(), 2);
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
                    config.add(service.clone());
                    default_svc_table.add(service);
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
        
        utils::result_or_error(config.save(CONFIG_FILE), 3);
        
        let ssl_context = Arc::new(
            utils::result_or_error(init_ssl(ca_file), 4));
        
        log_info!(logger, &format!("application started (uuid: {}, mac: {})", 
            config.uuid_string(), arrow_mac));
        
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
        
        event_loop.timeout_ms(TimerEvent::ScanNetwork, 0)
            .unwrap();
        
        event_loop.run(&mut cmd_handler)
            .unwrap();
    }
}
