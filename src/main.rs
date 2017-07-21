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

extern crate libc;
extern crate regex;
extern crate native_tls;
extern crate openssl;
extern crate time;
extern crate uuid;

extern crate bytes;

#[macro_use]
extern crate futures;

#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;

extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_timer;
extern crate tokio_tls;

pub mod futures_ex;

#[macro_use]
pub mod utils;

pub mod net;

mod config;
mod context;
mod svc_table;

/*use std::io;
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
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use utils::logger;

use utils::{Shared, RuntimeError};
use utils::logger::{Logger, Severity, BoxedLogger};
use utils::config::{ArrowConfig, AppContext};

#[cfg(feature = "discovery")]
use net::discovery;

use net::raw::ether::MacAddr;
use net::raw::devices::EthernetDevice;
use net::arrow::error::{ArrowError, ErrorKind};
use net::arrow::{ArrowClient, Sender, Command};
use net::arrow::protocol::{Service, ServiceTable};

use openssl::ssl;

use openssl::nid::Nid;
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

/// Initialize SSL context.
fn init_ssl(
    method: SslMethod,
    cipher_list: &str) -> Result<SslContext, ssl::Error> {
    let mut ssl_context = try!(SslContext::new(method));
    try!(ssl_context.set_cipher_list(cipher_list));
    ssl_context.set_options(SSL_OP_NO_COMPRESSION);
    ssl_context.set_verify(SSL_VERIFY_PEER);
    ssl_context.set_verify_depth(4);
    Ok(ssl_context)
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
    if let Some(cert) = x509_ctx.current_cert() {
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
    state_file: &str,
    ssl_context: SslContext,
    cmd_sender: CommandSender,
    addr: &str,
    arrow_mac: &MacAddr,
    app_context: &Shared<AppContext>) {
    let state_file  = state_file.to_string();
    let addr        = addr.to_string();
    let arrow_mac   = arrow_mac.clone();
    let app_context = app_context.clone();

    thread::spawn(move || arrow_thread(logger, &state_file,
        ssl_context, cmd_sender,
        &addr, &arrow_mac, app_context));
}

/// Arrow Client main thread.
///
/// This function ensures maintaining connection with a remote Arrow Service.
fn arrow_thread<L: Logger + Clone, Q: Sender<Command> + Clone>(
    mut logger: L,
    state_file: &str,
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
    let tmp_vdata   = verify_data.clone();

    ssl_context.set_verify_callback(
        SSL_VERIFY_PEER,
        move |pv, x509c| openssl_verify_callback(pv, x509c, &tmp_vdata));

    loop {
        log_info!(logger, "connecting to remote Arrow Service {}", cur_addr);

        let lgr = logger.clone();
        let ctx = app_context.clone();

        last_attempt = time::precise_time_s();

        utils::result_or_log(&mut logger, Severity::INFO,
            "unable to save current connection state",
            save_connection_state(CONN_STATE_CONNECTED, state_file));

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
                         save_connection_state(CONN_STATE_UNAUTHORIZED, state_file),
                    _ => save_connection_state(CONN_STATE_DISCONNECTED, state_file)
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
fn save_connection_state(
    state: &str,
    state_file: &str) -> Result<(), io::Error> {
    let file = try!(File::create(state_file));
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
    let addr = try!(net::utils::get_socket_address(addr)
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
    rtsp_paths_file: &str,
    mjpeg_paths_file: &str,
    app_context: Shared<AppContext>) {
    log_info!(logger, "looking for local services...");
    let report = utils::result_or_log(&mut logger, Severity::WARN,
        "network scanner error",
        discovery::scan_network(
            rtsp_paths_file,
            mjpeg_paths_file));

    if let Some(report) = report {
        let mut app_context = app_context.lock()
            .unwrap();

        {
            let config   = &mut app_context.config;
            let services = report.services();
            let count    = services.len();

            for svc in services {
                config.add(svc.clone());
            }

            config.update_active_services();

            log_info!(logger, "{} services found, current service table: {}",
                count, config.service_table());
        }

        app_context.scan_report = report;
    }
}

#[cfg(not(feature = "discovery"))]
/// Dummy scanner.
fn network_scanner_thread<L>(_: L, _: &str, _: &str, _: Shared<AppContext>) {
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
    config_file:       String,
    rtsp_paths_file:   String,
    mjpeg_paths_file:  String,
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
        config_file: &str,
        rtsp_paths_file: &str,
        mjpeg_paths_file: &str,
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
            config_file:       config_file.to_string(),
            rtsp_paths_file:   rtsp_paths_file.to_string(),
            mjpeg_paths_file:  mjpeg_paths_file.to_string(),
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

        event_loop.timeout_ms(
                TimerEvent::ScanNetwork,
                (timeout * 1000.0) as u64)
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

            let logger           = self.logger.clone();
            let rtsp_paths_file  = self.rtsp_paths_file.clone();
            let mjpeg_paths_file = self.mjpeg_paths_file.clone();
            let app_context      = self.app_context.clone();
            let sender           = event_loop.channel();

            let handle = thread::spawn(move || {
                network_scanner_thread(logger,
                    &rtsp_paths_file,
                    &mjpeg_paths_file,
                    app_context);

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
                format!("unable to save config file \"{}\"", self.config_file),
                config.save(&self.config_file));
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
            format!("unable to save config file \"{}\"", self.config_file),
            config.save(&self.config_file));
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
    let mut app_config = AppConfiguration::init();

    let app_context = app_config.app_context;

    utils::result_or_error(app_context.config.save(&app_config.config_file),
        EXIT_CODE_CONFIG_ERROR,
        format!("unable to save config file \"{}\"", &app_config.config_file));

    log_info!(&mut app_config.logger,
        "application started (uuid: {}, mac: {})",
        app_context.config.uuid_string(), app_config.arrow_mac);

    let app_context = Shared::new(app_context);

    let mut event_loop = EventLoop::new()
        .unwrap();

    let mut cmd_handler = CommandHandler::new(
        app_config.logger.clone(),
        &app_config.config_file,
        &app_config.rtsp_paths_file,
        &app_config.mjpeg_paths_file,
        app_config.default_svc_table,
        app_context.clone());

    let cmd_sender = CommandSender::new(event_loop.channel());

    spawn_arrow_thread(
        app_config.logger,
        &app_config.state_file,
        app_config.ssl_context,
        cmd_sender,
        &app_config.arrow_svc_addr,
        &app_config.arrow_mac,
        &app_context);

    event_loop.timeout_ms(TimerEvent::ScanNetwork, 0)
        .unwrap();

    event_loop.run(&mut cmd_handler)
        .unwrap();
}*/

use std::fmt::Debug;
use std::error::Error;

use config::usage;

use config::ApplicationConfig;
use context::ApplicationContext;

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

/// Arrow Client main function.
fn main() {
    let config = result_or_usage(
        ApplicationConfig::create());

    let context = ApplicationContext::new(config);

    println!("Hello, World!!!");
}
