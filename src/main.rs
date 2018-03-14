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

extern crate bytes;
extern crate farmhash;
extern crate libc;
extern crate native_tls;
extern crate openssl;
extern crate time;
extern crate uuid;

#[macro_use]
extern crate json;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate futures;

extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_timer;
extern crate tokio_tls;

pub mod futures_ex;

#[macro_use]
pub mod utils;

pub mod net;

pub mod config;
pub mod context;
pub mod cmd_handler;
pub mod scanner;
pub mod svc_table;
pub mod timer;

use std::process;
use std::thread;

use std::error::Error;
use std::fmt::Debug;
use std::time::Duration;

use tokio_core::reactor::Core as TokioCore;

use config::usage;

use config::ApplicationConfig;
use context::{ApplicationContext, ConnectionState};

use cmd_handler::{Command, CommandChannel};

use net::arrow;

use net::arrow::{ArrowError, ErrorKind};

use timer::DEFAULT_TIMER;

use utils::logger::Logger;

/// Connectionn retry timeout.
const RETRY_TIMEOUT: f64 = 60.0;

/// Get maximum duration of the pairing mode.
const PAIRING_MODE_TIMEOUT: f64 = 1200.0;

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

/// Arrow Client main thread.
///
/// This function ensures maintaining connection with a remote Arrow Service.
fn arrow_thread(mut app_context: ApplicationContext, cmd_channel: CommandChannel) {
    let mut logger = app_context.get_logger();

    let diagnostic_mode = app_context.get_diagnostic_mode();
    let addr = app_context.get_arrow_service_address();

    let t = time::precise_time_s();

    let pairing_mode_timeout = t + PAIRING_MODE_TIMEOUT;

    let mut cur_addr = addr.clone();
    let mut last_attempt;

    loop {
        log_info!(logger, "connecting to remote Arrow Service {}", cur_addr);

        last_attempt = time::precise_time_s();

        app_context.set_connection_state(ConnectionState::Connected);

        let res = arrow::connect(
            app_context.clone(),
            cmd_channel.clone(),
            &cur_addr);

        if diagnostic_mode {
            diagnose_connection_result(&res);
        }

        match res {
            Ok(addr) => cur_addr = addr,
            Err(err) => {
                if err.kind() == ErrorKind::Unauthorized {
                    log_info!(logger, "connection rejected by the remote service {}; is the client paired?", cur_addr);
                } else {
                    log_warn!(logger, "{}", err.description());
                }

                let cstate = match err.kind() {
                    ErrorKind::Unauthorized => ConnectionState::Unauthorized,
                    _                       => ConnectionState::Disconnected,
                };

                app_context.set_connection_state(cstate);

                let retry = process_connection_error(
                    err,
                    last_attempt,
                    pairing_mode_timeout);

                wait_for_retry(&mut logger, retry);

                cur_addr = addr.to_string();
            }
        }
    }
}

/// Connection retry variants. There are only two options - the connection can
/// be either retried after a specified timeout or there should be no more
/// connection attempts because of a specified reason.
#[derive(Debug, Copy, Clone)]
enum ConnectionRetry {
    Timeout(f64),
    Suspend(SuspendReason),
}

/// Reason for suspending the Arrow connection thread.
#[derive(Debug, Copy, Clone)]
enum SuspendReason {
    NotInPairingMode,
    UnsupportedProtocolVersion,
}

impl SuspendReason {
    fn to_string(&self) -> &str {
        match *self {
            SuspendReason::NotInPairingMode =>
                "pairing window timeout",
            SuspendReason::UnsupportedProtocolVersion =>
                "unsupported protocol version",
        }
    }
}

/// Process a given connection error and return a ConnectionRetry instance.
fn process_connection_error(
    connection_error: ArrowError,
    last_attempt: f64,
    pairing_mode_timeout: f64) -> ConnectionRetry {
    let t = time::precise_time_s();

    match connection_error.kind() {
        // the client is not authorized to access the service yet; check the
        // pairing mode timeout
        ErrorKind::Unauthorized => match pairing_mode_timeout {
            // retry every 10 seconds in the first 10 minutes since the first
            // "unauthorized" response
            timeout if t < (timeout - 600.0) => ConnectionRetry::Timeout(10.0),
            // retry every 30 seconds after the first 10 minutes since the
            // first "unauthorized" response
            timeout if t < timeout => ConnectionRetry::Timeout(30.0),
            // suspend the thread after the first 20 minutes since the client
            // thread start
            _ => ConnectionRetry::Suspend(SuspendReason::NotInPairingMode),
        },
        // suspend the thread if the version of the Arrow Protocol is not
        // supported by either side
        ErrorKind::UnsupportedProtocolVersion =>
            ConnectionRetry::Suspend(SuspendReason::UnsupportedProtocolVersion),
        // in all other cases
        _ => ConnectionRetry::Timeout(RETRY_TIMEOUT + last_attempt - t),
    }
}

/// Process a given connection retry object.
fn wait_for_retry(logger: &mut Logger, connection_retry: ConnectionRetry) {
    match connection_retry {
        ConnectionRetry::Timeout(t) if t > 0.5 => {
            log_info!(logger, "retrying in {:.3} seconds", t);

            thread::sleep(Duration::from_millis((t * 1000.0) as u64));
        },
        ConnectionRetry::Timeout(_) => (),
        ConnectionRetry::Suspend(reason) => {
            log_info!(logger, "{}", reason.to_string());
            log_info!(logger, "suspending the connection thread");

            loop {
                thread::sleep(Duration::from_millis(60000));
            }
        },
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

/// Arrow Client main function.
fn main() {
    let mut core = TokioCore::new()
        .expect("unable to create an event loop");

    let handle = core.handle();

    let config = result_or_usage(
        ApplicationConfig::create());

    let context = ApplicationContext::new(config);

    let mut logger = context.get_logger();

    log_info!(&mut logger,
        "application started (uuid: {}, mac: {})",
        context.get_arrow_uuid(), context.get_arrow_mac_address());

    // create command handler
    let (tx, rx) = cmd_handler::new(context.clone());

    let cmd_channel = tx.clone();

    // schedule periodic network scan
    let periodic_network_scan = DEFAULT_TIMER
        .create_periodic_task(
            Duration::from_secs(1),
            move || {
                tx.send(Command::PeriodicNetworkScan)
            }
        );

    handle.spawn(periodic_network_scan);

    // start the Arrow client thread
    thread::spawn(move || {
        arrow_thread(context, cmd_channel)
    });

    // run the command handler event loop
    core.run(rx)
        .unwrap_or_default();
}
