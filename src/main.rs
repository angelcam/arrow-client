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
extern crate native_tls;
extern crate openssl;
extern crate time;
extern crate uuid;

#[macro_use]
extern crate json;

extern crate bytes;

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

    let mut pairing_mode_timeout = t + 1200.0;
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

        pairing_mode_timeout = get_pairing_mode_timeout(
            &res,
            last_attempt,
            pairing_mode_timeout);

        if diagnostic_mode {
            diagnose_connection_result(&res);
        }

        match res {
            Ok(addr) => cur_addr = addr,
            Err(err) => {
                log_warn!(logger, "{}", err.description());

                let cstate = match err.kind() {
                    ErrorKind::Unauthorized => ConnectionState::Unauthorized,
                    _                       => ConnectionState::Disconnected,
                };

                app_context.set_connection_state(cstate);

                let t = get_next_retry_timeout(
                    err,
                    last_attempt,
                    pairing_mode_timeout);

                if t > 0.5 {
                    log_info!(logger, "retrying in {:.3} seconds", t);
                    thread::sleep(Duration::from_millis((t * 1000.0) as u64));
                }

                cur_addr = addr.to_string();
            }
        }
    }
}

/// Get new timeout for the pairing mode.
fn get_pairing_mode_timeout(
    connection_result: &Result<String, ArrowError>,
    last_connection_attempt: f64,
    current_timeout: f64) -> f64 {
    let t = time::precise_time_s();

    match connection_result {
        // We know the client is authorized, we can update the timeout.
        &Ok(_)        => t + PAIRING_MODE_TIMEOUT,
        &Err(ref err) => match err.kind() {
            // We don't update the timeout in case the client is unauthorized.
            ErrorKind::Unauthorized => current_timeout,
            // We don't know if the client is authorized but we assume it is
            // if the last connection was longer than RETRY_TIMEOUT seconds.
            _ => if (last_connection_attempt + RETRY_TIMEOUT) < t {
                t + PAIRING_MODE_TIMEOUT
            } else {
                current_timeout
            }
        }
    }
}

/// Get next reconnect timeout for the Arrow Client thread.
fn get_next_retry_timeout(
    connection_error: ArrowError,
    last_connection_attempt: f64,
    pairing_mode_timeout: f64) -> f64 {
    let t = time::precise_time_s();

    match connection_error.kind() {
        // the client is not authorized to access the service yet; check the
        // pairing mode timeout
        ErrorKind::Unauthorized => match pairing_mode_timeout {
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
    let periodic_network_scan = context.get_timer()
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
