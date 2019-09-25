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

#[macro_use]
extern crate futures;

#[macro_use]
extern crate json;

#[cfg(feature = "discovery")]
#[macro_use]
extern crate lazy_static;

#[macro_use]
pub mod utils;

pub mod cmd_handler;
pub mod config;
pub mod context;
pub mod futures_ex;
pub mod net;
pub mod runtime;
pub mod scanner;
pub mod svc_table;

use std::process;

use std::error::Error;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{Future, Stream};

use tokio::timer::{Delay, Interval};

use crate::net::arrow;

use crate::cmd_handler::{Command, CommandChannel};
use crate::config::ApplicationConfig;
use crate::context::{ApplicationContext, ConnectionState};
use crate::net::arrow::{ArrowError, ErrorKind};
use crate::utils::logger::{BoxLogger, Logger};

use crate::config::usage;

/// Connectionn retry timeout.
const RETRY_TIMEOUT: f64 = 60.0;

/// Get maximum duration of the pairing mode.
const PAIRING_MODE_TIMEOUT: f64 = 1200.0;

/// Unwrap a given result (if possible) or print the error message and exit
/// the process printing application usage.
fn result_or_usage<T, E>(res: Result<T, E>) -> T
where
    E: Error + Debug,
{
    match res {
        Ok(res) => res,
        Err(err) => {
            println!("ERROR: {}\n", err);
            usage(1);
        }
    }
}

/// This future ensures maintaining connection with a remote Arrow Service.
struct ArrowMainTask {
    app_context: ApplicationContext,
    cmd_channel: CommandChannel,
    logger: BoxLogger,
    default_addr: String,
    current_addr: String,
    last_attempt: f64,
    pairing_mode_timeout: f64,
    diagnostic_mode: bool,
}

impl ArrowMainTask {
    /// Create a new task.
    fn new(
        app_context: ApplicationContext,
        cmd_channel: CommandChannel,
    ) -> impl Future<Item = (), Error = ()> {
        let logger = app_context.get_logger();
        let addr = app_context.get_arrow_service_address();
        let diagnostic_mode = app_context.get_diagnostic_mode();

        let t = time::precise_time_s();

        let pairing_mode_timeout = t + PAIRING_MODE_TIMEOUT;

        let task = ArrowMainTask {
            app_context: app_context,
            cmd_channel: cmd_channel,
            logger: logger,
            default_addr: addr.clone(),
            current_addr: addr,
            last_attempt: t,
            pairing_mode_timeout: pairing_mode_timeout,
            diagnostic_mode: diagnostic_mode,
        };

        let task = Arc::new(Mutex::new(task));

        let connector = task.clone();
        let rhandler = task;

        futures::stream::repeat(())
            .and_then(move |_| connector.lock().unwrap().connect())
            .then(move |res| rhandler.lock().unwrap().process_result(res))
            .for_each(|_| Ok(()))
    }

    /// Connect to the Arrow service.
    fn connect(&mut self) -> impl Future<Item = String, Error = ArrowError> {
        log_info!(
            &mut self.logger,
            "connecting to remote Arrow Service {}",
            self.current_addr
        );

        self.last_attempt = time::precise_time_s();

        self.app_context
            .set_connection_state(ConnectionState::Connected);

        arrow::connect(
            self.app_context.clone(),
            self.cmd_channel.clone(),
            &self.current_addr,
        )
    }

    /// Process a given connection result.
    fn process_result(
        &mut self,
        res: Result<String, ArrowError>,
    ) -> impl Future<Item = (), Error = ()> {
        if self.diagnostic_mode {
            diagnose_connection_result(&res);
        } else if let Ok(addr) = res {
            // set redirection
            self.current_addr = addr;

            Box::new(futures::future::ok(()))
        } else if let Err(err) = res {
            if err.kind() == ErrorKind::Unauthorized {
                log_info!(
                    &mut self.logger,
                    "connection rejected by the remote service {}; is the client paired?",
                    self.current_addr
                );
            } else {
                log_warn!(&mut self.logger, "{}", err.description());
            }

            let cstate = match err.kind() {
                ErrorKind::Unauthorized => ConnectionState::Unauthorized,
                _ => ConnectionState::Disconnected,
            };

            self.app_context.set_connection_state(cstate);

            let retry = process_connection_error(err, self.last_attempt, self.pairing_mode_timeout);

            self.current_addr = self.default_addr.clone();

            wait_for_retry(&mut self.logger, retry)
        } else {
            panic!("unexpected Result variant")
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
            SuspendReason::NotInPairingMode => "pairing window timeout",
            SuspendReason::UnsupportedProtocolVersion => "unsupported protocol version",
        }
    }
}

/// Process a given connection error and return a ConnectionRetry instance.
fn process_connection_error(
    connection_error: ArrowError,
    last_attempt: f64,
    pairing_mode_timeout: f64,
) -> ConnectionRetry {
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
        ErrorKind::UnsupportedProtocolVersion => {
            ConnectionRetry::Suspend(SuspendReason::UnsupportedProtocolVersion)
        }
        // in all other cases
        _ => ConnectionRetry::Timeout(RETRY_TIMEOUT + last_attempt - t),
    }
}

/// Process a given connection retry object.
fn wait_for_retry(
    logger: &mut dyn Logger,
    connection_retry: ConnectionRetry,
) -> Box<dyn Future<Item = (), Error = ()> + Send + Sync> {
    match connection_retry {
        ConnectionRetry::Timeout(t) if t > 0.5 => {
            log_info!(logger, "retrying in {:.3} seconds", t);

            let time = Duration::from_millis((t * 1000.0) as u64);
            let sleep = Delay::new(Instant::now() + time).map_err(|_| ());

            Box::new(sleep)
        }
        ConnectionRetry::Timeout(_) => Box::new(futures::future::ok(())),
        ConnectionRetry::Suspend(reason) => {
            log_info!(logger, "{}", reason.to_string());
            log_info!(logger, "suspending the connection thread");

            Box::new(futures::future::empty())
        }
    }
}

/// Diagnose a given connection result and exit with exit code 0 if the
/// connection was successful or the server responded with UNAUTHORIZED,
/// otherwise exit with exit code 1.
fn diagnose_connection_result(connection_result: &Result<String, ArrowError>) -> ! {
    match connection_result {
        &Ok(_) => process::exit(0),
        &Err(ref err) => match err.kind() {
            ErrorKind::Unauthorized => process::exit(0),
            _ => process::exit(1),
        },
    }
}

/// Arrow Client main function.
fn main() {
    let config = result_or_usage(ApplicationConfig::create());

    let context = ApplicationContext::new(config);

    let mut logger = context.get_logger();

    log_info!(
        &mut logger,
        "application started (uuid: {}, mac: {})",
        context.get_arrow_uuid(),
        context.get_arrow_mac_address()
    );

    // create command handler
    let (tx, rx) = cmd_handler::new(context.clone());

    let cmd_channel = tx.clone();

    // create Arrow client main task
    let arrow_main_task = ArrowMainTask::new(context, cmd_channel);

    let interval = Duration::from_millis(1000);

    // schedule periodic network scan
    let periodic_network_scan = Interval::new(Instant::now() + interval, interval)
        .for_each(move |_| {
            tx.send(Command::PeriodicNetworkScan);

            Ok(())
        })
        .map_err(|_| ());

    runtime::run(futures::future::lazy(|| {
        tokio::spawn(rx);
        tokio::spawn(periodic_network_scan);

        arrow_main_task
    }));
}
