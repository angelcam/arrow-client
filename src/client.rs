// Copyright 2019 Angelcam, Inc.
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

use std::process;

use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::sync::oneshot::Sender;
use futures::{Future, Poll, Stream};

use tokio::timer::{Delay, Interval};

use uuid::Uuid;

use crate::cmd_handler;
use crate::net::arrow;

use crate::cmd_handler::{Command, CommandChannel};
use crate::config::Config;
use crate::context::{ApplicationContext, ConnectionState};
use crate::net::arrow::{ArrowError, ErrorKind};
use crate::net::raw::ether::MacAddr;
use crate::utils::logger::{BoxLogger, Logger};

/// Connection retry timeout.
const RETRY_TIMEOUT: Duration = Duration::from_secs(60);

/// Get maximum duration of the pairing mode.
const PAIRING_MODE_TIMEOUT: Duration = Duration::from_secs(1200);

/// This future ensures maintaining connection with a remote Arrow Service.
struct ArrowMainTask {
    app_context: ApplicationContext,
    cmd_channel: CommandChannel,
    logger: BoxLogger,
    default_addr: String,
    current_addr: String,
    last_attempt: Instant,
    pairing_mode_timeout: Instant,
    diagnostic_mode: bool,
}

impl ArrowMainTask {
    /// Create a new task.
    #[allow(clippy::new_ret_no_self)]
    fn new(
        app_context: ApplicationContext,
        cmd_channel: CommandChannel,
    ) -> impl Future<Item = (), Error = ()> {
        let logger = app_context.get_logger();
        let addr = app_context.get_arrow_service_address();
        let diagnostic_mode = app_context.get_diagnostic_mode();

        let now = Instant::now();

        let pairing_mode_timeout = now + PAIRING_MODE_TIMEOUT;

        let task = ArrowMainTask {
            app_context,
            cmd_channel,
            logger,
            default_addr: addr.clone(),
            current_addr: addr,
            last_attempt: now,
            pairing_mode_timeout,
            diagnostic_mode,
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

        self.last_attempt = Instant::now();

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
            let cstate = if err.kind() == ErrorKind::Unauthorized {
                log_info!(
                    &mut self.logger,
                    "connection rejected by the remote service {}; is the client paired?",
                    self.current_addr
                );

                ConnectionState::Unauthorized
            } else {
                log_warn!(&mut self.logger, "{}", err.description());

                ConnectionState::Disconnected
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
    Timeout(Duration),
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
    last_attempt: Instant,
    pairing_mode_timeout: Instant,
) -> ConnectionRetry {
    let now = Instant::now();

    match connection_error.kind() {
        // the client is not authorized to access the service yet; check the
        // pairing mode timeout
        ErrorKind::Unauthorized => {
            if (now + Duration::from_secs(600)) < pairing_mode_timeout {
                // retry every 10 seconds in the first 10 minutes since the
                // first "unauthorized" response
                ConnectionRetry::Timeout(Duration::from_secs(10))
            } else if now < pairing_mode_timeout {
                // retry every 30 seconds after the first 10 minutes since the
                // first "unauthorized" response
                ConnectionRetry::Timeout(Duration::from_secs(30))
            } else {
                // suspend the thread after the first 20 minutes since the
                // client thread start
                ConnectionRetry::Suspend(SuspendReason::NotInPairingMode)
            }
        }
        // suspend the thread if the version of the Arrow Protocol is not
        // supported by either side
        ErrorKind::UnsupportedProtocolVersion => {
            ConnectionRetry::Suspend(SuspendReason::UnsupportedProtocolVersion)
        }
        // in all other cases
        _ => {
            let next_attempt = last_attempt + RETRY_TIMEOUT;

            if next_attempt > now {
                ConnectionRetry::Timeout(next_attempt - now)
            } else {
                ConnectionRetry::Timeout(Duration::from_secs(0))
            }
        }
    }
}

/// Process a given connection retry object.
fn wait_for_retry(
    logger: &mut dyn Logger,
    connection_retry: ConnectionRetry,
) -> Box<dyn Future<Item = (), Error = ()> + Send + Sync> {
    match connection_retry {
        ConnectionRetry::Timeout(t) if t > Duration::from_millis(500) => {
            log_info!(
                logger,
                "retrying in {}.{:03} seconds",
                t.as_secs(),
                t.subsec_millis()
            );

            let sleep = Delay::new(Instant::now() + t).map_err(|_| ());

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
        Ok(_) => process::exit(0),
        Err(err) => match err.kind() {
            ErrorKind::Unauthorized => process::exit(0),
            _ => process::exit(1),
        },
    }
}

/// Arrow client task. It must be awaited, otherwise it won't do anything.
pub struct ArrowClientTask {
    inner: Box<dyn Future<Item = (), Error = ()> + Send>,
}

impl Future for ArrowClientTask {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.inner.poll()
    }
}

/// Arrow client.
pub struct ArrowClient {
    application_context: ApplicationContext,

    cancel_main_task: Option<Sender<()>>,
    cancel_nw_scan: Option<Sender<()>>,
}

impl ArrowClient {
    /// Create a new Arrow client from a given config.
    pub fn new(config: Config) -> (ArrowClient, ArrowClientTask) {
        let context = ApplicationContext::new(config);

        // create command handler
        let (tx, rx) = cmd_handler::new(context.clone());

        let cmd_channel = tx.clone();

        let (cancel_main_task, main_task_cancelled) = futures::sync::oneshot::channel();
        let (cancel_nw_scan, nw_scan_cancelled) = futures::sync::oneshot::channel();

        // create Arrow client main task
        let arrow_main_task = ArrowMainTask::new(context.clone(), cmd_channel)
            .select(main_task_cancelled.map_err(|_| ()))
            .then(|_| Ok(()));

        let interval = Duration::from_millis(1000);

        // schedule periodic network scan
        let periodic_network_scan = Interval::new(Instant::now() + interval, interval)
            .for_each(move |_| {
                tx.send(Command::PeriodicNetworkScan);

                Ok(())
            })
            .map_err(|_| ())
            .select(nw_scan_cancelled.map_err(|_| ()))
            .then(|_| Ok(()));

        let ctx = context.clone();

        let task = futures::future::lazy(move || {
            tokio::spawn(rx);
            tokio::spawn(periodic_network_scan);

            let mut logger = ctx.get_logger();

            log_info!(
                &mut logger,
                "Arrow Client started (uuid: {}, mac: {})",
                ctx.get_arrow_uuid(),
                ctx.get_arrow_mac_address()
            );

            arrow_main_task
        });

        let arrow_client_task = ArrowClientTask {
            inner: Box::new(task),
        };

        let arrow_client = Self {
            application_context: context,

            cancel_main_task: Some(cancel_main_task),
            cancel_nw_scan: Some(cancel_nw_scan),
        };

        (arrow_client, arrow_client_task)
    }

    /// Get Arrow client UUID.
    pub fn get_arrow_uuid(&self) -> Uuid {
        self.application_context.get_arrow_uuid()
    }

    /// Get Arrow client MAC address.
    pub fn get_mac_address(&self) -> MacAddr {
        self.application_context.get_arrow_mac_address()
    }

    /// Get connection state.
    pub fn get_connection_state(&self) -> ConnectionState {
        self.application_context.get_connection_state()
    }

    /// Check if the client is currently scanning network.
    pub fn is_scanning(&self) -> bool {
        self.application_context.is_scanning()
    }

    /// Close the Arrow client.
    pub fn close(&mut self) {
        if let Some(cancel) = self.cancel_nw_scan.take() {
            cancel.send(()).unwrap_or_default()
        }

        if let Some(cancel) = self.cancel_main_task.take() {
            cancel.send(()).unwrap_or_default()
        }
    }
}

impl Drop for ArrowClient {
    fn drop(&mut self) {
        self.close()
    }
}
