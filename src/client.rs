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

use std::pin::Pin;
use std::time::{Duration, Instant};

use futures::future::{AbortHandle, Future, FutureExt};
use futures::stream::StreamExt;
use futures::task::{Context, Poll};

use uuid::Uuid;

use crate::cmd_handler;
use crate::net::arrow;

use crate::cmd_handler::{Command, CommandChannel};
use crate::config::Config;
use crate::context::{ApplicationContext, ConnectionState};
use crate::net::arrow::{ArrowError, ErrorKind};
use crate::net::raw::ether::MacAddr;
use crate::svc_table::Service;
use crate::utils::logger::{BoxLogger, Logger};
use crate::ArrowClientEventListener;

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
    async fn start(app_context: ApplicationContext, cmd_channel: CommandChannel) {
        let logger = app_context.get_logger();
        let addr = app_context.get_arrow_service_address();
        let diagnostic_mode = app_context.get_diagnostic_mode();

        let now = Instant::now();

        let pairing_mode_timeout = now + PAIRING_MODE_TIMEOUT;

        let mut task = ArrowMainTask {
            app_context,
            cmd_channel,
            logger,
            default_addr: addr.clone(),
            current_addr: addr,
            last_attempt: now,
            pairing_mode_timeout,
            diagnostic_mode,
        };

        loop {
            let connection_result = task.connect().await;

            task.process_result(connection_result).await;
        }
    }

    /// Connect to the Arrow service.
    async fn connect(&mut self) -> Result<String, ArrowError> {
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
        .await
    }

    /// Process a given connection result.
    async fn process_result(&mut self, res: Result<String, ArrowError>) {
        if self.diagnostic_mode {
            diagnose_connection_result(&res);
        } else if let Ok(addr) = res {
            // set redirection
            self.current_addr = addr;
        } else if let Err(err) = res {
            let cstate = if err.kind() == ErrorKind::Unauthorized {
                log_info!(
                    &mut self.logger,
                    "connection rejected by the remote service {}; is the client paired?",
                    self.current_addr
                );

                ConnectionState::Unauthorized
            } else {
                log_warn!(&mut self.logger, "{}", err);

                ConnectionState::Disconnected
            };

            self.app_context.set_connection_state(cstate);

            let retry = process_connection_error(err, self.last_attempt, self.pairing_mode_timeout);

            self.current_addr = self.default_addr.clone();

            let fut = wait_for_retry(&mut self.logger, retry);

            fut.await;
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
async fn wait_for_retry(logger: &mut dyn Logger, connection_retry: ConnectionRetry) {
    match connection_retry {
        ConnectionRetry::Timeout(t) if t > Duration::from_millis(500) => {
            log_info!(
                logger,
                "retrying in {}.{:03} seconds",
                t.as_secs(),
                t.subsec_millis()
            );

            let delay = tokio::time::delay_for(t);

            delay.await;
        }
        ConnectionRetry::Timeout(_) => (),
        ConnectionRetry::Suspend(reason) => {
            log_info!(logger, "{}", reason.to_string());
            log_info!(logger, "suspending the connection thread");

            let halt = futures::future::pending::<()>();

            halt.await;
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
    inner: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Future for ArrowClientTask {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.inner.poll_unpin(cx)
    }
}

/// Arrow client.
pub struct ArrowClient {
    application_context: ApplicationContext,

    command_channel: Option<CommandChannel>,

    cancel_main_task: Option<AbortHandle>,
    cancel_nw_scan: Option<AbortHandle>,
}

impl ArrowClient {
    /// Create a new Arrow client from a given config.
    pub fn new(config: Config) -> (ArrowClient, ArrowClientTask) {
        let context = ApplicationContext::new(config);

        // create command handler
        let (cmd_channel, cmd_handler) = cmd_handler::new(context.clone());

        // create Arrow client main task
        let arrow_main_task = ArrowMainTask::start(context.clone(), cmd_channel.clone());

        let nw_scan_cmd_channel = cmd_channel.clone();

        // schedule periodic network scan
        let periodic_network_scan = async move {
            let mut interval = tokio::time::interval(Duration::from_millis(1000));
            while interval.next().await.is_some() {
                nw_scan_cmd_channel.send(Command::PeriodicNetworkScan);
            }
        };

        let (arrow_main_task, cancel_main_task) = futures::future::abortable(arrow_main_task);
        let (periodic_network_scan, cancel_nw_scan) =
            futures::future::abortable(periodic_network_scan.boxed());

        let ctx = context.clone();

        let task = async move {
            tokio::spawn(cmd_handler);
            tokio::spawn(periodic_network_scan.map(|_| ()));

            let mut logger = ctx.get_logger();

            log_info!(
                &mut logger,
                "Arrow Client started (uuid: {}, mac: {})",
                ctx.get_arrow_uuid(),
                ctx.get_arrow_mac_address()
            );

            arrow_main_task.await.unwrap_or(());
        };

        let arrow_client_task = ArrowClientTask {
            inner: task.boxed(),
        };

        let arrow_client = Self {
            application_context: context,

            command_channel: Some(cmd_channel),

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

    /// Get current service table.
    pub fn get_service_table(&self) -> Vec<(u16, Service)> {
        self.application_context
            .get_service_table()
            .visible()
            .filter_map(|(id, svc)| {
                if svc.is_control() {
                    None
                } else {
                    Some((id, svc))
                }
            })
            .collect()
    }

    /// Add a new event listener.
    pub fn add_event_listener<T>(&mut self, listener: T)
    where
        T: 'static + ArrowClientEventListener + Send,
    {
        self.application_context.add_event_listener(listener)
    }

    /// Scan the local network.
    pub fn scan_network(&mut self) {
        if let Some(channel) = self.command_channel.as_ref() {
            channel.send(Command::ScanNetwork);
        }
    }

    /// Clear the service table and scan the local network again.
    pub fn rescan_network(&mut self) {
        if let Some(channel) = self.command_channel.as_ref() {
            channel.send(Command::ResetServiceTable);
            channel.send(Command::ScanNetwork);
        }
    }

    /// Close the Arrow client.
    pub fn close(&mut self) {
        if let Some(handle) = self.cancel_nw_scan.take() {
            handle.abort();
        }

        if let Some(handle) = self.cancel_main_task.take() {
            handle.abort();
        }

        // we need to drop also the command channel in order to stop the related background task
        self.command_channel = None;
    }
}

impl Drop for ArrowClient {
    fn drop(&mut self) {
        self.close()
    }
}
