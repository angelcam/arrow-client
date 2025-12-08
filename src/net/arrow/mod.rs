// Copyright 2025 Angelcam, Inc.
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

mod rpc;
mod session;
mod svc_table;
mod utils;

use std::{
    fmt::{self, Display, Formatter},
    io,
    time::Duration,
};

use arrow_protocol::v3::{
    ControlProtocolClientConnection, ControlProtocolConnectionError,
    msg::hello::ControlProtocolHelloMessage,
};

use crate::{
    cmd_handler::CommandChannel,
    config::{ClientId, ClientKey},
    context::ApplicationContext,
    error::Error,
    net::raw::ether::MacAddr,
    tls::TlsConnector,
};

use self::{rpc::ArrowClientRpcService, svc_table::ServiceTableUpdater};

pub use self::session::{DefaultServiceConnector, ServiceConnection, ServiceConnector};

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(20);
const PING_INTERVAL: Duration = Duration::from_secs(60);
const PONG_TIMEOUT: Duration = Duration::from_secs(20);

/// Arrow error kind.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    UnsupportedProtocolVersion,
    Unauthorized,
    Other,
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::UnsupportedProtocolVersion => "unsupported protocol version",
            Self::Unauthorized => "unauthorized",
            Self::Other => "other error",
        };

        f.write_str(msg)
    }
}

/// Arrow error.
#[derive(Debug)]
pub struct ArrowError {
    kind: ErrorKind,
    cause: Option<Error>,
}

impl ArrowError {
    /// Get the error kind.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl Display for ArrowError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(cause) = self.cause.as_ref() {
            Display::fmt(cause, f)
        } else {
            Display::fmt(&self.kind, f)
        }
    }
}

impl std::error::Error for ArrowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(|cause| cause as _)
    }
}

impl From<io::Error> for ArrowError {
    fn from(err: io::Error) -> Self {
        Self {
            kind: ErrorKind::Other,
            cause: Some(err.into()),
        }
    }
}

impl From<Error> for ArrowError {
    fn from(err: Error) -> Self {
        Self {
            kind: ErrorKind::Other,
            cause: Some(err),
        }
    }
}

impl From<ControlProtocolConnectionError> for ArrowError {
    fn from(err: ControlProtocolConnectionError) -> Self {
        let (kind, cause) = match err {
            ControlProtocolConnectionError::Unauthorized => (ErrorKind::Unauthorized, None),
            ControlProtocolConnectionError::UnsupportedProtocolVersion => {
                (ErrorKind::UnsupportedProtocolVersion, None)
            }
            ControlProtocolConnectionError::Other(err) => (ErrorKind::Other, Some(err)),
        };

        let cause = cause.map(Error::from_other);

        Self { kind, cause }
    }
}

/// Connect Arrow Client to a given address and return either a redirect
/// address or an error.
pub async fn connect<C>(
    app_context: ApplicationContext,
    cmd_channel: CommandChannel,
    svc_connector: C,
    addr: &str,
) -> Result<String, ArrowError>
where
    C: ServiceConnector + Send + Sync + 'static,
    C::Connection: Send,
{
    let tls_connector = app_context.get_tls_connector();

    let client_id = app_context.get_client_id();
    let client_key = app_context.get_client_key();
    let client_mac = app_context.get_arrow_mac_address();
    let gateway_mode = app_context.get_gateway_mode();
    let extended_info = app_context.get_extended_info();

    let connect = connect_inner(
        tls_connector,
        addr,
        client_id,
        client_key,
        client_mac,
        gateway_mode,
        extended_info,
    );

    let connection = tokio::time::timeout(CONNECTION_TIMEOUT, connect)
        .await
        .map_err(|_| Error::from_static_msg("connection timeout"))??;

    let svc_table = app_context.get_service_table();

    let svc_table_updater = ServiceTableUpdater::new(svc_table, connection.handle());

    let svc_table_updater_task = tokio::spawn(svc_table_updater.run());

    let arrow_client_service = ArrowClientRpcService::new(app_context, cmd_channel, svc_connector);

    let res = connection
        .process_incoming_messages(arrow_client_service)
        .await;

    svc_table_updater_task.abort();

    res.map_err(ArrowError::from)
}

/// Connect to a given Arrow Control Protocol server.
async fn connect_inner<T>(
    tls_connector: TlsConnector,
    addr: &str,
    client_id: ClientId,
    client_key: ClientKey,
    client_mac: MacAddr,
    gateway_mode: bool,
    extended_info: T,
) -> Result<ControlProtocolClientConnection, ArrowError>
where
    T: Into<String>,
{
    let io = tls_connector.connect(addr).await?;

    let mut flags = 0;

    if gateway_mode {
        flags |= ControlProtocolHelloMessage::FLAG_GATEWAY_MODE;
    }

    let client_mac = arrow_protocol::MacAddr::from(client_mac.octets());

    let hello = ControlProtocolHelloMessage::new(client_id, client_key, client_mac)
        .with_flags(flags)
        .with_extended_info(extended_info);

    debug!("sending Control Protocol Hello message...");

    let connection = ControlProtocolClientConnection::builder()
        .with_max_local_concurrent_requests(8)
        .with_max_rx_payload_size(8192)
        .with_ping_interval(PING_INTERVAL)
        .with_pong_timeout(PONG_TIMEOUT)
        .connect(io, hello)
        .await?;

    debug!("Control Protocol connection established");

    Ok(connection)
}
