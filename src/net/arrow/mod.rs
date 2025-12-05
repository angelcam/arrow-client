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

mod session;
mod utils;

use std::{
    fmt::{self, Display, Formatter},
    io,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

use arrow_protocol::v3::{
    ControlProtocolClientConnection, ControlProtocolClientConnectionHandle,
    ControlProtocolConnectionError, ControlProtocolService,
    msg::{
        hello::ControlProtocolHelloMessage,
        json::{JsonRpcError, JsonRpcMethod, JsonRpcParams, JsonRpcValue},
    },
};
use serde_lite::{Deserialize, Serialize};
use tokio_native_tls::TlsConnector;

use crate::{
    cmd_handler::{Command, CommandChannel},
    config::{ClientId, ClientKey},
    context::ApplicationContext,
    error::Error,
    net::raw::ether::MacAddr,
    scanner::{HostRecord, ScanResult},
    svc_table::{Service, ServiceTable, ServiceType, SharedServiceTableRef},
};

use self::{session::SessionManager, utils::TlsConnectorExt};

pub use self::session::{DefaultServiceConnector, ServiceConnection, ServiceConnector};

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(20);
const PING_INTERVAL: Duration = Duration::from_secs(60);
const PONG_TIMEOUT: Duration = Duration::from_secs(20);
const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(5);

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

/// Local Arrow Client service.
struct ArrowClientService<C> {
    inner: Arc<InternalArrowClientService<C>>,
}

impl<C> ArrowClientService<C> {
    /// Create a new Arrow Client service.
    fn new(app_context: ApplicationContext, cmd_channel: CommandChannel, svc_connector: C) -> Self {
        let tls_connector = app_context.get_tls_connector();
        let svc_table = app_context.get_service_table();
        let gateway_mode = app_context.get_gateway_mode();

        let sessions = SessionManager::new(tls_connector, svc_table, svc_connector, gateway_mode);

        let inner = InternalArrowClientService {
            app_context,
            cmd_channel,
            sessions,
        };

        Self {
            inner: Arc::new(inner),
        }
    }
}

impl<C> Clone for ArrowClientService<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<C> ControlProtocolService for ArrowClientService<C>
where
    C: ServiceConnector + Send + Sync,
    C::Connection: Send + 'static,
{
    async fn handle_request(
        self,
        method: JsonRpcMethod,
        params: JsonRpcParams,
    ) -> Result<JsonRpcValue, JsonRpcError> {
        let method = method.as_ref();

        debug!("received JSON-RPC request: {method}");

        match method {
            "connect" => self.inner.connect(params).await,
            "reset_service_table" => self.inner.reset_service_table(),
            "scan_network" => self.inner.scan_network(),
            "get_status" => self.inner.get_status(),
            "get_last_scan_report" => self.inner.get_last_scan_report(),
            _ => Err(JsonRpcError::new(-32601, "Method not found")),
        }
    }
}

/// Internal Arrow Client service.
struct InternalArrowClientService<C> {
    app_context: ApplicationContext,
    cmd_channel: CommandChannel,
    sessions: SessionManager<C>,
}

impl<C> InternalArrowClientService<C>
where
    C: ServiceConnector,
    C::Connection: Send + 'static,
{
    /// Process a given `connect` request.
    async fn connect(&self, params: JsonRpcParams) -> Result<JsonRpcValue, JsonRpcError> {
        let params: ConnectParams = params
            .decode()
            .map_err(|_| JsonRpcError::new(-32602, "Invalid params"))?;

        self.sessions
            .create_session(
                params.service_id,
                &params.proxy_service,
                &params.access_token,
            )
            .await
            .map_err(|err| JsonRpcError::new(0, err.to_string()))?;

        Ok(JsonRpcValue::None)
    }
}

impl<C> InternalArrowClientService<C> {
    /// Process a given `reset_service_table` request.
    fn reset_service_table(&self) -> Result<JsonRpcValue, JsonRpcError> {
        self.app_context.reset_service_table();

        Ok(JsonRpcValue::None)
    }

    /// Process a given `scan_network` request.
    fn scan_network(&self) -> Result<JsonRpcValue, JsonRpcError> {
        self.cmd_channel.send(Command::ScanNetwork);

        Ok(JsonRpcValue::None)
    }

    /// Process a given `get_status` request.
    fn get_status(&self) -> Result<JsonRpcValue, JsonRpcError> {
        let response = GetStatusResponse {
            is_scanning: self.app_context.is_scanning(),
            active_sessions: self.sessions.active_sessions(),
        };

        let res = response
            .serialize()
            .expect("unable to serialize GetStatusResponse");

        Ok(res)
    }

    /// Process a given `get_last_scan_report` request.
    fn get_last_scan_report(&self) -> Result<JsonRpcValue, JsonRpcError> {
        let scan_result = self.app_context.get_scan_result();
        let svc_table = self.app_context.get_service_table();

        let response = ScanReportResponse::new(scan_result, svc_table)
            .serialize()
            .expect("unable to serialize ScanReportResponse");

        Ok(response)
    }
}

/// Connect request parameters.
#[derive(Deserialize)]
struct ConnectParams {
    service_id: u16,
    proxy_service: String,
    access_token: String,
}

/// Get status response.
#[derive(Serialize)]
struct GetStatusResponse {
    is_scanning: bool,
    active_sessions: usize,
}

/// Scan report response.
#[derive(Serialize)]
struct ScanReportResponse {
    hosts: Vec<ScanReportHost>,
    services: Vec<ServiceTableElement>,
}

impl ScanReportResponse {
    /// Create a new scan report response.
    fn new(scan_result: ScanResult, svc_table: SharedServiceTableRef) -> Self {
        let hosts = scan_result.hosts().map(ScanReportHost::from).collect();

        let services = scan_result
            .services()
            .filter_map(|svc| {
                svc_table
                    .get_id(&svc.to_service_identifier())
                    .map(|service_id| ServiceTableElement::new(service_id, svc))
            })
            .collect();

        Self { hosts, services }
    }
}

/// Scan report host entry.
#[derive(Serialize)]
struct ScanReportHost {
    arp_scan: bool,
    icmp_scan: bool,
    mac: String,
    ip: String,
    ports: Vec<u16>,
}

impl From<&HostRecord> for ScanReportHost {
    fn from(host: &HostRecord) -> Self {
        Self {
            arp_scan: (host.flags & HostRecord::FLAG_ARP) != 0,
            icmp_scan: (host.flags & HostRecord::FLAG_ARP) != 0,
            mac: host.mac.to_string(),
            ip: host.ip.to_string(),
            ports: Vec::from_iter(host.ports()),
        }
    }
}

/// Scan report service entry.
#[derive(Serialize)]
struct ServiceTableElement {
    service_id: u16,
    #[serde(rename = "type")]
    kind: &'static str,
    mac: String,
    host: String,
    port: u16,
    path: String,
}

impl ServiceTableElement {
    /// Create a new service table element.
    fn new(service_id: u16, service: &Service) -> Self {
        let kind = match service.service_type() {
            ServiceType::ControlProtocol => "control",
            ServiceType::RTSP => "rtsp",
            ServiceType::LockedRTSP => "rtsp_locked",
            ServiceType::UnknownRTSP => "rtsp_unknown",
            ServiceType::UnsupportedRTSP => "rtsp_unsupported",
            ServiceType::HTTP => "http",
            ServiceType::MJPEG => "mjpeg",
            ServiceType::LockedMJPEG => "mjpeg_locked",
            ServiceType::TCP => "tcp",
        };

        let mac = service.mac().unwrap_or(MacAddr::ZERO).to_string();
        let host = service
            .ip_address()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            .to_string();
        let port = service.port().unwrap_or(0);
        let path = service.path().unwrap_or("").to_string();

        Self {
            service_id,
            kind,
            mac,
            host,
            port,
            path,
        }
    }
}

/// Service table updater.
struct ServiceTableUpdater {
    connection: ControlProtocolClientConnectionHandle,
    svc_table: SharedServiceTableRef,
    last_reported_version: Option<u32>,
}

impl ServiceTableUpdater {
    /// Create a new service table updater.
    fn new(
        svc_table: SharedServiceTableRef,
        connection: ControlProtocolClientConnectionHandle,
    ) -> Self {
        Self {
            connection,
            svc_table,
            last_reported_version: None,
        }
    }

    /// Run the service table updater.
    async fn run(mut self) {
        while self.send_update().await.is_ok() {
            tokio::time::sleep(UPDATE_CHECK_INTERVAL).await;
        }
    }

    /// Send a service table update if needed.
    async fn send_update(&mut self) -> Result<(), Error> {
        // helper struct
        #[derive(Serialize)]
        struct Params {
            services: Vec<ServiceTableElement>,
        }

        let current_version = self.svc_table.visible_set_version();

        if self.last_reported_version == Some(current_version) {
            return Ok(());
        }

        self.last_reported_version = Some(current_version);

        let mut params = Params {
            services: Vec::new(),
        };

        for (service_id, service) in self.svc_table.visible() {
            params
                .services
                .push(ServiceTableElement::new(service_id, &service));
        }

        let msg = params
            .serialize()
            .expect("unable to serialize service table");

        debug!("sending service table update...");

        self.connection
            .send_notification("update_service_table", msg)
            .await
            .map_err(Error::from_other)
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

    let arrow_client_service = ArrowClientService::new(app_context, cmd_channel, svc_connector);

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
    let io = tls_connector.tcp_connect(addr).await?;

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
