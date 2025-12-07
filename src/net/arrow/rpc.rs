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

use std::{
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use arrow_protocol::v3::{
    ControlProtocolService,
    msg::json::{JsonRpcError, JsonRpcMethod, JsonRpcParams, JsonRpcValue},
};
use serde_lite::{Deserialize, Serialize};

use crate::{
    cmd_handler::{Command, CommandChannel},
    context::ApplicationContext,
    error::Error,
    net::arrow::{
        session::{ServiceConnector, SessionManager},
        svc_table::ServiceTableElement,
    },
    scanner::{HostRecord, ScanResult},
    svc_table::{Service, ServiceSource, ServiceTableHandle},
};

/// Local Arrow Client service.
pub struct ArrowClientRpcService<C> {
    inner: Arc<InternalRpcService<C>>,
}

impl<C> ArrowClientRpcService<C> {
    /// Create a new Arrow Client service.
    pub fn new(
        app_context: ApplicationContext,
        cmd_channel: CommandChannel,
        svc_connector: C,
    ) -> Self {
        let tls_connector = app_context.get_tls_connector();
        let svc_table = app_context.get_service_table();
        let gateway_mode = app_context.get_gateway_mode();

        let sessions = SessionManager::new(tls_connector, svc_table, svc_connector, gateway_mode);

        let inner = InternalRpcService {
            app_context,
            cmd_channel,
            sessions,
        };

        Self {
            inner: Arc::new(inner),
        }
    }
}

impl<C> Clone for ArrowClientRpcService<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<C> ControlProtocolService for ArrowClientRpcService<C>
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
            "add_service" => self.inner.add_service(params),
            "reset_service_table" => self.inner.reset_service_table(),
            "scan_network" => self.inner.scan_network(),
            "get_status" => self.inner.get_status(),
            "get_last_scan_report" => self.inner.get_last_scan_report(),
            _ => Err(JsonRpcError::new(-32601, "Method not found")),
        }
    }
}

/// Internal Arrow Client service.
struct InternalRpcService<C> {
    app_context: ApplicationContext,
    cmd_channel: CommandChannel,
    sessions: SessionManager<C>,
}

impl<C> InternalRpcService<C>
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
            .map_err(|err| JsonRpcError::new(502, err.to_string()))?;

        Ok(JsonRpcValue::None)
    }
}

impl<C> InternalRpcService<C> {
    /// Process a given `add_service` request.
    fn add_service(&self, params: JsonRpcParams) -> Result<JsonRpcValue, JsonRpcError> {
        if !self.app_context.get_gateway_mode() {
            return Err(JsonRpcError::new(403, "The device is not a gateway"));
        }

        let service = params
            .decode()
            .ok()
            .map(AddServiceParams::into_service)
            .and_then(Result::ok)
            .ok_or_else(|| JsonRpcError::new(-32602, "Invalid params"))?;

        let service_id = self.app_context.add_service(service, ServiceSource::Custom);

        let response = AddServiceResponse { service_id };

        let res = response
            .serialize()
            .expect("unable to serialize add_service response");

        Ok(res)
    }

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
            .expect("unable to serialize get_status response");

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

/// Helper struct.
#[derive(Deserialize)]
struct ConnectParams {
    service_id: u16,
    proxy_service: String,
    access_token: String,
}

/// Helper struct.
#[derive(Deserialize)]
struct AddServiceParams {
    kind: String,
    host: String,
    port: u16,
    path: String,
}

impl AddServiceParams {
    /// Create a service from the parameters if possible.
    fn into_service(self) -> Result<Service, Error> {
        let ip = Ipv4Addr::from_str(&self.host)
            .map_err(|_| Error::from_static_msg("invalid IP address"))?;

        let addr = SocketAddr::from((ip, self.port));

        let optional_path = if self.path.is_empty() {
            None
        } else {
            Some(self.path.clone())
        };

        let required_path = if self.path.is_empty() {
            Err(Error::from_static_msg("missing service path"))
        } else {
            Ok(self.path)
        };

        let mac = crate::utils::get_fake_mac_from_ipv4(0xffff, ip);

        let res = match self.kind.as_str() {
            "rtsp" => Service::rtsp(mac, addr, required_path?),
            "rtsp_locked" => Service::locked_rtsp(mac, addr, optional_path),
            "rtsp_unknown" => Service::unknown_rtsp(mac, addr),
            "rtsp_unsupported" => Service::unsupported_rtsp(mac, addr, required_path?),
            "http" => Service::http(mac, addr),
            "mjpeg" => Service::mjpeg(mac, addr, required_path?),
            "mjpeg_locked" => Service::locked_mjpeg(mac, addr, optional_path),
            "tcp" => Service::tcp(mac, addr),
            _ => return Err(Error::from_static_msg("invalid service type")),
        };

        Ok(res)
    }
}

/// Helper struct.
#[derive(Serialize)]
struct AddServiceResponse {
    service_id: u16,
}

/// Helper struct.
#[derive(Serialize)]
struct GetStatusResponse {
    is_scanning: bool,
    active_sessions: usize,
}

/// Helper struct.
#[derive(Serialize)]
struct ScanReportResponse {
    hosts: Vec<ScanReportHost>,
    services: Vec<ServiceTableElement>,
}

impl ScanReportResponse {
    /// Create a new scan report response.
    fn new(scan_result: ScanResult, svc_table: ServiceTableHandle) -> Self {
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
