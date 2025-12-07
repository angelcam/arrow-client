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
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use arrow_protocol::v3::{ServiceProtocolConnection, msg::hello::ServiceProtocolHelloMessage};
use futures::{
    SinkExt, StreamExt, TryStreamExt,
    future::{AbortHandle, AbortRegistration, Abortable},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_native_tls::TlsConnector;

use crate::{
    error::Error,
    net::{
        arrow::utils::{StreamedIO, TlsConnectorExt},
        raw::ether::MacAddr,
    },
    svc_table::{ServiceTableHandle, ServiceType},
};

const PING_INTERVAL: Duration = Duration::from_secs(60);
const PONG_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Service connection.
pub trait ServiceConnection: AsyncRead + AsyncWrite {}

impl<T> ServiceConnection for T where T: AsyncRead + AsyncWrite {}

/// Service connector.
#[trait_variant::make(Send)]
pub trait ServiceConnector {
    type Connection: ServiceConnection;

    /// Connect to a given service.
    async fn connect(
        &self,
        svc_type: ServiceType,
        mac: MacAddr,
        addr: SocketAddr,
    ) -> io::Result<Self::Connection>;
}

/// Default service connector.
#[derive(Default, Copy, Clone)]
pub struct DefaultServiceConnector(());

impl DefaultServiceConnector {
    /// Create a new service connector.
    #[inline]
    pub const fn new() -> Self {
        Self(())
    }
}

impl ServiceConnector for DefaultServiceConnector {
    type Connection = TcpStream;

    #[inline]
    fn connect(
        &self,
        _: ServiceType,
        _: MacAddr,
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<Self::Connection>> {
        TcpStream::connect(addr)
    }
}

/// Service session manager.
pub struct SessionManager<C> {
    tls_connector: TlsConnector,
    context: Arc<Mutex<SessionManagerContext>>,
    svc_table: ServiceTableHandle,
    svc_connector: C,
    gateway_mode: bool,
}

impl<C> SessionManager<C> {
    /// Create a new session manager.
    pub fn new(
        tls_connector: TlsConnector,
        svc_table: ServiceTableHandle,
        svc_connector: C,
        gateway_mode: bool,
    ) -> Self {
        Self {
            tls_connector,
            context: Arc::new(Mutex::new(SessionManagerContext::new())),
            svc_table,
            svc_connector,
            gateway_mode,
        }
    }
}

impl<C> SessionManager<C>
where
    C: ServiceConnector,
    C::Connection: Send + 'static,
{
    /// Create a new session for a given service ID and connect it to the given
    /// Arrow Proxy Service.
    pub async fn create_session(
        &self,
        service_id: u16,
        proxy_service: &str,
        access_token: &str,
    ) -> Result<(), Error> {
        let service = self
            .svc_table
            .get(service_id)
            .ok_or_else(|| Error::from_msg(format!("unknown service ID: {:04x}", service_id)))?;

        let svc_type = service.service_type();
        let mac = service.mac().unwrap_or(MacAddr::ZERO);

        let addr = service.address().ok_or_else(|| {
            Error::from_msg(format!(
                "address not available for service ID: {:04x}",
                service_id
            ))
        })?;

        let ip = addr.ip();

        if !self.gateway_mode && !ip.is_loopback() {
            return Err(Error::from_static_msg("gateway mode disabled"));
        }

        let registration = self.context.lock().unwrap().register_session();

        let session_id = registration.session_id;

        let session = Session {
            context: self.context.clone(),
            session_id,
        };

        info!(
            "connecting to local service: {addr}, service ID: {service_id:04x}, session ID: {session_id:08x}",
        );

        let local_connection = connect_to_local_service(&self.svc_connector, svc_type, mac, addr)
            .await
            .map_err(|err| {
                Error::from_static_msg_and_cause("unable to connect to local service", err)
            })
            .inspect_err(|err| warn!("{err}"))?;

        let tls_connector = self.tls_connector.clone();

        debug!("connecting to Arrow proxy service: {proxy_service}, session ID: {session_id:08x}");

        let proxy_connection =
            connect_to_arrow_proxy_service(tls_connector, proxy_service, access_token)
                .await
                .map_err(|err| {
                    Error::from_static_msg_and_cause(
                        "unable to connect to Arrow proxy service",
                        err,
                    )
                })
                .inspect_err(|err| warn!("{err}"))?;

        tokio::spawn(async move {
            let forward = session.forward(local_connection, proxy_connection);

            let abortable = Abortable::new(forward, registration.abort_registration);

            if let Ok(Err(err)) = abortable.await {
                warn!("service connection error; session ID: {session_id:08x}: {err}");
            }

            info!("service connection closed; session ID: {session_id:08x}");
        });

        Ok(())
    }
}

impl<C> SessionManager<C> {
    /// Get the number of active sessions.
    pub fn active_sessions(&self) -> usize {
        self.context.lock().unwrap().active_sessions()
    }
}

/// Session manager context.
struct SessionManagerContext {
    sessions: HashMap<u32, SessionHandle>,
    next_session_id: u32,
}

impl SessionManagerContext {
    /// Create a new session manager context.
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_session_id: 0,
        }
    }

    /// Get the number of active sessions.
    fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Register a new session and get its ID.
    fn register_session(&mut self) -> SessionRegistration {
        for i in 0..u32::MAX {
            let session_id = self.next_session_id.wrapping_add(i);

            if self.sessions.contains_key(&session_id) {
                continue;
            } else {
                self.next_session_id = session_id.wrapping_add(1);
            }

            let (abort_handle, abort_registration) = AbortHandle::new_pair();

            let handle = SessionHandle { abort_handle };

            let registration = SessionRegistration {
                session_id,
                abort_registration,
            };

            self.sessions.insert(session_id, handle);

            return registration;
        }

        panic!("no free session ID available");
    }

    /// Remove a given session.
    fn remove_session(&mut self, session_id: u32) {
        self.sessions.remove(&session_id);
    }
}

/// Session instance.
struct Session {
    context: Arc<Mutex<SessionManagerContext>>,
    session_id: u32,
}

impl Session {
    /// Forward data between given local and proxy connections.
    async fn forward<C>(
        self,
        local_connection: C,
        proxy_connection: ServiceProtocolConnection,
    ) -> Result<(), Error>
    where
        C: AsyncRead + AsyncWrite,
    {
        let (local_tx, local_rx) = StreamedIO::new(local_connection)
            .map_err(Error::from_other)
            .sink_map_err(Error::from_other)
            .split();

        let (proxy_tx, proxy_rx) = proxy_connection
            .map_err(Error::from_other)
            .sink_map_err(Error::from_other)
            .split();

        let (local_rx, abort_local_rx) = futures::stream::abortable(local_rx);
        let (proxy_rx, abort_proxy_rx) = futures::stream::abortable(proxy_rx);

        let local_to_proxy = async move {
            let res = local_rx.forward(proxy_tx).await;

            // Make sure the proxy RX won't yield any more items after proxy TX
            // is closed. This prevents hanging or half-closed connections as
            // it effectively shuts down the other direction as well.
            abort_proxy_rx.abort();

            res
        };

        let proxy_to_local = async move {
            let res = proxy_rx.forward(local_tx).await;

            // Make sure the local RX won't yield any more items after local TX
            // is closed. This prevents hanging or half-closed connections as
            // it effectively shuts down the other direction as well.
            abort_local_rx.abort();

            res
        };

        let join = futures::future::join(local_to_proxy, proxy_to_local);

        match join.await {
            (Err(err), _) => Err(err),
            (_, Err(err)) => Err(err),
            _ => Ok(()),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.context.lock().unwrap().remove_session(self.session_id);
    }
}

/// Session registration.
struct SessionRegistration {
    session_id: u32,
    abort_registration: AbortRegistration,
}

/// Session handle.
struct SessionHandle {
    abort_handle: AbortHandle,
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}

/// Connect to a given local service.
async fn connect_to_local_service<C>(
    connector: &C,
    svc_type: ServiceType,
    mac: MacAddr,
    addr: SocketAddr,
) -> Result<C::Connection, Error>
where
    C: ServiceConnector,
{
    let connect = connector.connect(svc_type, mac, addr);

    let res = tokio::time::timeout(CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| Error::from_static_msg("connection timeout"))??;

    Ok(res)
}

/// Connect to a given Arrow Proxy Service.
async fn connect_to_arrow_proxy_service(
    tls_connector: TlsConnector,
    proxy_service: &str,
    access_token: &str,
) -> Result<ServiceProtocolConnection, Error> {
    let connect = connect_to_arrow_proxy_service_inner(tls_connector, proxy_service, access_token);

    let res = tokio::time::timeout(CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| Error::from_static_msg("connection timeout"))??;

    Ok(res)
}

/// Connect to a given Arrow Proxy Service.
async fn connect_to_arrow_proxy_service_inner(
    tls_connector: TlsConnector,
    proxy_service: &str,
    access_token: &str,
) -> Result<ServiceProtocolConnection, Error> {
    let io = tls_connector.tcp_connect(proxy_service).await?;

    let hello = ServiceProtocolHelloMessage::new(access_token);

    ServiceProtocolConnection::builder()
        .with_max_rx_payload_size(8_192)
        .with_rx_capacity(65_536)
        .with_ping_interval(PING_INTERVAL)
        .with_pong_timeout(PONG_TIMEOUT)
        .connect(io, hello)
        .await
        .map_err(Error::from_other)
}
