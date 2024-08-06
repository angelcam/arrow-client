use std::{future::Future, io, net::SocketAddr};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use crate::net::raw::ether::MacAddr;
use crate::svc_table::ServiceType;

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
