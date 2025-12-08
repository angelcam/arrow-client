use std::{io, path::Path, pin::Pin};

use openssl::{
    error::ErrorStack,
    ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVersion},
};
use tokio::net::TcpStream;

use crate::error::Error;

pub use tokio_openssl::SslStream as TlsStream;

/// TLS connector builder.
pub struct TlsConnectorBuilder {
    inner: SslConnectorBuilder,
}

impl TlsConnectorBuilder {
    /// Create a new TLS connector builder.
    fn new() -> Result<Self, ErrorStack> {
        let mut inner = SslConnector::builder(SslMethod::tls())?;

        inner.set_min_proto_version(Some(SslVersion::TLS1_2))?;

        let res = Self { inner };

        Ok(res)
    }

    /// Add a root certificate from a given file.
    pub async fn add_root_certificate(&mut self, file: &Path) -> io::Result<()> {
        tokio::task::block_in_place(|| self.inner.set_ca_file(file))
            .map_err(|_| io::Error::other("invalid CA certificate"))
    }

    /// Build the TLS connector.
    pub fn build(self) -> Result<TlsConnector, Error> {
        let res = TlsConnector {
            inner: self.inner.build(),
        };

        Ok(res)
    }
}

/// TLS connector.
#[derive(Clone)]
pub struct TlsConnector {
    inner: SslConnector,
}

impl TlsConnector {
    /// Get a TLS connector builder.
    pub fn builder() -> Result<TlsConnectorBuilder, Error> {
        TlsConnectorBuilder::new().map_err(|err| {
            Error::from_static_msg_and_cause("unable to create a TLS connection builder", err)
        })
    }

    /// Connect to a given address using TLS.
    pub async fn connect(&self, addr: &str) -> Result<TlsStream<TcpStream>, Error> {
        let stream = TcpStream::connect(addr).await?;

        let (hostname, _) = addr.rsplit_once(':').unwrap_or((addr, ""));

        let mut stream = self
            .inner
            .configure()
            .and_then(|configuration| configuration.into_ssl(hostname))
            .and_then(|ssl| TlsStream::new(ssl, stream))
            .map_err(|err| {
                Error::from_static_msg_and_cause("unable to create a TLS stream", err)
            })?;

        Pin::new(&mut stream).connect().await.map_err(|err| {
            Error::from_static_msg_and_cause("unable to establish a TLS connection", err)
        })?;

        Ok(stream)
    }
}
