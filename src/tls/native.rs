use std::{io, path::Path};

use tokio::net::TcpStream;
use tokio_native_tls::native_tls::{Certificate, Protocol};

use crate::error::Error;

pub use tokio_native_tls::TlsStream;

/// TLS connector builder.
pub struct TlsConnectorBuilder {
    inner: tokio_native_tls::native_tls::TlsConnectorBuilder,
}

impl TlsConnectorBuilder {
    /// Create a new TLS connector builder.
    fn new() -> Self {
        let mut inner = tokio_native_tls::native_tls::TlsConnector::builder();

        inner
            .min_protocol_version(Some(Protocol::Tlsv12))
            .disable_built_in_roots(true);

        Self { inner }
    }

    /// Add a root certificate from a given file.
    pub async fn add_root_certificate(&mut self, file: &Path) -> io::Result<()> {
        let content = tokio::fs::read(file).await?;

        let res = if content.starts_with(b"-----BEGIN ") {
            Certificate::from_pem(&content)
        } else {
            Certificate::from_der(&content)
        };

        let cert = res.map_err(|_| io::Error::other("invalid CA certificate"))?;

        self.inner.add_root_certificate(cert);

        Ok(())
    }

    /// Build the TLS connector.
    pub fn build(self) -> Result<TlsConnector, Error> {
        let inner = self.inner.build().map_err(Error::from_other)?.into();

        let res = TlsConnector { inner };

        Ok(res)
    }
}

/// TLS connector.
#[derive(Clone)]
pub struct TlsConnector {
    inner: tokio_native_tls::TlsConnector,
}

impl TlsConnector {
    /// Get a TLS connector builder.
    pub fn builder() -> Result<TlsConnectorBuilder, Error> {
        Ok(TlsConnectorBuilder::new())
    }

    /// Connect to a given address using TLS.
    pub async fn connect(&self, addr: &str) -> Result<TlsStream<TcpStream>, Error> {
        let stream = TcpStream::connect(addr).await?;

        let (hostname, _) = addr.rsplit_once(':').unwrap_or((addr, ""));

        self.inner
            .connect(hostname, stream)
            .await
            .map_err(Error::from_other)
    }
}
