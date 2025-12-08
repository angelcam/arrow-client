#[cfg(feature = "native-tls")]
mod native;

#[cfg(feature = "openssl")]
mod openssl;

#[cfg(feature = "native-tls")]
pub use self::native::{TlsConnector, TlsConnectorBuilder, TlsStream};

#[cfg(feature = "openssl")]
pub use self::openssl::{TlsConnector, TlsConnectorBuilder, TlsStream};
