//! Transport selection for TASE.2 over OSI/TCP.
//!
//! The [`Transport`] enum encapsulates how a client reaches a peer (or, for a
//! server, how it accepts). Plain TCP is always available; a TLS variant
//! (IEC 62351-4-style transport security) is available behind the `tls` cargo
//! feature.

use std::net::SocketAddr;

#[cfg(feature = "tls")]
use std::sync::Arc;

#[cfg(feature = "tls")]
use tokio_rustls::rustls::ClientConfig;

/// How a client should reach a peer.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Transport {
    /// Plain TCP connection.
    Tcp {
        /// The peer address.
        addr: SocketAddr,
    },

    /// TLS-over-TCP connection (IEC 62351-4 style).
    ///
    /// Only available with the `tls` cargo feature.
    #[cfg(feature = "tls")]
    Tls {
        /// The peer address.
        addr: SocketAddr,
        /// The TLS server name used for SNI and certificate verification.
        server_name: String,
        /// The rustls client configuration (roots, optional client cert/key).
        config: Arc<ClientConfig>,
    },
}

impl Transport {
    /// Convenience constructor for the plain-TCP variant.
    pub fn tcp(addr: SocketAddr) -> Self {
        Self::Tcp { addr }
    }

    /// Convenience constructor for the TLS variant.
    #[cfg(feature = "tls")]
    pub fn tls(
        addr: SocketAddr,
        server_name: impl Into<String>,
        config: Arc<ClientConfig>,
    ) -> Self {
        Self::Tls {
            addr,
            server_name: server_name.into(),
            config,
        }
    }

    /// The peer address this transport targets.
    pub fn addr(&self) -> SocketAddr {
        match self {
            Self::Tcp { addr } => *addr,
            #[cfg(feature = "tls")]
            Self::Tls { addr, .. } => *addr,
        }
    }
}

/// Default TASE.2 / MMS port (plaintext, "iso-tsap").
pub const DEFAULT_PORT: u16 = 102;

/// Default TASE.2 / MMS port for TLS ("iso-tsap-tls" / IEC 62351-4).
///
/// Referenced by callers that construct TLS transports; exported
/// unconditionally so it is available regardless of the `tls` feature.
#[allow(dead_code)]
pub const DEFAULT_TLS_PORT: u16 = 3782;
