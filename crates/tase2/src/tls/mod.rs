//! TLS support via `tokio-rustls`. Available behind the `tls` cargo feature.
//!
//! ## IEC 62351-4 deployment notes
//!
//! IEC 62351-4 specifies TLS for TASE.2 / MMS over untrusted or shared
//! networks. The conventional TLS port is **3782** (see
//! [`crate::DEFAULT_TLS_PORT`]); the standard **expects mutual TLS** —
//! both the client and the server are authenticated with X.509 certificates
//! issued by an organisation-controlled CA.
//!
//! Helpers in this module:
//!
//! | Helper | Use for |
//! | --- | --- |
//! | [`client_config_with_roots`] | Server-authenticated TLS (server proves identity, client does not). Acceptable for **lab / development** only. |
//! | [`client_config_with_client_cert`] | **Recommended** for production — client also presents a certificate, satisfying mTLS expectations. |
//! | [`server_config_single_cert`] | Server-only authentication. Same caveat as `client_config_with_roots`. |
//! | [`server_config_requiring_client_cert`] | **Recommended** for production — verifies the client certificate chain against the given root store and rejects unauthenticated peers. |
//!
//! `rustls` is configured with the `ring` provider; cipher suites and TLS
//! versions follow `rustls` defaults (TLS 1.2 and 1.3 only, no SSL/early TLS).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use mms_proto::assoc::AssocConfig;

use crate::error::{Error, Result};
use crate::handler::{EventHandler, NoopHandler};
use crate::server::ServerConnection;
use crate::transport::Transport;
use crate::Tase2Client;

// ---------------------------------------------------------------------------
// Re-exports for convenience
// ---------------------------------------------------------------------------

pub use tls_config::{
    fingerprint_sha256_of_pem_file, load_certs, load_private_key, parse_hex_fingerprint,
    CertificateChain, ClientCertPolicy, CustomVerifierFn, TlsServerConfig, VerifyError,
};

mod tls_config;
mod verifier;

// ---------------------------------------------------------------------------
// Client config helpers
// ---------------------------------------------------------------------------

/// Build a `ClientConfig` that trusts the given list of root certificate
/// authorities. **The client does not authenticate itself** — use
/// [`client_config_with_client_cert`] for IEC 62351-4 deployments.
pub fn client_config_with_roots(roots: RootCertStore) -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Build a `ClientConfig` for **mutual TLS**: the client trusts peers signed
/// by `roots`, and presents `cert_chain` + `key` when the server requests a
/// client certificate.
///
/// This is the configuration IEC 62351-4 expects for production deployments.
///
/// Returns an error if rustls cannot consume the given key (e.g. malformed
/// PKCS#8).
pub fn client_config_with_client_cert(
    roots: RootCertStore,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ClientConfig>> {
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .map_err(|e| Error::Tls(format!("invalid client key/cert: {e}")))?;
    Ok(Arc::new(cfg))
}

// ---------------------------------------------------------------------------
// Server config helpers
// ---------------------------------------------------------------------------

/// Build a `ServerConfig` that presents `cert_chain` + `key` and does **not**
/// request a client certificate. Acceptable for lab use; use
/// [`server_config_requiring_client_cert`] for IEC 62351-4 deployments.
pub fn server_config_single_cert(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>> {
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| Error::Tls(format!("invalid server key/cert: {e}")))?;
    Ok(Arc::new(cfg))
}

/// Build a `ServerConfig` for **mutual TLS**: presents `cert_chain` + `key`
/// to the peer, and *requires* the peer to present a client certificate
/// signed by one of the roots in `client_roots`. Connections from
/// unauthenticated peers are rejected during the TLS handshake.
///
/// This is the configuration IEC 62351-4 expects for production deployments.
pub fn server_config_requiring_client_cert(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_roots: RootCertStore,
) -> Result<Arc<ServerConfig>> {
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .map_err(|e| Error::Tls(format!("building client cert verifier: {e}")))?;
    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|e| Error::Tls(format!("invalid server key/cert: {e}")))?;
    Ok(Arc::new(cfg))
}

// ---------------------------------------------------------------------------
// PEM loading helpers (re-exported from tls_config)
// ---------------------------------------------------------------------------

/// Load a [`RootCertStore`] from one or more PEM certificate files.
pub fn root_store_from_pem_files(paths: &[&Path]) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for path in paths {
        for cert in load_certs(path)? {
            roots
                .add(cert)
                .map_err(|e| Error::Tls(format!("adding CA from {}: {e}", path.display())))?;
        }
    }
    Ok(roots)
}

// ---------------------------------------------------------------------------
// Type aliases — preserved for source compatibility.
// ---------------------------------------------------------------------------

/// Alias for the unified [`Tase2Client`] handle. TLS connections produce the
/// same client type as plain TCP — only the constructor differs.
pub type TlsClient = Tase2Client;

/// Alias for the unified [`ServerConnection`] handle. TLS-accepted connections
/// produce the same type as plain-TCP-accepted ones.
pub type TlsServerConnection = ServerConnection;

// ---------------------------------------------------------------------------
// Client connect
// ---------------------------------------------------------------------------

/// Connect a TASE.2 / MMS client over TLS using a [`NoopHandler`].
pub async fn tls_client_connect(transport: Transport, config: AssocConfig) -> Result<Tase2Client> {
    tls_client_connect_with(transport, config, NoopHandler).await
}

/// Connect a TASE.2 / MMS client over TLS with a custom [`EventHandler`].
///
/// Expects a [`Transport::Tls`] variant. Performs the TCP connect, TLS
/// handshake, and TASE.2 association in sequence, then returns the handle.
pub async fn tls_client_connect_with<H: EventHandler>(
    transport: Transport,
    config: AssocConfig,
    handler: H,
) -> Result<Tase2Client> {
    let Transport::Tls {
        addr,
        server_name,
        config: client_config,
    } = transport
    else {
        return Err(Error::Tls("transport is not TLS".into()));
    };
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;
    let connector = TlsConnector::from(client_config);
    let name = ServerName::try_from(server_name.clone())
        .map_err(|e| Error::Tls(format!("invalid server name: {e}")))?;
    let stream = connector
        .connect(name, stream)
        .await
        .map_err(|e| Error::Tls(format!("tls handshake: {e}")))?;
    Tase2Client::spawn(stream, config, handler).await
}

// ---------------------------------------------------------------------------
// TlsServer convenience wrapper
// ---------------------------------------------------------------------------

/// Convenience wrapper that holds a [`TcpListener`], a shared
/// [`rustls::ServerConfig`], and a TASE.2 [`AssocConfig`]. Exposes
/// `bind` + `accept_with` so callers don't have to manage the listener and
/// acceptor separately.
pub struct TlsServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    config: AssocConfig,
}

impl std::fmt::Debug for TlsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServer")
            .field("listener", &self.listener)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl TlsServer {
    /// Bind a `TlsServer` on `addr` using the given rustls `ServerConfig`.
    pub async fn bind(
        addr: SocketAddr,
        assoc_config: AssocConfig,
        server_config: Arc<ServerConfig>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let acceptor = TlsAcceptor::from(server_config);
        Ok(Self {
            listener,
            acceptor,
            config: assoc_config,
        })
    }

    /// Bind a `TlsServer` from a [`TlsServerConfig`], which bundles server
    /// cert/key, trusted client-CA roots, optional cipher and
    /// signature-scheme allowlists, and a [`ClientCertPolicy`] in one place.
    pub async fn bind_with_security(
        addr: SocketAddr,
        assoc_config: AssocConfig,
        tls_security: TlsServerConfig,
    ) -> Result<Self> {
        let server_config = tls_security.build_server_config()?;
        Self::bind(addr, assoc_config, server_config).await
    }

    /// Return the local socket address the listener is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept one connection using a [`NoopHandler`].
    pub async fn accept(&self) -> Result<ServerConnection> {
        self.accept_with(NoopHandler).await
    }

    /// Accept one connection with a custom event handler.
    pub async fn accept_with<H: EventHandler>(&self, handler: H) -> Result<ServerConnection> {
        let (stream, peer) = self.listener.accept().await?;
        stream.set_nodelay(true)?;
        let tls_stream = self
            .acceptor
            .accept(stream)
            .await
            .map_err(|e| Error::Tls(format!("tls accept: {e}")))?;
        ServerConnection::spawn(tls_stream, peer, self.config.clone(), handler).await
    }
}
