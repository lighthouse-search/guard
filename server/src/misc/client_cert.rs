//! Client certificate capture.
//!
//! rustls verifies a client certificate during the TLS handshake, but what it
//! verified is not visible to an axum handler: `axum-server` calls
//! `make_service(socket_addr)` and never hands the service the connection. The
//! `Accept` trait is the way in — unlike `make_service` it receives *both* the
//! stream and the service, and may return a different service type. So this
//! wraps the rustls acceptor, reads the peer certificates off the completed
//! handshake, and attaches them to the service as a request extension.
//!
//! Handlers then read `Extension<Option<ClientCertificate>>`. `None` means no
//! certificate was presented — verification is deliberately optional at the TLS
//! layer, because rustls fixes the client verifier per `ServerConfig` and cannot
//! vary it per SNI. Whether a certificate is *required* is therefore a decision
//! for the hostname being requested, not for the listener.

use std::future::Future;
use std::io;
use std::pin::Pin;

use axum::extract::Extension;
use axum_server::accept::{Accept, DefaultAcceptor};
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower::Layer;

/// A client certificate that passed TLS verification.
///
/// Only present when the client offered one AND rustls accepted it against the
/// configured CA, so handlers never have to judge cryptographic validity — only
/// whether this identity is authorised.
#[derive(Clone, Debug)]
pub struct ClientCertificate {
    /// SHA-256 of the DER, lowercase hex. The stable handle Guard stores and
    /// revokes against: unlike a serial it does not depend on trusting the
    /// issuer to keep serials unique.
    pub fingerprint: String,
    /// The leaf certificate, DER-encoded, for extracting subject and SANs.
    pub der: Vec<u8>,
}

impl ClientCertificate {
    pub fn from_der(der: &[u8]) -> Self {
        Self {
            fingerprint: hex::encode(Sha256::digest(der)),
            der: der.to_vec(),
        }
    }
}

/// The service type produced once the certificate extension is layered on.
type WithCertificate<S> = <Extension<Option<ClientCertificate>> as Layer<S>>::Service;

/// Wraps the rustls acceptor to attach the verified client certificate, if any,
/// to every request on the connection.
#[derive(Clone)]
pub struct ClientCertAcceptor {
    inner: RustlsAcceptor<DefaultAcceptor>,
}

impl ClientCertAcceptor {
    pub fn new(config: RustlsConfig) -> Self {
        Self { inner: RustlsAcceptor::new(config) }
    }
}

impl<I, S> Accept<I, S> for ClientCertAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = WithCertificate<S>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(TlsStream<I>, WithCertificate<S>)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let handshake = self.inner.accept(stream, service);

        Box::pin(async move {
            let (stream, service) = handshake.await?;

            // peer_certificates() is populated only after a successful
            // handshake, and only when the client sent a chain rustls accepted.
            // The leaf is first.
            let certificate = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|leaf| ClientCertificate::from_der(leaf));

            if let Some(certificate) = &certificate {
                log::debug!("TLS client certificate presented: {}", certificate.fingerprint);
            }

            Ok((stream, Extension(certificate).layer(service)))
        })
    }
}
