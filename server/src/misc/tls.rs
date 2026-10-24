use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::structs::TlsCertificate;
use crate::CONFIG_VALUE;

pub async fn init_tls() -> Option<RustlsConfig> {
    if CONFIG_VALUE.features.clone().unwrap().tls.unwrap_or(true) == true {
        // TODO: In the future, allow getting certificates from environment variables (e.g. to accomodate Docker).
        let config_tls = CONFIG_VALUE.clone().tls;
        if config_tls.is_none() == false {
            // Use TLS certificates provided in Guard configuration.
            let config_tls_unwrapped = config_tls.clone().unwrap();

            println!("certificate {}", &config_tls_unwrapped.clone().certificate.expect("Missing config.tls.certificate"));
            println!("private_key {}", &config_tls_unwrapped.clone().private_key.expect("Missing config.tls.private_key"));

            log::debug!("Using TLS certificate specified in configuration (paths: certificate {}, private_key {}).", &config_tls_unwrapped.certificate.clone().expect("Missing config.tls.certificate"), &config_tls_unwrapped.private_key.clone().expect("Missing config.tls.private_key"));

            let certificate_path = config_tls_unwrapped.certificate.expect("Missing config.tls.certificate");
            let private_key_path = config_tls_unwrapped.private_key.expect("Missing config.tls.private_key");
            let certificate = std::fs::read(&certificate_path)
                .unwrap_or_else(|error| panic!("Could not read config.tls.certificate '{}': {}", certificate_path, error));
            let private_key = std::fs::read(&private_key_path)
                .unwrap_or_else(|error| panic!("Could not read config.tls.private_key '{}': {}", private_key_path, error));

            Some(build_config(&certificate, &private_key).expect("Failed to build the TLS configuration"))
        } else {
            // Use one-time generated self-signed certificate.

            log::warn!("No TLS certificate specified in configuration, using self-signed certificate. Note: do not use self-signed certificates in production.");
            let certificate = generate_self_signed_certificate().await.expect("Failed to generate self-signed certificate");
            Some(
                build_config(certificate.certificate.as_bytes(), certificate.private_key.as_bytes())
                    .expect("Failed to build the self-signed TLS configuration"),
            )
        }
    } else {
        // No TLS configuration specified, return None.
        log::warn!("config.features.tls is set to false, not using TLS.");
        return None;
    }
}

pub async fn generate_self_signed_certificate() -> Result<TlsCertificate, String> {
    log::info!("Generating self-signed certificate using openssl...");

    let output = Command::new("openssl")
        .args([
            "req", "-x509",
            "-nodes",
            "-newkey", "rsa:4096",
            "-days", "365",
            "-keyout", "-",
            "-out", "-",
            "-subj", "/CN=localhost",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null()) // Silence terminal output
        .spawn()
        .expect("Failed to spawn child")
        .wait_with_output()
        .expect("Failed to wait for output");

    if output.status.success() {
        log::debug!("OpenSSL exited successfully!");
    } else {
        return Err(format!("OpenSSL exited with {}", output.status));
    }

    // stdout looks like:
    // -----BEGIN PRIVATE KEY-----\n
    // [key contnet]
    // -----END PRIVATE KEY-----\n
    // -----BEGIN CERTIFICATE-----\n
    // [certificate content]
    // -----END CERTIFICATE-----\n
    log::debug!("Parsing stdout from_utf8");
    let pem = String::from_utf8(output.stdout).expect("Failed to convert from utf 8");

    log::debug!("Splitting from_utf8");
    let end_marker = "-----END PRIVATE KEY-----";
    let (private_key_cropped, certificate) = pem.split_once(end_marker).expect("Fail");

    // Append "-----END PRIVATE KEY-----" back onto private_key - It was removed during stdout parsing.
    let private_key = format!("{}\n{end_marker}", private_key_cropped);

    log::info!("Successfully generated and parsed self-signed certificate.");

    Ok(TlsCertificate {
        private_key: private_key,
        certificate: certificate.to_string()
    })
}

/// Build the rustls configuration, attaching a client-certificate verifier when
/// any authentication method uses mTLS.
///
/// Built by hand rather than via `RustlsConfig::from_pem_file` because the
/// client verifier can only be set while constructing `ServerConfig`. The ALPN
/// list mirrors what axum-server sets for itself — omitting it silently drops
/// HTTP/2.
fn build_config(certificate_pem: &[u8], private_key_pem: &[u8]) -> Result<RustlsConfig, String> {
    let certificates: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(certificate_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Could not parse the TLS certificate: {}", error))?;
    if certificates.is_empty() {
        return Err("The TLS certificate file contained no certificates.".to_string());
    }

    // Scan the whole file: the key is not necessarily the first PEM block.
    let private_key = PrivateKeyDer::from_pem_slice(private_key_pem)
        .map_err(|error| format!("Could not parse the TLS private key: {}", error))?;

    let builder = ServerConfig::builder();
    let mut config = match client_verifier()? {
        Some(verifier) => builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, private_key),
        None => builder.with_no_client_auth().with_single_cert(certificates, private_key),
    }
    .map_err(|error| format!("Could not build the TLS configuration: {}", error))?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(RustlsConfig::from_config(Arc::new(config)))
}

/// A verifier trusting every CA configured across all `method_type = "mtls"`
/// authentication methods, or `None` when none use mTLS.
///
/// Deliberately `allow_unauthenticated`: rustls fixes the client verifier per
/// `ServerConfig` and cannot vary it per SNI, so demanding a certificate here
/// would demand one for every hostname on the listener. Verification is offered
/// to every connection, and which hostnames *require* a certificate is decided
/// per request.
fn client_verifier() -> Result<Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>, String> {
    let methods = match CONFIG_VALUE.authentication_methods.clone() {
        Some(methods) => methods,
        None => return Ok(None),
    };

    let mut roots = RootCertStore::empty();
    let mut sources = 0;
    for (id, method) in methods {
        if method.method_type != "mtls" || method.active == false {
            continue;
        }
        let ca_path = method.mtls_ca.clone().ok_or_else(|| {
            format!("[authentication_methods.{}] is method_type \"mtls\" but has no mtls_ca.", id)
        })?;
        let ca_pem = std::fs::read(&ca_path)
            .map_err(|error| format!("Could not read mtls_ca '{}' for '{}': {}", ca_path, id, error))?;

        let mut added = 0;
        for certificate in CertificateDer::pem_slice_iter(&ca_pem) {
            let certificate =
                certificate.map_err(|error| format!("Could not parse mtls_ca '{}': {}", ca_path, error))?;
            roots
                .add(certificate)
                .map_err(|error| format!("Could not trust a certificate in mtls_ca '{}': {}", ca_path, error))?;
            added += 1;
        }
        if added == 0 {
            return Err(format!("mtls_ca '{}' for '{}' contained no certificates.", ca_path, id));
        }
        sources += 1;
        log::info!("Trusting {} client CA certificate(s) from '{}' for mTLS method '{}'.", added, ca_path, id);
    }

    if sources == 0 {
        return Ok(None);
    }

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        // See the note above: enforcement is per hostname, not per listener.
        .allow_unauthenticated()
        .build()
        .map_err(|error| format!("Could not build the client certificate verifier: {}", error))?;

    Ok(Some(verifier))
}
