use std::process::Command;
use std::process::Stdio;

use rocket::config::{TlsConfig, CipherSuite};

use crate::structs::TlsCertificate;
use crate::CONFIG_VALUE;

pub async fn init_tls() -> Option<TlsConfig> {
    if CONFIG_VALUE.features.clone().unwrap().tls.unwrap_or(true) == true {
        // TODO: In the future, allow getting certificates from environment variables (e.g. to accomodate Docker).
        let config_tls = CONFIG_VALUE.clone().tls;
        if config_tls.is_none() == false {
            // Use TLS certificates provided in Guard configuration.
            let config_tls_unwrapped = config_tls.clone().unwrap();

            println!("certificate {}", &config_tls_unwrapped.clone().certificate.expect("Missing config.tls.certificate"));
            println!("private_key {}", &config_tls_unwrapped.clone().private_key.expect("Missing config.tls.private_key"));

            log::debug!("Using TLS certificate specified in configuration (paths: certificate {}, private_key {}).", &config_tls_unwrapped.certificate.clone().expect("Missing config.tls.certificate"), &config_tls_unwrapped.private_key.clone().expect("Missing config.tls.private_key"));

            Some(TlsConfig::from_paths(&config_tls_unwrapped.certificate.expect("Missing config.tls.certificate"), &config_tls_unwrapped.private_key.expect("Missing config.tls.private_key")).with_ciphers(CipherSuite::TLS_V13_SET))
        } else {
            // Use one-time generated self-signed certificate.
            
            log::warn!("No TLS certificate specified in configuration, using self-signed certificate. Note: do not use self-signed certificates in production.");
            let certificate = generate_self_signed_certificate().await.expect("Failed to generate self-signed certificate");
            Some(TlsConfig::from_bytes(&certificate.certificate.into_bytes(), &certificate.private_key.into_bytes()).with_ciphers(CipherSuite::TLS_V13_SET))
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