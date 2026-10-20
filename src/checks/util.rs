//! Helpers shared by checks: resolver, trust store, TLS configs, byte escapes.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::config::TlsConfig;

pub fn system_resolver() -> anyhow::Result<TokioResolver> {
    match TokioResolver::builder_tokio() {
        Ok(builder) => Ok(builder.build()?),
        Err(e) => {
            tracing::warn!(error = %e, "cannot read /etc/resolv.conf, falling back to Cloudflare and Google resolvers");
            let mut config = ResolverConfig::default();
            for ip in ["1.1.1.1", "8.8.8.8"] {
                config.add_name_server(hickory_resolver::config::NameServerConfig::udp_and_tcp(
                    ip.parse().expect("valid ip"),
                ));
            }
            let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
            *builder.options_mut() = ResolverOpts::default();
            Ok(builder.build()?)
        }
    }
}

pub fn load_roots(tls: &TlsConfig) -> anyhow::Result<(RootCertStore, Vec<CertificateDer<'static>>)> {
    let mut roots = RootCertStore::empty();
    if !tls.disable_system_roots {
        let native = rustls_native_certs::load_native_certs();
        for e in &native.errors {
            tracing::warn!(error = %e, "error while loading system certificates");
        }
        let (added, ignored) = roots.add_parsable_certificates(native.certs);
        tracing::debug!(added, ignored, "loaded system trust store");
        if added == 0 {
            tracing::warn!("no system CA certificate found; TLS verification will fail unless tls.ca_files is set");
        }
    }
    let mut extra = Vec::new();
    for file in &tls.ca_files {
        let certs = read_pem_certs(file)?;
        for c in &certs {
            roots
                .add(c.clone())
                .with_context(|| format!("{}: invalid CA certificate", file.display()))?;
        }
        extra.extend(certs);
    }
    Ok((roots, extra))
}

pub fn read_pem_certs(file: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    let data = fs::read(file).with_context(|| format!("cannot read {}", file.display()))?;
    let certs = CertificateDer::pem_slice_iter(&data)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("{}: invalid PEM", file.display()))?;
    if certs.is_empty() {
        anyhow::bail!("{}: no certificate found", file.display());
    }
    Ok(certs)
}

/// TLS client configuration that verifies the server, or not at all.
pub fn client_config(roots: Arc<RootCertStore>, verify: bool) -> Arc<ClientConfig> {
    let builder = ClientConfig::builder();
    let config = if verify {
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier::default()))
            .with_no_client_auth()
    };
    Arc::new(config)
}

pub fn server_name(name: &str) -> Result<ServerName<'static>, String> {
    let name = name.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(name.to_owned()).map_err(|e| format!("invalid server name {name:?}: {e}"))
}

/// Accepts any certificate but still checks handshake signatures.
#[derive(Debug)]
pub struct NoVerifier(Arc<rustls::crypto::CryptoProvider>);

impl Default for NoVerifier {
    fn default() -> Self {
        Self(Arc::new(rustls::crypto::ring::default_provider()))
    }
}

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Decode `\n`, `\r`, `\t`, `\0`, `\\` and `\xHH` escapes.
pub fn unescape(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b != b'\\' {
            out.push(b);
            i += 1;
            continue;
        }
        let next = *bytes.get(i + 1).ok_or("trailing backslash")?;
        i += 2;
        match next {
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'0' => out.push(0),
            b'\\' => out.push(b'\\'),
            b'x' => {
                let hex = s.get(i..i + 2).ok_or("incomplete \\x escape")?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| format!("invalid \\x{hex} escape"))?);
                i += 2;
            }
            other => return Err(format!("unknown escape \\{}", other as char)),
        }
    }
    Ok(out)
}

/// Decode hexadecimal, ignoring whitespace and `:` separators.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    if !clean.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|_| format!("invalid hex {:?}", &clean[i..i + 2])))
        .collect()
}

/// Bytes to send or expect: from an escaped string or from hex.
pub fn bytes_option(text: &Option<String>, hex: &Option<String>, what: &str) -> Result<Option<Vec<u8>>, String> {
    match (text, hex) {
        (Some(_), Some(_)) => Err(format!("set only one of `{what}` and `{what}_hex`")),
        (Some(t), None) => unescape(t).map(Some).map_err(|e| format!("{what}: {e}")),
        (None, Some(h)) => parse_hex(h).map(Some).map_err(|e| format!("{what}_hex: {e}")),
        (None, None) => Ok(None),
    }
}

pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}

pub fn fmt_latency(d: Duration) -> String {
    let us = d.as_micros();
    if us < 1000 {
        format!("{us}µs")
    } else if us < 1_000_000 {
        format!("{:.1}ms", us as f64 / 1000.0)
    } else {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    }
}

/// Printable excerpt of received bytes for messages.
pub fn excerpt(data: &[u8]) -> String {
    let text = String::from_utf8_lossy(&data[..data.len().min(64)]);
    let mut s: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    s = s.trim().to_owned();
    if data.len() > 64 {
        s.push('…');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescapes() {
        assert_eq!(unescape(r"a\r\n\x00\\").unwrap(), b"a\r\n\0\\");
        assert!(unescape(r"\q").is_err());
        assert!(unescape(r"\x0").is_err());
    }

    #[test]
    fn parses_hex() {
        assert_eq!(parse_hex("de ad:BE ef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(parse_hex("abc").is_err());
        assert!(parse_hex("zz").is_err());
    }

    #[test]
    fn finds_bytes() {
        assert!(contains_bytes(b"SSH-2.0-OpenSSH", b"SSH-"));
        assert!(!contains_bytes(b"HTTP/1.1", b"SSH-"));
    }
}
