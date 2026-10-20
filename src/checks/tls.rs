//! Certificate check. The handshake always completes (the verifier records
//! the chain and the verification error instead of aborting), so expired,
//! self-signed or mismatched certificates can still be reported in detail.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::util::{fmt_latency, read_pem_certs, server_name};
use super::{CheckContext, CheckResult, resolve_addr};
use crate::config::{IpVersion, StartTls, TlsCheck};
use crate::model::Outcome;

pub struct TlsPlan {
    host: String,
    port: u16,
    sni: String,
    starttls: StartTls,
    verify_chain: bool,
    verify_hostname: bool,
    warning_secs: i64,
    down_secs: i64,
    extra_roots: Vec<CertificateDer<'static>>,
    ip_version: IpVersion,
}

impl TlsPlan {
    pub fn prepare(c: &TlsCheck) -> Result<Self, String> {
        let sni = c.sni.clone().unwrap_or_else(|| c.host.clone());
        server_name(&sni)?;
        if c.expiry_down > c.expiry_warning {
            return Err("`expiry_down` must not exceed `expiry_warning`".into());
        }
        let extra_roots = match &c.ca_file {
            Some(f) => read_pem_certs(f).map_err(|e| e.to_string())?,
            None => Vec::new(),
        };
        Ok(Self {
            host: c.host.clone(),
            port: c.port,
            sni,
            starttls: c.starttls,
            verify_chain: c.verify_chain,
            verify_hostname: c.verify_hostname,
            warning_secs: i64::try_from(c.expiry_warning.0.as_secs()).unwrap_or(i64::MAX),
            down_secs: i64::try_from(c.expiry_down.0.as_secs()).unwrap_or(i64::MAX),
            extra_roots,
            ip_version: c.ip_version,
        })
    }

    pub async fn run(&self, ctx: &CheckContext) -> CheckResult {
        let addr = match resolve_addr(ctx, &self.host, self.port, self.ip_version).await {
            Ok(a) => a,
            Err(e) => return CheckResult::down(e),
        };
        let start = Instant::now();
        let mut stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) => return CheckResult::down(format!("{addr}: {e}")),
        };
        if let Err(e) = starttls(&mut stream, self.starttls).await {
            return CheckResult::down(format!("{addr}: STARTTLS failed: {e}"));
        }
        let roots = if self.extra_roots.is_empty() {
            ctx.roots.clone()
        } else {
            let mut r = (*ctx.roots).clone();
            for c in &self.extra_roots {
                let _ = r.add(c.clone());
            }
            Arc::new(r)
        };
        let verifier = match CapturingVerifier::new(roots) {
            Ok(v) => Arc::new(v),
            Err(e) => return CheckResult::down(e),
        };
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        let name = match server_name(&self.sni) {
            Ok(n) => n,
            Err(e) => return CheckResult::down(e),
        };
        let handshake = TlsConnector::from(Arc::new(config)).connect(name, stream).await;
        let latency = start.elapsed();
        let captured = verifier.captured.lock().map(|mut c| c.take()).unwrap_or(None);
        let Some(captured) = captured else {
            return match handshake {
                Err(e) => CheckResult::down(format!("{addr}: TLS handshake failed: {e}")),
                Ok(_) => CheckResult::down(format!("{addr}: no certificate presented")),
            };
        };
        if let Err(e) = handshake {
            return CheckResult::down(format!("{addr}: TLS handshake failed: {e}"));
        }
        self.evaluate(captured, latency)
    }

    fn evaluate(&self, captured: Captured, latency: std::time::Duration) -> CheckResult {
        let now = jiff::Timestamp::now().as_second();
        let mut earliest: Option<(i64, String)> = None;
        let mut leaf_desc = String::new();
        for (i, der) in captured.chain.iter().enumerate() {
            let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
                return CheckResult::down("cannot parse server certificate");
            };
            let not_after = cert.validity().not_after.timestamp();
            let subject = cert.subject().to_string();
            if i == 0 {
                leaf_desc = format!("{subject}, issued by {}", cert.issuer());
            }
            if earliest.as_ref().is_none_or(|(t, _)| not_after < *t) {
                let who = if i == 0 {
                    "certificate".to_owned()
                } else {
                    format!("intermediate {subject}")
                };
                earliest = Some((not_after, who));
            }
        }
        let Some((expiry, who)) = earliest else {
            return CheckResult::down("no certificate presented");
        };
        let remaining = expiry - now;
        let until = jiff::Timestamp::from_second(expiry)
            .map(|t| t.strftime("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|_| expiry.to_string());
        let days = remaining.div_euclid(86_400);

        let mut outcome = Outcome::Up;
        let mut problems = Vec::new();
        if let Some(err) = &captured.error {
            let name_only = matches!(
                err,
                rustls::Error::InvalidCertificate(
                    CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
                )
            );
            // Expiry is evaluated below, with the configured thresholds.
            let expired = matches!(
                err,
                rustls::Error::InvalidCertificate(CertificateError::Expired | CertificateError::ExpiredContext { .. })
            );
            let relevant = if name_only {
                self.verify_hostname
            } else {
                self.verify_chain && !expired
            };
            if relevant {
                outcome = Outcome::Down;
                problems.push(describe(err));
            }
        }
        if remaining <= self.down_secs {
            outcome = Outcome::Down;
            if remaining <= 0 {
                problems.push(format!("{who} expired on {until}"));
            } else {
                problems.push(format!("{who} expires on {until} ({days} days)"));
            }
        } else if remaining <= self.warning_secs {
            outcome = outcome.worst(Outcome::Degraded);
            problems.push(format!("{who} expires on {until} ({days} days)"));
        }

        let message = if problems.is_empty() {
            format!(
                "{leaf_desc}; valid until {until} ({days} days), handshake in {}",
                fmt_latency(latency)
            )
        } else {
            format!("{}; {leaf_desc}", problems.join("; "))
        };
        let mut result = match outcome {
            Outcome::Up => CheckResult::up(Some(latency), message),
            Outcome::Degraded => CheckResult::degraded(Some(latency), message),
            Outcome::Down => CheckResult::down(message).with_latency(Some(latency)),
        };
        result.cert_expiry = Some(expiry);
        result
    }
}

fn describe(err: &rustls::Error) -> String {
    match err {
        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer) => {
            "certificate is not trusted (unknown issuer or self-signed)".into()
        }
        rustls::Error::InvalidCertificate(CertificateError::NotValidForName)
        | rustls::Error::InvalidCertificate(CertificateError::NotValidForNameContext { .. }) => {
            "certificate does not match the host name".into()
        }
        rustls::Error::InvalidCertificate(CertificateError::Expired)
        | rustls::Error::InvalidCertificate(CertificateError::ExpiredContext { .. }) => {
            "certificate has expired".into()
        }
        rustls::Error::InvalidCertificate(CertificateError::NotValidYet)
        | rustls::Error::InvalidCertificate(CertificateError::NotValidYetContext { .. }) => {
            "certificate is not valid yet".into()
        }
        rustls::Error::InvalidCertificate(CertificateError::Revoked) => "certificate is revoked".into(),
        other => format!("certificate verification failed: {other}"),
    }
}

struct Captured {
    chain: Vec<CertificateDer<'static>>,
    error: Option<rustls::Error>,
}

#[derive(Debug)]
struct CapturingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    captured: Mutex<Option<Captured>>,
}

impl std::fmt::Debug for Captured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Captured").field("certs", &self.chain.len()).finish()
    }
}

impl CapturingVerifier {
    fn new(roots: Arc<RootCertStore>) -> Result<Self, String> {
        let inner = WebPkiServerVerifier::builder(roots)
            .build()
            .map_err(|e| format!("cannot build certificate verifier: {e}"))?;
        Ok(Self {
            inner,
            captured: Mutex::new(None),
        })
    }
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let error = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .err();
        let mut chain = Vec::with_capacity(1 + intermediates.len());
        chain.push(end_entity.clone().into_owned());
        chain.extend(intermediates.iter().map(|c| c.clone().into_owned()));
        if let Ok(mut slot) = self.captured.lock() {
            *slot = Some(Captured { chain, error });
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// --------------------------------------------------------------- STARTTLS

async fn starttls(stream: &mut TcpStream, proto: StartTls) -> Result<(), String> {
    match proto {
        StartTls::None => Ok(()),
        StartTls::Postgres => {
            // SSLRequest: length 8, code 80877103.
            stream
                .write_all(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f])
                .await
                .map_err(|e| e.to_string())?;
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            if b[0] == b'S' {
                Ok(())
            } else {
                Err("server refused SSL".into())
            }
        }
        StartTls::Ldap => ldap_starttls(stream).await,
        StartTls::Smtp => {
            let mut r = BufReader::new(stream);
            expect_code(&mut r, "220").await?;
            send(r.get_mut(), "EHLO pingwarden\r\n").await?;
            expect_code(&mut r, "250").await?;
            send(r.get_mut(), "STARTTLS\r\n").await?;
            expect_code(&mut r, "220").await?;
            ensure_drained(&r)
        }
        StartTls::Ftp => {
            let mut r = BufReader::new(stream);
            expect_code(&mut r, "220").await?;
            send(r.get_mut(), "AUTH TLS\r\n").await?;
            expect_code(&mut r, "234").await?;
            ensure_drained(&r)
        }
        StartTls::Pop3 => {
            let mut r = BufReader::new(stream);
            expect_prefix(&mut r, "+OK").await?;
            send(r.get_mut(), "STLS\r\n").await?;
            expect_prefix(&mut r, "+OK").await?;
            ensure_drained(&r)
        }
        StartTls::Imap => {
            let mut r = BufReader::new(stream);
            expect_prefix(&mut r, "* OK").await?;
            send(r.get_mut(), "pw1 STARTTLS\r\n").await?;
            loop {
                let line = read_line(&mut r).await?;
                if let Some(rest) = line.strip_prefix("pw1 ") {
                    return if rest.starts_with("OK") {
                        ensure_drained(&r)
                    } else {
                        Err(format!("server replied {line:?}"))
                    };
                }
            }
        }
    }
}

fn ensure_drained(r: &BufReader<&mut TcpStream>) -> Result<(), String> {
    if r.buffer().is_empty() {
        Ok(())
    } else {
        Err("unexpected data before TLS handshake".into())
    }
}

async fn send(s: &mut TcpStream, line: &str) -> Result<(), String> {
    s.write_all(line.as_bytes()).await.map_err(|e| e.to_string())
}

async fn read_line(r: &mut BufReader<&mut TcpStream>) -> Result<String, String> {
    let mut line = String::new();
    let n = (&mut *r)
        .take(4096)
        .read_line(&mut line)
        .await
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err("connection closed".into());
    }
    Ok(line.trim_end().to_owned())
}

/// Read an SMTP/FTP style reply (`250-…` continuation lines, `250 …` last).
async fn expect_code(r: &mut BufReader<&mut TcpStream>, code: &str) -> Result<(), String> {
    loop {
        let line = read_line(r).await?;
        if line.len() < 3 || !line.is_char_boundary(3) {
            return Err(format!("malformed reply {line:?}"));
        }
        if &line[..3] != code {
            return Err(format!("expected {code}, server replied {line:?}"));
        }
        if line.as_bytes().get(3) != Some(&b'-') {
            return Ok(());
        }
    }
}

async fn expect_prefix(r: &mut BufReader<&mut TcpStream>, prefix: &str) -> Result<(), String> {
    let line = read_line(r).await?;
    if line.starts_with(prefix) {
        Ok(())
    } else {
        Err(format!("expected {prefix:?}, server replied {line:?}"))
    }
}

/// LDAP StartTLS extended operation (RFC 4511 §4.14).
async fn ldap_starttls(stream: &mut TcpStream) -> Result<(), String> {
    const OID: &[u8] = b"1.3.6.1.4.1.1466.20037";
    let mut req = vec![0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16];
    req.extend_from_slice(OID);
    stream.write_all(&req).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
    match ldap_result_code(&buf[..n]) {
        Some(0) => Ok(()),
        Some(code) => Err(format!("server returned LDAP result code {code}")),
        None => Err("malformed LDAP response".into()),
    }
}

/// Extract the resultCode of an ExtendedResponse.
fn ldap_result_code(msg: &[u8]) -> Option<u8> {
    fn header(b: &[u8]) -> Option<(u8, usize, usize)> {
        let tag = *b.first()?;
        let first = *b.get(1)? as usize;
        if first < 0x80 {
            return Some((tag, first, 2));
        }
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        Some((tag, len, 2 + n))
    }
    let (tag, _, off) = header(msg)?;
    if tag != 0x30 {
        return None;
    }
    let rest = &msg[off..];
    let (tag, len, off) = header(rest)?; // messageID
    if tag != 0x02 {
        return None;
    }
    let rest = rest.get(off + len..)?;
    let (tag, _, off) = header(rest)?; // ExtendedResponse
    if tag != 0x78 {
        return None;
    }
    let rest = &rest[off..];
    let (tag, len, off) = header(rest)?; // resultCode ENUMERATED
    if tag != 0x0a || len != 1 {
        return None;
    }
    rest.get(off).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ldap_result() {
        let ok = [
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
        ];
        assert_eq!(ldap_result_code(&ok), Some(0));
        let mut refused = ok;
        refused[9] = 2;
        assert_eq!(ldap_result_code(&refused), Some(2));
        assert_eq!(ldap_result_code(&[0x30, 0x01]), None);
        // Long-form length.
        let long = [
            0x30, 0x81, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
        ];
        assert_eq!(ldap_result_code(&long), Some(0));
    }
}
