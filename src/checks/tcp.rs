//! TCP connect, optionally over TLS, optionally sending a probe and matching
//! the reply (banners such as `SSH-`, `220 `, `+OK`).

use std::time::Instant;

use regex::bytes::Regex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::util::{bytes_option, client_config, contains_bytes, excerpt, fmt_latency, server_name};
use super::{CheckContext, CheckResult, resolve_addr};
use crate::config::{IpVersion, TcpCheck};

const MAX_READ: usize = 8192;

pub struct TcpPlan {
    host: String,
    port: u16,
    tls: Option<TlsOptions>,
    send: Option<Vec<u8>>,
    expect: Option<Vec<u8>>,
    expect_regex: Option<Regex>,
    ip_version: IpVersion,
}

struct TlsOptions {
    verify: bool,
    sni: String,
}

impl TcpPlan {
    pub fn prepare(c: &TcpCheck) -> Result<Self, String> {
        if c.port == 0 {
            return Err("`port` must not be 0".into());
        }
        let send = bytes_option(&c.send, &c.send_hex, "send")?;
        let expect = match &c.expect {
            Some(e) => Some(super::util::unescape(e).map_err(|e| format!("expect: {e}"))?),
            None => None,
        };
        let expect_regex = c
            .expect_regex
            .as_deref()
            .map(Regex::new)
            .transpose()
            .map_err(|e| format!("expect_regex: {e}"))?;
        let tls = if c.tls {
            let sni = c.sni.clone().unwrap_or_else(|| c.host.clone());
            server_name(&sni)?;
            Some(TlsOptions {
                verify: c.tls_verify,
                sni,
            })
        } else {
            if c.sni.is_some() {
                return Err("`sni` requires `tls: true`".into());
            }
            None
        };
        Ok(Self {
            host: c.host.clone(),
            port: c.port,
            tls,
            send,
            expect,
            expect_regex,
            ip_version: c.ip_version,
        })
    }

    pub async fn run(&self, ctx: &CheckContext) -> CheckResult {
        let addr = match resolve_addr(ctx, &self.host, self.port, self.ip_version).await {
            Ok(a) => a,
            Err(e) => return CheckResult::down(e),
        };
        let start = Instant::now();
        let stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) => return CheckResult::down(format!("{addr}: {e}")),
        };
        let connect = start.elapsed();
        let _ = stream.set_nodelay(true);
        let result = match &self.tls {
            None => self.converse(stream).await,
            Some(tls) => {
                let config = client_config(ctx.roots.clone(), tls.verify);
                let name = match server_name(&tls.sni) {
                    Ok(n) => n,
                    Err(e) => return CheckResult::down(e),
                };
                match TlsConnector::from(config).connect(name, stream).await {
                    Ok(s) => self.converse(s).await,
                    Err(e) => Err(format!("TLS handshake failed: {e}")),
                }
            }
        };
        match result {
            Ok(detail) => CheckResult::up(
                Some(connect),
                format!("{addr}: connected in {}{detail}", fmt_latency(connect)),
            ),
            Err(e) => CheckResult::down(format!("{addr}: {e}")).with_latency(Some(connect)),
        }
    }

    async fn converse<S: AsyncRead + AsyncWrite + Unpin>(&self, mut stream: S) -> Result<String, String> {
        if let Some(data) = &self.send {
            stream.write_all(data).await.map_err(|e| format!("send failed: {e}"))?;
            stream.flush().await.map_err(|e| format!("send failed: {e}"))?;
        }
        if self.expect.is_none() && self.expect_regex.is_none() {
            return Ok(String::new());
        }
        let mut buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 1024];
        loop {
            if self.matches(&buf) {
                return Ok(format!(", received {:?}", excerpt(&buf)));
            }
            if buf.len() >= MAX_READ {
                break;
            }
            let n = stream.read(&mut chunk).await.map_err(|e| format!("read failed: {e}"))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        Err(if buf.is_empty() {
            "connection closed without data".into()
        } else {
            format!("unexpected reply {:?}", excerpt(&buf))
        })
    }

    fn matches(&self, buf: &[u8]) -> bool {
        if buf.is_empty() {
            return false;
        }
        self.expect.as_deref().is_none_or(|e| contains_bytes(buf, e))
            && self.expect_regex.as_ref().is_none_or(|r| r.is_match(buf))
    }
}
