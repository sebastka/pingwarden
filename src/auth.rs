//! Bearer authentication: static API tokens, and JWT access tokens issued by
//! an OpenID Connect provider.
//!
//! Pingwarden is only a resource server: it never issues tokens. JWTs are
//! verified locally with the provider's published keys (JWKS), which are
//! discovered from the issuer, cached and refreshed periodically or when a
//! token names an unknown key. Signatures are checked with `ring`, the
//! crypto library already used for TLS.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::config::{OidcConfig, TokenScope};

/// Who made a request, for authorization and audit logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// `token:<name>`, `oidc:<subject>` or `anonymous`.
    pub name: String,
    pub scope: Option<TokenScope>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported signing algorithm {0:?}")]
    UnsupportedAlgorithm(String),
    #[error("no matching signing key")]
    UnknownKey,
    #[error("invalid signature")]
    BadSignature,
    #[error("token expired")]
    Expired,
    #[error("token not valid yet")]
    NotYetValid,
    #[error("wrong issuer")]
    Issuer,
    #[error("wrong audience")]
    Audience,
    #[error("signing keys unavailable: {0}")]
    Unavailable(String),
}

/// Minimum delay between two key refreshes triggered by unknown key ids, so
/// forged tokens cannot make Pingwarden hammer the provider.
const ON_DEMAND_REFRESH: Duration = Duration::from_secs(30);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alg {
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    EdDsa,
}

impl Alg {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "RS256" => Alg::Rs256,
            "RS384" => Alg::Rs384,
            "RS512" => Alg::Rs512,
            "PS256" => Alg::Ps256,
            "PS384" => Alg::Ps384,
            "PS512" => Alg::Ps512,
            "ES256" => Alg::Es256,
            "ES384" => Alg::Es384,
            "EdDSA" => Alg::EdDsa,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Alg::Rs256 => "RS256",
            Alg::Rs384 => "RS384",
            Alg::Rs512 => "RS512",
            Alg::Ps256 => "PS256",
            Alg::Ps384 => "PS384",
            Alg::Ps512 => "PS512",
            Alg::Es256 => "ES256",
            Alg::Es384 => "ES384",
            Alg::EdDsa => "EdDSA",
        }
    }
}

#[derive(Clone, Debug)]
enum KeyMaterial {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    P256(Vec<u8>),
    P384(Vec<u8>),
    Ed25519(Vec<u8>),
}

#[derive(Clone, Debug)]
struct Key {
    kid: Option<String>,
    alg: Option<String>,
    material: KeyMaterial,
}

impl Key {
    fn supports(&self, alg: Alg) -> bool {
        if self.alg.as_deref().is_some_and(|a| a != alg.name()) {
            return false;
        }
        matches!(
            (&self.material, alg),
            (
                KeyMaterial::Rsa { .. },
                Alg::Rs256 | Alg::Rs384 | Alg::Rs512 | Alg::Ps256 | Alg::Ps384 | Alg::Ps512
            ) | (KeyMaterial::P256(_), Alg::Es256)
                | (KeyMaterial::P384(_), Alg::Es384)
                | (KeyMaterial::Ed25519(_), Alg::EdDsa)
        )
    }

    fn verify(&self, alg: Alg, message: &[u8], sig: &[u8]) -> bool {
        let ok = match (&self.material, alg) {
            (KeyMaterial::Rsa { n, e }, _) => {
                let params: &signature::RsaParameters = match alg {
                    Alg::Rs256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    Alg::Rs384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    Alg::Rs512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    Alg::Ps256 => &signature::RSA_PSS_2048_8192_SHA256,
                    Alg::Ps384 => &signature::RSA_PSS_2048_8192_SHA384,
                    Alg::Ps512 => &signature::RSA_PSS_2048_8192_SHA512,
                    _ => return false,
                };
                RsaPublicKeyComponents { n, e }.verify(params, message, sig)
            }
            (KeyMaterial::P256(point), Alg::Es256) => {
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point).verify(message, sig)
            }
            (KeyMaterial::P384(point), Alg::Es384) => {
                UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, point).verify(message, sig)
            }
            (KeyMaterial::Ed25519(x), Alg::EdDsa) => {
                UnparsedPublicKey::new(&signature::ED25519, x).verify(message, sig)
            }
            _ => return false,
        };
        ok.is_ok()
    }
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    crv: Option<String>,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

fn b64(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

/// Left-pad an EC coordinate to the curve's field size.
fn coordinate(s: &str, len: usize) -> Option<Vec<u8>> {
    let mut v = b64(s)?;
    if v.len() > len {
        return None;
    }
    let mut padded = vec![0; len - v.len()];
    padded.append(&mut v);
    Some(padded)
}

impl Jwk {
    fn into_key(self) -> Option<Key> {
        if self.usage.as_deref().is_some_and(|u| u != "sig") {
            return None;
        }
        let material = match (self.kty.as_str(), self.crv.as_deref()) {
            ("RSA", _) => KeyMaterial::Rsa {
                n: b64(self.n.as_deref()?)?,
                e: b64(self.e.as_deref()?)?,
            },
            ("EC", Some(crv @ ("P-256" | "P-384"))) => {
                let size = if crv == "P-256" { 32 } else { 48 };
                let mut point = vec![0x04];
                point.extend(coordinate(self.x.as_deref()?, size)?);
                point.extend(coordinate(self.y.as_deref()?, size)?);
                if crv == "P-256" {
                    KeyMaterial::P256(point)
                } else {
                    KeyMaterial::P384(point)
                }
            }
            ("OKP", Some("Ed25519")) => KeyMaterial::Ed25519(b64(self.x.as_deref()?)?),
            _ => return None,
        };
        Some(Key {
            kid: self.kid,
            alg: self.alg,
            material,
        })
    }
}

fn parse_jwks(body: &Value) -> Result<Vec<Key>, String> {
    let keys = body
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("JWKS has no `keys` array")?;
    let parsed: Vec<Key> = keys
        .iter()
        .filter_map(|k| serde_json::from_value::<Jwk>(k.clone()).ok())
        .filter_map(Jwk::into_key)
        .collect();
    if parsed.is_empty() {
        return Err("JWKS holds no usable signing key".into());
    }
    Ok(parsed)
}

fn trim_slash(s: &str) -> &str {
    s.trim_end_matches('/')
}

/// The values of a dotted claim path: a space-separated string, a string
/// list, or a single scalar.
fn claim_values(claims: &Value, path: &str) -> Vec<String> {
    let mut v = claims;
    for seg in path.split('.') {
        match v.get(seg) {
            Some(next) => v = next,
            None => return Vec::new(),
        }
    }
    match v {
        Value::String(s) => s.split_whitespace().map(str::to_owned).collect(),
        Value::Array(a) => a.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
        Value::Bool(_) | Value::Number(_) => vec![v.to_string()],
        _ => Vec::new(),
    }
}

pub struct OidcVerifier {
    config: OidcConfig,
    audiences: Vec<String>,
    http: reqwest::Client,
    keys: RwLock<Vec<Key>>,
    /// Serializes refreshes and remembers when the last one happened.
    last_refresh: Mutex<Option<Instant>>,
}

impl OidcVerifier {
    pub fn new(config: OidcConfig, http: reqwest::Client) -> Self {
        Self {
            audiences: config.audience.to_vec(),
            config,
            http,
            keys: RwLock::new(Vec::new()),
            last_refresh: Mutex::new(None),
        }
    }

    /// Keep the signing keys fresh until `shutdown`.
    pub async fn refresh_loop(self: std::sync::Arc<Self>, shutdown: tokio_util::sync::CancellationToken) {
        let mut retry = Duration::from_secs(5);
        loop {
            let wait = match self.refresh(Duration::ZERO).await {
                Ok(n) => {
                    tracing::debug!(keys = n, "OIDC signing keys refreshed");
                    retry = Duration::from_secs(5);
                    self.config.jwks_refresh.0
                }
                Err(e) => {
                    tracing::warn!(error = %e, retry_in = ?retry, "cannot fetch OIDC signing keys");
                    let w = retry;
                    retry = (retry * 2).min(Duration::from_secs(300));
                    w
                }
            };
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }

    /// Fetch the keys unless another refresh happened within `min_interval`.
    async fn refresh(&self, min_interval: Duration) -> Result<usize, String> {
        let mut last = self.last_refresh.lock().await;
        if let Some(t) = *last
            && t.elapsed() < min_interval
        {
            return Ok(0);
        }
        *last = Some(Instant::now());
        let keys = self.fetch_keys().await?;
        let n = keys.len();
        if let Ok(mut k) = self.keys.write() {
            *k = keys;
        }
        Ok(n)
    }

    async fn get_json(&self, url: &str) -> Result<Value, String> {
        let resp = self
            .http
            .get(url)
            .timeout(HTTP_TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("{url}: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("{url}: HTTP {}", resp.status()));
        }
        resp.json().await.map_err(|e| format!("{url}: {e}"))
    }

    async fn fetch_keys(&self) -> Result<Vec<Key>, String> {
        let jwks_url = match &self.config.jwks_url {
            Some(u) => u.clone(),
            None => {
                let url = format!("{}/.well-known/openid-configuration", trim_slash(&self.config.issuer));
                let doc = self.get_json(&url).await?;
                // OpenID Connect Discovery 1.0, section 4.3.
                let issuer = doc.get("issuer").and_then(Value::as_str).unwrap_or_default();
                if trim_slash(issuer) != trim_slash(&self.config.issuer) {
                    return Err(format!(
                        "discovery document announces issuer {issuer:?}, expected {:?}",
                        self.config.issuer
                    ));
                }
                doc.get("jwks_uri")
                    .and_then(Value::as_str)
                    .ok_or("discovery document has no jwks_uri")?
                    .to_owned()
            }
        };
        parse_jwks(&self.get_json(&jwks_url).await?)
    }

    /// Keys that may have signed the token: the one named by `kid`, or
    /// every key compatible with `alg` when the token names none.
    fn candidates(&self, kid: Option<&str>, alg: Alg) -> Vec<Key> {
        let Ok(keys) = self.keys.read() else { return Vec::new() };
        keys.iter()
            .filter(|k| k.supports(alg))
            .filter(|k| kid.is_none_or(|kid| k.kid.as_deref() == Some(kid)))
            .cloned()
            .collect()
    }

    /// Verify a JWT access token and map its claims to a principal.
    pub async fn verify(&self, token: &str) -> Result<Principal, AuthError> {
        let now = jiff::Timestamp::now().as_second();
        self.verify_at(token, now).await
    }

    async fn verify_at(&self, token: &str, now: i64) -> Result<Principal, AuthError> {
        let mut parts = token.split('.');
        let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return Err(AuthError::Malformed);
        };
        let header: Value = b64(h)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or(AuthError::Malformed)?;
        let alg_name = header.get("alg").and_then(Value::as_str).unwrap_or_default();
        // Never `none`, never HMAC: only the asymmetric algorithms above.
        let alg = Alg::parse(alg_name).ok_or_else(|| AuthError::UnsupportedAlgorithm(alg_name.to_owned()))?;
        let kid = header.get("kid").and_then(Value::as_str);
        let sig = b64(s).ok_or(AuthError::Malformed)?;

        let mut keys = self.candidates(kid, alg);
        if keys.is_empty() {
            // Unknown key: the provider may have rotated its keys.
            self.refresh(ON_DEMAND_REFRESH).await.map_err(AuthError::Unavailable)?;
            keys = self.candidates(kid, alg);
            if keys.is_empty() {
                return Err(AuthError::UnknownKey);
            }
        }
        let signed = &token[..h.len() + 1 + p.len()];
        if !keys.iter().any(|k| k.verify(alg, signed.as_bytes(), &sig)) {
            return Err(AuthError::BadSignature);
        }

        let claims: Value = b64(p)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or(AuthError::Malformed)?;
        let leeway = self.config.leeway.0.as_secs() as i64;
        let exp = claims.get("exp").and_then(Value::as_i64).ok_or(AuthError::Malformed)?;
        if now > exp + leeway {
            return Err(AuthError::Expired);
        }
        if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64)
            && now + leeway < nbf
        {
            return Err(AuthError::NotYetValid);
        }
        let iss = claims.get("iss").and_then(Value::as_str).unwrap_or_default();
        if trim_slash(iss) != trim_slash(&self.config.issuer) {
            return Err(AuthError::Issuer);
        }
        let aud = claim_values(&claims, "aud");
        if !aud.iter().any(|a| self.audiences.contains(a)) {
            return Err(AuthError::Audience);
        }

        let values = claim_values(&claims, &self.config.claim);
        let has = |list: &[String]| values.iter().any(|v| list.contains(v));
        let scope = if has(&self.config.admin) {
            Some(TokenScope::Admin)
        } else if has(&self.config.read) {
            Some(TokenScope::Read)
        } else {
            None
        };
        // Readable names first: Keycloak's `sub` is an opaque UUID.
        let subject = ["preferred_username", "client_id", "sub", "azp"]
            .iter()
            .find_map(|c| claims.get(*c).and_then(Value::as_str))
            .unwrap_or("unknown");
        Ok(Principal {
            name: format!("oidc:{subject}"),
            scope,
        })
    }

    #[cfg(test)]
    fn set_keys(&self, keys: Vec<Key>) {
        *self.keys.write().unwrap() = keys;
    }
}

/// Whether a bearer value looks like a JWT rather than a static token.
pub fn looks_like_jwt(token: &str) -> bool {
    token.split('.').count() == 3 && token.starts_with("eyJ")
}

#[cfg(test)]
mod tests;
