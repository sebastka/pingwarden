//! The HTTP API with static tokens, OIDC access tokens (from a mock identity
//! provider serving discovery and JWKS) and CORS.

mod common;

use std::sync::{Arc, RwLock};

use axum::Router;
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pingwarden::api::{self, AppState};
use pingwarden::auth::OidcVerifier;
use pingwarden::config::Endpoints;
use pingwarden::metrics::Metrics;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const STATIC_TOKEN: &str = "static-read-token-0123456789";

fn enc(v: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(v)
}

struct Idp {
    issuer: String,
    key: EcdsaKeyPair,
}

impl Idp {
    async fn start() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let point = key.public_key().as_ref().to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}/realms/home", listener.local_addr().unwrap());
        let jwks = json!({"keys": [{
            "kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig", "alg": "ES256",
            "x": enc(&point[1..33]), "y": enc(&point[33..65]),
        }]});
        let discovery = json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/protocol/openid-connect/certs"),
        });
        let app = Router::new()
            .route(
                "/realms/home/.well-known/openid-configuration",
                get(move || {
                    let d = discovery.clone();
                    async move { axum::Json(d) }
                }),
            )
            .route(
                "/realms/home/protocol/openid-connect/certs",
                get(move || {
                    let j = jwks.clone();
                    async move { axum::Json(j) }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Idp { issuer, key }
    }

    fn token(&self, roles: &[&str], exp_offset: i64) -> String {
        let now = jiff::Timestamp::now().as_second();
        let header = json!({"alg": "ES256", "kid": "k1", "typ": "JWT"});
        let claims = json!({
            "iss": self.issuer, "aud": "pingwarden", "sub": "alice",
            "exp": now + exp_offset, "realm_access": {"roles": roles},
        });
        let input = format!(
            "{}.{}",
            enc(header.to_string().as_bytes()),
            enc(claims.to_string().as_bytes())
        );
        let sig = self.key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
        format!("{input}.{}", enc(sig.as_ref()))
    }
}

async fn serve(url: &str, idp: &Idp) -> String {
    let yaml = format!(
        r#"
database: {{ url: "{url}" }}
server:
  api_tokens:
    - {{ name: script, token: {STATIC_TOKEN}, scope: read }}
  auth:
    oidc:
      issuer: "{issuer}"
      audience: pingwarden
      claim: realm_access.roles
      read: [pw-read]
      admin: [pw-admin]
  cors:
    allowed_origins: ["https://ui.example.com"]
"#,
        issuer = idp.issuer
    );
    let config = Arc::new(pingwarden::config::from_str(&yaml).unwrap());
    let store = common::store(url).await;
    let verifier = OidcVerifier::new(config.server.auth.oidc.clone().unwrap(), reqwest::Client::new());
    let (reload, _rx) = tokio::sync::mpsc::channel(1);
    let state = Arc::new(AppState {
        config: RwLock::new(config),
        engine: RwLock::new(None),
        store,
        metrics: Metrics::new(),
        reload,
        oidc: Some(Arc::new(verifier)),
    });
    let router = api::router(state, &Endpoints::ALL);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn api_accepts_static_and_oidc_tokens() {
    let Some((_, url)) = common::database_urls().into_iter().next() else {
        return;
    };
    let idp = Idp::start().await;
    let base = serve(&url, &idp).await;
    let http = reqwest::Client::new();
    let status = |req: reqwest::RequestBuilder| async move { req.send().await.unwrap().status().as_u16() };
    let get = |token: Option<&str>| {
        let r = http.get(format!("{base}/api/v1/status"));
        match token {
            Some(t) => r.bearer_auth(t),
            None => r,
        }
    };
    let pause = |token: &str| http.post(format!("{base}/api/v1/monitors/x/pause")).bearer_auth(token);

    assert_eq!(status(get(None)).await, 401);
    assert_eq!(status(get(Some("wrong-token-0123456789"))).await, 401);
    assert_eq!(status(get(Some(STATIC_TOKEN))).await, 200);
    assert_eq!(status(pause(STATIC_TOKEN)).await, 403, "read token cannot pause");

    // The first OIDC token triggers discovery and the JWKS fetch.
    let reader = idp.token(&["pw-read"], 300);
    let admin = idp.token(&["offline_access", "pw-admin"], 300);
    assert_eq!(status(get(Some(&reader))).await, 200);
    assert_eq!(status(pause(&reader)).await, 403);
    // Authorized: the standby instance (no engine here) answers 503.
    assert_eq!(status(pause(&admin)).await, 503);
    assert_eq!(status(get(Some(&idp.token(&["nothing"], 300)))).await, 403);
    let expired = http
        .get(format!("{base}/api/v1/status"))
        .bearer_auth(idp.token(&["pw-admin"], -3600));
    let resp = expired.send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    assert!(resp.text().await.unwrap().contains("token expired"));

    // Probes and push stay outside API authentication.
    assert_eq!(status(http.get(format!("{base}/healthz"))).await, 200);

    // CORS: preflight answered without credentials, for allowed origins only.
    let preflight = |origin: &str| {
        http.request(reqwest::Method::OPTIONS, format!("{base}/api/v1/monitors/x/pause"))
            .header("Origin", origin)
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "authorization")
    };
    let ok = preflight("https://ui.example.com").send().await.unwrap();
    assert!(ok.status().is_success(), "{}", ok.status());
    assert_eq!(ok.headers()["access-control-allow-origin"], "https://ui.example.com");
    assert!(
        ok.headers()["access-control-allow-headers"]
            .to_str()
            .unwrap()
            .contains("authorization")
    );
    let denied = preflight("https://evil.example.com").send().await.unwrap();
    assert!(denied.headers().get("access-control-allow-origin").is_none());
    let simple = get(Some(&reader))
        .header("Origin", "https://ui.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(
        simple.headers()["access-control-allow-origin"],
        "https://ui.example.com"
    );
    let body: Value = simple.json().await.unwrap();
    assert_eq!(body["leader"], false);
}
