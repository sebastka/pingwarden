use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair};
use serde_json::{Value, json};

use super::*;
use crate::config::{Dur, OidcConfig, OneOrMany};

/// Throwaway key, generated for these tests only.
const RSA_PKCS1: &[u8] = include_bytes!("test-rsa-2048.pkcs1.der");
const ISSUER: &str = "https://idp.example.com/realms/home";
const NOW: i64 = 1_800_000_000;

fn enc(v: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(v)
}

fn config() -> OidcConfig {
    OidcConfig {
        issuer: ISSUER.into(),
        audience: OneOrMany::Many(vec!["pingwarden".into(), "other".into()]),
        claim: "realm_access.roles".into(),
        read: vec!["pw-read".into()],
        admin: vec!["pw-admin".into()],
        // An unroutable address: refreshes fail fast instead of reaching out.
        jwks_url: Some("https://127.0.0.1:1/jwks".into()),
        jwks_refresh: Dur::secs(3600),
        leeway: Dur::secs(60),
    }
}

fn claims() -> Value {
    json!({
        "iss": ISSUER,
        "aud": ["account", "pingwarden"],
        "sub": "alice",
        "exp": NOW + 300,
        "nbf": NOW - 10,
        "realm_access": {"roles": ["offline_access", "pw-admin"]},
        "scope": "openid pw-read",
    })
}

enum Signer {
    Rsa(RsaKeyPair, &'static dyn signature::RsaEncoding),
    Ec(EcdsaKeyPair),
    Ed(Ed25519KeyPair),
}

struct TestKey {
    alg: &'static str,
    kid: &'static str,
    signer: Signer,
    jwk: Key,
}

impl TestKey {
    fn rsa(alg: &'static str, kid: &'static str) -> Self {
        let pair = RsaKeyPair::from_der(RSA_PKCS1).unwrap();
        let parts: signature::RsaPublicKeyComponents<Vec<u8>> = pair.public().into();
        let (n, e) = (parts.n, parts.e);
        let enc: &'static dyn signature::RsaEncoding = match alg {
            "RS256" => &signature::RSA_PKCS1_SHA256,
            "PS256" => &signature::RSA_PSS_SHA256,
            _ => unreachable!(),
        };
        TestKey {
            alg,
            kid,
            signer: Signer::Rsa(pair, enc),
            jwk: Key {
                kid: Some(kid.into()),
                alg: None,
                material: KeyMaterial::Rsa { n, e },
            },
        }
    }

    fn es256(kid: &'static str) -> Self {
        let rng = SystemRandom::new();
        let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap();
        let point = pair.public_key().as_ref().to_vec();
        TestKey {
            alg: "ES256",
            kid,
            signer: Signer::Ec(pair),
            jwk: Key {
                kid: Some(kid.into()),
                alg: Some("ES256".into()),
                material: KeyMaterial::P256(point),
            },
        }
    }

    fn ed25519(kid: &'static str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let x = pair.public_key().as_ref().to_vec();
        TestKey {
            alg: "EdDSA",
            kid,
            signer: Signer::Ed(pair),
            jwk: Key {
                kid: Some(kid.into()),
                alg: None,
                material: KeyMaterial::Ed25519(x),
            },
        }
    }

    fn sign_with_header(&self, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            enc(header.to_string().as_bytes()),
            enc(claims.to_string().as_bytes())
        );
        let rng = SystemRandom::new();
        let sig = match &self.signer {
            Signer::Rsa(pair, encoding) => {
                let mut sig = vec![0; pair.public().modulus_len()];
                pair.sign(*encoding, &rng, input.as_bytes(), &mut sig).unwrap();
                sig
            }
            Signer::Ec(pair) => pair.sign(&rng, input.as_bytes()).unwrap().as_ref().to_vec(),
            Signer::Ed(pair) => pair.sign(input.as_bytes()).as_ref().to_vec(),
        };
        format!("{input}.{}", enc(&sig))
    }

    fn sign(&self, claims: &Value) -> String {
        self.sign_with_header(&json!({"alg": self.alg, "kid": self.kid, "typ": "JWT"}), claims)
    }
}

fn http() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::new()
}

fn verifier(keys: &[&TestKey]) -> Arc<OidcVerifier> {
    let v = Arc::new(OidcVerifier::new(config(), http()));
    v.set_keys(keys.iter().map(|k| k.jwk.clone()).collect());
    v
}

#[tokio::test]
async fn accepts_every_supported_algorithm() {
    let keys = [
        TestKey::rsa("RS256", "rs"),
        TestKey::rsa("PS256", "ps"),
        TestKey::es256("es"),
        TestKey::ed25519("ed"),
    ];
    let v = verifier(&keys.iter().collect::<Vec<_>>());
    for k in &keys {
        let p = v
            .verify_at(&k.sign(&claims()), NOW)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", k.alg));
        assert_eq!(p.name, "oidc:alice");
        assert_eq!(p.scope, Some(TokenScope::Admin), "{}", k.alg);
    }
}

#[tokio::test]
async fn maps_claims_to_scopes() {
    let k = TestKey::es256("k");
    let v = verifier(&[&k]);
    let mut c = claims();
    c["realm_access"]["roles"] = json!(["pw-read"]);
    assert_eq!(
        v.verify_at(&k.sign(&c), NOW).await.unwrap().scope,
        Some(TokenScope::Read)
    );
    c["realm_access"]["roles"] = json!(["unrelated"]);
    assert_eq!(v.verify_at(&k.sign(&c), NOW).await.unwrap().scope, None);
    c.as_object_mut().unwrap().remove("realm_access");
    assert_eq!(v.verify_at(&k.sign(&c), NOW).await.unwrap().scope, None);

    // A space-separated `scope` claim.
    let mut cfg = config();
    cfg.claim = "scope".into();
    let v2 = Arc::new(OidcVerifier::new(cfg, http()));
    v2.set_keys(vec![k.jwk.clone()]);
    assert_eq!(
        v2.verify_at(&k.sign(&claims()), NOW).await.unwrap().scope,
        Some(TokenScope::Read)
    );

    // The readable name wins over the opaque subject.
    let mut c = claims();
    c["preferred_username"] = json!("alice@example.com");
    assert_eq!(
        v.verify_at(&k.sign(&c), NOW).await.unwrap().name,
        "oidc:alice@example.com"
    );
    // A client without `sub` is named after its client id.
    let mut c = claims();
    c.as_object_mut().unwrap().remove("sub");
    c["azp"] = json!("backup-script");
    assert_eq!(v.verify_at(&k.sign(&c), NOW).await.unwrap().name, "oidc:backup-script");
}

#[tokio::test]
async fn rejects_invalid_tokens() {
    let k = TestKey::es256("k");
    let other = TestKey::es256("k");
    let v = verifier(&[&k]);
    let check = |c: Value| k.sign(&c);

    let mut expired = claims();
    expired["exp"] = json!(NOW - 61);
    assert_eq!(v.verify_at(&check(expired), NOW).await, Err(AuthError::Expired));
    let mut within_leeway = claims();
    within_leeway["exp"] = json!(NOW - 30);
    assert!(v.verify_at(&check(within_leeway), NOW).await.is_ok());

    let mut early = claims();
    early["nbf"] = json!(NOW + 120);
    assert_eq!(v.verify_at(&check(early), NOW).await, Err(AuthError::NotYetValid));

    let mut no_exp = claims();
    no_exp.as_object_mut().unwrap().remove("exp");
    assert_eq!(v.verify_at(&check(no_exp), NOW).await, Err(AuthError::Malformed));

    let mut iss = claims();
    iss["iss"] = json!("https://evil.example.com/realms/home");
    assert_eq!(v.verify_at(&check(iss), NOW).await, Err(AuthError::Issuer));

    let mut aud = claims();
    aud["aud"] = json!("account");
    assert_eq!(v.verify_at(&check(aud), NOW).await, Err(AuthError::Audience));

    // Same kid, different key: a forged signature.
    assert_eq!(
        v.verify_at(&other.sign(&claims()), NOW).await,
        Err(AuthError::BadSignature)
    );

    // Tampered payload.
    let token = k.sign(&claims());
    let mut parts: Vec<&str> = token.split('.').collect();
    let mut tampered = claims();
    tampered["realm_access"]["roles"] = json!(["pw-admin", "root"]);
    let payload = enc(tampered.to_string().as_bytes());
    parts[1] = &payload;
    assert_eq!(v.verify_at(&parts.join("."), NOW).await, Err(AuthError::BadSignature));

    for bad in ["", "a.b", "a.b.c.d", "eyJ.e30.", "x.y.z"] {
        assert!(v.verify_at(bad, NOW).await.is_err(), "{bad:?}");
    }
}

#[tokio::test]
async fn rejects_none_and_symmetric_algorithms() {
    let k = TestKey::es256("k");
    let v = verifier(&[&k]);
    for alg in ["none", "HS256", "None", ""] {
        let token = format!(
            "{}.{}.{}",
            enc(json!({"alg": alg, "kid": "k"}).to_string().as_bytes()),
            enc(claims().to_string().as_bytes()),
            enc(b"signature")
        );
        assert!(
            matches!(v.verify_at(&token, NOW).await, Err(AuthError::UnsupportedAlgorithm(_))),
            "{alg}"
        );
    }
    // A header claiming another algorithm than the key's.
    let forged = k.sign_with_header(&json!({"alg": "ES384", "kid": "k"}), &claims());
    assert!(v.verify_at(&forged, NOW).await.is_err());
}

#[tokio::test]
async fn unknown_keys_trigger_a_rate_limited_refresh() {
    let k = TestKey::es256("known");
    let unknown = TestKey::es256("rotated");
    let v = verifier(&[&k]);
    // The refresh fails (unreachable JWKS URL), which is reported as such.
    assert!(matches!(
        v.verify_at(&unknown.sign(&claims()), NOW).await,
        Err(AuthError::Unavailable(_))
    ));
    // Within the rate limit, no new fetch happens: the key stays unknown.
    assert_eq!(
        v.verify_at(&unknown.sign(&claims()), NOW).await,
        Err(AuthError::UnknownKey)
    );
    // Tokens without kid are checked against every compatible key.
    let no_kid = k.sign_with_header(&json!({"alg": "ES256"}), &claims());
    assert!(v.verify_at(&no_kid, NOW).await.is_ok());
}

#[test]
fn parses_jwks() {
    let k = TestKey::es256("ec");
    let KeyMaterial::P256(point) = &k.jwk.material else {
        unreachable!()
    };
    let jwks = json!({"keys": [
        {"kty": "EC", "crv": "P-256", "kid": "ec", "use": "sig",
         "x": enc(&point[1..33]), "y": enc(&point[33..65])},
        {"kty": "RSA", "kid": "enc-only", "use": "enc", "n": "AQAB", "e": "AQAB"},
        {"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"},
        {"kty": "EC", "crv": "P-521", "kid": "unsupported", "x": "AA", "y": "AA"},
    ]});
    let keys = parse_jwks(&jwks).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid.as_deref(), Some("ec"));
    assert!(matches!(&keys[0].material, KeyMaterial::P256(p) if p == point));
    assert!(parse_jwks(&json!({"keys": []})).is_err());
    assert!(parse_jwks(&json!({})).is_err());
}

#[test]
fn pads_short_ec_coordinates() {
    assert_eq!(coordinate(&enc(&[1, 2]), 4).unwrap(), vec![0, 0, 1, 2]);
    assert!(coordinate(&enc(&[1; 5]), 4).is_none());
}

#[test]
fn reads_claim_values() {
    let c = json!({"scope": "a b  c", "groups": ["x", 1, "y"], "n": {"deep": "v"}, "flag": true});
    assert_eq!(claim_values(&c, "scope"), ["a", "b", "c"]);
    assert_eq!(claim_values(&c, "groups"), ["x", "y"]);
    assert_eq!(claim_values(&c, "n.deep"), ["v"]);
    assert_eq!(claim_values(&c, "flag"), ["true"]);
    assert!(claim_values(&c, "missing.path").is_empty());
}

#[test]
fn recognizes_jwts() {
    assert!(looks_like_jwt("eyJhbGciOiJFUzI1NiJ9.e30.c2ln"));
    assert!(!looks_like_jwt("a-static-api-token-0123456789"));
    assert!(!looks_like_jwt("eyJ.only-two"));
}
