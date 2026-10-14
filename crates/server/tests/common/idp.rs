//! A minimal OpenID Connect provider in the test process: discovery, JWKS and a token
//! endpoint that hands out the ID token the test set up (signed with a test-only key)
//! to the client with the right secret. Start as many as a test needs.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreResponseType, CoreRsaPrivateSigningKey, CoreSubjectIdentifierType,
};
use openidconnect::{
    Audience, AuthUrl, EmptyAdditionalClaims, EmptyAdditionalProviderMetadata, EndUserEmail,
    IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl, Nonce, PrivateSigningKey, ResponseTypes,
    StandardClaims, SubjectIdentifier, TokenUrl,
};
use serde_json::{Value, json};

const KEY: &str = include_str!("../fixtures/idp-test-key.pem");

/// Who the next token says logs in.
#[derive(Clone, Default)]
pub struct Next {
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
    pub nonce: String,
    /// A token that must be refused: one claim not what the login expects.
    pub forge: Option<Forge>,
}

#[derive(Clone, Copy, Debug)]
pub enum Forge {
    Nonce,
    Audience,
    Issuer,
}

/// How the provider misbehaves in its discovery document.
#[derive(Clone, Default)]
pub struct Quirks {
    /// Advertised instead of its own `/jwks`.
    pub jwks_uri: Option<String>,
    /// Bytes of padding in the document.
    pub pad: usize,
}

#[derive(Clone)]
pub struct Idp {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub next: Arc<Mutex<Next>>,
    /// How often its discovery document was fetched.
    pub discoveries: Arc<AtomicUsize>,
    pub quirks: Arc<Mutex<Quirks>>,
}

impl Idp {
    pub fn discovered(&self) -> usize {
        self.discoveries.load(Ordering::SeqCst)
    }
}

#[derive(Clone)]
struct Shared {
    issuer: String,
    client_id: String,
    client_secret: String,
    next: Arc<Mutex<Next>>,
    discoveries: Arc<AtomicUsize>,
    quirks: Arc<Mutex<Quirks>>,
}

fn signing_key() -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(KEY, Some(JsonWebKeyId::new("test".into()))).unwrap()
}

/// A provider for client `client_id` with `client_secret`.
pub async fn start(client_id: &str, client_secret: &str) -> Idp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let next = Arc::new(Mutex::new(Next::default()));
    let discoveries = Arc::new(AtomicUsize::new(0));
    let quirks = Arc::new(Mutex::new(Quirks::default()));
    let shared = Shared {
        quirks: quirks.clone(),
        issuer: issuer.clone(),
        client_id: client_id.to_owned(),
        client_secret: client_secret.to_owned(),
        next: next.clone(),
        discoveries: discoveries.clone(),
    };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(shared);
    tokio::spawn(async move { axum::serve(listener, app).await });
    Idp {
        issuer,
        client_id: client_id.to_owned(),
        client_secret: client_secret.to_owned(),
        next,
        discoveries,
        quirks,
    }
}

async fn discovery(State(s): State<Shared>) -> Json<Value> {
    s.discoveries.fetch_add(1, Ordering::SeqCst);
    let quirks = s.quirks.lock().unwrap().clone();
    let jwks = quirks
        .jwks_uri
        .unwrap_or_else(|| format!("{}/jwks", s.issuer));
    let metadata = CoreProviderMetadata::new(
        IssuerUrl::new(s.issuer.clone()).unwrap(),
        AuthUrl::new(format!("{}/authorize", s.issuer)).unwrap(),
        JsonWebKeySetUrl::new(jwks).unwrap(),
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Public],
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(TokenUrl::new(format!("{}/token", s.issuer)).unwrap()));
    let mut doc = serde_json::to_value(metadata).unwrap();
    if quirks.pad > 0 {
        doc["x_padding"] = json!("x".repeat(quirks.pad));
    }
    Json(doc)
}

async fn jwks() -> Json<CoreJsonWebKeySet> {
    Json(CoreJsonWebKeySet::new(vec![
        signing_key().as_verification_key(),
    ]))
}

/// `client_secret_basic`, as the server authenticates.
fn basic(id: &str, secret: &str) -> String {
    use base64::Engine;
    let enc = |v: &str| url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>();
    let pair = format!("{}:{}", enc(id), enc(secret));
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(pair)
    )
}

async fn token(State(s): State<Shared>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if auth != Some(basic(&s.client_id, &s.client_secret).as_str()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_client" })),
        );
    }
    let next = s.next.lock().unwrap().clone();
    let now = chrono::Utc::now();
    let (mut issuer, mut audience, mut nonce) =
        (s.issuer.clone(), s.client_id.clone(), next.nonce.clone());
    match next.forge {
        Some(Forge::Nonce) => nonce = "another login's nonce".into(),
        Some(Forge::Audience) => audience = "another-client".into(),
        Some(Forge::Issuer) => issuer = "https://impostor.example.org".into(),
        None => {}
    }
    let claims = CoreIdTokenClaims::new(
        IssuerUrl::new(issuer).unwrap(),
        vec![Audience::new(audience)],
        now + chrono::Duration::minutes(5),
        now,
        StandardClaims::new(SubjectIdentifier::new(next.subject))
            .set_email(Some(EndUserEmail::new(next.email)))
            .set_email_verified(Some(next.email_verified)),
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new(nonce)));
    let id_token = CoreIdToken::new(
        claims,
        &signing_key(),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .unwrap();
    (
        StatusCode::OK,
        Json(json!({
            "access_token": "access",
            "token_type": "Bearer",
            "expires_in": 300,
            "id_token": id_token.to_string(),
        })),
    )
}
