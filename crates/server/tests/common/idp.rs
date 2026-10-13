//! A minimal OpenID Connect provider in the test process: discovery, JWKS and a token
//! endpoint that hands out the ID token the test set up (signed with a test-only key).

use std::sync::{Arc, Mutex};

use axum::extract::State;
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
}

#[derive(Clone)]
pub struct Idp {
    pub issuer: String,
    pub next: Arc<Mutex<Next>>,
}

#[derive(Clone)]
struct Shared {
    issuer: String,
    client_id: String,
    next: Arc<Mutex<Next>>,
}

fn signing_key() -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(KEY, Some(JsonWebKeyId::new("test".into()))).unwrap()
}

pub async fn start(client_id: &str) -> Idp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let next = Arc::new(Mutex::new(Next::default()));
    let shared = Shared {
        issuer: issuer.clone(),
        client_id: client_id.to_owned(),
        next: next.clone(),
    };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(shared);
    tokio::spawn(async move { axum::serve(listener, app).await });
    Idp { issuer, next }
}

async fn discovery(State(s): State<Shared>) -> Json<CoreProviderMetadata> {
    let metadata = CoreProviderMetadata::new(
        IssuerUrl::new(s.issuer.clone()).unwrap(),
        AuthUrl::new(format!("{}/authorize", s.issuer)).unwrap(),
        JsonWebKeySetUrl::new(format!("{}/jwks", s.issuer)).unwrap(),
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Public],
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(TokenUrl::new(format!("{}/token", s.issuer)).unwrap()));
    Json(metadata)
}

async fn jwks() -> Json<CoreJsonWebKeySet> {
    Json(CoreJsonWebKeySet::new(vec![
        signing_key().as_verification_key(),
    ]))
}

async fn token(State(s): State<Shared>) -> Json<Value> {
    let next = s.next.lock().unwrap().clone();
    let now = chrono::Utc::now();
    let claims = CoreIdTokenClaims::new(
        IssuerUrl::new(s.issuer.clone()).unwrap(),
        vec![Audience::new(s.client_id.clone())],
        now + chrono::Duration::minutes(5),
        now,
        StandardClaims::new(SubjectIdentifier::new(next.subject))
            .set_email(Some(EndUserEmail::new(next.email)))
            .set_email_verified(Some(next.email_verified)),
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new(next.nonce)));
    let id_token = CoreIdToken::new(
        claims,
        &signing_key(),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .unwrap();
    Json(json!({
        "access_token": "access",
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token.to_string(),
    }))
}
