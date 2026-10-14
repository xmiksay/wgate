//! The embedded UI: the app for client-side routes, its assets as they are, and no
//! app where the API or a stale asset is asked for.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

mod common;

async fn get(app: &axum::Router, path: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let res = app
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let body = axum::body::to_bytes(res.into_body(), 1 << 22)
        .await
        .unwrap();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn client_routes_get_the_app_with_its_policy() {
    let e = common::env().await;
    for path in ["/", "/tenants/7", "/networks/3/peers"] {
        let (status, headers, body) = get(&e.app, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(
            body.to_lowercase().starts_with("<!doctype html>"),
            "{path}: {body}"
        );
        assert_eq!(headers[header::CACHE_CONTROL], "no-cache");
        let csp = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'none'") && csp.contains("script-src 'self'"));
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
    }
}

#[tokio::test]
async fn the_api_and_stale_assets_are_never_the_app() {
    let e = common::env().await;
    let (status, headers, body) = get(&e.app, "/api/v1/no-such-thing").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    assert!(body.contains("not_found"), "{body}");
    let (status, _, _) = get(&e.app, "/assets/index-0ld.js").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// With a real bundle embedded (`make test` builds it first), its entry script is
/// served as JavaScript and cached for good; the stub page has none.
#[tokio::test]
async fn the_bundles_assets_are_served_as_they_are() {
    let e = common::env().await;
    let (_, _, index) = get(&e.app, "/").await;
    if index.contains("make web") {
        return; // the stub (plain `cargo test`): no bundle to check
    }
    let start = index
        .find("\"/assets/")
        .map(|i| i + 1)
        .unwrap_or_else(|| panic!("a bundle without /assets/ paths: {index}"));
    let script = &index[start..];
    let script = &script[..script.find('"').expect("a quoted asset path")];
    let (status, headers, _) = get(&e.app, script).await;
    assert_eq!(status, StatusCode::OK, "{script}");
    let kind = headers[header::CONTENT_TYPE].to_str().unwrap();
    assert!(
        kind.contains("javascript") || kind.contains("css"),
        "{script}: {kind}"
    );
    assert!(
        headers[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .contains("immutable")
    );
}
