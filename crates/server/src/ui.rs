//! The embedded Vue UI (`web/dist`, staged by `build.rs`): its files as they are, and
//! `index.html` for any other path outside `/api` and `/auth`, so the client-side
//! router owns those.

use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "$OUT_DIR/ui"]
struct Assets;

/// The app loads only itself; the QR code is a `data:` image.
const CSP: &str = "default-src 'self'; img-src 'self' data:; style-src 'self'; \
                   script-src 'self'; connect-src 'self'; frame-ancestors 'none'; \
                   base-uri 'none'; form-action 'self'";

pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if let Some(file) = Assets::get(path).filter(|_| !path.is_empty()) {
        // Vite fingerprints everything under assets/: it never changes under a name.
        let cache = if path.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        return respond(file, cache);
    }
    // A missing asset is a 404, not the app (a stale tab asking for an old bundle).
    if path.starts_with("assets/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    match Assets::get("index.html") {
        Some(index) => respond(index, "no-cache"),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn respond(file: rust_embed::EmbeddedFile, cache: &'static str) -> Response {
    let mime = file.metadata.mimetype().to_owned();
    let mut res = file.data.into_owned().into_response();
    let headers = res.headers_mut();
    if let Ok(mime) = HeaderValue::from_str(&mime) {
        headers.insert(header::CONTENT_TYPE, mime);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    // `/account/<token>` carries a live link's token: no request may pass it on.
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    res
}
