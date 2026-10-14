//! `POST /auth/logout`, whichever way the session was made.

use axum::extract::State;
use axum::http::StatusCode;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::Cookie;
use serde_json::json;

use super::session;
use crate::audit;
use crate::error::ApiError;
use crate::state::AppState;

/// Ends the session if it is still there and clears the cookie (also for a session
/// that already went idle). A failure to end it is an error, not a quiet success: the
/// session would live on behind the user's back. No CSRF token: the cookie is
/// `SameSite=Lax`, so no other site can post with it.
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), ApiError> {
    if let Some(cookie) = jar.get(session::COOKIE) {
        end_session(&state, cookie.value()).await?;
    }
    Ok((
        jar.remove(Cookie::build(session::COOKIE).path("/")),
        StatusCode::NO_CONTENT,
    ))
}

async fn end_session(state: &AppState, token: &str) -> Result<(), ApiError> {
    let txn = crate::api::begin(&state.db).await?;
    if let Some(user_id) = session::end(&txn, token).await? {
        audit::record(
            &txn,
            Some(user_id),
            "logout",
            format!("app_user/{user_id}"),
            json!({}),
        )
        .await?;
    }
    txn.commit().await?;
    Ok(())
}
