//! What a client is told when a request fails: a stable code and a message written
//! here, never the database's own words (constraint and table names stay in the log).

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sea_orm::{DbErr, RuntimeErr};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not signed in")]
    Unauthorized,
    /// Every failed login, whatever failed: the reply tells nothing about the account.
    #[error("invalid credentials")]
    InvalidCredentials,
    /// The client's attempts are used up for now: try again after this long.
    #[error("too many attempts")]
    TooManyAttempts(std::time::Duration),
    /// Every password hash slot taken: try again in a moment.
    #[error("the server is busy; try again")]
    Busy,
    #[error("not allowed")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    BadRequest(String),
    /// Taken or overlapping (a unique or exclusion constraint), or a race to retry.
    #[error("{0}")]
    Conflict(String),
    /// Well-formed but not allowed by the rules (a ceiling, a tenant boundary, a range).
    #[error("{message}")]
    Invalid {
        message: String,
        detail: Option<serde_json::Value>,
    },
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

/// The JSON body of every error.
#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    /// `unauthorized`, `invalid_credentials`, `too_many_attempts`, `busy`, `forbidden`,
    /// `not_found`, `bad_request`, `conflict`, `invalid` or `internal`.
    pub error: &'static str,
    pub message: String,
    /// What is in the way (e.g. the part of a rule no ceiling covers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl ApiError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid {
            message: message.into(),
            detail: None,
        }
    }

    fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            Self::TooManyAttempts(_) => (StatusCode::TOO_MANY_REQUESTS, "too_many_attempts"),
            Self::Busy => (StatusCode::SERVICE_UNAVAILABLE, "busy"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            Self::Invalid { .. } => (StatusCode::UNPROCESSABLE_ENTITY, "invalid"),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Internal(e) = &self {
            tracing::error!(error = format!("{e:#}"), "request failed");
        }
        let (status, error) = self.parts();
        let detail = match &self {
            Self::Invalid { detail, .. } => detail.clone(),
            _ => None,
        };
        let body = ErrorBody {
            error,
            message: self.to_string(),
            detail,
        };
        let mut res = (status, Json(body)).into_response();
        let wait = match &self {
            Self::TooManyAttempts(wait) => Some(*wait),
            Self::Busy => Some(std::time::Duration::from_secs(1)),
            _ => None,
        };
        if let Some(wait) = wait {
            // Whole seconds, never 0 (that would invite an instant retry).
            let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
            res.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs.max(1)));
        }
        res
    }
}

/// The unique constraint `e` violates, if that is what it is.
pub fn unique_violation(e: &DbErr) -> Option<String> {
    let db = sqlx_error(e)?.as_database_error()?;
    (db.code()?.as_ref() == "23505").then(|| db.constraint().unwrap_or_default().to_owned())
}

/// The SQLSTATE classes the schema raises on purpose: they say what is wrong in the
/// request, so they become 409 or 422 with a message of ours.
impl From<DbErr> for ApiError {
    fn from(e: DbErr) -> Self {
        let Some((code, from_trigger, message)) = database_error(&e) else {
            return Self::Internal(e.into());
        };
        tracing::debug!(%code, %message, "refused by the database");
        match code.as_str() {
            "23505" => Self::Conflict("already taken".into()),
            "23P01" => Self::Conflict("overlaps an existing range".into()),
            "23503" => Self::invalid("refers to something that does not exist"),
            // The schema's own RAISEs carry a message written for people; a bare
            // constraint's would name tables and columns.
            "23514" if from_trigger => Self::invalid(message),
            "23514" | "23502" | "22P02" | "23000" => Self::invalid("a value is not allowed"),
            "40001" | "40P01" => {
                Self::Conflict("a concurrent change got in the way; try again".into())
            }
            _ => Self::Internal(e.into()),
        }
    }
}

/// (SQLSTATE, raised by a trigger rather than a constraint, message).
fn database_error(e: &DbErr) -> Option<(String, bool, String)> {
    let db = sqlx_error(e)?.as_database_error()?;
    let code = db.code()?.into_owned();
    Some((code, db.constraint().is_none(), db.message().to_owned()))
}

fn sqlx_error(e: &DbErr) -> Option<&sea_orm::SqlxError> {
    match e {
        DbErr::Exec(RuntimeErr::SqlxError(sqlx)) | DbErr::Query(RuntimeErr::SqlxError(sqlx)) => {
            Some(sqlx)
        }
        _ => None,
    }
}
