use crate::app_state::AppState;
use crate::domain::error::TwoFACodeStoreError;
use crate::domain::types::{Email, LoginAttemptId, TwoFACode};
use crate::domain::TwoFACodeStore;
use crate::routes::helpers::update_cookie_jar;
use crate::AuthAPIError;
use axum::{extract::State, http::StatusCode, Json};
use axum_extra::extract::CookieJar;
use color_eyre::eyre::Report;
use serde::{Deserialize, Serialize};

#[tracing::instrument(skip_all)]
pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> Result<(CookieJar, (StatusCode, Json<Verify2FAResponse>)), AuthAPIError> {
    let email = Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let login_attempt_id = LoginAttemptId::parse(request.login_attempt_id)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;
    let two_fa_code =
        TwoFACode::parse(request.two_fa_code).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    let (stored_login_attempt_id, stored_two_fa_code) = two_fa_code_store
        .get_two_fa_code(&email)
        .await
        .map_err(|e| match e {
            TwoFACodeStoreError::LoginAttemptIdNotFound => AuthAPIError::InvalidToken, // or MissingToken
            TwoFACodeStoreError::UnexpectedError(r) => AuthAPIError::UnexpectedError(r), // already a Report
            _ => AuthAPIError::UnexpectedError(Report::msg(e.to_string())),
        })?;

    if stored_two_fa_code != two_fa_code || stored_login_attempt_id != login_attempt_id {
        return Err(AuthAPIError::InvalidToken);
    }

    let updated_jar = update_cookie_jar(jar, &email)?;

    match two_fa_code_store.remove_two_fa_code(&email).await {
        Ok(()) => {}
        Err(TwoFACodeStoreError::LoginAttemptIdNotFound) => {}
        Err(TwoFACodeStoreError::UnexpectedError(r)) => {
            return Err(AuthAPIError::UnexpectedError(r))
        }
        Err(e) => return Err(AuthAPIError::UnexpectedError(Report::msg(e.to_string()))),
    }

    let response = Json(Verify2FAResponse {
        message: "Token verified successfully".to_string(),
    });

    Ok((updated_jar, (StatusCode::OK, response)))
}

#[derive(Deserialize)]
pub struct Verify2FARequest {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Verify2FAResponse {
    pub message: String,
}
