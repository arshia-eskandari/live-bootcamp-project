use crate::app_state::AppState;
use crate::domain::types::{Email, LoginAttemptId, TwoFACode};
use crate::domain::TwoFACodeStore;
use crate::AuthAPIError;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

pub async fn verify_2fa(
    State(state): State<AppState>,
    Json(request): Json<Verify2FARequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let login_attempt_id = LoginAttemptId::parse(request.login_attempt_id)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;
    let two_fa_code =
        TwoFACode::parse(request.two_fa_code).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let two_fa_code_store = state.two_fa_code_store.read().await;

    let (stored_login_attempt_id, stored_two_fa_code) = two_fa_code_store
        .get_two_fa_code(&email)
        .await
        .map_err(|_| AuthAPIError::MissingToken)?;

    if stored_two_fa_code != two_fa_code || stored_login_attempt_id != login_attempt_id {
        return Err(AuthAPIError::InvalidToken);
    }

    let response = Json(Verify2FAResponse {
        message: "Token verified successfully".to_string(),
    });

    Ok((StatusCode::OK, response))
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
