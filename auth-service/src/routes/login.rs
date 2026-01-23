use crate::domain::{Email, Password};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::User, domain::UserStore, AuthAPIError};

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password =
        Password::parse(request.password).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store = state.user_store.read().await;

    let user = user_store
        .get_user(&email)
        .await
        .map_err(|_| AuthAPIError::UserNotFound)?;

    if password != user.password {
        return Err(AuthAPIError::IncorrectCredentials);
    }

    let response = Json(LoginResponse {
        message: "User logged in successfully!".to_string(),
        login_attempt_id: "fixed2983H238HJD238JE".to_string(),
    });

    Ok((StatusCode::PARTIAL_CONTENT, response))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct LoginResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}
