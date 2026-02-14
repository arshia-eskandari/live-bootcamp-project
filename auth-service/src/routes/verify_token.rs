use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Token},
    utils::auth::validate_token,
};

#[tracing::instrument(skip_all)]
pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    Token::parse(&request.token).map_err(|_| AuthAPIError::MissingToken)?;

    validate_token(&request.token, state.banned_token_store.clone())
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}
