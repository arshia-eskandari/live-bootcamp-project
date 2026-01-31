pub mod app_state;
pub mod domain;
pub mod routes;
pub mod services;
pub mod utils;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use domain::AuthAPIError;
use serde::{Deserialize, Serialize};

pub mod prelude {
    pub use crate::app_state::{AppState, BannedTokenType};
    pub use crate::routes::Application;
    pub use crate::services::{
        hashmap_two_fa_code_store::HashmapTwoFACodeStore, hashmap_user_store::HashmapUserStore,
        hashset_banned_token_store::HashsetBannedTokenStore,
    };
    pub use crate::ErrorResponse;
}

pub mod dto {
    pub use crate::routes::{SignupRequest, SignupResponse, TwoFactorAuthResponse};
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
            AuthAPIError::UserNotFound => (StatusCode::UNAUTHORIZED, "User doesn't exist"),
            AuthAPIError::IncorrectCredentials => {
                (StatusCode::UNAUTHORIZED, "User crendetials do not match")
            }
            AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "Missing token"),
            AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}
