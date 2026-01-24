pub mod app_state;
pub mod domain;
pub mod routes;
pub mod services;
pub mod utils;

pub use app_state::AppState;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use domain::AuthAPIError;
pub use routes::{Application, SignupRequest, SignupResponse};
use serde::{Deserialize, Serialize};
pub use services::hashmap_user_store::HashmapUserStore;

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
            AuthAPIError::UserNotFound => (StatusCode::UNAUTHORIZED, "user doesn't exist"),
            AuthAPIError::IncorrectCredentials => {
                (StatusCode::UNAUTHORIZED, "user crendetials do not match")
            }
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}
