pub mod app_state;
pub mod domain;
pub mod routes;
pub mod services;
pub mod utils;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use domain::AuthAPIError;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub mod prelude {
    pub use crate::app_state::{AppState, BannedTokenType};
    pub use crate::domain::EmailClient;
    pub use crate::routes::Application;
    pub use crate::services::{
        hashmap_two_fa_code_store::HashmapTwoFACodeStore, hashmap_user_store::HashmapUserStore,
        hashset_banned_token_store::HashsetBannedTokenStore, mock_email_client::MockEmailClient,
        postgres_user_store::PostgresUserStore, redis_banned_token_store::RedisBannedTokenStore,
        redis_two_fa_code_store::RedisTwoFACodeStore,
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

pub async fn get_postgres_pool(url: &str) -> Result<PgPool, sqlx::Error> {
    // Create a new PostgreSQL connection pool
    PgPoolOptions::new().max_connections(5).connect(url).await
}

pub fn get_redis_client(redis_hostname: String) -> redis::RedisResult<redis::Client> {
    let redis_url = format!("redis://{}/", redis_hostname);
    redis::Client::open(redis_url)
}
