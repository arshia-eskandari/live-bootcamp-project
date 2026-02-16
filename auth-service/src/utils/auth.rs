use super::constants::{JWT_COOKIE_NAME, JWT_SECRET};
use crate::domain::{data_store::BannedTokenStore, Email};
use crate::prelude::BannedTokenType;
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use color_eyre::eyre::{eyre, Report, Result, WrapErr};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Create cookie with a new JWT auth toke
#[tracing::instrument(skip_all)]
pub fn generate_auth_cookie(email: &Email) -> Result<Cookie<'static>> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

// Create cookie and set the value to the passed-in token string
#[tracing::instrument(skip_all)]
fn create_auth_cookie(token: String) -> Cookie<'static> {
    let cookie = Cookie::build((JWT_COOKIE_NAME, token))
        .path("/") // apply cookie to all URLs on the server
        .http_only(true) // prevent JavaScript from accessing the cookie
        .same_site(SameSite::Lax) // send cookie with "same-site" requests, and with "cross-site" top-level navigations.
        .build();

    cookie
}

#[derive(Debug, Error)]
pub enum GenerateTokenError {
    #[error("token error")]
    TokenError(#[from] jsonwebtoken::errors::Error),

    #[error("unexpected error")]
    UnexpectedError(#[from] Report),
}

// This value determines how long the JWT auth token is valid for
pub const TOKEN_TTL_SECONDS: i64 = 600; // 10 minutes

// Create JWT auth token
#[tracing::instrument(skip_all)]
fn generate_auth_token(email: &Email) -> Result<String> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
        .ok_or_else(|| Report::msg("TOKEN_TTL_SECONDS out of range for chrono::Duration"))?;

    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or_else(|| Report::msg("failed to compute JWT expiration timestamp (overflow?)"))?
        .timestamp();

    let exp: usize = exp
        .try_into()
        .map_err(|e| Report::msg(format!("JWT exp timestamp cannot fit into usize: {e}")))?;

    let sub = email.as_ref().expose_secret().to_owned();

    let claims = Claims { sub, exp };

    create_token(&claims).wrap_err("failed to create JWT token")
}

// Check if JWT auth token is valid by decoding it using the JWT secret
#[tracing::instrument(skip_all)]
pub async fn validate_token(token: &str, banned_token_store: BannedTokenType) -> Result<Claims> {
    let is_banned = banned_token_store
        .read()
        .await
        .token_exists(&SecretString::new(token.to_owned().into_boxed_str()))
        .await
        .wrap_err("failed to check if token is banned")?;

    if is_banned {
        return Err(eyre!("invalid token"));
    }

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
        &Validation::default(),
    )
    .wrap_err("failed to decode/verify JWT")?;

    Ok(data.claims)
}

// Create JWT auth token by encoding claims using the JWT secret
#[tracing::instrument(skip_all)]
fn create_token(claims: &Claims) -> Result<String> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
    )
    .wrap_err("encoding failed")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub fn generate_6_digit_code() -> u32 {
    rand::random_range(100_000..=999_999)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::get_redis_client;
    use crate::prelude::RedisBannedTokenStore;
    use crate::utils::constants::REDIS_HOST_NAME;
    use secrecy::SecretString;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn configure_redis() -> redis::Connection {
        get_redis_client(REDIS_HOST_NAME.to_owned())
            .expect("Failed to get Redis client")
            .get_connection()
            .expect("Failed to get Redis connection")
    }

    #[test]
    fn test_6_digit_code_generator() {
        let code = generate_6_digit_code();
        assert!((100_000..=999_999).contains(&code))
    }

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let cookie = generate_auth_cookie(&email).unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = "test_token".to_owned();
        let cookie = create_auth_cookie(token.clone());
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let result = generate_auth_token(&email).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let token = generate_auth_token(&email).unwrap();
        let redis_conn = Arc::new(RwLock::new(configure_redis()));
        let result = validate_token(
            &token,
            Arc::new(RwLock::new(RedisBannedTokenStore::new(redis_conn))),
        )
        .await
        .unwrap();
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let token = "invalid_token".to_owned();
        let redis_conn = Arc::new(RwLock::new(configure_redis()));
        let result = validate_token(
            &token,
            Arc::new(RwLock::new(RedisBannedTokenStore::new(redis_conn))),
        )
        .await;
        assert!(result.is_err());
    }
}
