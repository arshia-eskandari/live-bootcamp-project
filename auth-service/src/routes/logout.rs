use axum::{http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;

use crate::{domain::AuthAPIError, utils::auth::validate_token};

pub async fn logout(jar: CookieJar) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    // Retrieve JWT cookie from the `CookieJar`
    // Return AuthAPIError::MissingToken is the cookie is not found
    let cookie = jar.get("jwt").ok_or(AuthAPIError::MissingToken)?;

    let token = cookie.value().to_owned();

    validate_token(&token)
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    Ok((jar, StatusCode::OK))
}
