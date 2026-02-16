use crate::{
    app_state::AppState,
    domain::data_store::BannedTokenStore,
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};
use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use color_eyre::eyre::Report;
use secrecy::SecretString;

#[tracing::instrument(skip_all)]
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    // Retrieve JWT cookie from the `CookieJar`
    // Return AuthAPIError::MissingToken is the cookie is not found
    let cookie = jar.get(JWT_COOKIE_NAME).ok_or(AuthAPIError::MissingToken)?;

    let token = cookie.value().to_owned();

    validate_token(&token, state.banned_token_store.clone())
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    let mut banned_token_store = state.banned_token_store.write().await;
    banned_token_store
        .add_token(SecretString::new(token.into_boxed_str()))
        .await
        .map_err(|e| AuthAPIError::UnexpectedError(Report::new(e)))?;

    let jar = jar.remove(JWT_COOKIE_NAME);

    Ok((jar, StatusCode::OK))
}
