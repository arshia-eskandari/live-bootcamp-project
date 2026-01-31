use crate::{
    app_state::AppState,
    domain::data_store::TwoFACodeStore,
    domain::types::{LoginAttemptId, TwoFACode},
    domain::{AuthAPIError, Email, Password, User, UserStore},
    utils::auth::{generate_6_digit_code, generate_auth_cookie},
};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    let email = Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password =
        Password::parse(request.password).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store = state.user_store.read().await;

    let user = user_store
        .get_user(&email)
        .await
        .map_err(|_| AuthAPIError::UserNotFound)?;

    match user.requires_2fa {
        true => handle_2fa(&user, &state, jar).await,
        false => handle_no_2fa(&user, &password, jar).await,
    }
}

// New!
async fn handle_2fa(
    user: &User,
    state: &AppState,
    jar: CookieJar,
) -> Result<(CookieJar, (StatusCode, Json<LoginResponse>)), AuthAPIError> {
    let login_attempt_id = LoginAttemptId::parse(uuid::Uuid::new_v4().to_string())
        .map_err(|_| AuthAPIError::InvalidCredentials)?;
    let two_fa_code = TwoFACode::parse(generate_6_digit_code().to_string())
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let mut two_fa_code_store = state.two_fa_code_store.write().await;
    two_fa_code_store
        .add_two_fa_code(user.email.clone(), login_attempt_id.clone(), two_fa_code)
        .await
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    let updated_jar = update_cookie_jar(jar, &user.email)?;
    Ok((
        updated_jar,
        (
            StatusCode::PARTIAL_CONTENT,
            Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
                message: "2FA required".to_string(),
                login_attempt_id: login_attempt_id.as_ref().to_owned(),
            })),
        ),
    ))
}

// New!
async fn handle_no_2fa(
    user: &User,
    password: &Password,
    jar: CookieJar,
) -> Result<(CookieJar, (StatusCode, Json<LoginResponse>)), AuthAPIError> {
    if password != &user.password {
        return Err(AuthAPIError::IncorrectCredentials);
    }

    let updated_jar = update_cookie_jar(jar, &user.email)?;

    Ok((
        updated_jar,
        (StatusCode::OK, Json(LoginResponse::RegularAuth)),
    ))
}

fn update_cookie_jar(jar: CookieJar, email: &Email) -> Result<CookieJar, AuthAPIError> {
    let auth_cookie = generate_auth_cookie(email).map_err(|_| AuthAPIError::UnexpectedError)?;

    let updated_jar = jar.add(auth_cookie);

    Ok(updated_jar)
}

// The login route can return 2 possible success responses.
// This enum models each response!
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
