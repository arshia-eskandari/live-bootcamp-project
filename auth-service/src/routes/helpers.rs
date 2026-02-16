use crate::{
    domain::{AuthAPIError, Email},
    utils::auth::generate_auth_cookie,
};
use axum_extra::extract::CookieJar;

pub fn update_cookie_jar(jar: CookieJar, email: &Email) -> Result<CookieJar, AuthAPIError> {
    let auth_cookie = generate_auth_cookie(email).map_err(AuthAPIError::UnexpectedError)?;

    let updated_jar = jar.add(auth_cookie);

    Ok(updated_jar)
}
