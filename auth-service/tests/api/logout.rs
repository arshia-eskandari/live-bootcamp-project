use crate::helpers::{get_random_email, TestApp};
use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use reqwest::Url;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new().await;

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 400);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Missing token".to_owned()
    );
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Invalid token".to_owned()
    );
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let app = TestApp::new().await;
    let random_email = get_random_email();
    let user_request = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@456789",
        "requires2FA": true
    });

    app.post_signup(&user_request).await;

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@456789",
    });

    let response = app.post_login(&login_body).await;
    let token = response
        .cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .expect("jwt token doesn't exist");

    let body = serde_json::json!({
        "token": token,
    });
    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 200);

    let response = app.post_verify_token(&body).await;

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Invalid token".to_owned()
    );
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let app = TestApp::new().await;
    let random_email = get_random_email();
    let user_request = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@456789",
        "requires2FA": true
    });

    app.post_signup(&user_request).await;

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@456789",
    });

    app.post_login(&login_body).await;

    app.post_logout().await;
    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 400);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Missing token".to_owned()
    );
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let app = TestApp::new().await;
    let random_email = get_random_email();
    let user_request = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@456789",
        "requires2FA": true
    });

    app.post_signup(&user_request).await;

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@456789",
    });

    let response = app.post_login(&login_body).await;
    let token = response
        .cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .expect("jwt token doesn't exist");

    let body = serde_json::json!({
        "token": token,
    });
    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 200);

    let response = app.post_verify_token(&body).await;

    assert_eq!(response.status().as_u16(), 401);
}
