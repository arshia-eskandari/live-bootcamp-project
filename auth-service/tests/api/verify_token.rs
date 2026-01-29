use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@456789",
        "requires2FA": false
    });

    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@456789",
    });

    let login_response = app.post_login(&login_body).await;
    assert_eq!(login_response.status().as_u16(), 200);

    let token = login_response
        .cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .expect("jwt token doesn't exist");

    let verify_token_body = serde_json::json!({ "token": token });

    let verify_response = app.post_verify_token(&verify_token_body).await;
    assert_eq!(verify_response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;
    let login_body = serde_json::json!({
        "token": "invalid-token-123DSDFdasd@@456789",
    });

    let response = app.post_verify_token(&login_body).await;

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
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let login_body = serde_json::json!({});

    let response = app.post_verify_token(&login_body).await;

    assert_eq!(response.status().as_u16(), 422);
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
