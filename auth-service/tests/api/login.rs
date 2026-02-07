use crate::helpers::{get_random_email, TestApp};
use auth_macros::db_test;
use auth_service::dto::TwoFactorAuthResponse;
use auth_service::utils::constants::JWT_COOKIE_NAME;

#[db_test]
async fn should_return_422_if_malformed_credentials() {
    let random_email = get_random_email();
    let post_signup_request = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@456789",
        "requires2FA": true
    });
    app.post_signup(&post_signup_request).await;

    let test_cases = [
        serde_json::json!({
            "email": random_email,
        }),
        serde_json::json!({
            "password": "123DSDFdasd@@456789",

        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[db_test]
async fn should_return_400_if_invalid_input() {
    let random_email = get_random_email();
    let post_signup_request = serde_json::json!({
        "email": random_email,
        "password": "123DSDFddasd@@456789",
        "requires2FA": true
    });
    app.post_signup(&post_signup_request).await;

    let login_resquest = serde_json::json!({
        "email": random_email,
        "password": "123D SDF",
    });

    let response = app.post_login(&login_resquest).await;

    assert_eq!(
        response.status().as_u16(),
        400,
        "Failed for input: {:?}",
        login_resquest,
    );
}

#[db_test]
async fn should_return_401_if_incorrect_credentials() {
    let random_email = get_random_email();
    let post_signup_request = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@456789",
        "requires2FA": false
    });
    app.post_signup(&post_signup_request).await;

    let login_resquest = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@45678",
    });

    let response = app.post_login(&login_resquest).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Failed for input: {:?}",
        login_resquest,
    );
}

#[db_test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@456789",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@456789",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[db_test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@456789",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "123DSDFdasd@@456789",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(
        response
            .json::<TwoFactorAuthResponse>()
            .await
            .expect("Could not deserialize response body to TwoFactorAuthResponse")
            .message,
        "2FA required".to_owned()
    );
}
