use crate::helpers::TestApp;

// Tokio's test macro is used to run the test in an async environment
#[tokio::test]
async fn root_returns_auth_ui() {
    let app = TestApp::new().await;

    let response = app.get_root().await;

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
}

#[tokio::test]
async fn signup_returns_200_http_status_code() {
    let app = TestApp::new().await;

    let response = app
        .signup(
            "test@example.com".to_string(),
            "1233456789".to_string(),
            false,
        )
        .await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn login_returns_200_http_status_code() {
    let app = TestApp::new().await;

    let response = app
        .login("test@example.com".to_string(), "1233456789".to_string())
        .await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn logout_returns_200_http_status_code() {
    let app = TestApp::new().await;

    let response = app.logout("testtoken".to_string()).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_2fa_returns_200_http_status_code() {
    let app = TestApp::new().await;

    let response = app
        .verify_2fa(
            "test@example.com".to_string(),
            "1233456789".to_string(),
            "testtoken".to_string(),
        )
        .await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_token_returns_200_http_status_code() {
    let app = TestApp::new().await;

    let response = app.verify_token("testtoken".to_string()).await;

    assert_eq!(response.status().as_u16(), 200);
}
