use crate::helpers::TestApp;

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
