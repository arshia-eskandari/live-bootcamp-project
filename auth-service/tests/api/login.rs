use crate::helpers::TestApp;

#[tokio::test]
async fn login_returns_200_http_status_code() {
    let app = TestApp::new().await;

    let response = app
        .login("test@example.com".to_string(), "1233456789".to_string())
        .await;

    assert_eq!(response.status().as_u16(), 200);
}
