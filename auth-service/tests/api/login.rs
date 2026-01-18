use crate::helpers::TestApp;

#[tokio::test]
async fn login_returns_200_http_status_code() {
    let app = TestApp::new().await;

    let body = serde_json::json!({
        "email": "test@example.com",
        "password": "123456789",
    });

    let response = app.post_login(&body).await;

    assert_eq!(response.status().as_u16(), 200);
}
