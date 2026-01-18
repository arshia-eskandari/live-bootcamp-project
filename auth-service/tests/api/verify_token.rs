use crate::helpers::TestApp;

#[tokio::test]
async fn verify_token_returns_200_http_status_code() {
    let app = TestApp::new().await;

    let body = serde_json::json!({
        "token": "random_token_102002",
    });

    let response = app.post_verify_token(&body).await;

    assert_eq!(response.status().as_u16(), 200);
}
