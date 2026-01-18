use crate::helpers::TestApp;

#[tokio::test]
async fn logout_returns_200_http_status_code() {
    let app = TestApp::new().await;

    let response = app.post_logout("testtoken".to_string()).await;

    assert_eq!(response.status().as_u16(), 200);
}
