use crate::helpers::TestApp;

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
