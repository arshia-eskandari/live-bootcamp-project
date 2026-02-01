use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "loginAttemptId": "c9a2865b-467d-498b-93b8-634903ae68e0",
            "2FACode": "302912"
        }),
        serde_json::json!({
            "email": random_email,
            "loginAttemptId": "c9a2865b-467d-498b-93b8-634903ae68e0",

        }),
        serde_json::json!({
            "email": random_email,
            "2FACode": "302912"
        }),
        serde_json::json!({}),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let test_case = serde_json::json!({
        "email": "invalidemaidatdomaindotcom",
        "loginAttemptId": "",
        "2FACode": ""
    });

    let response = app.post_verify_2fa(&test_case).await;
    assert_eq!(
        response.status().as_u16(),
        400,
        "Failed for input: {:?}",
        test_case
    );
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_case = serde_json::json!({
        "email": random_email,
        "loginAttemptId": "c9a2865b-467d-498b-93b8-634903ae68e0",
        "2FACode": "123445"
    });

    let response = app.post_verify_2fa(&test_case).await;
    assert_eq!(
        response.status().as_u16(),
        400,
        "Failed for input: {:?}",
        test_case
    );
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login requet. This should fail.
    todo!()
}
