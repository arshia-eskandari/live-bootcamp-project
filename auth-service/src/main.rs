use auth_service::prelude::{
    AppState, Application, HashmapTwoFACodeStore, HashmapUserStore, HashsetBannedTokenStore,
    MockEmailClient,
};
use auth_service::utils::constants::prod;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = HashmapUserStore::new();
    let banned_token_store = HashsetBannedTokenStore::new();
    let two_fa_code_store = HashmapTwoFACodeStore::new();
    let email_client = MockEmailClient::new();
    let app_state = AppState::new(
        Arc::new(RwLock::new(user_store)),
        Arc::new(RwLock::new(banned_token_store)),
        Arc::new(RwLock::new(two_fa_code_store)),
        Arc::new(RwLock::new(email_client)),
    );

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
