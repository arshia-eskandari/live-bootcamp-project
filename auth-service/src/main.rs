use auth_service::utils::constants::prod;
use auth_service::AppState;
use auth_service::Application;
use auth_service::HashmapUserStore;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = HashmapUserStore::new();
    let app_state = AppState::new(Arc::new(RwLock::new(user_store)));

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
