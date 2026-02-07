use auth_service::get_postgres_pool;
use auth_service::prelude::{
    AppState, Application, HashmapTwoFACodeStore, HashsetBannedTokenStore, MockEmailClient,
    PostgresUserStore,
};
use auth_service::utils::constants::prod;
use auth_service::utils::constants::DATABASE_URL;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let pg_pool = configure_postgresql().await;
    let user_store = PostgresUserStore::new(pg_pool);
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

async fn configure_postgresql() -> PgPool {
    // Create a new database connection pool

    let pg_pool = get_postgres_pool(DATABASE_URL.as_str())
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our test database!
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}
