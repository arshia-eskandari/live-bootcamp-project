use auth_service::get_postgres_pool;
use auth_service::get_redis_client;
use auth_service::init_tracing;
use auth_service::prelude::{
    AppState, Application, MockEmailClient, PostgresUserStore, RedisBannedTokenStore,
    RedisTwoFACodeStore,
};
use auth_service::utils::constants::prod;
use auth_service::utils::constants::{DATABASE_URL, REDIS_HOST_NAME};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    color_eyre::install().expect("Failed to install color_eyre");
    init_tracing().expect("Failed to initialize tracing");
    let pg_pool = configure_postgresql().await;
    let redis_conn = Arc::new(RwLock::new(configure_redis()));
    let user_store = PostgresUserStore::new(pg_pool);
    let banned_token_store = RedisBannedTokenStore::new(redis_conn.clone());
    let two_fa_code_store = RedisTwoFACodeStore::new(redis_conn);
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

    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our test database!
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}
