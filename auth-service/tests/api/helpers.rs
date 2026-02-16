use auth_service::app_state::{BannedTokenType, TwoFACodeType};
use auth_service::prelude::{
    AppState, Application, MockEmailClient, PostgresUserStore, RedisBannedTokenStore,
    RedisTwoFACodeStore,
};
use auth_service::utils::constants::test;
use auth_service::utils::constants::{DATABASE_URL, REDIS_HOST_NAME};
use auth_service::{get_postgres_pool, get_redis_client};
use reqwest::cookie::Jar;
use secrecy::{ExposeSecret, SecretString};
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPoolOptions};
use sqlx::{Connection, Executor, PgPool};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub banned_token_store: BannedTokenType,
    pub two_fa_code_store: TwoFACodeType,
    pub http_client: reqwest::Client,
    cleanup_called: bool,
    db_name: String,
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if !self.cleanup_called {
            panic!(
                "TestApp was dropped without calling clean_up(). \
                 Call `app.clean_up().await` at the end of the test."
            );
        }
    }
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}

impl TestApp {
    pub async fn new() -> Self {
        let (pg_pool, db_name) = configure_postgresql().await;
        let redis_conn = Arc::new(RwLock::new(configure_redis()));
        let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
        let banned_token_store =
            Arc::new(RwLock::new(RedisBannedTokenStore::new(redis_conn.clone())));
        let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFACodeStore::new(redis_conn)));
        let email_client = Arc::new(RwLock::new(MockEmailClient::new()));

        let app_state = AppState::new(
            user_store,
            banned_token_store.clone(),
            two_fa_code_store.clone(),
            email_client,
        );

        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let cookie_jar = Arc::new(Jar::default());
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();
        // Create new `TestApp` instance and return it
        Self {
            address,
            cookie_jar,
            http_client,
            banned_token_store,
            two_fa_code_store,
            cleanup_called: false,
            db_name,
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to signup")
    }

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to login")
    }

    pub async fn post_logout(&self) -> reqwest::Response {
        self.http_client
            .post(format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to logout")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to verify 2fa")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn clean_up(mut self) {
        self.cleanup_called = true;

        delete_database(&self.db_name).await;
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

async fn configure_postgresql() -> (PgPool, String) {
    let base_db_url: &SecretString = &DATABASE_URL;
    let db_name = Uuid::new_v4().to_string();

    configure_database(base_db_url, &db_name).await;

    let postgresql_conn_url_with_db = format!("{}/{}", base_db_url.expose_secret(), db_name);

    // Create a new connection pool and return it
    let pg_pool = get_postgres_pool(&SecretString::new(
        postgresql_conn_url_with_db.into_boxed_str(),
    ))
    .await
    .expect("Failed to create Postgres connection pool!");
    (pg_pool, db_name)
}

async fn configure_database(base_db_url: &SecretString, db_name: &str) {
    // Create database connection
    let connection = PgPoolOptions::new()
        .connect(base_db_url.expose_secret())
        .await
        .expect("Failed to create Postgres connection pool.");

    // Create a new database
    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to create database.");

    // Connect to new database
    let db_conn_string = format!("{}/{}", base_db_url.expose_secret(), db_name);

    let connection = PgPoolOptions::new()
        .connect(&db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Run migrations against new database
    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");
}

async fn delete_database(db_name: &str) {
    let postgresql_conn_url: &SecretString = &DATABASE_URL;

    let connection_options = PgConnectOptions::from_str(postgresql_conn_url.expose_secret())
        .expect("Failed to parse PostgreSQL connection string");

    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    // Kill any active connections to the database
    connection
        .execute(
            format!(
                r#"
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{}'
                  AND pid <> pg_backend_pid();
        "#,
                db_name
            )
            .as_str(),
        )
        .await
        .expect("Failed to drop the database.");

    // Drop the database
    connection
        .execute(format!(r#"DROP DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to drop the database.");
}
