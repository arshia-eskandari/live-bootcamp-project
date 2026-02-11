use std::sync::Arc;

use redis::{Commands, Connection};
use tokio::sync::RwLock;

use crate::domain::data_store::BannedTokenStore;
use crate::domain::error::BannedTokenStoreError;
use crate::utils::auth::TOKEN_TTL_SECONDS;

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        let ttl: u64 = TOKEN_TTL_SECONDS
            .try_into()
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        let key = get_key(&token);

        let mut connection = self.conn.write().await;

        connection
            .set_ex::<_, _, ()>(key, true, ttl)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn token_exists(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let key = get_key(token);

        let mut connection = self.conn.write().await;

        let exists: bool = connection
            .exists(key)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        Ok(exists)
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}
