use crate::domain::data_store::BannedTokenStore;
use crate::domain::error::BannedTokenStoreError;
use std::collections::HashSet;

#[derive(Clone)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token);
        Ok(())
    }

    async fn token_exists(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let exists = self.tokens.contains(token);
        Ok(exists)
    }
}

impl HashsetBannedTokenStore {
    pub fn new() -> Self {
        Self {
            tokens: HashSet::new(),
        }
    }
}

impl Default for HashsetBannedTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn adds_token_correctly() {
        let mut banned_token_store = HashsetBannedTokenStore::new();

        let _ = banned_token_store
            .add_token(String::from("token1234567890"))
            .await;
        assert!(banned_token_store
            .token_exists("token1234567890")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn returns_false_for_nonexisting_token() {
        let mut banned_token_store = HashsetBannedTokenStore::new();

        let _ = banned_token_store
            .add_token(String::from("token123456790"))
            .await;
        let _ = banned_token_store
            .add_token(String::from("token1234567901"))
            .await;
        let _ = banned_token_store
            .add_token(String::from("token1234567902"))
            .await;
        let _ = banned_token_store
            .add_token(String::from("token1234567903"))
            .await;
        assert!(!banned_token_store
            .token_exists("token12345678904")
            .await
            .unwrap());
    }
}
