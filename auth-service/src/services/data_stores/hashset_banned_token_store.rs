use crate::domain::data_store::BannedTokenStore;
use crate::domain::error::BannedTokenStoreError;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashSet;

#[derive(Clone)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token.expose_secret().to_owned());
        Ok(())
    }

    async fn token_exists(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError> {
        let exists = self.tokens.contains(token.expose_secret());
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
    use secrecy::SecretString;

    #[tokio::test]
    async fn adds_token_correctly() {
        let mut banned_token_store = HashsetBannedTokenStore::new();

        let token = SecretString::new("token1234567890".to_owned().into_boxed_str());

        banned_token_store.add_token(token.clone()).await.unwrap();

        assert!(banned_token_store.token_exists(&token).await.unwrap());
    }

    #[tokio::test]
    async fn returns_false_for_nonexisting_token() {
        let mut banned_token_store = HashsetBannedTokenStore::new();

        let tokens = [
            "token123456790",
            "token1234567901",
            "token1234567902",
            "token1234567903",
        ];

        for t in tokens {
            banned_token_store
                .add_token(SecretString::new(t.to_owned().into_boxed_str()))
                .await
                .unwrap();
        }

        let missing = SecretString::new("token12345678904".to_owned().into_boxed_str());

        assert!(!banned_token_store.token_exists(&missing).await.unwrap());
    }
}
