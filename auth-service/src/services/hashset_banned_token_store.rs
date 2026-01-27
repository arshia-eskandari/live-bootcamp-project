use crate::domain::data_store::BannedTokenStore;
use std::collections::HashSet;

pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

impl BannedTokenStore for HashsetBannedTokenStore {
    fn add_token(&mut self, token: String) {
        self.tokens.insert(token);
    }

    fn token_exists(&self, token: &str) -> bool {
        self.tokens.contains(token)
    }
}

impl HashsetBannedTokenStore {
    fn new() -> Self {
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

    #[test]
    fn adds_token_correctly() {
        let mut banned_token_store = HashsetBannedTokenStore::new();

        banned_token_store.add_token(String::from("token1234567890"));
        assert!(banned_token_store.token_exists("token1234567890"));
    }

    #[test]
    fn returns_false_for_nonexisting_token() {
        let mut banned_token_store = HashsetBannedTokenStore::new();

        banned_token_store.add_token(String::from("token123456790"));
        banned_token_store.add_token(String::from("token1234567901"));
        banned_token_store.add_token(String::from("token1234567902"));
        banned_token_store.add_token(String::from("token1234567903"));
        assert!(!banned_token_store.token_exists("token12345678904"));
    }
}
