use crate::prelude::{HashmapUserStore, HashsetBannedTokenStore};
use std::sync::Arc;
use tokio::sync::RwLock;

// Using a type alias to improve readability!
pub type UserStoreType = Arc<RwLock<HashmapUserStore>>;
pub type BannedTokenType = Arc<RwLock<HashsetBannedTokenStore>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
    pub banned_token_store: BannedTokenType,
}

impl AppState {
    pub fn new(user_store: UserStoreType, banned_token_store: BannedTokenType) -> Self {
        Self {
            user_store,
            banned_token_store,
        }
    }
}
