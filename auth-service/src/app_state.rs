use crate::prelude::{
    HashmapTwoFACodeStore, HashmapUserStore, HashsetBannedTokenStore, MockEmailClient,
};
use std::sync::Arc;
use tokio::sync::RwLock;

// Using a type alias to improve readability!
pub type UserStoreType = Arc<RwLock<HashmapUserStore>>;
pub type BannedTokenType = Arc<RwLock<HashsetBannedTokenStore>>;
pub type TwoFACodeType = Arc<RwLock<HashmapTwoFACodeStore>>;
pub type EmailClientType = Arc<RwLock<MockEmailClient>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
    pub banned_token_store: BannedTokenType,
    pub two_fa_code_store: TwoFACodeType,
    pub email_client: EmailClientType,
}

impl AppState {
    pub fn new(
        user_store: UserStoreType,
        banned_token_store: BannedTokenType,
        two_fa_code_store: TwoFACodeType,
        email_client: EmailClientType,
    ) -> Self {
        Self {
            user_store,
            banned_token_store,
            two_fa_code_store,
            email_client,
        }
    }
}
