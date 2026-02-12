use super::error::BannedTokenStoreError;
use super::error::{TwoFACodeStoreError, UserStoreError};
use super::types::{Email, LoginAttemptId, TwoFACode};
use super::User;

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: Email, password: &str) -> Result<(), UserStoreError>;
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn token_exists(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_two_fa_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        two_fa_code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn two_fa_code_exists(&self, email: &Email) -> Result<bool, TwoFACodeStoreError>;
    async fn remove_two_fa_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_two_fa_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}
