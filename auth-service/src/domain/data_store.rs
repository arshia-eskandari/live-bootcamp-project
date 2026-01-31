use super::error::{TwoFACodeStoreError, UserStoreError};
use super::types::{Email, LoginAttemptId, Password, TwoFACode};
use super::User;

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: Email, password: Password) -> Result<(), UserStoreError>;
}

pub trait BannedTokenStore {
    fn add_token(&mut self, token: String);
    fn token_exists(&self, token: &str) -> bool;
}

#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_two_fa_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        two_fa_code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn two_fa_code_exists(&self, email: &Email) -> bool;
    async fn remove_two_fa_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
}
