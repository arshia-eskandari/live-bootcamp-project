use std::collections::HashMap;

use crate::domain::data_store::TwoFACodeStore;
use crate::domain::error::TwoFACodeStoreError;
use crate::domain::types::{Email, LoginAttemptId, TwoFACode};
use secrecy::SecretString;

pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_two_fa_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        two_fa_code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        if let Ok(true) = self.two_fa_code_exists(&email).await {
            return Err(TwoFACodeStoreError::EmailAlreadyExists);
        }
        self.codes.insert(email, (login_attempt_id, two_fa_code));
        Ok(())
    }
    async fn two_fa_code_exists(&self, email: &Email) -> Result<bool, TwoFACodeStoreError> {
        Ok(self.codes.contains_key(email))
    }
    async fn remove_two_fa_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        if let Ok(false) = self.two_fa_code_exists(email).await {
            return Err(TwoFACodeStoreError::EmailNotFound);
        }
        self.codes.remove(email);
        Ok(())
    }
    async fn get_two_fa_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        self.codes
            .get(email)
            .map(|(_login_attempt_id, two_fa_code)| {
                (_login_attempt_id.clone(), two_fa_code.clone())
            })
            .ok_or(TwoFACodeStoreError::EmailNotFound)
    }
}

impl HashmapTwoFACodeStore {
    pub fn new() -> Self {
        Self {
            codes: HashMap::new(),
        }
    }
}

impl Default for HashmapTwoFACodeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    async fn setup_store_and_add_code(
    ) -> Result<(HashmapTwoFACodeStore, Email), TwoFACodeStoreError> {
        let mut store = HashmapTwoFACodeStore::default();

        let email = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let login_attempt_id = LoginAttemptId::parse(Uuid::new_v4().to_string()).unwrap();
        let two_fa_code = TwoFACode::parse("123456").unwrap();

        store
            .add_two_fa_code(email.clone(), login_attempt_id, two_fa_code)
            .await?;

        Ok((store, email))
    }

    #[tokio::test]
    async fn test_add_two_fa_code() -> Result<(), TwoFACodeStoreError> {
        let (store, email) = setup_store_and_add_code().await?;

        assert!(store.two_fa_code_exists(&email).await.unwrap());
        Ok(())
    }

    #[tokio::test]
    async fn test_add_two_fa_code_returns_err_if_email_already_exists(
    ) -> Result<(), TwoFACodeStoreError> {
        let (mut store, email) = setup_store_and_add_code().await?;

        let login_attempt_id = LoginAttemptId::parse(Uuid::new_v4().to_string()).unwrap();
        let two_fa_code = TwoFACode::parse("654321").unwrap();

        let err = store
            .add_two_fa_code(email.clone(), login_attempt_id, two_fa_code)
            .await
            .unwrap_err();

        assert!(matches!(err, TwoFACodeStoreError::EmailAlreadyExists));
        Ok(())
    }

    #[tokio::test]
    async fn test_remove_two_fa_code() -> Result<(), TwoFACodeStoreError> {
        let (mut store, email) = setup_store_and_add_code().await?;

        store.remove_two_fa_code(&email).await?;

        assert!(!store.two_fa_code_exists(&email).await.unwrap());
        Ok(())
    }

    #[tokio::test]
    async fn test_remove_two_fa_code_returns_err_if_email_not_found(
    ) -> Result<(), TwoFACodeStoreError> {
        let mut store = HashmapTwoFACodeStore::default();

        let email = Email::parse(SecretString::new(
            "missing@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();

        let err = store.remove_two_fa_code(&email).await.unwrap_err();
        assert!(matches!(err, TwoFACodeStoreError::EmailNotFound));

        Ok(())
    }
}
