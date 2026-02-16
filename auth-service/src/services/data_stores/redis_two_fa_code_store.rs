use crate::domain::{
    types::{LoginAttemptId, TwoFACode},
    Email, TwoFACodeStore, TwoFACodeStoreError,
};
use color_eyre::eyre::Report;
use redis::{Commands, Connection};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::to_string;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    #[tracing::instrument(skip_all)]
    async fn add_two_fa_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let two_fa_code = TwoFATuple(
            login_attempt_id.as_ref().to_string(),
            code.as_ref().to_string(),
        );
        let two_fa_code_json = to_string(&two_fa_code)
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(Report::new(e)))?;

        let mut connection = self.conn.write().await;
        connection
            .set_ex::<_, _, ()>(key, two_fa_code_json, TEN_MINUTES_IN_SECONDS)
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(Report::new(e)))?;

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn remove_two_fa_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(email);

        let mut connection = self.conn.write().await;
        connection
            .del::<_, ()>(key)
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(Report::new(e)))?;
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn get_two_fa_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(email);

        let mut connection = self.conn.write().await;

        let value: String = connection
            .get::<_, String>(key)
            .map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;

        let tuple: TwoFATuple = serde_json::from_str(&value)
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(Report::new(e)))?;

        let login_attempt_id =
            LoginAttemptId::parse(tuple.0).map_err(TwoFACodeStoreError::UnexpectedError)?;
        let code = TwoFACode::parse(tuple.1).map_err(TwoFACodeStoreError::UnexpectedError)?;
        Ok((login_attempt_id, code))
    }

    #[tracing::instrument(skip_all)]
    async fn two_fa_code_exists(&self, email: &Email) -> Result<bool, TwoFACodeStoreError> {
        let key = get_key(email);

        let mut connection = self.conn.write().await;

        let exists: bool = connection
            .exists::<_, bool>(key)
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(Report::new(e)))?;

        Ok(exists)
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref().expose_secret())
}
