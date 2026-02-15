use crate::domain::{Email, HashedPassword, User, UserStore, UserStoreError};
use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let User {
            email,
            password: password_hash,
            requires_2fa,
        } = user;

        sqlx::query!(
            r#"
                INSERT INTO users (email, password_hash, requires_2fa)
                VALUES ($1, $2, $3)
            "#,
            email.as_ref(),
            password_hash.as_ref().expose_secret(),
            requires_2fa,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

        Ok(())
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        sqlx::query!(
            r#"
            SELECT email, password_hash, requires_2fa
            FROM users
            WHERE email = $1
            "#,
            email.as_ref()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?
        .map(|row| {
            Ok(User {
                email: Email::parse(row.email)
                    .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?,
                password: HashedPassword::parse_password_hash(SecretString::new(
                    row.password_hash.to_owned().into_boxed_str(),
                ))
                .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?,
                requires_2fa: row.requires_2fa,
            })
        })
        .ok_or(UserStoreError::UserNotFound)?
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
    async fn validate_user(
        &self,
        email: Email,
        password: &SecretString,
    ) -> Result<(), UserStoreError> {
        let user = self.get_user(&email).await?;
        if user.password.verify_raw_password(password).await.is_err() {
            return Err(UserStoreError::InvalidCredentials);
        }
        Ok(())
    }
}
