use crate::domain::{Email, HashedPassword, User, UserStore, UserStoreError};
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
            password_hash.as_ref(),
            requires_2fa,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let Some(db_err) = e.as_database_error() {
                if db_err.code().as_deref() == Some("23505") {
                    return UserStoreError::UserAlreadyExists;
                }
            }
            UserStoreError::UnexpectedError
        })?;

        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let record = sqlx::query!(
            r#"
                SELECT email, password_hash, requires_2fa
                FROM users
                WHERE email = $1
            "#,
            email.as_ref(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if matches!(e, sqlx::Error::RowNotFound) {
                UserStoreError::UserNotFound
            } else {
                UserStoreError::UnexpectedError
            }
        })?;

        Ok(User {
            email: Email::parse(record.email).map_err(|_| UserStoreError::UnexpectedError)?,

            password: HashedPassword::parse_password_hash(record.password_hash)
                .map_err(|_| UserStoreError::UnexpectedError)?,

            requires_2fa: record.requires_2fa,
        })
    }

    async fn validate_user(&self, email: Email, password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(&email).await?;
        if user.password.verify_raw_password(password).await.is_err() {
            return Err(UserStoreError::InvalidCredentials);
        }
        Ok(())
    }
}
