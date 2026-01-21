use std::collections::HashMap;

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

impl Default for HashmapUserStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HashmapUserStore {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        // Return `UserStoreError::UserAlreadyExists` if the user already exists,
        // otherwise insert the user into the hashmap and return `Ok(())`.
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: Email, password: Password) -> Result<(), UserStoreError> {
        let user = self.get_user(&email).await?;
        if user.password != password {
            return Err(UserStoreError::InvalidCredentials);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_store_and_get_user() -> Result<(HashmapUserStore, User), UserStoreError> {
        let mut store = HashmapUserStore::new();
        store
            .add_user(User::new(
                Email::parse("test@example.com").unwrap(),
                Password::parse("123DSDFdasd@@456789").unwrap(),
                false,
            ))
            .await?;
        let user = store
            .get_user(&Email::parse("test@example.com").unwrap())
            .await?;

        Ok((store, user))
    }

    #[tokio::test]
    async fn test_add_user() -> Result<(), UserStoreError> {
        let (_, store_user) = setup_store_and_get_user().await?;

        assert_eq!(
            store_user.password,
            Password::parse("123DSDFdasd@@456789").unwrap()
        );
        assert!(!store_user.requires_2fa);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_user() -> Result<(), UserStoreError> {
        setup_store_and_get_user().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_validate_user() -> Result<(), UserStoreError> {
        let (store, _) = setup_store_and_get_user().await?;

        store
            .validate_user(
                Email::parse("test@example.com").unwrap(),
                Password::parse("123DSDFdasd@@456789").unwrap(),
            )
            .await?;

        Ok(())
    }
}
