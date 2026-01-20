use std::collections::HashMap;

use crate::domain::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

pub struct HashmapUserStore {
    users: HashMap<String, User>,
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

    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        // Return `UserStoreError::UserAlreadyExists` if the user already exists,
        // otherwise insert the user into the hashmap and return `Ok(())`.
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    pub fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email)?;
        if user.password != password {
            return Err(UserStoreError::InvalidCredentials);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_store_and_get_user() -> Result<(HashmapUserStore, User), UserStoreError> {
        let mut store = HashmapUserStore::new();
        store.add_user(User::new("test@example.com", "123456789", false))?;
        let user = store.get_user("test@example.com")?;

        Ok((store, user))
    }

    #[tokio::test]
    async fn test_add_user() -> Result<(), UserStoreError> {
        let (_, store_user) = setup_store_and_get_user()?;

        assert_eq!(store_user.password, "123456789");
        assert!(!store_user.requires_2fa);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_user() -> Result<(), UserStoreError> {
        setup_store_and_get_user()?;

        Ok(())
    }

    #[tokio::test]
    async fn test_validate_user() -> Result<(), UserStoreError> {
        let (store, _) = setup_store_and_get_user()?;

        store.validate_user("test@example.com", "123456789")?;

        Ok(())
    }
}
