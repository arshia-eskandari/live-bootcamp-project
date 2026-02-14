use color_eyre::eyre::Report;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthAPIError {
    #[error("User not found")]
    UserNotFound,
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Incorrect credentials")]
    IncorrectCredentials,
    #[error("Missing token")]
    MissingToken,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PasswordError {
    #[error("password is too short")]
    ShortLength,

    #[error("password must not contain spaces")]
    IncludesSpaces,

    #[error("password must include at least one symbol")]
    MissingSymbol,

    #[error("password must include at least one uppercase letter")]
    MissingCapitalLetter,

    #[error("password must include at least one lowercase letter")]
    MissingLowercaseLetter,

    #[error("password must include at least one number")]
    MissingNumber,

    #[error("password is empty")]
    Empty,

    #[error("password must contain only ASCII characters")]
    IsNotASCII,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EmailError {
    #[error("email is missing '@' symbol")]
    MissingAtSymbol,

    #[error("email format is invalid")]
    InvalidFormat,

    #[error("email is empty")]
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LoginAttemptIdError {
    #[error("login attempt id is empty")]
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TwoFACodeError {
    #[error("two fa code is empty")]
    Empty,
}

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("email already exists")]
    EmailAlreadyExists,

    #[error("email not found")]
    EmailNotFound,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),

    #[error("login attempt id not found")]
    LoginAttemptIdNotFound,
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}
