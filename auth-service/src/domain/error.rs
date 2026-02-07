use std::fmt;

pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    UnexpectedError,
    UserNotFound,
    IncorrectCredentials,
    MissingToken,
    InvalidToken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordError {
    ShortLength,
    IncludesSpaces,
    MissingSymbol,
    MissingCapitalLetter,
    MissingLowercaseLetter,
    MissingNumber,
    Empty,
    IsNotASCII,
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            PasswordError::ShortLength => "Password is too short",
            PasswordError::IncludesSpaces => "Password must not include spaces",
            PasswordError::MissingSymbol => "Password must include at least one symbol",
            PasswordError::MissingCapitalLetter => {
                "Password must include at least one capital letter"
            }
            PasswordError::MissingLowercaseLetter => {
                "Password must include at least one lowercase letter"
            }
            PasswordError::MissingNumber => "Password must include at least one number",
            PasswordError::Empty => "Password must not be empty",
            PasswordError::IsNotASCII => "Password must contain only ASCII characters",
        };

        write!(f, "{message}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailError {
    MissingAtSymbol,
    InvalidFormat,
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginAttemptIdError {
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwoFACodeError {
    Empty,
}

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[derive(Debug, PartialEq)]
pub enum TwoFACodeStoreError {
    EmailAlreadyExists,
    EmailNotFound,
    InvalidCredentials,
    UnexpectedError,
}
