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
