pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    UnexpectedError,
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
