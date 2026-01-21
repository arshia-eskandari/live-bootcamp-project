use super::error::{EmailError, PasswordError};
use validator::ValidateEmail;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Password(pub String);

impl Password {
    pub fn parse(password: impl AsRef<str>) -> Result<Self, PasswordError> {
        let password = password.as_ref();
        if password.is_empty() {
            return Err(PasswordError::Empty);
        } else if !password.is_ascii() {
            return Err(PasswordError::IsNotASCII);
        } else if password.contains([' ', '\t', '\n', '\r']) {
            return Err(PasswordError::IncludesSpaces);
        } else if password.len() < 8 {
            return Err(PasswordError::ShortLength);
        } else if !password.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(PasswordError::MissingCapitalLetter);
        } else if !password.chars().any(|c| c.is_ascii_lowercase()) {
            return Err(PasswordError::MissingLowercaseLetter);
        } else if !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(PasswordError::MissingNumber);
        } else if !password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
        {
            return Err(PasswordError::MissingSymbol);
        }

        Ok(Password(password.to_string()))
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(pub String);

impl Email {
    pub fn parse(email: impl AsRef<str>) -> Result<Self, EmailError> {
        let email = email.as_ref().trim();

        if email.is_empty() {
            return Err(EmailError::Empty);
        }
        if !email.contains('@') {
            return Err(EmailError::MissingAtSymbol);
        }
        if !ValidateEmail::validate_email(&email) {
            return Err(EmailError::InvalidFormat);
        }

        Ok(Email(email.to_string()))
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::{Fake, Faker};
    use quickcheck_macros::quickcheck;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_valid_email_parsing() {
        let valid_emails = [
            "test@example.com",
            "user.name@domain.co.uk",
            "user+tag@example.org",
            "123@numbers.com",
            "user_name@example-domain.com",
        ];

        for email in valid_emails {
            let result = Email::parse(email);
            assert!(result.is_ok(), "Should parse valid email: {}", email);

            let parsed_email = result.unwrap();
            assert_eq!(parsed_email.as_ref(), email);
        }
    }

    #[test]
    fn test_invalid_email_parsing() {
        let test_cases = [
            ("", EmailError::Empty),
            ("   ", EmailError::Empty),
            ("no-at-symbol", EmailError::MissingAtSymbol),
            ("@domain.com", EmailError::InvalidFormat),
            ("user@", EmailError::InvalidFormat),
            ("user@@domain.com", EmailError::InvalidFormat),
            ("user name@domain.com", EmailError::InvalidFormat),
        ];

        for (email, expected_error) in test_cases {
            let result = Email::parse(email);
            assert!(result.is_err(), "Should reject invalid email: '{}'", email);

            let actual_error = result.unwrap_err();
            assert_eq!(
                actual_error, expected_error,
                "Wrong error type for '{}': expected {:?}, got {:?}",
                email, expected_error, actual_error
            );
        }
    }

    #[test]
    fn test_email_as_ref_implementation() {
        let email = Email::parse("test@example.com").unwrap();
        let email_str: &str = email.as_ref();
        assert_eq!(email_str, "test@example.com");

        fn takes_string_ref(s: impl AsRef<str>) -> String {
            s.as_ref().to_uppercase()
        }

        assert_eq!(takes_string_ref(&email), "TEST@EXAMPLE.COM");
    }

    #[test]
    fn test_email_equality() {
        let email1 = Email::parse("test@example.com").unwrap();
        let email2 = Email::parse("test@example.com").unwrap();
        let email3 = Email::parse("other@example.com").unwrap();

        assert_eq!(email1, email2);
        assert_ne!(email1, email3);
    }

    #[test]
    fn test_email_trimming() {
        let email_with_spaces = "  test@example.com  ";
        let result = Email::parse(email_with_spaces).unwrap();
        assert_eq!(result.as_ref(), "test@example.com");
    }

    #[test]
    fn test_valid_password_parsing() {
        let valid_passwords = [
            "MySecure123!",
            "Password1@",
            "Complex9#Pass",
            "Str0ng$Pass",
            "Valid123!@#",
        ];

        for password in valid_passwords {
            let result = Password::parse(password);
            assert!(result.is_ok(), "Should parse valid password: {}", password);

            let parsed_password = result.unwrap();
            assert_eq!(parsed_password.as_ref(), password);
        }
    }

    #[test]
    fn test_password_empty() {
        let result = Password::parse("");
        assert_eq!(result.unwrap_err(), PasswordError::Empty);
    }

    #[test]
    fn test_password_non_ascii() {
        let non_ascii_passwords = ["Pässwörd123!", "密码123!", "Contraseña1!"];

        for password in non_ascii_passwords {
            let result = Password::parse(password);
            assert_eq!(
                result.unwrap_err(),
                PasswordError::IsNotASCII,
                "Should reject non-ASCII password: {}",
                password
            );
        }
    }

    #[test]
    fn test_password_includes_spaces() {
        let passwords_with_spaces = [
            "My Password123!",
            "Password\t123!",
            "Password\n123!",
            "Password\r123!",
        ];

        for password in passwords_with_spaces {
            let result = Password::parse(password);
            assert_eq!(
                result.unwrap_err(),
                PasswordError::IncludesSpaces,
                "Should reject password with whitespace: {:?}",
                password
            );
        }
    }

    #[test]
    fn test_password_short_length() {
        let short_passwords = ["Short1!", "Abc1!", "1234567"];

        for password in short_passwords {
            let result = Password::parse(password);
            assert_eq!(
                result.unwrap_err(),
                PasswordError::ShortLength,
                "Should reject short password: {}",
                password
            );
        }
    }

    #[test]
    fn test_password_missing_capital_letter() {
        let passwords = ["lowercase123!", "nouppercase1!", "password123@"];

        for password in passwords {
            let result = Password::parse(password);
            assert_eq!(
                result.unwrap_err(),
                PasswordError::MissingCapitalLetter,
                "Should reject password without capital letter: {}",
                password
            );
        }
    }

    #[test]
    fn test_password_missing_lowercase_letter() {
        let passwords = ["UPPERCASE123!", "NOLOWERCASE1!", "PASSWORD123@"];

        for password in passwords {
            let result = Password::parse(password);
            assert_eq!(
                result.unwrap_err(),
                PasswordError::MissingLowercaseLetter,
                "Should reject password without lowercase letter: {}",
                password
            );
        }
    }

    #[test]
    fn test_password_missing_number() {
        let passwords = ["NoNumbers!", "Password!", "OnlyLetters@"];

        for password in passwords {
            let result = Password::parse(password);
            assert_eq!(
                result.unwrap_err(),
                PasswordError::MissingNumber,
                "Should reject password without number: {}",
                password
            );
        }
    }

    #[test]
    fn test_password_missing_symbol() {
        let passwords = ["NoSymbols123", "Password123", "OnlyAlphaNum1"];

        for password in passwords {
            let result = Password::parse(password);
            assert_eq!(
                result.unwrap_err(),
                PasswordError::MissingSymbol,
                "Should reject password without symbol: {}",
                password
            );
        }
    }

    #[test]
    fn test_password_as_ref_implementation() {
        let password = Password::parse("MySecure123!").unwrap();
        let password_str: &str = password.as_ref();
        assert_eq!(password_str, "MySecure123!");
        fn get_length(s: impl AsRef<str>) -> usize {
            s.as_ref().len()
        }
        assert_eq!(get_length(&password), 12);
    }

    #[test]
    fn test_password_equality() {
        let password1 = Password::parse("MySecure123!").unwrap();
        let password2 = Password::parse("MySecure123!").unwrap();
        let password3 = Password::parse("Different1!").unwrap();
        assert_eq!(password1, password2);
        assert_ne!(password1, password3);
    }

    #[test]
    fn test_password_validation_order() {
        assert_eq!(Password::parse("").unwrap_err(), PasswordError::Empty);
        assert_eq!(Password::parse("ñ").unwrap_err(), PasswordError::IsNotASCII);
        assert_eq!(
            Password::parse("a b").unwrap_err(),
            PasswordError::IncludesSpaces
        );
        assert_eq!(
            Password::parse("Short1!").unwrap_err(),
            PasswordError::ShortLength
        );
    }

    #[quickcheck]
    fn prop_valid_emails_contain_at_symbol(email_str: String) -> bool {
        match Email::parse(&email_str) {
            Ok(email) => email.as_ref().contains('@'),
            Err(_) => true,
        }
    }

    #[quickcheck]
    fn prop_email_parse_as_ref_consistency(email_str: String) -> bool {
        match Email::parse(&email_str) {
            Ok(email) => {
                let back_to_str = email.as_ref();
                back_to_str == email_str.trim()
            }
            Err(_) => true,
        }
    }

    #[quickcheck]
    fn prop_valid_passwords_meet_requirements(password_str: String) -> bool {
        match Password::parse(&password_str) {
            Ok(password) => {
                let pwd = password.as_ref();
                !pwd.is_empty()
                    && pwd.is_ascii()
                    && !pwd.contains([' ', '\t', '\n', '\r'])
                    && pwd.len() >= 8
                    && pwd.chars().any(|c| c.is_ascii_uppercase())
                    && pwd.chars().any(|c| c.is_ascii_lowercase())
                    && pwd.chars().any(|c| c.is_ascii_digit())
                    && pwd
                        .chars()
                        .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
            }
            Err(_) => true,
        }
    }

    #[quickcheck]
    fn prop_password_parse_as_ref_consistency(password_str: String) -> bool {
        match Password::parse(&password_str) {
            Ok(password) => {
                let back_to_str = password.as_ref();
                back_to_str == password_str
            }
            Err(_) => true,
        }
    }

    #[test]
    fn test_with_fake_email_data() {
        let mut rng = StdRng::seed_from_u64(42);

        for _ in 0..10 {
            let fake_email: String = Faker.fake_with_rng(&mut rng);

            match Email::parse(&fake_email) {
                Ok(email) => {
                    assert_eq!(email.as_ref(), fake_email.trim());
                    assert!(fake_email.contains('@'));
                }
                Err(_) => {
                    println!("Generated invalid fake email: {}", fake_email);
                }
            }
        }
    }

    #[test]
    fn test_edge_cases() {
        assert!(Email::parse("a@b.co").is_ok());
        assert!(Email::parse("test+tag@example.com").is_ok());

        assert!(Password::parse("Minimum1!").is_ok());

        let symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        for symbol in symbols.chars() {
            let test_password = format!("Password1{}", symbol);
            assert!(
                Password::parse(&test_password).is_ok(),
                "Should accept password with symbol: {}",
                symbol
            );
        }
    }
}
