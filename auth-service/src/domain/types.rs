use super::error::{EmailError, LoginAttemptIdError, PasswordError, TokenError, TwoFACodeError};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use color_eyre::eyre::{eyre, Context, Report, Result};
use secrecy::{ExposeSecret, SecretString};
use std::hash::Hash;
use validator::ValidateEmail;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Password(pub String);

impl Password {
    pub fn parse(password: impl AsRef<str>) -> Result<Self> {
        let password = password.as_ref();
        if password.is_empty() {
            return Err(PasswordError::Empty.into());
        } else if !password.is_ascii() {
            return Err(PasswordError::IsNotASCII.into());
        } else if password.contains([' ', '\t', '\n', '\r']) {
            return Err(PasswordError::IncludesSpaces.into());
        } else if password.len() < 8 {
            return Err(PasswordError::ShortLength.into());
        } else if !password.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(PasswordError::MissingCapitalLetter.into());
        } else if !password.chars().any(|c| c.is_ascii_lowercase()) {
            return Err(PasswordError::MissingLowercaseLetter.into());
        } else if !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(PasswordError::MissingNumber.into());
        } else if !password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
        {
            return Err(PasswordError::MissingSymbol.into());
        }

        Ok(Password(password.to_string()))
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct Email(pub SecretString);

impl Email {
    pub fn parse(email: SecretString) -> Result<Self, EmailError> {
        let email_exposed = email.expose_secret().trim();

        if email_exposed.is_empty() {
            return Err(EmailError::Empty);
        }
        if !email_exposed.contains('@') {
            return Err(EmailError::MissingAtSymbol);
        }
        if !ValidateEmail::validate_email(&email_exposed) {
            return Err(EmailError::InvalidFormat);
        }

        Ok(Email(SecretString::new(
            email_exposed.to_owned().into_boxed_str(),
        )))
    }
}

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl Eq for Email {}

impl AsRef<SecretString> for Email {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token(pub String);

impl Token {
    pub fn parse(token: impl AsRef<str>) -> Result<Self, TokenError> {
        let token = token.as_ref();
        if token.is_empty() {
            return Err(TokenError::Empty);
        }

        Ok(Token(token.to_string()))
    }
}

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginAttemptId(pub String);

impl LoginAttemptId {
    pub fn parse(login_attempt_id: impl AsRef<str>) -> Result<Self> {
        let login_attempt_id = login_attempt_id.as_ref();
        if login_attempt_id.is_empty() {
            return Err(LoginAttemptIdError::Empty.into());
        }
        let login_attempt_id =
            uuid::Uuid::parse_str(login_attempt_id).wrap_err("Invalid login attempt id")?;

        Ok(LoginAttemptId(login_attempt_id.to_string()))
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoFACode(pub String);

impl TwoFACode {
    pub fn parse(two_fa_code: impl AsRef<str>) -> Result<Self> {
        let two_fa_code = two_fa_code.as_ref();
        if two_fa_code.is_empty() {
            return Err(TwoFACodeError::Empty.into());
        }

        let code_as_u32 = two_fa_code.parse::<u32>().wrap_err("Invalid 2FA code")?;

        if (100_000..=999_999).contains(&code_as_u32) {
            Ok(TwoFACode(two_fa_code.to_string()))
        } else {
            Err(eyre!("Invalid 2FA code")) // Updated!
        }
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct HashedPassword(SecretString);

impl PartialEq for HashedPassword {
    // New!
    fn eq(&self, other: &Self) -> bool {
        // We can use the expose_secret method to expose the SecretString
        // in a controlled manner when needed!
        self.0.expose_secret() == other.0.expose_secret() // Updated!
    }
}

impl HashedPassword {
    #[tracing::instrument(name = "Verify raw password", skip_all)]
    pub async fn parse(password: SecretString) -> Result<Self> {
        Password::parse(password.expose_secret())
            .map_err(|e| Report::msg(e.to_string()))
            .wrap_err("Invalid password")?;

        let hash = compute_password_hash(&password)
            .await
            .wrap_err("Failed to compute password hash")?;

        HashedPassword::parse_password_hash(hash).wrap_err("Failed to parse password hash")
    }

    pub fn parse_password_hash(hash: SecretString) -> Result<HashedPassword> {
        if let Ok(hashed_string) = PasswordHash::new(hash.expose_secret()) {
            Ok(Self(SecretString::new(
                hashed_string.to_string().into_boxed_str(),
            )))
        } else {
            Err(eyre!("Failed to parse string to a HashedPassword type"))
        }
    }

    #[tracing::instrument(name = "Verify password hash", skip_all)]
    pub async fn verify_raw_password(&self, password_candidate: &SecretString) -> Result<()> {
        let current_span = tracing::Span::current();

        let password_hash = self.as_ref().expose_secret().to_owned();
        let password_candidate = password_candidate.expose_secret().to_owned();

        tokio::task::spawn_blocking(move || {
            current_span.in_scope(|| {
                let expected_password_hash =
                    PasswordHash::new(&password_hash).wrap_err("Failed to parse password hash")?;

                Argon2::default()
                    .verify_password(password_candidate.as_bytes(), &expected_password_hash)
                    .wrap_err("failed to verify password hash")
            })
        })
        .await
        .wrap_err("Password verification task panicked or was cancelled")?
    }
}

#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: &SecretString) -> Result<SecretString> {
    let current_span: tracing::Span = tracing::Span::current();

    let password = password.expose_secret().to_owned();
    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt: SaltString = SaltString::generate(&mut OsRng);
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

            Ok(SecretString::new(password_hash.into_boxed_str()))
        })
    })
    .await?;

    result
}

impl AsRef<SecretString> for HashedPassword {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{
        // new
        password_hash::{rand_core::OsRng, SaltString},
        Algorithm,
        Argon2,
        Params,
        PasswordHasher,
        Version,
    };
    use fake::{Fake, Faker};
    use quickcheck_macros::quickcheck;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_two_fa_code_parsing() {
        let is_valid_two_fa_code = TwoFACode::parse("123456").is_ok();
        let err = TwoFACode::parse("").unwrap_err();
        assert!(err.to_string().contains("empty"));
        assert!(is_valid_two_fa_code)
    }

    #[test]
    fn test_login_attempt_id_parsing() {
        let is_valid_login_attempt_id =
            LoginAttemptId::parse("550e8400-e29b-41d4-a716-446655440000").is_ok();
        let err = TwoFACode::parse("").unwrap_err();
        assert!(err.to_string().contains("empty"));

        assert!(is_valid_login_attempt_id)
    }

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
            let email_secret = SecretString::new(email.to_owned().into_boxed_str());
            let result = Email::parse(email_secret);
            assert!(result.is_ok(), "Should parse valid email: {}", email);

            let parsed_email = result.unwrap();
            assert_eq!(parsed_email.as_ref().expose_secret(), email);
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
            let email_secret = SecretString::new(email.to_owned().into_boxed_str());
            let result = Email::parse(email_secret);

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
        let email_secret = SecretString::new("test@example.com".to_owned().into_boxed_str());
        let email_str: &str = email_secret.expose_secret();
        assert_eq!(email_str, "test@example.com");
    }

    #[test]
    fn test_email_equality() {
        let email1 = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let email2 = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let email3 = Email::parse(SecretString::new(
            "other@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();

        assert_eq!(email1, email2);
        assert_ne!(email1, email3);
    }

    #[test]
    fn test_email_trimming() {
        let email_with_spaces =
            SecretString::new("   test@example.com   ".to_owned().into_boxed_str());
        let result = Email::parse(email_with_spaces).unwrap();
        assert_eq!(result.as_ref().expose_secret(), "test@example.com");
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
        assert!(result.is_err(), "Empty password should be rejected");

        let report = result.unwrap_err();

        // Downcast Report → PasswordError
        let actual_error = report
            .downcast_ref::<PasswordError>()
            .expect("Error should be PasswordError");

        assert_eq!(actual_error, &PasswordError::Empty);
    }

    #[test]
    fn test_password_non_ascii() {
        let non_ascii_passwords = ["Pässwörd123!", "密码123!", "Contraseña1!"];

        for password in non_ascii_passwords {
            let result = Password::parse(password);
            assert!(
                result.is_err(),
                "Should reject non-ASCII password: {}",
                password
            );

            let report = result.unwrap_err();

            // Downcast Report → PasswordError
            let actual_error = report
                .downcast_ref::<PasswordError>()
                .expect("Error should be PasswordError");

            assert_eq!(
                actual_error,
                &PasswordError::IsNotASCII,
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
            assert!(
                result.is_err(),
                "Should reject password with whitespace: {:?}",
                password
            );

            let report = result.unwrap_err();
            let actual_error = report
                .downcast_ref::<PasswordError>()
                .expect("Error should be PasswordError");

            assert_eq!(
                actual_error,
                &PasswordError::IncludesSpaces,
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
            assert!(
                result.is_err(),
                "Should reject short password: {}",
                password
            );

            let report = result.unwrap_err();
            let actual_error = report
                .downcast_ref::<PasswordError>()
                .expect("Error should be PasswordError");

            assert_eq!(
                actual_error,
                &PasswordError::ShortLength,
                "Should reject short password: {}",
                password
            );
        }
    }

    fn assert_password_error(input: &str, expected: PasswordError) {
        let result = Password::parse(input);
        assert!(result.is_err(), "Expected error for password: {}", input);

        let report = result.unwrap_err();
        let actual = report
            .downcast_ref::<PasswordError>()
            .expect("Error should be PasswordError");

        assert_eq!(actual, &expected, "Wrong error for password: {}", input);
    }

    #[test]
    fn test_password_missing_capital_letter() {
        let passwords = ["lowercase123!", "nouppercase1!", "password123@"];

        for password in passwords {
            assert_password_error(password, PasswordError::MissingCapitalLetter);
        }
    }

    #[test]
    fn test_password_missing_lowercase_letter() {
        let passwords = ["UPPERCASE123!", "NOLOWERCASE1!", "PASSWORD123@"];

        for password in passwords {
            assert_password_error(password, PasswordError::MissingLowercaseLetter);
        }
    }

    #[test]
    fn test_password_missing_number() {
        let passwords = ["NoNumbers!", "Password!", "OnlyLetters@"];

        for password in passwords {
            assert_password_error(password, PasswordError::MissingNumber);
        }
    }

    #[test]
    fn test_password_missing_symbol() {
        let passwords = ["NoSymbols123", "Password123", "OnlyAlphaNum1"];

        for password in passwords {
            assert_password_error(password, PasswordError::MissingSymbol);
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
        fn assert_password_error(input: &str, expected: PasswordError) {
            let result = Password::parse(input);
            assert!(result.is_err(), "Expected error for password: {:?}", input);

            let report = result.unwrap_err();
            let actual = report
                .downcast_ref::<PasswordError>()
                .expect("Error should be PasswordError");

            assert_eq!(actual, &expected, "Wrong error for password: {:?}", input);
        }

        assert_password_error("", PasswordError::Empty);
        assert_password_error("ñ", PasswordError::IsNotASCII);
        assert_password_error("a b", PasswordError::IncludesSpaces);
        assert_password_error("Short1!", PasswordError::ShortLength);
    }

    #[quickcheck]
    fn prop_valid_emails_contain_at_symbol(email_str: String) -> bool {
        match Email::parse(SecretString::new(email_str.into_boxed_str())) {
            Ok(email) => email.as_ref().expose_secret().contains('@'),
            Err(_) => true,
        }
    }

    #[quickcheck]
    fn prop_email_parse_as_ref_consistency(email_str: String) -> bool {
        match Email::parse(SecretString::new(email_str.to_owned().into_boxed_str())) {
            Ok(email) => {
                let back_to_str = email.as_ref().expose_secret();
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
            let fake_email_secret = SecretString::new(fake_email.to_owned().into_boxed_str());

            match Email::parse(fake_email_secret) {
                Ok(email) => {
                    assert_eq!(email.as_ref().expose_secret(), fake_email.trim());
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
        assert!(Email::parse(SecretString::new("a@b.co".to_owned().into_boxed_str())).is_ok());
        assert!(Email::parse(SecretString::new(
            "test+tag@example.com".to_owned().into_boxed_str()
        ))
        .is_ok());

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

    #[tokio::test]
    async fn empty_string_is_rejected() {
        let password = SecretString::new("".to_string().into_boxed_str());
        assert!(HashedPassword::parse(password).await.is_err());
    }

    #[tokio::test]
    async fn string_less_than_8_characters_is_rejected() {
        let password = SecretString::new("1234567".to_owned().into_boxed_str());
        assert!(HashedPassword::parse(password).await.is_err());
    }

    #[test]
    fn can_parse_valid_argon2_hash() {
        use secrecy::ExposeSecret;

        // Arrange - Create a valid Argon2 hash
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        // Act
        let hash_password = HashedPassword::parse_password_hash(SecretString::new(
            hash_string.clone().into_boxed_str(),
        ))
        .unwrap();

        // ✅ Assert (expose in test only)
        assert_eq!(hash_password.as_ref().expose_secret(), hash_string.as_str());
        assert!(hash_password
            .as_ref()
            .expose_secret()
            .starts_with("$argon2id$v=19$"));
    }

    #[tokio::test]
    async fn can_verify_raw_password() {
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let hash_password = HashedPassword::parse_password_hash(SecretString::new(
            hash_string.clone().into_boxed_str(),
        ))
        .unwrap();

        // ✅ Fix #2: construct candidate properly + pass by reference
        let candidate = SecretString::new(raw_password.to_owned().into_boxed_str());

        hash_password.verify_raw_password(&candidate).await.unwrap();
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub String);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            use rand::{rngs::SmallRng, Rng, SeedableRng};

            // Seed RNG using quickcheck's generator (stable-ish, but fine)
            let seed = u64::arbitrary(g);
            let mut rng = SmallRng::seed_from_u64(seed);

            // Must be from YOUR allowed symbol set
            const SYMBOLS: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

            // Choose length >= 8
            let len = rng.random_range(8..=30);

            // Start by guaranteeing required categories
            let mut chars: Vec<u8> = Vec::with_capacity(len);
            chars.push(rng.random_range(b'A'..=b'Z')); // uppercase
            chars.push(rng.random_range(b'a'..=b'z')); // lowercase
            chars.push(rng.random_range(b'0'..=b'9')); // digit
            chars.push(SYMBOLS[rng.random_range(0..SYMBOLS.len())]); // allowed symbol

            // Fill the rest with allowed ASCII that is NOT whitespace
            // (letters, digits, allowed symbols)
            while chars.len() < len {
                let pick = rng.random_range(0..3);
                let c = match pick {
                    0 => rng.random_range(b'A'..=b'Z'),
                    1 => rng.random_range(b'a'..=b'z'),
                    _ => {
                        // mix digits + allowed symbols
                        if rng.random_bool(0.5) {
                            rng.random_range(b'0'..=b'9')
                        } else {
                            SYMBOLS[rng.random_range(0..SYMBOLS.len())]
                        }
                    }
                };
                chars.push(c);
            }

            // Shuffle so the guaranteed chars aren’t always at the front
            for i in (1..chars.len()).rev() {
                let j = rng.random_range(0..=i);
                chars.swap(i, j);
            }

            Self(String::from_utf8(chars).unwrap())
        }
    }

    #[tokio::test]
    #[quickcheck_macros::quickcheck]
    async fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        let password = secrecy::SecretString::new(valid_password.0.into_boxed_str());
        HashedPassword::parse(password).await.is_ok()
    }
}
