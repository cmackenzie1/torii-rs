use crate::error::ValidationError;
use regex::Regex;
use std::sync::LazyLock;

/// Centralized validation utilities for the Torii authentication framework
///
/// This module provides a single source of truth for all validation logic,
/// reducing code duplication and ensuring consistent validation across the codebase.
/// Lazy-loaded email validation regex
///
/// This regex validates email addresses according to a practical subset of RFC 5322.
/// It's loaded once at runtime and reused for all email validation operations.
static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        .expect("Invalid email regex pattern")
});

/// Validates an email address
///
/// # Arguments
///
/// * `email` - The email address to validate
///
/// # Returns
///
/// Returns `Ok(())` if the email is valid, or a `ValidationError::InvalidEmail` if invalid.
///
/// # Examples
///
/// ```rust
/// use torii_core::validation::validate_email;
///
/// assert!(validate_email("user@example.com").is_ok());
/// assert!(validate_email("invalid-email").is_err());
/// ```
pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    if email.is_empty() {
        return Err(ValidationError::MissingField(
            "Email is required".to_string(),
        ));
    }

    if email.len() > 254 {
        return Err(ValidationError::InvalidEmail(
            "Email is too long".to_string(),
        ));
    }

    if EMAIL_REGEX.is_match(email) {
        Ok(())
    } else {
        Err(ValidationError::InvalidEmail(format!(
            "Invalid email format: {email}"
        )))
    }
}

/// Validates a password according to security requirements
///
/// # Arguments
///
/// * `password` - The password to validate
///
/// # Returns
///
/// Returns `Ok(())` if the password meets requirements, or a `ValidationError` if invalid.
///
/// # Password Requirements
///
/// - Minimum 8 characters
/// - Maximum 128 characters
/// - Cannot be empty or whitespace only
///
/// # Examples
///
/// ```rust
/// use torii_core::validation::validate_password;
///
/// assert!(validate_password("securepassword123").is_ok());
/// assert!(validate_password("weak").is_err());
/// ```
pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.is_empty() {
        return Err(ValidationError::MissingField(
            "Password is required".to_string(),
        ));
    }

    if password.trim().is_empty() {
        return Err(ValidationError::InvalidPassword(
            "Password cannot be only whitespace".to_string(),
        ));
    }

    if password.len() < 8 {
        return Err(ValidationError::InvalidPassword(
            "Password must be at least 8 characters long".to_string(),
        ));
    }

    if password.len() > 128 {
        return Err(ValidationError::InvalidPassword(
            "Password must be no more than 128 characters long".to_string(),
        ));
    }

    Ok(())
}

/// Validates a user name
///
/// # Arguments
///
/// * `name` - The name to validate (optional)
///
/// # Returns
///
/// Returns `Ok(())` if the name is valid, or a `ValidationError` if invalid.
///
/// # Name Requirements
///
/// - If provided, cannot be empty or whitespace only
/// - Maximum 100 characters
///
/// # Examples
///
/// ```rust
/// use torii_core::validation::validate_name;
///
/// assert!(validate_name(Some("John Doe")).is_ok());
/// assert!(validate_name(None).is_ok());
/// assert!(validate_name(Some("")).is_err());
/// ```
pub fn validate_name(name: Option<&str>) -> Result<(), ValidationError> {
    if let Some(name) = name {
        if name.trim().is_empty() {
            return Err(ValidationError::InvalidName(
                "Name cannot be empty or whitespace only".to_string(),
            ));
        }

        if name.len() > 100 {
            return Err(ValidationError::InvalidName(
                "Name must be no more than 100 characters long".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validates a user ID string format
///
/// # Arguments
///
/// * `user_id` - The user ID string to validate
///
/// # Returns
///
/// Returns `Ok(())` if the user ID is valid, or a `ValidationError` if invalid.
///
/// # User ID Requirements
///
/// - Cannot be empty
/// - Must be URL-safe (alphanumeric, hyphens, underscores only)
/// - Maximum 50 characters
///
/// # Examples
///
/// ```rust
/// use torii_core::validation::validate_user_id_string;
///
/// assert!(validate_user_id_string("usr_1234567890abcdef").is_ok());
/// assert!(validate_user_id_string("").is_err());
/// assert!(validate_user_id_string("user@invalid").is_err());
/// ```
pub fn validate_user_id_string(user_id: &str) -> Result<(), ValidationError> {
    if user_id.is_empty() {
        return Err(ValidationError::MissingField(
            "User ID is required".to_string(),
        ));
    }

    if user_id.len() > 50 {
        return Err(ValidationError::InvalidUserId(
            "User ID must be no more than 50 characters long".to_string(),
        ));
    }

    // Check for URL-safe characters only (lowercase alphanumeric, hyphens, underscores)
    if !user_id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(ValidationError::InvalidUserId(
            "User ID must contain only lowercase letters, numbers, hyphens, and underscores"
                .to_string(),
        ));
    }

    Ok(())
}

/// Validates an OAuth provider name
///
/// # Arguments
///
/// * `provider` - The OAuth provider name to validate
///
/// # Returns
///
/// Returns `Ok(())` if the provider name is valid, or a `ValidationError` if invalid.
///
/// # Provider Requirements
///
/// - Cannot be empty
/// - Must be lowercase alphanumeric with optional hyphens
/// - Maximum 50 characters
///
/// # Examples
///
/// ```rust
/// use torii_core::validation::validate_oauth_provider;
///
/// assert!(validate_oauth_provider("google").is_ok());
/// assert!(validate_oauth_provider("github-enterprise").is_ok());
/// assert!(validate_oauth_provider("").is_err());
/// assert!(validate_oauth_provider("Invalid_Provider").is_err());
/// ```
pub fn validate_oauth_provider(provider: &str) -> Result<(), ValidationError> {
    if provider.is_empty() {
        return Err(ValidationError::MissingField(
            "OAuth provider is required".to_string(),
        ));
    }

    if provider.len() > 50 {
        return Err(ValidationError::InvalidProvider(
            "OAuth provider name must be no more than 50 characters long".to_string(),
        ));
    }

    // Check for lowercase alphanumeric with hyphens only
    if !provider
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ValidationError::InvalidProvider(
            "OAuth provider name must contain only lowercase letters, numbers, and hyphens"
                .to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email_valid() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("test.email+tag@domain.co.uk").is_ok());
        assert!(validate_email("user123@test-domain.com").is_ok());
    }

    #[test]
    fn test_validate_email_invalid() {
        assert!(validate_email("").is_err());
        assert!(validate_email("invalid-email").is_err());
        assert!(validate_email("@domain.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("user@domain").is_err());

        // Test email too long
        let long_email = format!("{}@example.com", "a".repeat(250));
        assert!(validate_email(&long_email).is_err());
    }

    #[test]
    fn test_validate_password_valid() {
        assert!(validate_password("password123").is_ok());
        assert!(validate_password("a_very_secure_password_with_symbols!@#").is_ok());
        assert!(validate_password("12345678").is_ok()); // Minimum length
    }

    #[test]
    fn test_validate_password_invalid() {
        assert!(validate_password("").is_err());
        assert!(validate_password("   ").is_err()); // Whitespace only
        assert!(validate_password("short").is_err()); // Too short
        assert!(validate_password(&"a".repeat(129)).is_err()); // Too long
    }

    #[test]
    fn test_validate_name_valid() {
        assert!(validate_name(None).is_ok());
        assert!(validate_name(Some("John Doe")).is_ok());
        assert!(validate_name(Some("Jane")).is_ok());
        assert!(validate_name(Some("José María García-López")).is_ok());
    }

    #[test]
    fn test_validate_name_invalid() {
        assert!(validate_name(Some("")).is_err());
        assert!(validate_name(Some("   ")).is_err()); // Whitespace only
        assert!(validate_name(Some(&"a".repeat(101))).is_err()); // Too long
    }

    #[test]
    fn test_validate_user_id_string_valid() {
        assert!(validate_user_id_string("usr_1234567890abcdef").is_ok());
        assert!(validate_user_id_string("user-123").is_ok());
        assert!(validate_user_id_string("simple_id").is_ok());
        assert!(validate_user_id_string("12345").is_ok());
    }

    #[test]
    fn test_validate_user_id_string_invalid() {
        assert!(validate_user_id_string("").is_err());
        assert!(validate_user_id_string("user@invalid").is_err()); // Invalid character
        assert!(validate_user_id_string("User_ID").is_err()); // Uppercase not allowed
        assert!(validate_user_id_string(&"a".repeat(51)).is_err()); // Too long
    }

    #[test]
    fn test_validate_oauth_provider_valid() {
        assert!(validate_oauth_provider("google").is_ok());
        assert!(validate_oauth_provider("github").is_ok());
        assert!(validate_oauth_provider("microsoft-azure").is_ok());
        assert!(validate_oauth_provider("auth0").is_ok());
    }

    #[test]
    fn test_validate_oauth_provider_invalid() {
        assert!(validate_oauth_provider("").is_err());
        assert!(validate_oauth_provider("Google").is_err()); // Uppercase
        assert!(validate_oauth_provider("provider_name").is_err()); // Underscore
        assert!(validate_oauth_provider("provider.name").is_err()); // Dot
        assert!(validate_oauth_provider(&"a".repeat(51)).is_err()); // Too long
    }
}
