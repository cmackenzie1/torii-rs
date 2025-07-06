//! ID generation utilities with prefix support
//!
//! This module provides utilities for generating unique IDs with prefixes,
//! similar to Stripe's API. IDs are generated with at least 96 bits of entropy
//! and are URL-safe.

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use rand::{TryRngCore, rngs::OsRng};

/// Generate a prefixed ID with at least 96 bits of entropy
///
/// The ID format is: `{prefix}_{random_string}`
/// Where the random string is base64 URL-safe encoded without padding.
///
/// # Arguments
/// * `prefix` - The prefix for the ID (e.g., "usr", "sess", "tok")
///
/// # Example
/// ```
/// let user_id = generate_prefixed_id("usr");
/// assert!(user_id.starts_with("usr_"));
/// ```
pub fn generate_prefixed_id(prefix: &str) -> String {
    // Generate 12 bytes (96 bits) of random data
    let mut bytes = [0u8; 12];
    OsRng.try_fill_bytes(&mut bytes).unwrap();

    // Encode to base64 URL-safe without padding
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(bytes);

    format!("{prefix}_{encoded}")
}

/// Generate a prefixed ID with custom entropy size
///
/// # Arguments
/// * `prefix` - The prefix for the ID
/// * `bytes` - Number of random bytes to generate (minimum 12 for 96 bits)
///
/// # Panics
/// Panics if bytes is less than 12
pub fn generate_prefixed_id_with_bytes(prefix: &str, bytes: usize) -> String {
    if bytes < 12 {
        panic!("Minimum 12 bytes (96 bits) of entropy required");
    }

    let mut random_bytes = vec![0u8; bytes];
    OsRng.try_fill_bytes(&mut random_bytes).unwrap();

    let encoded = BASE64_URL_SAFE_NO_PAD.encode(random_bytes);

    format!("{prefix}_{encoded}")
}

/// Validate that a prefixed ID has the expected format
///
/// # Arguments
/// * `id` - The ID to validate
/// * `expected_prefix` - The expected prefix
///
/// # Returns
/// `true` if the ID has the correct format, `false` otherwise
pub fn validate_prefixed_id(id: &str, expected_prefix: &str) -> bool {
    // Check if ID starts with prefix followed by underscore
    if !id.starts_with(&format!("{expected_prefix}_")) {
        return false;
    }

    // Extract the random part
    let random_part = &id[expected_prefix.len() + 1..];

    // Try to decode to ensure it's valid base64
    match BASE64_URL_SAFE_NO_PAD.decode(random_part) {
        Ok(decoded) => decoded.len() >= 12, // At least 96 bits
        Err(_) => false,
    }
}

/// Extract the prefix from a prefixed ID
///
/// # Arguments
/// * `id` - The ID to extract the prefix from
///
/// # Returns
/// The prefix if the ID has a valid format, None otherwise
pub fn extract_prefix(id: &str) -> Option<&str> {
    id.split_once('_').map(|(prefix, _)| prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_prefixed_id() {
        let id = generate_prefixed_id("usr");
        assert!(id.starts_with("usr_"));
        assert!(id.len() > 4); // prefix + underscore + base64

        // Ensure uniqueness
        let id2 = generate_prefixed_id("usr");
        assert_ne!(id, id2);
    }

    #[test]
    fn test_generate_prefixed_id_with_bytes() {
        let id = generate_prefixed_id_with_bytes("sess", 16);
        assert!(id.starts_with("sess_"));

        // Extract and decode the random part
        let random_part = &id[5..]; // "sess_".len() = 5
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(random_part).unwrap();
        assert_eq!(decoded.len(), 16);
    }

    #[test]
    #[should_panic(expected = "Minimum 12 bytes")]
    fn test_generate_prefixed_id_insufficient_entropy() {
        generate_prefixed_id_with_bytes("usr", 8);
    }

    #[test]
    fn test_validate_prefixed_id() {
        let id = generate_prefixed_id("usr");
        assert!(validate_prefixed_id(&id, "usr"));
        assert!(!validate_prefixed_id(&id, "sess"));

        // Test invalid formats
        assert!(!validate_prefixed_id("usr", "usr"));
        assert!(!validate_prefixed_id("usr_", "usr"));
        assert!(!validate_prefixed_id("usr_invalid!", "usr"));
    }

    #[test]
    fn test_extract_prefix() {
        assert_eq!(extract_prefix("usr_abc123"), Some("usr"));
        assert_eq!(extract_prefix("sess_xyz789"), Some("sess"));
        assert_eq!(extract_prefix("no_underscore"), Some("no"));
        assert_eq!(extract_prefix("noprefix"), None);
    }

    #[test]
    fn test_id_is_url_safe() {
        let id = generate_prefixed_id("usr");
        // URL-safe characters: A-Z, a-z, 0-9, -, _, ~
        // Our IDs use: prefix (alphanumeric), _, base64 URL-safe (A-Z, a-z, 0-9, -, _)
        assert!(
            id.chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        );
    }
}
