//! Cryptographic utilities for secure token handling
//!
//! This module provides secure token hashing and constant-time verification
//! to prevent timing attacks on token verification (magic links, password reset, sessions, etc.).
//!
//! # Security
//!
//! Token verification is vulnerable to timing attacks when using standard string
//! comparison because the comparison may exit early on the first mismatch, creating
//! measurable timing differences. This module addresses this by:
//!
//! 1. Storing SHA256 hashes of tokens instead of plaintext tokens
//! 2. Using constant-time comparison via the `subtle` crate
//! 3. Providing hash-based lookups to avoid iterating over all tokens
//!
//! ## Why SHA256 instead of Argon2?
//!
//! For high-entropy tokens (256 bits of randomness), SHA256 provides sufficient
//! security because brute-force attacks are infeasible. Argon2 is designed for
//! low-entropy secrets (passwords) and adds significant computational overhead
//! that's unnecessary for random tokens.
//!
//! See: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#compare-password-hashes-using-safe-functions>

use rand::{TryRngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Generate a cryptographically secure random token.
///
/// This produces a 256-bit (32-byte) random token encoded as URL-safe base64.
/// The token has sufficient entropy for security-critical applications like
/// magic links, password reset tokens, and invitation tokens.
///
/// # Returns
///
/// A URL-safe base64-encoded random token (43 characters)
///
/// # Panics
///
/// Panics if the OS random number generator fails. This indicates a critical
/// system failure (e.g., /dev/urandom unavailable) from which recovery is not
/// possible for security-sensitive operations.
pub fn generate_secure_token() -> String {
    let mut bytes = [0u8; 32]; // 256 bits of entropy
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG failure - system entropy source unavailable");
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

/// Hash a token for secure storage using SHA256.
///
/// This produces a deterministic hash that can be used for database lookups.
/// The token should have at least 256 bits of entropy (e.g., from a CSPRNG).
///
/// # Arguments
///
/// * `token` - The plaintext token to hash
///
/// # Returns
///
/// A hex-encoded SHA256 hash of the token
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Verify a token against a stored hash with constant-time comparison.
///
/// This function computes the SHA256 hash of the provided token and compares
/// it against the stored hash using constant-time comparison to prevent timing attacks.
///
/// # Arguments
///
/// * `token` - The plaintext token to verify
/// * `stored_hash` - The stored SHA256 hash (hex-encoded) to verify against
///
/// # Returns
///
/// `true` if the token matches the hash, `false` otherwise
pub fn verify_token_hash(token: &str, stored_hash: &str) -> bool {
    let computed_hash = hash_token(token);
    constant_time_compare(computed_hash.as_bytes(), stored_hash.as_bytes())
}

/// Perform constant-time comparison of two byte slices.
///
/// This function uses the `subtle` crate to ensure the comparison takes
/// the same amount of time regardless of where (or if) the bytes differ.
///
/// # Arguments
///
/// * `a` - First byte slice
/// * `b` - Second byte slice
///
/// # Returns
///
/// `true` if the slices are equal, `false` otherwise
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_token() {
        let token = "test_token_12345";
        let hash = hash_token(token);

        // Should verify correctly
        assert!(verify_token_hash(token, &hash));

        // Should fail with wrong token
        assert!(!verify_token_hash("wrong_token", &hash));
    }

    #[test]
    fn test_hash_is_deterministic() {
        let token = "test_token";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);

        // SHA256 is deterministic - same input = same output
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_produces_hex_string() {
        let token = "test_token";
        let hash = hash_token(token);

        // SHA256 produces 32 bytes = 64 hex chars
        assert_eq!(hash.len(), 64);

        // Should be valid hex
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_different_tokens_produce_different_hashes() {
        let hash1 = hash_token("token_a");
        let hash2 = hash_token("token_b");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_constant_time_compare_equal() {
        assert!(constant_time_compare(b"hello", b"hello"));
        assert!(constant_time_compare(b"", b""));
        assert!(constant_time_compare(
            b"a_longer_string_here",
            b"a_longer_string_here"
        ));
    }

    #[test]
    fn test_constant_time_compare_not_equal() {
        assert!(!constant_time_compare(b"hello", b"world"));
        assert!(!constant_time_compare(b"hello", b"hello!"));
        assert!(!constant_time_compare(b"a", b"b"));
    }

    #[test]
    fn test_constant_time_compare_different_lengths() {
        assert!(!constant_time_compare(b"short", b"longer_string"));
        assert!(!constant_time_compare(b"", b"something"));
    }
}
