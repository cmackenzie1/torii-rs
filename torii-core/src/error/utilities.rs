use crate::{
    Error,
    error::{StorageError, ValidationError},
};

/// Extension trait for Result types to simplify database error mapping
///
/// This trait provides convenient methods to convert database errors into Torii errors,
/// reducing boilerplate code throughout the codebase.
///
/// # Example
///
/// ```rust
/// use torii_core::error::utilities::DatabaseResultExt;
///
/// // Instead of:
/// // query.execute(&pool).await.map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
///
/// // Use:
/// query.execute(&pool).await.map_db_err()?;
/// ```
pub trait DatabaseResultExt<T> {
    /// Convert a database error to a Torii storage error
    fn map_db_err(self) -> Result<T, Error>;

    /// Convert a database error to a Torii storage error with additional context
    fn map_db_err_with_context(self, context: &str) -> Result<T, Error>;
}

impl<T, E: std::fmt::Display> DatabaseResultExt<T> for Result<T, E> {
    fn map_db_err(self) -> Result<T, Error> {
        self.map_err(|e| Error::Storage(StorageError::Database(e.to_string())))
    }

    fn map_db_err_with_context(self, context: &str) -> Result<T, Error> {
        self.map_err(|e| Error::Storage(StorageError::Database(format!("{context}: {e}"))))
    }
}

/// Extension trait for Option types to simplify required field validation
///
/// This trait provides convenient methods to convert None values into ValidationError,
/// reducing boilerplate in builder patterns.
///
/// # Example
///
/// ```rust
/// use torii_core::error::utilities::RequiredFieldExt;
///
/// // Instead of:
/// // let email = self.email.ok_or(ValidationError::MissingField("Email is required".to_string()))?;
///
/// // Use:
/// let email = self.email.require_field("Email")?;
/// ```
pub trait RequiredFieldExt<T> {
    /// Convert None to a ValidationError::MissingField
    fn require_field(self, field_name: &str) -> Result<T, ValidationError>;
}

impl<T> RequiredFieldExt<T> for Option<T> {
    fn require_field(self, field_name: &str) -> Result<T, ValidationError> {
        self.ok_or_else(|| ValidationError::MissingField(format!("{field_name} is required")))
    }
}

/// Macro to convert any error to a storage database error
///
/// This macro reduces boilerplate when you need to convert various error types
/// to the standard Torii database error format.
///
/// # Example
///
/// ```rust
/// use torii_core::map_storage_err;
///
/// // Instead of:
/// // query.execute(&pool).await.map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
///
/// // Use:
/// map_storage_err!(query.execute(&pool).await)?;
/// ```
#[macro_export]
macro_rules! map_storage_err {
    ($result:expr) => {
        $result.map_err(|e| {
            $crate::Error::Storage($crate::error::StorageError::Database(e.to_string()))
        })
    };
}

/// Macro to convert any error to a storage database error with context
///
/// # Example
///
/// ```rust
/// use torii_core::map_storage_err_with_context;
///
/// map_storage_err_with_context!(query.execute(&pool).await, "Failed to create user")?;
/// ```
#[macro_export]
macro_rules! map_storage_err_with_context {
    ($result:expr, $context:expr) => {
        $result.map_err(|e| {
            $crate::Error::Storage($crate::error::StorageError::Database(format!(
                "{}: {}",
                $context, e
            )))
        })
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{StorageError, ValidationError};

    #[test]
    fn test_database_result_ext() {
        let error_result: Result<i32, &str> = Err("database connection failed");
        let mapped = error_result.map_db_err();

        assert!(mapped.is_err());
        match mapped.unwrap_err() {
            Error::Storage(StorageError::Database(msg)) => {
                assert_eq!(msg, "database connection failed");
            }
            _ => panic!("Expected storage database error"),
        }
    }

    #[test]
    fn test_database_result_ext_with_context() {
        let error_result: Result<i32, &str> = Err("timeout");
        let mapped = error_result.map_db_err_with_context("Failed to save user");

        assert!(mapped.is_err());
        match mapped.unwrap_err() {
            Error::Storage(StorageError::Database(msg)) => {
                assert_eq!(msg, "Failed to save user: timeout");
            }
            _ => panic!("Expected storage database error"),
        }
    }

    #[test]
    fn test_required_field_ext_some() {
        let some_value = Some("test@example.com".to_string());
        let result = some_value.require_field("Email");

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test@example.com");
    }

    #[test]
    fn test_required_field_ext_none() {
        let none_value: Option<String> = None;
        let result = none_value.require_field("Email");

        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::MissingField(msg) => {
                assert_eq!(msg, "Email is required");
            }
            _ => panic!("Expected missing field validation error"),
        }
    }

    #[test]
    fn test_map_storage_err_macro() {
        let error_result: Result<i32, &str> = Err("query failed");
        let mapped = map_storage_err!(error_result);

        assert!(mapped.is_err());
        match mapped.unwrap_err() {
            Error::Storage(StorageError::Database(msg)) => {
                assert_eq!(msg, "query failed");
            }
            _ => panic!("Expected storage database error"),
        }
    }

    #[test]
    fn test_map_storage_err_with_context_macro() {
        let error_result: Result<i32, &str> = Err("foreign key constraint");
        let mapped = map_storage_err_with_context!(error_result, "Creating user");

        assert!(mapped.is_err());
        match mapped.unwrap_err() {
            Error::Storage(StorageError::Database(msg)) => {
                assert_eq!(msg, "Creating user: foreign key constraint");
            }
            _ => panic!("Expected storage database error"),
        }
    }
}
