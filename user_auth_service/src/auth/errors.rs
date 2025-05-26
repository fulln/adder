use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde_json::json; // Ensure serde_json is in Cargo.toml
use std::fmt;

use crate::responses::ErrorResponse; // Assuming ErrorResponse is in src/responses.rs

#[derive(Debug)]
pub enum AuthError {
    ValidationError(String),
    DatabaseError(sqlx::Error),
    AuthenticationError(String),
    JwtGenerationError(jsonwebtoken::errors::Error),
    PasswordHashingError(String),
    InternalError(String), // Generic internal error
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::ValidationError(msg) => write!(f, "Validation Error: {}", msg),
            AuthError::DatabaseError(err) => write!(f, "Database Error: {}", err),
            AuthError::AuthenticationError(msg) => write!(f, "Authentication Error: {}", msg),
            AuthError::JwtGenerationError(err) => write!(f, "JWT Generation Error: {}", err),
            AuthError::PasswordHashingError(msg) => write!(f, "Password Hashing Error: {}", msg),
            AuthError::InternalError(msg) => write!(f, "Internal Error: {}", msg),
        }
    }
}

impl ResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        match self {
            AuthError::ValidationError(_) => StatusCode::BAD_REQUEST,
            AuthError::DatabaseError(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => StatusCode::CONFLICT,
            AuthError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::AuthenticationError(_) => StatusCode::UNAUTHORIZED,
            AuthError::JwtGenerationError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::PasswordHashingError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let error_message = self.to_string();

        HttpResponse::build(status_code).json(ErrorResponse {
            status: match status_code.is_success() { // Should always be false for errors
                true => "success".to_string(), // Should not happen with this logic
                false => "error".to_string(),
            },
            message: error_message,
        })
    }
}

// Helper for converting sqlx::Error to AuthError
impl From<sqlx::Error> for AuthError {
    fn from(err: sqlx::Error) -> Self {
        AuthError::DatabaseError(err)
    }
}

// Helper for converting jsonwebtoken::errors::Error to AuthError
impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        AuthError::JwtGenerationError(err)
    }
}
