use actix_web::{web, HttpResponse, Responder};
use sqlx::PgPool;
use bcrypt::{hash, DEFAULT_COST};
// use validator::Validate; // Placeholder, can be re-enabled if validator crate is used more formally

use crate::models::{RegisterUser, User, UserResponse};
use crate::auth::errors::AuthError; // Import AuthError

// Basic email format validation (presence of '@')
fn is_valid_email(email: &str) -> bool {
    email.contains('@') && email.len() > 3 // Basic check
}

pub async fn register_user(
    user_data: web::Json<RegisterUser>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AuthError> {
    // Input Validation
    if user_data.username.is_empty() {
        return Err(AuthError::ValidationError("Username cannot be empty".to_string()));
    }
    if user_data.email.is_empty() || !is_valid_email(&user_data.email) {
        return Err(AuthError::ValidationError("Invalid or empty email".to_string()));
    }
    if user_data.password.len() < 8 {
        return Err(AuthError::ValidationError("Password must be at least 8 characters long".to_string()));
    }

    // Password Hashing
    let password_hash = hash(&user_data.password, DEFAULT_COST)
        .map_err(|e| AuthError::PasswordHashingError(format!("Failed to hash password: {}", e)))?;

    // Database Insertion
    let new_user = sqlx::query_as!(
        User,
        "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email, password_hash, created_at, updated_at",
        user_data.username,
        user_data.email,
        password_hash
    )
    .fetch_one(pool.get_ref())
    .await
    .map_err(AuthError::from)?; // Converts sqlx::Error to AuthError::DatabaseError

    let user_response = UserResponse::from(new_user);
    Ok(HttpResponse::Created().json(user_response))
}

pub async fn login_user(
    login_data: web::Json<crate::models::LoginUser>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AuthError> {
    // Input Validation
    if login_data.email.is_empty() || !is_valid_email(&login_data.email) {
        return Err(AuthError::ValidationError("Invalid or empty email".to_string()));
    }
    if login_data.password.is_empty() {
        return Err(AuthError::ValidationError("Password cannot be empty".to_string()));
    }

    // Retrieve User
    let user = sqlx::query_as!(
        User,
        "SELECT id, username, email, password_hash, created_at, updated_at FROM users WHERE email = $1",
        login_data.email
    )
    .fetch_optional(pool.get_ref())
    .await
    .map_err(AuthError::from)? // Converts sqlx::Error to AuthError::DatabaseError
    .ok_or_else(|| AuthError::AuthenticationError("Invalid credentials - user not found".to_string()))?;

    // Verify Password
    let valid_password = bcrypt::verify(&login_data.password, &user.password_hash)
        .map_err(|_| AuthError::InternalError("Error verifying password".to_string()))?;

    if !valid_password {
        return Err(AuthError::AuthenticationError("Invalid credentials - password mismatch".to_string()));
    }

    // Generate JWT
    let token = crate::auth::jwt::generate_jwt(user.id, &user.username)
        .map_err(AuthError::from)?; // Converts jsonwebtoken::errors::Error to AuthError::JwtGenerationError

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "token": token,
        "token_type": "Bearer"
    })))
}
