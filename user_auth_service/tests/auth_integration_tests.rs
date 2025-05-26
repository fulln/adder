use actix_web::{test, web, App, http::StatusCode};
use sqlx::{PgPool, Executor};
use serde_json::{json, Value};
use uuid::Uuid;
use std::env;

use user_auth_service::{configure_app, models::{UserResponse, LoginUser}, auth::jwt::{Claims, validate_jwt}}; // Adjust path as necessary

// Helper to setup environment and database connection
async fn setup_test_db() -> PgPool {
    dotenv::dotenv().ok();
    env::set_var("JWT_SECRET", "test_integration_secret_key"); // Use a dedicated test secret

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set for integration tests");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to test database");

    // Clean the users table before each test run (or suite)
    // For simplicity, we delete all users. In a real scenario, transactions or sqlx-test might be better.
    sqlx::query("TRUNCATE TABLE users RESTART IDENTITY CASCADE") // Clears the table
        .execute(&pool)
        .await
        .expect("Failed to clean users table");
    pool
}

// Helper to create a user directly in the DB for testing login, etc.
#[allow(dead_code)] // To avoid warnings if not used in all test scenarios initially
async fn create_test_user_direct(pool: &PgPool, username: &str, email: &str, password_plain: &str) -> Result<Uuid, sqlx::Error> {
    let password_hash = bcrypt::hash(password_plain, bcrypt::DEFAULT_COST).unwrap();
    let user_id = sqlx::query_scalar!(
        "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
        username,
        email,
        password_hash
    )
    .fetch_one(pool)
    .await?;
    Ok(user_id)
}


#[actix_rt::test]
async fn test_register_user_success() {
    let pool = setup_test_db().await;
    let app = test::init_service(App::new().configure(|cfg| configure_app(cfg, pool.clone()))).await;

    let register_payload = json!({
        "username": "testuser_reg_success",
        "email": "test_reg_success@example.com",
        "password": "password123"
    });

    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(&register_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body: UserResponse = test::read_body_json(resp).await;
    assert_eq!(body.username, "testuser_reg_success");
    assert_eq!(body.email, "test_reg_success@example.com");

    // Verify in DB
    let db_user = sqlx::query!("SELECT email, password_hash FROM users WHERE username = $1", "testuser_reg_success")
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch user from DB");
    assert_eq!(db_user.email, "test_reg_success@example.com");
    assert!(bcrypt::verify("password123", &db_user.password_hash).unwrap());
}

#[actix_rt::test]
async fn test_register_user_duplicate_email() {
    let pool = setup_test_db().await;
    create_test_user_direct(&pool, "existinguser_email", "duplicate@example.com", "password123").await.unwrap();
    let app = test::init_service(App::new().configure(|cfg| configure_app(cfg, pool.clone()))).await;

    let register_payload = json!({
        "username": "newuser_dup_email",
        "email": "duplicate@example.com", // Duplicate email
        "password": "password123"
    });

    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(&register_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "error");
    assert!(body["message"].as_str().unwrap().contains("Database Error")); // Generic, from AuthError
}

#[actix_rt::test]
async fn test_register_user_duplicate_username() {
    let pool = setup_test_db().await;
    create_test_user_direct(&pool, "duplicate_username", "new_email@example.com", "password123").await.unwrap();
    let app = test::init_service(App::new().configure(|cfg| configure_app(cfg, pool.clone()))).await;
    
    let register_payload = json!({
        "username": "duplicate_username", // Duplicate username
        "email": "another_email@example.com",
        "password": "password123"
    });

    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(&register_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "error");
}

#[actix_rt::test]
async fn test_register_user_invalid_input_short_password() {
    let pool = setup_test_db().await;
    let app = test::init_service(App::new().configure(|cfg| configure_app(cfg, pool.clone()))).await;

    let register_payload = json!({
        "username": "testuser_shortpass",
        "email": "shortpass@example.com",
        "password": "short" 
    });

    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(&register_payload)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["message"], "Validation Error: Password must be at least 8 characters long");
}

#[actix_rt::test]
async fn test_register_user_invalid_input_empty_username() {
    let pool = setup_test_db().await;
    let app = test::init_service(App::new().configure(|cfg| configure_app(cfg, pool.clone()))).await;

    let register_payload = json!({
        "username": "", // Empty username
        "email": "emptyusername@example.com",
        "password": "password123" 
    });

    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(&register_payload)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["message"], "Validation Error: Username cannot be empty");
}


#[actix_rt::test]
async fn test_login_user_success() {
    let pool = setup_test_db().await;
    let original_username = "login_success_user";
    let original_email = "login_success@example.com";
    let user_id = create_test_user_direct(&pool, original_username, original_email, "password123").await.unwrap();
    
    let app = test::init_service(App::new().configure(|cfg| configure_app(cfg, pool.clone()))).await;

    let login_payload = json!({
        "email": original_email,
        "password": "password123"
    });

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["token_type"], "Bearer");
    let token = body["token"].as_str().expect("Token not found in response");

    // Validate JWT
    let claims = validate_jwt(token).expect("Failed to validate JWT");
    assert_eq!(claims.user_id, user_id);
    assert_eq!(claims.username, original_username);
}

#[actix_rt::test]
async fn test_login_user_not_found() {
    let pool = setup_test_db().await;
    let app = test::init_service(App::new().configure(|cfg| configure_app(cfg, pool.clone()))).await;

    let login_payload = json!({
        "email": "nonexistent@example.com",
        "password": "password123"
    });

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["message"], "Authentication Error: Invalid credentials - user not found");
}

#[actix_rt::test]
async fn test_login_user_wrong_password() {
    let pool = setup_test_db().await;
    create_test_user_direct(&pool, "wrongpass_user", "wrongpass@example.com", "correctpassword").await.unwrap();
    let app = test::init_service(App::new().configure(|cfg| configure_app(cfg, pool.clone()))).await;

    let login_payload = json!({
        "email": "wrongpass@example.com",
        "password": "incorrectpassword"
    });

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["message"], "Authentication Error: Invalid credentials - password mismatch");
}


#[actix_rt::test]
async fn test_login_user_invalid_input_empty_email() {
    let pool = setup_test_db().await;
    let app = test::init_service(App::new().configure(|cfg| configure_app(cfg, pool.clone()))).await;

    let login_payload = json!({
        "email": "", // Empty email
        "password": "password123"
    });

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["message"], "Validation Error: Invalid or empty email");
}

#[actix_rt::test]
async fn test_login_user_invalid_input_bad_email_format() {
    let pool = setup_test_db().await;
    let app = test::init_service(App::new().configure(|cfg| configure_app(cfg, pool.clone()))).await;

    let login_payload = json!({
        "email": "notanemail", // Invalid email format
        "password": "password123"
    });

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["message"], "Validation Error: Invalid or empty email");
}
