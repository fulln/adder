use actix_web::{web, App, HttpServer};
use sqlx::PgPool;
use dotenv::dotenv;
use std::env;

use actix_web::{web, App, HttpServer};
use sqlx::PgPool;
use dotenv::dotenv;
use std::env;

mod handlers;
mod models;
mod auth;
mod responses;

// Function to configure the application services
pub fn configure_app(cfg: &mut web::ServiceConfig, pool: PgPool) {
    cfg.app_data(web::Data::new(pool.clone()))
        .service(
            web::scope("/auth")
                .route("/register", web::post().to(handlers::register_user))
                .route("/login", web::post().to(handlers::login_user))
        );
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok(); // Load .env file

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env file");

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to create Postgres connection pool.");

    println!("Server starting on http://127.0.0.1:8080");

    HttpServer::new(move || {
        App::new().configure(|cfg| configure_app(cfg, pool.clone()))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
