pub mod health;
use axum::{extract::State, routing::{get, post}, Json, Router};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use serde::Serialize;

use crate::{app_state::AppState, error::AppError, features::auth};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/auth/register", post(auth::register))
        .route("/api/auth/login", post(auth::login))
        .with_state(state)
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    database: &'static str,
}

async fn health(State(state): State<AppState>) -> Result<Json<HealthResponse>, AppError> {
    state
        .db
        .query_one(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT 1".to_owned(),
        ))
        .await?;

    Ok(Json(HealthResponse {
        status: "ok",
        database: "reachable",
    }))
}