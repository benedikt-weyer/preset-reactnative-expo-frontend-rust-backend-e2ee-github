mod app_state;
mod config;
mod db;
mod error;
mod features;
mod routes;

use axum::{routing::get, Router};
use sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
use sea_orm_migration::MigratorTrait;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

use crate::{
    app_state::AppState,
    config::Config,
    db::migrations::Migrator,
    error::{AppError, AppResult},
};

#[tokio::main]
async fn main() -> AppResult<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = Config::from_env()?;
    let db = Database::connect(&config.database_url)
        .await
        .map_err(|_| AppError::internal("failed to connect to Postgres"))?;

    Migrator::up(&db, None)
        .await
        .map_err(|_| AppError::internal("failed to run database migrations"))?;

    let state = AppState { config, db };

    let app = Router::new()
        .route("/health", get(routes::health::health))
        .nest("/api/auth", features::auth::router())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    info!(address = %state.config.bind_addr, "backend listening");

    let listener = tokio::net::TcpListener::bind(state.config.bind_addr)
        .await
        .map_err(|_| AppError::internal("failed to bind the listening socket"))?;

    axum::serve(listener, app)
        .await
        .map_err(|_| AppError::internal("backend server terminated unexpectedly"))?;

    Ok(())
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "backend=debug,tower_http=info".into()),
        )
        .compact()
        .init();
}

pub async fn database_health(state: &AppState) -> AppResult<()> {
    state
        .db
        .query_one(Statement::from_string(DbBackend::Postgres, "select 1".to_owned()))
        .await
        .map_err(|_| AppError::internal("database health check failed"))?;

    Ok(())
}
