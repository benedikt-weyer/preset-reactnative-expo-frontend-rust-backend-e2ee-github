mod app_state;
mod config;
mod db;
mod domains;
mod error;

use std::time::Duration;

use axum::{routing::get, Router};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};
use sea_orm_migration::MigratorTrait;
use tokio::sync::broadcast;
use tokio::time::sleep;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{info, warn};

use crate::{
    app_state::AppState,
    config::Config,
    db::migrations::Migrator,
    error::{AppError, AppResult},
};

const DATABASE_CONNECT_RETRY_DELAY: Duration = Duration::from_secs(2);

#[tokio::main]
async fn main() -> AppResult<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = Config::from_env()?;
    let db = wait_for_database(&config.database_url).await?;
    let (note_events, _) = broadcast::channel(256);

    Migrator::up(&db, None).await.map_err(|error| {
        AppError::internal(format!("failed to run database migrations: {error}"))
    })?;

    let state = AppState {
        config,
        db,
        note_events,
    };

    let app = Router::new()
        .route("/health", get(domains::system::health))
        .nest("/api/auth", domains::auth::router())
        .nest("/api/notes", domains::notes::router())
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

async fn wait_for_database(database_url: &str) -> AppResult<DatabaseConnection> {
    let mut attempt = 1_u32;

    loop {
        match Database::connect(database_url).await {
            Ok(db) => match ping_database(&db).await {
                Ok(()) => {
                    info!(attempt, "Postgres is online");
                    return Ok(db);
                }
                Err(error) => {
                    warn!(
                        attempt,
                        error = ?error,
                        retry_in_seconds = DATABASE_CONNECT_RETRY_DELAY.as_secs(),
                        "connected to Postgres but readiness check failed, retrying"
                    );
                }
            },
            Err(error) => {
                warn!(
                    attempt,
                    error = %error,
                    retry_in_seconds = DATABASE_CONNECT_RETRY_DELAY.as_secs(),
                    "waiting for Postgres to become available"
                );
            }
        }

        sleep(DATABASE_CONNECT_RETRY_DELAY).await;
        attempt += 1;
    }
}

async fn ping_database(db: &DatabaseConnection) -> AppResult<()> {
    db.query_one(Statement::from_string(
        DbBackend::Postgres,
        "select 1".to_owned(),
    ))
    .await
    .map_err(|_| AppError::internal("database health check failed"))?;

    Ok(())
}

pub async fn database_health(state: &AppState) -> AppResult<()> {
    ping_database(&state.db).await
}
