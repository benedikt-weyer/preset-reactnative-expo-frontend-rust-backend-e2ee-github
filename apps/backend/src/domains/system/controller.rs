use axum::{extract::State, Json};
use serde::Serialize;

use crate::{app_state::AppState, error::AppResult};

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    database: &'static str,
}

pub async fn health(State(state): State<AppState>) -> AppResult<Json<HealthResponse>> {
    crate::database_health(&state).await?;

    Ok(Json(HealthResponse {
        status: "ok",
        database: "up",
    }))
}
