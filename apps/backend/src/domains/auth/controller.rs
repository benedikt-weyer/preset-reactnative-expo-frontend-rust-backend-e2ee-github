use axum::{extract::State, routing::{get, post}, Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    domains::auth::{service, AuthenticatedUser},
    error::AppResult,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/kek-status", get(kek_status))
        .route("/salt", post(salt))
        .route("/login", post(login))
        .route("/rotate-password", post(rotate_password))
        .route("/register", post(register))
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailRequest {
    email: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    email: String,
    auth_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    email: String,
    auth_key: String,
    kek_id: String,
    salt_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotatePasswordRequest {
    kek_id: String,
    new_auth_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    kek_metadatas: Vec<KekMetadataResponse>,
    token: String,
    refresh_token: String,
    user: UserResponse,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    id: Uuid,
    email: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaltResponse {
    kek_metadatas: Vec<KekMetadataResponse>,
    salt_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KekMetadataResponse {
    kek_epoch_version: i32,
    kek_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KekMigrationStatusResponse {
    all_deks_use_latest_kek: bool,
    latest_kek_dek_count: u64,
    latest_kek_epoch_version: i32,
    latest_kek_id: String,
    pending_dek_count: u64,
    total_dek_count: u64,
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> AppResult<Json<AuthResponse>> {
    let session = service::register(
        &state,
        service::RegisterCommand {
            email: payload.email,
            auth_key: payload.auth_key,
            kek_id: payload.kek_id,
            salt_hex: payload.salt_hex,
        },
    )
    .await?;

    Ok(Json(map_auth_response(session)))
}

pub async fn salt(
    State(state): State<AppState>,
    Json(payload): Json<EmailRequest>,
) -> AppResult<Json<SaltResponse>> {
    let salt_material = service::salt(&state, &payload.email).await?;

    Ok(Json(SaltResponse {
        kek_metadatas: salt_material
            .kek_metadatas
            .into_iter()
            .map(map_kek_metadata_response)
            .collect(),
        salt_hex: salt_material.salt_hex,
    }))
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<Json<AuthResponse>> {
    let session = service::login(
        &state,
        service::LoginCommand {
            email: payload.email,
            auth_key: payload.auth_key,
        },
    )
    .await?;

    Ok(Json(map_auth_response(session)))
}

pub async fn rotate_password(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<RotatePasswordRequest>,
) -> AppResult<Json<AuthResponse>> {
    let session = service::rotate_password(
        &state,
        &authenticated_user,
        service::RotatePasswordCommand {
            kek_id: payload.kek_id,
            new_auth_key: payload.new_auth_key,
        },
    )
    .await?;

    Ok(Json(map_auth_response(session)))
}

pub async fn kek_status(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<KekMigrationStatusResponse>> {
    Ok(Json(map_kek_migration_status_response(
        service::get_kek_migration_status(&state, &authenticated_user).await?,
    )))
}

fn map_auth_response(session: service::AuthSession) -> AuthResponse {
    AuthResponse {
        kek_metadatas: session
            .kek_metadatas
            .into_iter()
            .map(map_kek_metadata_response)
            .collect(),
        token: session.token,
        refresh_token: session.refresh_token,
        user: UserResponse {
            id: session.user_id,
            email: session.email,
        },
    }
}

fn map_kek_metadata_response(metadata: service::KekMetadata) -> KekMetadataResponse {
    KekMetadataResponse {
        kek_epoch_version: metadata.kek_epoch_version,
        kek_id: metadata.kek_id,
    }
}

fn map_kek_migration_status_response(
    status: service::KekMigrationStatus,
) -> KekMigrationStatusResponse {
    KekMigrationStatusResponse {
        all_deks_use_latest_kek: status.all_deks_use_latest_kek,
        latest_kek_dek_count: status.latest_kek_dek_count,
        latest_kek_epoch_version: status.latest_kek_epoch_version,
        latest_kek_id: status.latest_kek_id,
        pending_dek_count: status.pending_dek_count,
        total_dek_count: status.total_dek_count,
    }
}
