use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{app_state::AppState, domains::auth::service, error::AppResult};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/salt", post(salt))
        .route("/login", post(login))
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
    salt_hex: String,
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
    kek_id: Uuid,
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
