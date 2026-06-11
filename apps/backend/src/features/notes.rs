use axum::{
    extract::State,
    routing::get,
    Json, Router,
};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::entity::encrypted_note,
    error::{AppError, AppResult},
    features::auth::AuthenticatedUser,
};

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/test-note",
        get(get_test_note)
            .put(upsert_test_note)
            .delete(delete_test_note),
    )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertTestNoteRequest {
    algorithm: String,
    ciphertext_hex: String,
    nonce_hex: String,
    version: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestNoteResponse {
    algorithm: String,
    ciphertext_hex: String,
    nonce_hex: String,
    updated_at: String,
    version: i32,
}

pub async fn get_test_note(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<Option<TestNoteResponse>>> {
    let encrypted_note = encrypted_note::Entity::find()
        .filter(encrypted_note::Column::UserId.eq(authenticated_user.user_id))
        .one(&state.db)
        .await
        .map_err(|_| AppError::internal("failed to query the encrypted note"))?;

    Ok(Json(encrypted_note.map(map_note_response)))
}

pub async fn upsert_test_note(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<UpsertTestNoteRequest>,
) -> AppResult<Json<TestNoteResponse>> {
    validate_payload(&payload)?;

    let existing_note = encrypted_note::Entity::find()
        .filter(encrypted_note::Column::UserId.eq(authenticated_user.user_id))
        .one(&state.db)
        .await
        .map_err(|_| AppError::internal("failed to query the encrypted note"))?;

    let now = Utc::now().fixed_offset();
    let saved_note = match existing_note {
        Some(existing_note) => {
            let mut active_model: encrypted_note::ActiveModel = existing_note.into();
            active_model.algorithm = Set(payload.algorithm.trim().to_owned());
            active_model.ciphertext_hex = Set(payload.ciphertext_hex.trim().to_owned());
            active_model.nonce_hex = Set(payload.nonce_hex.trim().to_owned());
            active_model.version = Set(payload.version);
            active_model.updated_at = Set(now);
            active_model
                .update(&state.db)
                .await
                .map_err(|_| AppError::internal("failed to update the encrypted note"))?
        }
        None => encrypted_note::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(authenticated_user.user_id),
            algorithm: Set(payload.algorithm.trim().to_owned()),
            ciphertext_hex: Set(payload.ciphertext_hex.trim().to_owned()),
            nonce_hex: Set(payload.nonce_hex.trim().to_owned()),
            version: Set(payload.version),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&state.db)
        .await
        .map_err(|_| AppError::internal("failed to create the encrypted note"))?,
    };

    Ok(Json(map_note_response(saved_note)))
}

pub async fn delete_test_note(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<bool>> {
    if let Some(existing_note) = encrypted_note::Entity::find()
        .filter(encrypted_note::Column::UserId.eq(authenticated_user.user_id))
        .one(&state.db)
        .await
        .map_err(|_| AppError::internal("failed to query the encrypted note"))?
    {
        existing_note
            .delete(&state.db)
            .await
            .map_err(|_| AppError::internal("failed to delete the encrypted note"))?;
    }

    Ok(Json(true))
}

fn map_note_response(note: encrypted_note::Model) -> TestNoteResponse {
    TestNoteResponse {
        algorithm: note.algorithm,
        ciphertext_hex: note.ciphertext_hex,
        nonce_hex: note.nonce_hex,
        updated_at: note.updated_at.to_rfc3339(),
        version: note.version,
    }
}

fn validate_payload(payload: &UpsertTestNoteRequest) -> AppResult<()> {
    if payload.algorithm.trim() != "xsalsa20-poly1305" {
        return Err(AppError::validation(
            "algorithm must be xsalsa20-poly1305",
        ));
    }

    if payload.version != 1 {
        return Err(AppError::validation("version must be 1"));
    }

    normalize_hex_field(&payload.ciphertext_hex, "ciphertextHex")?;
    normalize_hex_field(&payload.nonce_hex, "nonceHex")?;

    Ok(())
}

fn normalize_hex_field(value: &str, field_name: &str) -> AppResult<()> {
    let normalized = value.trim().to_ascii_lowercase();

    if normalized.is_empty() {
        return Err(AppError::validation(format!("{field_name} is required")));
    }

    hex::decode(&normalized)
        .map_err(|_| AppError::validation(format!("{field_name} must be valid hex")))?;

    Ok(())
}