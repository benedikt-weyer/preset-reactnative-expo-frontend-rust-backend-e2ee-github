use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::entity::note,
    error::{AppError, AppResult},
    features::auth::AuthenticatedUser,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_notes).post(create_note))
        .route("/{note_id}", get(get_note).put(update_note).delete(delete_note))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveNoteRequest {
    algorithm: String,
    ciphertext_hex: String,
    nonce_hex: String,
    version: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoteResponse {
    id: Uuid,
    algorithm: String,
    ciphertext_hex: String,
    nonce_hex: String,
    created_at: String,
    updated_at: String,
    version: i32,
}

pub async fn list_notes(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<Vec<NoteResponse>>> {
    let notes = note::Entity::find()
        .filter(note::Column::UserId.eq(authenticated_user.user_id))
        .order_by_desc(note::Column::UpdatedAt)
        .all(&state.db)
        .await
        .map_err(|_| AppError::internal("failed to query notes"))?;

    Ok(Json(notes.into_iter().map(map_note_response).collect()))
}

pub async fn get_note(
    State(state): State<AppState>,
    Path(note_id): Path<Uuid>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<NoteResponse>> {
    let saved_note = find_note_by_id(&state, authenticated_user.user_id, note_id).await?;

    Ok(Json(map_note_response(saved_note)))
}

pub async fn create_note(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<SaveNoteRequest>,
) -> AppResult<Json<NoteResponse>> {
    validate_payload(&payload)?;

    let now = Utc::now().fixed_offset();
    let saved_note = note::ActiveModel {
        id: Set(Uuid::now_v7()),
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
    .map_err(|_| AppError::internal("failed to create the note"))?;

    Ok(Json(map_note_response(saved_note)))
}

pub async fn update_note(
    State(state): State<AppState>,
    Path(note_id): Path<Uuid>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<SaveNoteRequest>,
) -> AppResult<Json<NoteResponse>> {
    validate_payload(&payload)?;

    let existing_note = find_note_by_id(&state, authenticated_user.user_id, note_id).await?;

    let now = Utc::now().fixed_offset();
    let mut active_model: note::ActiveModel = existing_note.into();
    active_model.algorithm = Set(payload.algorithm.trim().to_owned());
    active_model.ciphertext_hex = Set(payload.ciphertext_hex.trim().to_owned());
    active_model.nonce_hex = Set(payload.nonce_hex.trim().to_owned());
    active_model.version = Set(payload.version);
    active_model.updated_at = Set(now);

    let saved_note = active_model
        .update(&state.db)
        .await
        .map_err(|_| AppError::internal("failed to update the note"))?;

    Ok(Json(map_note_response(saved_note)))
}

pub async fn delete_note(
    State(state): State<AppState>,
    Path(note_id): Path<Uuid>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<bool>> {
    let existing_note = find_note_by_id(&state, authenticated_user.user_id, note_id).await?;

    existing_note
        .delete(&state.db)
        .await
        .map_err(|_| AppError::internal("failed to delete the note"))?;

    Ok(Json(true))
}

fn map_note_response(note: note::Model) -> NoteResponse {
    NoteResponse {
        id: note.id,
        algorithm: note.algorithm,
        ciphertext_hex: note.ciphertext_hex,
        nonce_hex: note.nonce_hex,
        created_at: note.created_at.to_rfc3339(),
        updated_at: note.updated_at.to_rfc3339(),
        version: note.version,
    }
}

fn validate_payload(payload: &SaveNoteRequest) -> AppResult<()> {
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

async fn find_note_by_id(
    state: &AppState,
    user_id: Uuid,
    note_id: Uuid,
) -> AppResult<note::Model> {
    note::Entity::find()
        .filter(note::Column::Id.eq(note_id))
        .filter(note::Column::UserId.eq(user_id))
        .one(&state.db)
        .await
        .map_err(|_| AppError::internal("failed to query the note"))?
        .ok_or_else(|| AppError::not_found("note not found"))
}