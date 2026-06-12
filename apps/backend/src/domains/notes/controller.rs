use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    domains::{
        auth::AuthenticatedUser,
        notes::service,
    },
    error::AppResult,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_notes).post(create_note))
        .route(
            "/{note_id}",
            get(get_note).put(update_note).delete(delete_note),
        )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveNoteRequest {
    encrypted_dek: WrappedDekRequest,
    encrypted_payload: EncryptedBlobRequest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedBlobRequest {
    algorithm: String,
    ciphertext_hex: String,
    nonce_hex: String,
    version: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedDekRequest {
    algorithm: String,
    kek_id: String,
    nonce_hex: String,
    version: i32,
    wrapped_dek_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoteResponse {
    id: Uuid,
    encrypted_dek: WrappedDekResponse,
    encrypted_payload: EncryptedBlobResponse,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedBlobResponse {
    algorithm: String,
    ciphertext_hex: String,
    nonce_hex: String,
    version: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedDekResponse {
    algorithm: String,
    kek_id: String,
    nonce_hex: String,
    version: i32,
    wrapped_dek_hex: String,
}

pub async fn list_notes(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<Vec<NoteResponse>>> {
    let notes = service::list_notes(&state, &authenticated_user).await?;
    Ok(Json(notes.into_iter().map(map_note_response).collect()))
}

pub async fn get_note(
    State(state): State<AppState>,
    Path(note_id): Path<Uuid>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<NoteResponse>> {
    let note = service::get_note(&state, &authenticated_user, note_id).await?;
    Ok(Json(map_note_response(note)))
}

pub async fn create_note(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<SaveNoteRequest>,
) -> AppResult<Json<NoteResponse>> {
    let note = service::create_note(&state, &authenticated_user, map_save_command(payload)).await?;
    Ok(Json(map_note_response(note)))
}

pub async fn update_note(
    State(state): State<AppState>,
    Path(note_id): Path<Uuid>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<SaveNoteRequest>,
) -> AppResult<Json<NoteResponse>> {
    let note = service::update_note(
        &state,
        &authenticated_user,
        note_id,
        map_save_command(payload),
    )
    .await?;
    Ok(Json(map_note_response(note)))
}

pub async fn delete_note(
    State(state): State<AppState>,
    Path(note_id): Path<Uuid>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<bool>> {
    service::delete_note(&state, &authenticated_user, note_id).await?;
    Ok(Json(true))
}

fn map_save_command(payload: SaveNoteRequest) -> service::SaveNoteCommand {
    service::SaveNoteCommand {
        encrypted_dek: map_wrapped_dek_request(payload.encrypted_dek),
        encrypted_payload: map_blob_request(payload.encrypted_payload),
    }
}

fn map_wrapped_dek_request(payload: WrappedDekRequest) -> service::SaveWrappedDekCommand {
    service::SaveWrappedDekCommand {
        algorithm: payload.algorithm,
        kek_id: payload.kek_id,
        nonce_hex: payload.nonce_hex,
        version: payload.version,
        wrapped_dek_hex: payload.wrapped_dek_hex,
    }
}

fn map_blob_request(payload: EncryptedBlobRequest) -> service::SaveEncryptedBlobCommand {
    service::SaveEncryptedBlobCommand {
        algorithm: payload.algorithm,
        ciphertext_hex: payload.ciphertext_hex,
        nonce_hex: payload.nonce_hex,
        version: payload.version,
    }
}

fn map_note_response(note: service::StoredNote) -> NoteResponse {
    NoteResponse {
        id: note.id,
        encrypted_dek: map_wrapped_dek_response(note.encrypted_dek),
        encrypted_payload: map_blob_response(note.encrypted_payload),
        created_at: note.created_at,
        updated_at: note.updated_at,
    }
}

fn map_wrapped_dek_response(blob: service::StoredWrappedDek) -> WrappedDekResponse {
    WrappedDekResponse {
        algorithm: blob.algorithm,
        kek_id: blob.kek_id,
        nonce_hex: blob.nonce_hex,
        version: blob.version,
        wrapped_dek_hex: blob.wrapped_dek_hex,
    }
}

fn map_blob_response(blob: service::StoredEncryptedBlob) -> EncryptedBlobResponse {
    EncryptedBlobResponse {
        algorithm: blob.algorithm,
        ciphertext_hex: blob.ciphertext_hex,
        nonce_hex: blob.nonce_hex,
        version: blob.version,
    }
}
