use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    domains::{auth::AuthenticatedUser, notes::{entity, service}},
    error::AppResult,
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
    let note = service::update_note(&state, &authenticated_user, note_id, map_save_command(payload)).await?;
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
        algorithm: payload.algorithm,
        ciphertext_hex: payload.ciphertext_hex,
        nonce_hex: payload.nonce_hex,
        version: payload.version,
    }
}

fn map_note_response(note: entity::Model) -> NoteResponse {
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