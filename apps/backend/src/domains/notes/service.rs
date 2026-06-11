use chrono::Utc;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    domains::{auth::AuthenticatedUser, notes::{entity, repository}},
    error::{AppError, AppResult},
};

pub struct SaveNoteCommand {
    pub algorithm: String,
    pub ciphertext_hex: String,
    pub nonce_hex: String,
    pub version: i32,
}

pub async fn list_notes(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
) -> AppResult<Vec<entity::Model>> {
    repository::list_notes_for_user(&state.db, authenticated_user.user_id).await
}

pub async fn get_note(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
    note_id: Uuid,
) -> AppResult<entity::Model> {
    repository::find_note_by_id(&state.db, authenticated_user.user_id, note_id)
        .await?
        .ok_or_else(|| AppError::not_found("note not found"))
}

pub async fn create_note(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
    command: SaveNoteCommand,
) -> AppResult<entity::Model> {
    validate_payload(&command)?;

    let now = Utc::now().fixed_offset();
    repository::insert_note(
        &state.db,
        repository::NewNote {
            user_id: authenticated_user.user_id,
            algorithm: command.algorithm.trim().to_owned(),
            ciphertext_hex: command.ciphertext_hex.trim().to_owned(),
            nonce_hex: command.nonce_hex.trim().to_owned(),
            version: command.version,
            created_at: now,
            updated_at: now,
        },
    )
    .await
}

pub async fn update_note(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
    note_id: Uuid,
    command: SaveNoteCommand,
) -> AppResult<entity::Model> {
    validate_payload(&command)?;

    let existing_note = repository::find_note_by_id(&state.db, authenticated_user.user_id, note_id)
        .await?
        .ok_or_else(|| AppError::not_found("note not found"))?;

    repository::update_note(
        &state.db,
        existing_note,
        repository::NoteChanges {
            algorithm: command.algorithm.trim().to_owned(),
            ciphertext_hex: command.ciphertext_hex.trim().to_owned(),
            nonce_hex: command.nonce_hex.trim().to_owned(),
            version: command.version,
            updated_at: Utc::now().fixed_offset(),
        },
    )
    .await
}

pub async fn delete_note(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
    note_id: Uuid,
) -> AppResult<()> {
    let existing_note = repository::find_note_by_id(&state.db, authenticated_user.user_id, note_id)
        .await?
        .ok_or_else(|| AppError::not_found("note not found"))?;

    repository::delete_note(&state.db, existing_note).await
}

fn validate_payload(payload: &SaveNoteCommand) -> AppResult<()> {
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