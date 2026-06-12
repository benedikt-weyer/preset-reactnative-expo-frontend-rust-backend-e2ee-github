use chrono::Utc;
use sea_orm::TransactionTrait;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    domains::{
        auth::AuthenticatedUser,
        notes::repository,
    },
    error::{AppError, AppResult},
};

pub struct SaveNoteCommand {
    pub encrypted_dek: SaveEncryptedBlobCommand,
    pub encrypted_payload: SaveEncryptedBlobCommand,
}

pub struct SaveEncryptedBlobCommand {
    pub algorithm: String,
    pub ciphertext_hex: String,
    pub nonce_hex: String,
    pub version: i32,
}

pub struct StoredEncryptedBlob {
    pub algorithm: String,
    pub ciphertext_hex: String,
    pub nonce_hex: String,
    pub version: i32,
}

pub struct StoredNote {
    pub created_at: String,
    pub encrypted_dek: StoredEncryptedBlob,
    pub encrypted_payload: StoredEncryptedBlob,
    pub id: Uuid,
    pub updated_at: String,
}

pub async fn list_notes(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
) -> AppResult<Vec<StoredNote>> {
    Ok(repository::list_notes_for_user(&state.db, authenticated_user.user_id)
        .await?
        .into_iter()
        .map(map_stored_note)
        .collect())
}

pub async fn get_note(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
    note_id: Uuid,
) -> AppResult<StoredNote> {
    repository::find_note_by_id(&state.db, authenticated_user.user_id, note_id)
        .await?
        .ok_or_else(|| AppError::not_found("note not found"))
        .map(map_stored_note)
}

pub async fn create_note(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
    command: SaveNoteCommand,
) -> AppResult<StoredNote> {
    validate_payload(&command)?;

    let now = Utc::now().fixed_offset();
    let transaction = state
        .db
        .begin()
        .await
        .map_err(|_| AppError::internal("failed to start the note transaction"))?;
    let stored_note = repository::insert_note(
        &transaction,
        repository::NewNote {
            encrypted_dek: map_save_blob(&command.encrypted_dek),
            encrypted_payload: map_save_blob(&command.encrypted_payload),
            user_id: authenticated_user.user_id,
            created_at: now,
            updated_at: now,
        },
    )
    .await?;

    transaction
        .commit()
        .await
        .map_err(|_| AppError::internal("failed to commit the note transaction"))?;

    Ok(map_stored_note(stored_note))
}

pub async fn update_note(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
    note_id: Uuid,
    command: SaveNoteCommand,
) -> AppResult<StoredNote> {
    validate_payload(&command)?;

    let transaction = state
        .db
        .begin()
        .await
        .map_err(|_| AppError::internal("failed to start the note transaction"))?;
    let existing_note = repository::find_note_by_id(&transaction, authenticated_user.user_id, note_id)
        .await?
        .ok_or_else(|| AppError::not_found("note not found"))?;

    let stored_note = repository::update_note(
        &transaction,
        existing_note,
        repository::NoteChanges {
            encrypted_dek: map_save_blob(&command.encrypted_dek),
            encrypted_payload: map_save_blob(&command.encrypted_payload),
            updated_at: Utc::now().fixed_offset(),
        },
    )
    .await?;

    transaction
        .commit()
        .await
        .map_err(|_| AppError::internal("failed to commit the note transaction"))?;

    Ok(map_stored_note(stored_note))
}

pub async fn delete_note(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
    note_id: Uuid,
) -> AppResult<()> {
    let transaction = state
        .db
        .begin()
        .await
        .map_err(|_| AppError::internal("failed to start the note transaction"))?;
    let existing_note = repository::find_note_by_id(&transaction, authenticated_user.user_id, note_id)
        .await?
        .ok_or_else(|| AppError::not_found("note not found"))?;

    repository::delete_note(&transaction, existing_note).await?;

    transaction
        .commit()
        .await
        .map_err(|_| AppError::internal("failed to commit the note transaction"))?;

    Ok(())
}

fn validate_payload(payload: &SaveNoteCommand) -> AppResult<()> {
    validate_encrypted_blob(&payload.encrypted_payload, "encryptedPayload")?;
    validate_encrypted_blob(&payload.encrypted_dek, "encryptedDek")?;

    Ok(())
}

fn validate_encrypted_blob(payload: &SaveEncryptedBlobCommand, field_name: &str) -> AppResult<()> {
    if payload.algorithm.trim() != "xsalsa20-poly1305" {
        return Err(AppError::validation(format!(
            "{field_name}.algorithm must be xsalsa20-poly1305"
        )));
    }

    if payload.version != 1 {
        return Err(AppError::validation(format!("{field_name}.version must be 1")));
    }

    normalize_hex_field(&payload.ciphertext_hex, &format!("{field_name}.ciphertextHex"))?;
    normalize_hex_field(&payload.nonce_hex, &format!("{field_name}.nonceHex"))?;

    Ok(())
}

fn map_save_blob(payload: &SaveEncryptedBlobCommand) -> repository::EncryptedBlob {
    repository::EncryptedBlob {
        algorithm: payload.algorithm.trim().to_owned(),
        ciphertext_hex: payload.ciphertext_hex.trim().to_owned(),
        nonce_hex: payload.nonce_hex.trim().to_owned(),
        version: payload.version,
    }
}

fn map_stored_note(stored_note: repository::StoredNote) -> StoredNote {
    StoredNote {
        created_at: stored_note.note.created_at.to_rfc3339(),
        encrypted_dek: StoredEncryptedBlob {
            algorithm: stored_note.dek.algorithm,
            ciphertext_hex: stored_note.dek.ciphertext_hex,
            nonce_hex: stored_note.dek.nonce_hex,
            version: stored_note.dek.version,
        },
        encrypted_payload: StoredEncryptedBlob {
            algorithm: stored_note.note.algorithm,
            ciphertext_hex: stored_note.note.ciphertext_hex,
            nonce_hex: stored_note.note.nonce_hex,
            version: stored_note.note.version,
        },
        id: stored_note.note.id,
        updated_at: stored_note.note.updated_at.to_rfc3339(),
    }
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
