use chrono::Utc;
use sea_orm::TransactionTrait;
use serde::Serialize;
use std::collections::HashSet;
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
    pub encrypted_deks: Vec<SaveWrappedDekCommand>,
    pub encrypted_payload: SaveEncryptedBlobCommand,
}

pub struct SaveEncryptedBlobCommand {
    pub algorithm: String,
    pub ciphertext_hex: String,
    pub nonce_hex: String,
    pub version: i32,
}

pub struct SaveWrappedDekCommand {
    pub algorithm: String,
    pub kem_ciphertext_hex: String,
    pub kek_public_key: String,
    pub nonce_hex: String,
    pub user_id: Uuid,
    pub version: i32,
    pub wrapped_dek_hex: String,
}

pub struct StoredEncryptedBlob {
    pub algorithm: String,
    pub ciphertext_hex: String,
    pub nonce_hex: String,
    pub version: i32,
}

pub struct StoredWrappedDek {
    pub algorithm: String,
    pub kem_ciphertext_hex: String,
    pub kek_public_key: String,
    pub nonce_hex: String,
    pub user_id: Uuid,
    pub version: i32,
    pub wrapped_dek_hex: String,
}

pub struct StoredNote {
    pub created_at: String,
    pub encrypted_dek: StoredWrappedDek,
    pub encrypted_payload: StoredEncryptedBlob,
    pub id: Uuid,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoteChangeEvent {
    pub audience_principal_ids: Vec<Uuid>,
    pub kind: NoteChangeKind,
    pub note_id: Uuid,
    pub occurred_at: String,
    pub owner_user_id: Uuid,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteChangeKind {
    Created,
    Deleted,
    Updated,
}

pub async fn list_notes(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
) -> AppResult<Vec<StoredNote>> {
    Ok(repository::list_notes_for_principal(
        &state.db,
        authenticated_user.owner_user_id,
        authenticated_user.principal_id,
    )
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
    repository::find_note_by_id(
        &state.db,
        authenticated_user.owner_user_id,
        authenticated_user.principal_id,
        note_id,
    )
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
    let event_recipient_ids = collect_recipient_ids(&command.encrypted_deks, authenticated_user.owner_user_id);
    let transaction = state
        .db
        .begin()
        .await
        .map_err(|_| AppError::internal("failed to start the note transaction"))?;
    let encrypted_deks = map_wrapped_deks(&command.encrypted_deks)?;
    let stored_note = repository::insert_note(
        &transaction,
        authenticated_user.principal_id,
        repository::NewNote {
            encrypted_deks,
            encrypted_payload: map_save_blob(&command.encrypted_payload),
            owner_user_id: authenticated_user.owner_user_id,
            created_at: now,
            updated_at: now,
        },
    )
    .await?;

    transaction
        .commit()
        .await
        .map_err(|_| AppError::internal("failed to commit the note transaction"))?;

    broadcast_note_change(
        state,
        NoteChangeEvent {
            audience_principal_ids: event_recipient_ids,
            kind: NoteChangeKind::Created,
            note_id: stored_note.note.id,
            occurred_at: now.to_rfc3339(),
            owner_user_id: authenticated_user.owner_user_id,
        },
    );

    Ok(map_stored_note(stored_note))
}

pub async fn update_note(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
    note_id: Uuid,
    command: SaveNoteCommand,
) -> AppResult<StoredNote> {
    validate_payload(&command)?;

    let next_recipient_ids = collect_recipient_ids(&command.encrypted_deks, authenticated_user.owner_user_id);
    let transaction = state
        .db
        .begin()
        .await
        .map_err(|_| AppError::internal("failed to start the note transaction"))?;
    let existing_note = repository::find_note_by_id(
        &transaction,
        authenticated_user.owner_user_id,
        authenticated_user.principal_id,
        note_id,
    )
        .await?
        .ok_or_else(|| AppError::not_found("note not found"))?;
    let previous_recipient_ids = repository::list_note_recipient_ids(&transaction, note_id).await?;
    let updated_at = Utc::now().fixed_offset();

    let stored_note = repository::update_note(
        &transaction,
        authenticated_user.principal_id,
        existing_note,
        repository::NoteChanges {
            encrypted_deks: map_wrapped_deks(&command.encrypted_deks)?,
            encrypted_payload: map_save_blob(&command.encrypted_payload),
            updated_at,
        },
    )
    .await?;

    transaction
        .commit()
        .await
        .map_err(|_| AppError::internal("failed to commit the note transaction"))?;

    broadcast_note_change(
        state,
        NoteChangeEvent {
            audience_principal_ids: merge_recipient_ids(
                previous_recipient_ids,
                next_recipient_ids,
                authenticated_user.owner_user_id,
            ),
            kind: NoteChangeKind::Updated,
            note_id: stored_note.note.id,
            occurred_at: updated_at.to_rfc3339(),
            owner_user_id: authenticated_user.owner_user_id,
        },
    );

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
    let existing_note = repository::find_note_by_id(
        &transaction,
        authenticated_user.owner_user_id,
        authenticated_user.principal_id,
        note_id,
    )
        .await?
        .ok_or_else(|| AppError::not_found("note not found"))?;
    let recipient_ids = repository::list_note_recipient_ids(&transaction, note_id).await?;
    let occurred_at = Utc::now().fixed_offset().to_rfc3339();

    repository::delete_note(&transaction, existing_note).await?;

    transaction
        .commit()
        .await
        .map_err(|_| AppError::internal("failed to commit the note transaction"))?;

    broadcast_note_change(
        state,
        NoteChangeEvent {
            audience_principal_ids: merge_recipient_ids(
                recipient_ids,
                Vec::new(),
                authenticated_user.owner_user_id,
            ),
            kind: NoteChangeKind::Deleted,
            note_id,
            occurred_at,
            owner_user_id: authenticated_user.owner_user_id,
        },
    );

    Ok(())
}

fn broadcast_note_change(state: &AppState, event: NoteChangeEvent) {
    let _ = state.note_events.send(event);
}

fn collect_recipient_ids(
    encrypted_deks: &[SaveWrappedDekCommand],
    owner_user_id: Uuid,
) -> Vec<Uuid> {
    merge_recipient_ids(
        encrypted_deks.iter().map(|encrypted_dek| encrypted_dek.user_id).collect(),
        Vec::new(),
        owner_user_id,
    )
}

fn merge_recipient_ids(
    previous_recipient_ids: Vec<Uuid>,
    next_recipient_ids: Vec<Uuid>,
    owner_user_id: Uuid,
) -> Vec<Uuid> {
    let mut recipient_ids = HashSet::new();

    recipient_ids.insert(owner_user_id);
    recipient_ids.extend(previous_recipient_ids);
    recipient_ids.extend(next_recipient_ids);

    let mut recipient_ids = recipient_ids.into_iter().collect::<Vec<_>>();
    recipient_ids.sort_unstable();
    recipient_ids
}

fn validate_payload(payload: &SaveNoteCommand) -> AppResult<()> {
    validate_encrypted_blob(&payload.encrypted_payload, "encryptedPayload")?;

    if payload.encrypted_deks.is_empty() {
        return Err(AppError::validation("encryptedDeks must contain at least one wrapped dek"));
    }

    for encrypted_dek in &payload.encrypted_deks {
        validate_wrapped_dek(encrypted_dek)?;
    }

    Ok(())
}

fn validate_wrapped_dek(payload: &SaveWrappedDekCommand) -> AppResult<()> {
    if payload.algorithm.trim() != "ml-kem-768-encapsulated+xsalsa20-poly1305" {
        return Err(AppError::validation(
            "encryptedDeks.algorithm must be ml-kem-768-encapsulated+xsalsa20-poly1305",
        ));
    }

    if payload.version != 3 {
        return Err(AppError::validation("encryptedDeks.version must be 3"));
    }

    normalize_kek_public_key_field(&payload.kek_public_key, "encryptedDeks.kekId")?;
    normalize_hex_field(&payload.wrapped_dek_hex, "encryptedDeks.wrappedDekHex")?;
    normalize_hex_field(&payload.nonce_hex, "encryptedDeks.nonceHex")?;
    normalize_exact_hex_field(
        &payload.kem_ciphertext_hex,
        "encryptedDeks.kemCiphertextHex",
        1088,
    )?;

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

fn map_wrapped_deks(payloads: &[SaveWrappedDekCommand]) -> AppResult<Vec<repository::WrappedDek>> {
    payloads.iter().map(map_wrapped_dek).collect()
}

fn map_wrapped_dek(payload: &SaveWrappedDekCommand) -> AppResult<repository::WrappedDek> {
    Ok(repository::WrappedDek {
        algorithm: payload.algorithm.trim().to_owned(),
        kem_ciphertext_hex: payload.kem_ciphertext_hex.trim().to_ascii_lowercase(),
        kek_public_key: normalize_kek_public_key_field(&payload.kek_public_key, "encryptedDeks.kekId")?,
        nonce_hex: payload.nonce_hex.trim().to_owned(),
        user_id: payload.user_id,
        version: payload.version,
        wrapped_dek_hex: payload.wrapped_dek_hex.trim().to_owned(),
    })
}

fn map_stored_note(stored_note: repository::StoredNote) -> StoredNote {
    StoredNote {
        created_at: stored_note.note.created_at.to_rfc3339(),
        encrypted_dek: StoredWrappedDek {
            algorithm: stored_note.dek.algorithm,
            kem_ciphertext_hex: stored_note.dek.kem_ciphertext_hex,
            kek_public_key: stored_note.dek.kek_public_key,
            nonce_hex: stored_note.dek.nonce_hex,
            user_id: stored_note.dek.user_id,
            version: stored_note.dek.version,
            wrapped_dek_hex: stored_note.dek.wrapped_dek_hex,
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

fn normalize_exact_hex_field(value: &str, field_name: &str, expected_bytes: usize) -> AppResult<()> {
    let normalized = value.trim().to_ascii_lowercase();

    if normalized.is_empty() {
        return Err(AppError::validation(format!("{field_name} is required")));
    }

    let decoded = hex::decode(&normalized)
        .map_err(|_| AppError::validation(format!("{field_name} must be valid hex")))?;

    if decoded.len() != expected_bytes {
        return Err(AppError::validation(format!(
            "{field_name} must contain exactly {expected_bytes} bytes"
        )));
    }

    Ok(())
}

fn normalize_kek_public_key_field(value: &str, field_name: &str) -> AppResult<String> {
    const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1184;

    normalize_exact_hex_field(value, field_name, ML_KEM_768_PUBLIC_KEY_BYTES)?;
    Ok(value.trim().to_ascii_lowercase())
}
