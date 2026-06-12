use sea_orm::entity::prelude::DateTimeWithTimeZone;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait, QueryFilter,
    QueryOrder, Set,
};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    domains::notes::{dek_entity, entity},
    error::{AppError, AppResult},
};

pub struct KekUsageSummary {
    pub total_deks: u64,
    pub total_latest_kek_deks: u64,
}

pub struct EncryptedBlob {
    pub algorithm: String,
    pub ciphertext_hex: String,
    pub nonce_hex: String,
    pub version: i32,
}

pub struct WrappedDek {
    pub algorithm: String,
    pub kek_id: String,
    pub nonce_hex: String,
    pub version: i32,
    pub wrapped_dek_hex: String,
}

pub struct StoredNote {
    pub dek: dek_entity::Model,
    pub note: entity::Model,
}

pub struct NewNote {
    pub encrypted_dek: WrappedDek,
    pub encrypted_payload: EncryptedBlob,
    pub user_id: Uuid,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

pub struct NoteChanges {
    pub encrypted_dek: WrappedDek,
    pub encrypted_payload: EncryptedBlob,
    pub updated_at: DateTimeWithTimeZone,
}

pub async fn list_notes_for_user<C>(db: &C, user_id: Uuid) -> AppResult<Vec<StoredNote>>
where
    C: ConnectionTrait,
{
    let notes = entity::Entity::find()
        .filter(entity::Column::UserId.eq(user_id))
        .order_by_desc(entity::Column::UpdatedAt)
        .all(db)
        .await
        .map_err(|_| AppError::internal("failed to query notes"))?;

    let deks_by_resource_id =
        load_deks_for_resources(db, user_id, notes.iter().map(|note| note.id).collect()).await?;

    notes
        .into_iter()
        .map(|note| {
            let dek = deks_by_resource_id
                .get(&note.id)
                .cloned()
                .ok_or_else(|| AppError::internal("failed to query the resource dek"))?;

            Ok(StoredNote { dek, note })
        })
        .collect()
}

pub async fn find_note_by_id<C>(db: &C, user_id: Uuid, note_id: Uuid) -> AppResult<Option<StoredNote>>
where
    C: ConnectionTrait,
{
    let note = entity::Entity::find()
        .filter(entity::Column::Id.eq(note_id))
        .filter(entity::Column::UserId.eq(user_id))
        .one(db)
        .await
        .map_err(|_| AppError::internal("failed to query the note"))?;

    let Some(note) = note else {
        return Ok(None);
    };

    let dek = dek_entity::Entity::find()
        .filter(dek_entity::Column::ResourceId.eq(note_id))
        .filter(dek_entity::Column::UserId.eq(user_id))
        .one(db)
        .await
        .map_err(|_| AppError::internal("failed to query the resource dek"))?
        .ok_or_else(|| AppError::internal("failed to query the resource dek"))?;

    Ok(Some(StoredNote { dek, note }))
}

pub async fn insert_note<C>(db: &C, new_note: NewNote) -> AppResult<StoredNote>
where
    C: ConnectionTrait,
{
    let note_id = Uuid::now_v7();
    let note = entity::ActiveModel {
        id: Set(note_id),
        user_id: Set(new_note.user_id),
        algorithm: Set(new_note.encrypted_payload.algorithm),
        ciphertext_hex: Set(new_note.encrypted_payload.ciphertext_hex),
        nonce_hex: Set(new_note.encrypted_payload.nonce_hex),
        version: Set(new_note.encrypted_payload.version),
        created_at: Set(new_note.created_at),
        updated_at: Set(new_note.updated_at),
    }
    .insert(db)
    .await
    .map_err(|_| AppError::internal("failed to create the note"))?;

    let dek = dek_entity::ActiveModel {
        resource_id: Set(note_id),
        kek_id: Set(new_note.encrypted_dek.kek_id),
        user_id: Set(new_note.user_id),
        algorithm: Set(new_note.encrypted_dek.algorithm),
        wrapped_dek_hex: Set(new_note.encrypted_dek.wrapped_dek_hex),
        nonce_hex: Set(new_note.encrypted_dek.nonce_hex),
        version: Set(new_note.encrypted_dek.version),
        created_at: Set(new_note.created_at),
        updated_at: Set(new_note.updated_at),
    }
    .insert(db)
    .await
    .map_err(|_| AppError::internal("failed to create the resource dek"))?;

    Ok(StoredNote { dek, note })
}

pub async fn update_note<C>(db: &C, stored_note: StoredNote, changes: NoteChanges) -> AppResult<StoredNote>
where
    C: ConnectionTrait,
{
    let mut note_active_model: entity::ActiveModel = stored_note.note.into();
    note_active_model.algorithm = Set(changes.encrypted_payload.algorithm);
    note_active_model.ciphertext_hex = Set(changes.encrypted_payload.ciphertext_hex);
    note_active_model.nonce_hex = Set(changes.encrypted_payload.nonce_hex);
    note_active_model.version = Set(changes.encrypted_payload.version);
    note_active_model.updated_at = Set(changes.updated_at);

    let note = note_active_model
        .update(db)
        .await
        .map_err(|_| AppError::internal("failed to update the note"))?;

    let mut dek_active_model: dek_entity::ActiveModel = stored_note.dek.into();
    dek_active_model.algorithm = Set(changes.encrypted_dek.algorithm);
    dek_active_model.kek_id = Set(changes.encrypted_dek.kek_id);
    dek_active_model.wrapped_dek_hex = Set(changes.encrypted_dek.wrapped_dek_hex);
    dek_active_model.nonce_hex = Set(changes.encrypted_dek.nonce_hex);
    dek_active_model.version = Set(changes.encrypted_dek.version);
    dek_active_model.updated_at = Set(changes.updated_at);

    let dek = dek_active_model
        .update(db)
        .await
        .map_err(|_| AppError::internal("failed to update the resource dek"))?;

    Ok(StoredNote { dek, note })
}

pub async fn delete_note<C>(db: &C, stored_note: StoredNote) -> AppResult<()>
where
    C: ConnectionTrait,
{
    stored_note
        .dek
        .delete(db)
        .await
        .map_err(|_| AppError::internal("failed to delete the resource dek"))?;

    stored_note
        .note
        .delete(db)
        .await
        .map_err(|_| AppError::internal("failed to delete the note"))?;

    Ok(())
}

pub async fn summarize_kek_usage_for_user<C>(
    db: &C,
    user_id: Uuid,
    latest_kek_id: &str,
) -> AppResult<KekUsageSummary>
where
    C: ConnectionTrait,
{
    let deks = dek_entity::Entity::find()
        .filter(dek_entity::Column::UserId.eq(user_id))
        .all(db)
        .await
        .map_err(|_| AppError::internal("failed to query resource deks"))?;

    let total_deks = deks.len() as u64;
    let total_latest_kek_deks = deks
        .into_iter()
        .filter(|dek| dek.kek_id == latest_kek_id)
        .count() as u64;

    Ok(KekUsageSummary {
        total_deks,
        total_latest_kek_deks,
    })
}

async fn load_deks_for_resources<C>(
    db: &C,
    user_id: Uuid,
    resource_ids: Vec<Uuid>,
) -> AppResult<HashMap<Uuid, dek_entity::Model>>
where
    C: ConnectionTrait,
{
    if resource_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let deks = dek_entity::Entity::find()
        .filter(dek_entity::Column::UserId.eq(user_id))
        .filter(dek_entity::Column::ResourceId.is_in(resource_ids))
        .all(db)
        .await
        .map_err(|_| AppError::internal("failed to query resource deks"))?;

    Ok(deks
        .into_iter()
        .map(|dek| (dek.resource_id, dek))
        .collect())
}
