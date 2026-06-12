use sea_orm::entity::prelude::DateTimeWithTimeZone;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait, QueryFilter,
    QueryOrder, Set,
};
use std::collections::{HashMap, HashSet};
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
    pub kek_public_key: String,
    pub kem_ciphertext_hex: String,
    pub nonce_hex: String,
    pub user_id: Uuid,
    pub version: i32,
    pub wrapped_dek_hex: String,
}

pub struct ResourceWrappedDek {
    pub resource_id: Uuid,
    pub wrapped_dek: WrappedDek,
}

pub struct StoredNote {
    pub dek: dek_entity::Model,
    pub note: entity::Model,
}

pub struct NewNote {
    pub encrypted_deks: Vec<WrappedDek>,
    pub encrypted_payload: EncryptedBlob,
    pub owner_user_id: Uuid,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

pub struct NoteChanges {
    pub encrypted_deks: Vec<WrappedDek>,
    pub encrypted_payload: EncryptedBlob,
    pub updated_at: DateTimeWithTimeZone,
}

pub async fn list_notes_for_principal<C>(
    db: &C,
    owner_user_id: Uuid,
    principal_id: Uuid,
) -> AppResult<Vec<StoredNote>>
where
    C: ConnectionTrait,
{
    let notes = entity::Entity::find()
        .filter(entity::Column::UserId.eq(owner_user_id))
        .order_by_desc(entity::Column::UpdatedAt)
        .all(db)
        .await
        .map_err(|_| AppError::internal("failed to query notes"))?;

    let deks_by_resource_id = load_deks_for_resources(
        db,
        principal_id,
        notes.iter().map(|note| note.id).collect(),
    )
    .await?;

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

pub async fn find_note_by_id<C>(
    db: &C,
    owner_user_id: Uuid,
    principal_id: Uuid,
    note_id: Uuid,
) -> AppResult<Option<StoredNote>>
where
    C: ConnectionTrait,
{
    let note = entity::Entity::find()
        .filter(entity::Column::Id.eq(note_id))
        .filter(entity::Column::UserId.eq(owner_user_id))
        .one(db)
        .await
        .map_err(|_| AppError::internal("failed to query the note"))?;

    let Some(note) = note else {
        return Ok(None);
    };

    let dek = dek_entity::Entity::find()
        .filter(dek_entity::Column::ResourceId.eq(note_id))
        .filter(dek_entity::Column::UserId.eq(principal_id))
        .one(db)
        .await
        .map_err(|_| AppError::internal("failed to query the resource dek"))?
        .ok_or_else(|| AppError::internal("failed to query the resource dek"))?;

    Ok(Some(StoredNote { dek, note }))
}

pub async fn insert_note<C>(
    db: &C,
    current_principal_id: Uuid,
    new_note: NewNote,
) -> AppResult<StoredNote>
where
    C: ConnectionTrait,
{
    let note_id = Uuid::now_v7();
    let note = entity::ActiveModel {
        id: Set(note_id),
        user_id: Set(new_note.owner_user_id),
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

    for encrypted_dek in new_note.encrypted_deks {
        insert_wrapped_dek(
            db,
            note_id,
            encrypted_dek,
            new_note.created_at,
            new_note.updated_at,
        )
        .await?;
    }

    let dek = find_wrapped_dek(db, note_id, current_principal_id)
        .await?
        .ok_or_else(|| AppError::internal("failed to query the resource dek"))?;

    Ok(StoredNote { dek, note })
}

pub async fn update_note<C>(
    db: &C,
    current_principal_id: Uuid,
    stored_note: StoredNote,
    changes: NoteChanges,
) -> AppResult<StoredNote>
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

    delete_wrapped_deks_for_resource(db, note.id).await?;

    for encrypted_dek in changes.encrypted_deks {
        insert_wrapped_dek(
            db,
            note.id,
            encrypted_dek,
            note.created_at,
            changes.updated_at,
        )
        .await?;
    }

    let dek = find_wrapped_dek(db, note.id, current_principal_id)
        .await?
        .ok_or_else(|| AppError::internal("failed to query the resource dek"))?;

    Ok(StoredNote { dek, note })
}

pub async fn delete_note<C>(db: &C, stored_note: StoredNote) -> AppResult<()>
where
    C: ConnectionTrait,
{
    delete_wrapped_deks_for_resource(db, stored_note.note.id).await?;

    stored_note
        .note
        .delete(db)
        .await
        .map_err(|_| AppError::internal("failed to delete the note"))?;

    Ok(())
}

pub async fn summarize_kek_usage_for_principal<C>(
    db: &C,
    principal_id: Uuid,
    latest_kek_public_key: &str,
) -> AppResult<KekUsageSummary>
where
    C: ConnectionTrait,
{
    let deks = dek_entity::Entity::find()
        .filter(dek_entity::Column::UserId.eq(principal_id))
        .all(db)
        .await
        .map_err(|_| AppError::internal("failed to query resource deks"))?;

    let total_deks = deks.len() as u64;
    let total_latest_kek_deks = deks
        .into_iter()
        .filter(|dek| dek.kek_public_key == latest_kek_public_key)
        .count() as u64;

    Ok(KekUsageSummary {
        total_deks,
        total_latest_kek_deks,
    })
}

async fn load_deks_for_resources<C>(
    db: &C,
    principal_id: Uuid,
    resource_ids: Vec<Uuid>,
) -> AppResult<HashMap<Uuid, dek_entity::Model>>
where
    C: ConnectionTrait,
{
    if resource_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let deks = dek_entity::Entity::find()
        .filter(dek_entity::Column::UserId.eq(principal_id))
        .filter(dek_entity::Column::ResourceId.is_in(resource_ids))
        .all(db)
        .await
        .map_err(|_| AppError::internal("failed to query resource deks"))?;

    Ok(deks
        .into_iter()
        .map(|dek| (dek.resource_id, dek))
        .collect())
}

pub async fn list_note_ids_for_owner<C>(db: &C, owner_user_id: Uuid) -> AppResult<Vec<Uuid>>
where
    C: ConnectionTrait,
{
    entity::Entity::find()
        .filter(entity::Column::UserId.eq(owner_user_id))
        .all(db)
        .await
        .map_err(|_| AppError::internal("failed to query note ids"))
        .map(|notes| notes.into_iter().map(|note| note.id).collect())
}

pub async fn list_missing_note_ids_for_principal<C>(
    db: &C,
    owner_user_id: Uuid,
    principal_id: Uuid,
) -> AppResult<Vec<Uuid>>
where
    C: ConnectionTrait,
{
    let note_ids = list_note_ids_for_owner(db, owner_user_id).await?;

    if note_ids.is_empty() {
        return Ok(Vec::new());
    }

    let wrapped_resource_ids = dek_entity::Entity::find()
        .filter(dek_entity::Column::UserId.eq(principal_id))
        .filter(dek_entity::Column::ResourceId.is_in(note_ids.clone()))
        .all(db)
        .await
        .map_err(|_| AppError::internal("failed to query resource deks"))?
        .into_iter()
        .map(|dek| dek.resource_id)
        .collect::<HashSet<_>>();

    Ok(note_ids
        .into_iter()
        .filter(|note_id| !wrapped_resource_ids.contains(note_id))
        .collect())
}

pub async fn upsert_wrapped_deks<C>(
    db: &C,
    wrapped_deks: Vec<ResourceWrappedDek>,
    created_at: DateTimeWithTimeZone,
    updated_at: DateTimeWithTimeZone,
) -> AppResult<()>
where
    C: ConnectionTrait,
{
    for wrapped_dek in wrapped_deks {
        save_wrapped_dek(
            db,
            wrapped_dek.resource_id,
            wrapped_dek.wrapped_dek,
            created_at,
            updated_at,
        )
        .await?;
    }

    Ok(())
}

pub async fn find_wrapped_dek<C>(
    db: &C,
    resource_id: Uuid,
    principal_id: Uuid,
) -> AppResult<Option<dek_entity::Model>>
where
    C: ConnectionTrait,
{
    dek_entity::Entity::find_by_id((resource_id, principal_id))
        .one(db)
        .await
        .map_err(|_| AppError::internal("failed to query the resource dek"))
}

async fn insert_wrapped_dek<C>(
    db: &C,
    resource_id: Uuid,
    wrapped_dek: WrappedDek,
    created_at: DateTimeWithTimeZone,
    updated_at: DateTimeWithTimeZone,
) -> AppResult<dek_entity::Model>
where
    C: ConnectionTrait,
{
    dek_entity::ActiveModel {
        resource_id: Set(resource_id),
        user_id: Set(wrapped_dek.user_id),
        kek_public_key: Set(wrapped_dek.kek_public_key),
        algorithm: Set(wrapped_dek.algorithm),
        kem_ciphertext_hex: Set(wrapped_dek.kem_ciphertext_hex),
        wrapped_dek_hex: Set(wrapped_dek.wrapped_dek_hex),
        nonce_hex: Set(wrapped_dek.nonce_hex),
        version: Set(wrapped_dek.version),
        created_at: Set(created_at),
        updated_at: Set(updated_at),
    }
    .insert(db)
    .await
    .map_err(|_| AppError::internal("failed to create the resource dek"))
}

async fn save_wrapped_dek<C>(
    db: &C,
    resource_id: Uuid,
    wrapped_dek: WrappedDek,
    created_at: DateTimeWithTimeZone,
    updated_at: DateTimeWithTimeZone,
) -> AppResult<dek_entity::Model>
where
    C: ConnectionTrait,
{
    let Some(existing_dek) = find_wrapped_dek(db, resource_id, wrapped_dek.user_id).await? else {
        return insert_wrapped_dek(db, resource_id, wrapped_dek, created_at, updated_at).await;
    };

    let mut active_model: dek_entity::ActiveModel = existing_dek.into();
    active_model.kek_public_key = Set(wrapped_dek.kek_public_key);
    active_model.algorithm = Set(wrapped_dek.algorithm);
    active_model.kem_ciphertext_hex = Set(wrapped_dek.kem_ciphertext_hex);
    active_model.wrapped_dek_hex = Set(wrapped_dek.wrapped_dek_hex);
    active_model.nonce_hex = Set(wrapped_dek.nonce_hex);
    active_model.version = Set(wrapped_dek.version);
    active_model.updated_at = Set(updated_at);

    active_model
        .update(db)
        .await
        .map_err(|_| AppError::internal("failed to update the resource dek"))
}

async fn delete_wrapped_deks_for_resource<C>(db: &C, resource_id: Uuid) -> AppResult<()>
where
    C: ConnectionTrait,
{
    let deks = dek_entity::Entity::find()
        .filter(dek_entity::Column::ResourceId.eq(resource_id))
        .all(db)
        .await
        .map_err(|_| AppError::internal("failed to query resource deks"))?;

    for dek in deks {
        dek.delete(db)
            .await
            .map_err(|_| AppError::internal("failed to delete the resource dek"))?;
    }

    Ok(())
}
