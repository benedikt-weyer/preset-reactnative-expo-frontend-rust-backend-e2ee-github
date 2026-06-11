use sea_orm::entity::prelude::DateTimeWithTimeZone;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter,
    QueryOrder, Set,
};
use uuid::Uuid;

use crate::{
    domains::notes::entity,
    error::{AppError, AppResult},
};

pub struct NewNote {
    pub user_id: Uuid,
    pub algorithm: String,
    pub ciphertext_hex: String,
    pub nonce_hex: String,
    pub version: i32,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

pub struct NoteChanges {
    pub algorithm: String,
    pub ciphertext_hex: String,
    pub nonce_hex: String,
    pub version: i32,
    pub updated_at: DateTimeWithTimeZone,
}

pub async fn list_notes_for_user(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> AppResult<Vec<entity::Model>> {
    entity::Entity::find()
        .filter(entity::Column::UserId.eq(user_id))
        .order_by_desc(entity::Column::UpdatedAt)
        .all(db)
        .await
        .map_err(|_| AppError::internal("failed to query notes"))
}

pub async fn find_note_by_id(
    db: &DatabaseConnection,
    user_id: Uuid,
    note_id: Uuid,
) -> AppResult<Option<entity::Model>> {
    entity::Entity::find()
        .filter(entity::Column::Id.eq(note_id))
        .filter(entity::Column::UserId.eq(user_id))
        .one(db)
        .await
        .map_err(|_| AppError::internal("failed to query the note"))
}

pub async fn insert_note(db: &DatabaseConnection, new_note: NewNote) -> AppResult<entity::Model> {
    entity::ActiveModel {
        id: Set(Uuid::now_v7()),
        user_id: Set(new_note.user_id),
        algorithm: Set(new_note.algorithm),
        ciphertext_hex: Set(new_note.ciphertext_hex),
        nonce_hex: Set(new_note.nonce_hex),
        version: Set(new_note.version),
        created_at: Set(new_note.created_at),
        updated_at: Set(new_note.updated_at),
    }
    .insert(db)
    .await
    .map_err(|_| AppError::internal("failed to create the note"))
}

pub async fn update_note(
    db: &DatabaseConnection,
    note: entity::Model,
    changes: NoteChanges,
) -> AppResult<entity::Model> {
    let mut active_model: entity::ActiveModel = note.into();
    active_model.algorithm = Set(changes.algorithm);
    active_model.ciphertext_hex = Set(changes.ciphertext_hex);
    active_model.nonce_hex = Set(changes.nonce_hex);
    active_model.version = Set(changes.version);
    active_model.updated_at = Set(changes.updated_at);

    active_model
        .update(db)
        .await
        .map_err(|_| AppError::internal("failed to update the note"))
}

pub async fn delete_note(db: &DatabaseConnection, note: entity::Model) -> AppResult<()> {
    note.delete(db)
        .await
        .map_err(|_| AppError::internal("failed to delete the note"))?;

    Ok(())
}
