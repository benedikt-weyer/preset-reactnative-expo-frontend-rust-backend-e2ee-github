use sea_orm::entity::prelude::DateTimeWithTimeZone;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use crate::{
    domains::auth::{entity, kek_metadata_entity},
    error::{AppError, AppResult},
};

pub async fn find_user_by_email<C>(db: &C, email: &str) -> AppResult<Option<entity::Model>>
where
    C: ConnectionTrait,
{
    entity::Entity::find()
        .filter(entity::Column::Email.eq(email))
        .one(db)
        .await
        .map_err(|_| AppError::internal("failed to query the database"))
}

pub async fn insert_user<C>(
    db: &C,
    email: String,
    auth_key_hash: String,
    auth_salt: String,
    created_at: DateTimeWithTimeZone,
) -> AppResult<entity::Model>
where
    C: ConnectionTrait,
{
    entity::ActiveModel {
        id: Set(Uuid::new_v4()),
        email: Set(email),
        auth_key_hash: Set(auth_key_hash),
        auth_salt: Set(Some(auth_salt)),
        created_at: Set(created_at),
    }
    .insert(db)
    .await
    .map_err(|_| AppError::internal("failed to create the account"))
}

pub async fn insert_kek_metadata<C>(
    db: &C,
    user_id: Uuid,
    kek_epoch_version: i32,
    created_at: DateTimeWithTimeZone,
) -> AppResult<kek_metadata_entity::Model>
where
    C: ConnectionTrait,
{
    kek_metadata_entity::ActiveModel {
        kek_id: Set(Uuid::new_v4()),
        user_id: Set(user_id),
        kek_epoch_version: Set(kek_epoch_version),
        created_at: Set(created_at),
    }
    .insert(db)
    .await
    .map_err(|_| AppError::internal("failed to create the kek metadata"))
}

pub async fn list_kek_metadata_for_user<C>(
    db: &C,
    user_id: Uuid,
) -> AppResult<Vec<kek_metadata_entity::Model>>
where
    C: ConnectionTrait,
{
    kek_metadata_entity::Entity::find()
        .filter(kek_metadata_entity::Column::UserId.eq(user_id))
        .order_by_desc(kek_metadata_entity::Column::KekEpochVersion)
        .all(db)
        .await
        .map_err(|_| AppError::internal("failed to query the kek metadata"))
}
