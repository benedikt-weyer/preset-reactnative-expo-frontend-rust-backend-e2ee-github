use sea_orm::entity::prelude::DateTimeWithTimeZone;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::{
    domains::auth::entity,
    error::{AppError, AppResult},
};

pub async fn find_user_by_email(
    db: &DatabaseConnection,
    email: &str,
) -> AppResult<Option<entity::Model>> {
    entity::Entity::find()
        .filter(entity::Column::Email.eq(email))
        .one(db)
        .await
        .map_err(|_| AppError::internal("failed to query the database"))
}

pub async fn insert_user(
    db: &DatabaseConnection,
    email: String,
    auth_key_hash: String,
    auth_salt: String,
    created_at: DateTimeWithTimeZone,
) -> AppResult<entity::Model> {
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
