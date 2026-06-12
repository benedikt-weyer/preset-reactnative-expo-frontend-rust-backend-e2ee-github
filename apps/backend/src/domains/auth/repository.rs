use sea_orm::entity::prelude::DateTimeWithTimeZone;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use crate::{
    domains::auth::{api_user_entity, entity, kek_metadata_entity, PrincipalKind},
    error::{AppError, AppResult},
};

#[derive(Clone, Debug)]
pub struct PrincipalRecord {
    pub principal_id: Uuid,
    pub owner_user_id: Uuid,
    pub kind: PrincipalKind,
    pub email: Option<String>,
    pub username: Option<String>,
    pub auth_key_hash: String,
}

#[derive(Clone, Debug)]
pub struct LinkedPrincipalRecord {
    pub principal: PrincipalRecord,
    pub latest_kek: kek_metadata_entity::Model,
}

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

pub async fn find_user_by_id<C>(db: &C, user_id: Uuid) -> AppResult<Option<entity::Model>>
where
    C: ConnectionTrait,
{
    entity::Entity::find_by_id(user_id)
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

pub async fn update_user_auth_key_hash<C>(
    db: &C,
    user: entity::Model,
    auth_key_hash: String,
) -> AppResult<entity::Model>
where
    C: ConnectionTrait,
{
    let mut active_model: entity::ActiveModel = user.into();
    active_model.auth_key_hash = Set(auth_key_hash);

    active_model
        .update(db)
        .await
        .map_err(|_| AppError::internal("failed to update the auth key"))
}

pub async fn find_api_user_by_id<C>(db: &C, api_user_id: Uuid) -> AppResult<Option<api_user_entity::Model>>
where
    C: ConnectionTrait,
{
    api_user_entity::Entity::find_by_id(api_user_id)
        .one(db)
        .await
        .map_err(|_| AppError::internal("failed to query the api user"))
}

pub async fn find_api_user_by_username<C>(
    db: &C,
    username: &str,
) -> AppResult<Option<api_user_entity::Model>>
where
    C: ConnectionTrait,
{
    api_user_entity::Entity::find()
        .filter(api_user_entity::Column::Username.eq(username))
        .one(db)
        .await
        .map_err(|_| AppError::internal("failed to query the api user"))
}

pub async fn list_api_users_for_owner<C>(db: &C, owner_user_id: Uuid) -> AppResult<Vec<api_user_entity::Model>>
where
    C: ConnectionTrait,
{
    api_user_entity::Entity::find()
        .filter(api_user_entity::Column::UserId.eq(owner_user_id))
        .order_by_desc(api_user_entity::Column::UpdatedAt)
        .all(db)
        .await
        .map_err(|_| AppError::internal("failed to query the api users"))
}

pub async fn insert_api_user<C>(
    db: &C,
    id: Uuid,
    owner_user_id: Uuid,
    username: String,
    auth_key_hash: String,
    label_algorithm: String,
    label_ciphertext_hex: String,
    label_nonce_hex: String,
    label_version: i32,
    created_at: DateTimeWithTimeZone,
    updated_at: DateTimeWithTimeZone,
) -> AppResult<api_user_entity::Model>
where
    C: ConnectionTrait,
{
    api_user_entity::ActiveModel {
        id: Set(id),
        user_id: Set(owner_user_id),
        username: Set(username),
        auth_key_hash: Set(auth_key_hash),
        label_algorithm: Set(label_algorithm),
        label_ciphertext_hex: Set(label_ciphertext_hex),
        label_nonce_hex: Set(label_nonce_hex),
        label_version: Set(label_version),
        created_at: Set(created_at),
        updated_at: Set(updated_at),
    }
    .insert(db)
    .await
    .map_err(|_| AppError::internal("failed to create the api user"))
}

pub async fn insert_kek_metadata<C>(
    db: &C,
    user_id: Uuid,
    kek_public_key: String,
    kek_epoch_version: i32,
    created_at: DateTimeWithTimeZone,
) -> AppResult<kek_metadata_entity::Model>
where
    C: ConnectionTrait,
{
    kek_metadata_entity::ActiveModel {
        kek_public_key: Set(kek_public_key),
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

pub async fn next_kek_epoch_version_for_user<C>(db: &C, user_id: Uuid) -> AppResult<i32>
where
    C: ConnectionTrait,
{
    let latest_epoch = list_kek_metadata_for_user(db, user_id)
        .await?
        .into_iter()
        .map(|metadata| metadata.kek_epoch_version)
        .max()
        .unwrap_or(0);

    Ok(latest_epoch + 1)
}

pub async fn find_principal_by_id_and_kind<C>(
    db: &C,
    principal_id: Uuid,
    principal_kind: PrincipalKind,
) -> AppResult<Option<PrincipalRecord>>
where
    C: ConnectionTrait,
{
    match principal_kind {
        PrincipalKind::User => Ok(find_user_by_id(db, principal_id).await?.map(|user| PrincipalRecord {
            principal_id: user.id,
            owner_user_id: user.id,
            kind: PrincipalKind::User,
            email: Some(user.email),
            username: None,
            auth_key_hash: user.auth_key_hash,
        })),
        PrincipalKind::ApiUser => Ok(find_api_user_by_id(db, principal_id).await?.map(|api_user| PrincipalRecord {
            principal_id: api_user.id,
            owner_user_id: api_user.user_id,
            kind: PrincipalKind::ApiUser,
            email: None,
            username: Some(api_user.username),
            auth_key_hash: api_user.auth_key_hash,
        })),
    }
}

pub async fn list_linked_principals_for_owner<C>(
    db: &C,
    owner_user_id: Uuid,
) -> AppResult<Vec<LinkedPrincipalRecord>>
where
    C: ConnectionTrait,
{
    let owner_user = find_user_by_id(db, owner_user_id)
        .await?
        .ok_or_else(|| AppError::internal("missing owner user for linked principal query"))?;
    let mut principals = vec![PrincipalRecord {
        principal_id: owner_user.id,
        owner_user_id: owner_user.id,
        kind: PrincipalKind::User,
        email: Some(owner_user.email),
        username: None,
        auth_key_hash: owner_user.auth_key_hash,
    }];

    for api_user in list_api_users_for_owner(db, owner_user_id).await? {
        principals.push(PrincipalRecord {
            principal_id: api_user.id,
            owner_user_id: api_user.user_id,
            kind: PrincipalKind::ApiUser,
            email: None,
            username: Some(api_user.username),
            auth_key_hash: api_user.auth_key_hash,
        });
    }

    let mut linked_principals = Vec::with_capacity(principals.len());

    for principal in principals {
        let latest_kek = list_kek_metadata_for_user(db, principal.principal_id)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| AppError::internal("missing kek metadata for linked principal"))?;

        linked_principals.push(LinkedPrincipalRecord {
            principal,
            latest_kek,
        });
    }

    Ok(linked_principals)
}
