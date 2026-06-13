use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use sea_orm::{ConnectionTrait, TransactionTrait};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::future::ready;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    domains::{
        auth::{api_user_entity, entity, kek_metadata_entity, repository, PrincipalKind},
        notes,
    },
    error::{AppError, AppResult},
};

pub struct RegisterCommand {
    pub email: String,
    pub auth_key: String,
    pub kek_public_key: String,
    pub salt_hex: String,
}

pub struct LoginCommand {
    pub email: String,
    pub auth_key: String,
}

pub struct ApiUserLoginCommand {
    pub username: String,
    pub auth_key: String,
}

pub struct RotatePasswordCommand {
    pub kek_public_key: String,
    pub new_auth_key: String,
}

pub struct CreateApiUserCommand {
    pub api_user_id: Uuid,
    pub auth_key: String,
    pub encrypted_label: notes::service::SaveEncryptedBlobCommand,
    pub encrypted_label_deks: Vec<notes::service::SaveWrappedDekCommand>,
    pub kek_public_key: String,
}

pub struct ProvisionApiUserDekCommand {
    pub resource_id: Uuid,
    pub wrapped_dek: notes::service::SaveWrappedDekCommand,
}

pub struct AuthSession {
    pub current_principal: PrincipalSummary,
    pub kek_metadatas: Vec<KekMetadata>,
    pub linked_principals: Vec<LinkedPrincipal>,
    pub token: String,
    pub refresh_token: String,
    pub user_id: Uuid,
    pub email: String,
}

pub struct SaltMaterial {
    pub kek_metadatas: Vec<KekMetadata>,
    pub salt_hex: String,
}

pub struct KekMigrationStatus {
    pub all_deks_use_latest_kek: bool,
    pub latest_kek_dek_count: u64,
    pub latest_kek_epoch_version: i32,
    pub latest_kek_public_key: String,
    pub pending_dek_count: u64,
    pub total_dek_count: u64,
}

#[derive(Clone, Debug)]
pub struct KekMetadata {
    pub kek_epoch_version: i32,
    pub kek_public_key: String,
}

#[derive(Clone, Debug)]
pub struct PrincipalSummary {
    pub id: Uuid,
    pub kind: PrincipalKind,
    pub email: Option<String>,
    pub username: Option<String>,
}

#[derive(Clone, Debug)]
pub struct LinkedPrincipal {
    pub id: Uuid,
    pub kind: PrincipalKind,
    pub email: Option<String>,
    pub username: Option<String>,
    pub latest_kek_epoch_version: i32,
    pub latest_kek_public_key: String,
}

pub struct ApiUserProvisioningStatus {
    pub completed_resource_count: u64,
    pub pending_note_ids: Vec<Uuid>,
    pub pending_resource_count: u64,
    pub total_resource_count: u64,
}

pub struct ApiUserRecord {
    pub created_at: String,
    pub encrypted_label: notes::service::StoredEncryptedBlob,
    pub encrypted_label_dek: notes::service::StoredWrappedDek,
    pub id: Uuid,
    pub latest_kek_epoch_version: i32,
    pub latest_kek_public_key: String,
    pub provisioning: ApiUserProvisioningStatus,
    pub updated_at: String,
    pub username: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Claims {
    sub: String,
    owner_user_id: String,
    email: String,
    principal_kind: PrincipalKind,
    token_type: TokenType,
    exp: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TokenType {
    Access,
    Refresh,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub principal_id: Uuid,
    pub owner_user_id: Uuid,
    pub principal_kind: PrincipalKind,
}

pub fn authenticate_access_token(state: &AppState, token: &str) -> AppResult<AuthenticatedUser> {
    authenticate_token(state, token, TokenType::Access)
}

fn authenticate_refresh_token(state: &AppState, token: &str) -> AppResult<AuthenticatedUser> {
    authenticate_token(state, token, TokenType::Refresh)
}

fn authenticate_token(
    state: &AppState,
    token: &str,
    required_token_type: TokenType,
) -> AppResult<AuthenticatedUser> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| AppError::unauthorized("invalid bearer token"))?;

    if token_data.claims.token_type != required_token_type {
        let message = match required_token_type {
            TokenType::Access => "an access token is required",
            TokenType::Refresh => "a refresh token is required",
        };

        return Err(AppError::unauthorized(message));
    }

    Ok(AuthenticatedUser {
        principal_id: Uuid::parse_str(&token_data.claims.sub)
            .map_err(|_| AppError::unauthorized("invalid bearer token"))?,
        owner_user_id: Uuid::parse_str(&token_data.claims.owner_user_id)
            .map_err(|_| AppError::unauthorized("invalid bearer token"))?,
        principal_kind: token_data.claims.principal_kind,
    })
}

pub async fn refresh_session(state: &AppState, refresh_token: &str) -> AppResult<AuthSession> {
    let authenticated_user = authenticate_refresh_token(state, refresh_token)?;

    match authenticated_user.principal_kind {
        PrincipalKind::User => {
            let user = repository::find_user_by_id(&state.db, authenticated_user.owner_user_id)
                .await?
                .ok_or_else(|| AppError::unauthorized("invalid bearer token"))?;
            let kek_metadatas = repository::list_kek_metadata_for_user(
                &state.db,
                authenticated_user.principal_id,
            )
            .await?;

            build_auth_session(
                state,
                &user,
                repository::PrincipalRecord {
                    principal_id: user.id,
                    owner_user_id: user.id,
                    kind: PrincipalKind::User,
                    email: Some(user.email.clone()),
                    username: None,
                },
                kek_metadatas,
            )
            .await
        }
        PrincipalKind::ApiUser => {
            let api_user = repository::find_api_user_by_id(&state.db, authenticated_user.principal_id)
                .await?
                .filter(|api_user| api_user.user_id == authenticated_user.owner_user_id)
                .ok_or_else(|| AppError::unauthorized("invalid bearer token"))?;
            let owner_user = repository::find_user_by_id(&state.db, api_user.user_id)
                .await?
                .ok_or_else(|| AppError::internal("missing owner user for refresh token"))?;
            let kek_metadatas = repository::list_kek_metadata_for_user(&state.db, api_user.id).await?;

            build_auth_session(
                state,
                &owner_user,
                repository::PrincipalRecord {
                    principal_id: api_user.id,
                    owner_user_id: api_user.user_id,
                    kind: PrincipalKind::ApiUser,
                    email: None,
                    username: Some(api_user.username.clone()),
                },
                kek_metadatas,
            )
            .await
        }
    }
}

pub async fn register(state: &AppState, command: RegisterCommand) -> AppResult<AuthSession> {
    let email = normalize_email(&command.email)?;
    validate_auth_key(&command.auth_key)?;
    let kek_public_key = normalize_kek_public_key(&command.kek_public_key)?;
    let auth_salt = normalize_auth_salt(&command.salt_hex)?;

    if repository::find_user_by_email(&state.db, &email)
        .await?
        .is_some()
    {
        return Err(AppError::conflict(
            "an account already exists for this email",
        ));
    }

    let now = Utc::now().fixed_offset();
    let transaction = state
        .db
        .begin()
        .await
        .map_err(|_| AppError::internal("failed to start the auth transaction"))?;

    let new_user = repository::insert_user(
        &transaction,
        email,
        hash_auth_key(&command.auth_key),
        auth_salt,
        now,
    )
    .await?;

    let initial_kek_metadata = repository::insert_kek_metadata(
        &transaction,
        new_user.id,
        kek_public_key,
        1,
        now,
    )
    .await?;

    transaction
        .commit()
        .await
        .map_err(|_| AppError::internal("failed to commit the auth transaction"))?;

    build_auth_session(
        state,
        &new_user,
        repository::PrincipalRecord {
            principal_id: new_user.id,
            owner_user_id: new_user.id,
            kind: PrincipalKind::User,
            email: Some(new_user.email.clone()),
            username: None,
        },
        vec![initial_kek_metadata],
    )
    .await
}

pub async fn salt(state: &AppState, email: &str) -> AppResult<SaltMaterial> {
    let email = normalize_email(email)?;

    let user = repository::find_user_by_email(&state.db, &email)
        .await?
        .ok_or_else(|| AppError::unauthorized("invalid email or password"))?;

    let auth_salt = user
        .auth_salt
        .ok_or_else(|| AppError::unauthorized("invalid email or password"))?;

    Ok(SaltMaterial {
        kek_metadatas: repository::list_kek_metadata_for_user(&state.db, user.id)
            .await?
            .into_iter()
            .map(map_kek_metadata)
            .collect(),
        salt_hex: normalize_auth_salt(&auth_salt)?,
    })
}

pub async fn login(state: &AppState, command: LoginCommand) -> AppResult<AuthSession> {
    let email = normalize_email(&command.email)?;
    validate_auth_key(&command.auth_key)?;

    let user = repository::find_user_by_email(&state.db, &email)
        .await?
        .ok_or_else(|| AppError::unauthorized("invalid email or auth key"))?;

    assert_auth_key_matches(&command.auth_key, &user.auth_key_hash)?;

    let kek_metadatas = repository::list_kek_metadata_for_user(&state.db, user.id).await?;

    build_auth_session(
        state,
        &user,
        repository::PrincipalRecord {
            principal_id: user.id,
            owner_user_id: user.id,
            kind: PrincipalKind::User,
            email: Some(user.email.clone()),
            username: None,
        },
        kek_metadatas,
    )
    .await
}

pub async fn login_api_user(
    state: &AppState,
    command: ApiUserLoginCommand,
) -> AppResult<AuthSession> {
    let username = normalize_username(&command.username)?;
    validate_auth_key(&command.auth_key)?;

    let api_user = repository::find_api_user_by_username(&state.db, &username)
        .await?
        .ok_or_else(|| AppError::unauthorized("invalid username or auth key"))?;
    assert_auth_key_matches(&command.auth_key, &api_user.auth_key_hash)?;

    let owner_user = repository::find_user_by_id(&state.db, api_user.user_id)
        .await?
        .ok_or_else(|| AppError::internal("missing owner user for api user login"))?;
    let kek_metadatas = repository::list_kek_metadata_for_user(&state.db, api_user.id).await?;

    build_auth_session(
        state,
        &owner_user,
        repository::PrincipalRecord {
            principal_id: api_user.id,
            owner_user_id: api_user.user_id,
            kind: PrincipalKind::ApiUser,
            email: None,
            username: Some(api_user.username.clone()),
        },
        kek_metadatas,
    )
    .await
}

pub async fn rotate_password(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
    command: RotatePasswordCommand,
) -> AppResult<AuthSession> {
    if authenticated_user.principal_kind != PrincipalKind::User {
        return Err(AppError::bad_request("api users cannot rotate the account password"));
    }

    validate_auth_key(&command.new_auth_key)?;
    let kek_public_key = normalize_kek_public_key(&command.kek_public_key)?;

    let transaction = state
        .db
        .begin()
        .await
        .map_err(|_| AppError::internal("failed to start the auth transaction"))?;
    let user = repository::find_user_by_id(&transaction, authenticated_user.owner_user_id)
        .await?
        .ok_or_else(|| AppError::unauthorized("invalid bearer token"))?;
    let next_epoch_version = repository::next_kek_epoch_version_for_user(
        &transaction,
        authenticated_user.principal_id,
    )
    .await?;
    let now = Utc::now().fixed_offset();

    let updated_user = repository::update_user_auth_key_hash(
        &transaction,
        user,
        hash_auth_key(&command.new_auth_key),
    )
    .await?;
    repository::insert_kek_metadata(
        &transaction,
        authenticated_user.principal_id,
        kek_public_key,
        next_epoch_version,
        now,
    )
    .await?;

    transaction
        .commit()
        .await
        .map_err(|_| AppError::internal("failed to commit the auth transaction"))?;

    let kek_metadatas = repository::list_kek_metadata_for_user(&state.db, authenticated_user.principal_id)
        .await?;

    build_auth_session(
        state,
        &updated_user,
        repository::PrincipalRecord {
            principal_id: updated_user.id,
            owner_user_id: updated_user.id,
            kind: PrincipalKind::User,
            email: Some(updated_user.email.clone()),
            username: None,
        },
        kek_metadatas,
    )
    .await
}

pub async fn get_kek_migration_status(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
) -> AppResult<KekMigrationStatus> {
    let kek_metadatas = repository::list_kek_metadata_for_user(&state.db, authenticated_user.principal_id)
        .await?;
    let latest_kek = kek_metadatas
        .iter()
        .max_by_key(|metadata| metadata.kek_epoch_version)
        .ok_or_else(|| AppError::internal("missing kek metadata for the account"))?;
    let usage_summary = notes::repository::summarize_kek_usage_for_principal(
        &state.db,
        authenticated_user.principal_id,
        &latest_kek.kek_public_key,
    )
    .await?;
    let pending_dek_count = usage_summary
        .total_deks
        .saturating_sub(usage_summary.total_latest_kek_deks);

    Ok(KekMigrationStatus {
        all_deks_use_latest_kek: pending_dek_count == 0,
        latest_kek_dek_count: usage_summary.total_latest_kek_deks,
        latest_kek_epoch_version: latest_kek.kek_epoch_version,
        latest_kek_public_key: latest_kek.kek_public_key.clone(),
        pending_dek_count,
        total_dek_count: usage_summary.total_deks,
    })
}

pub async fn list_linked_principals(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
) -> AppResult<Vec<LinkedPrincipal>> {
    repository::list_linked_principals_for_owner(&state.db, authenticated_user.owner_user_id)
        .await?
        .into_iter()
        .map(map_linked_principal)
        .collect()
}

pub async fn list_api_users(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
) -> AppResult<Vec<ApiUserRecord>> {
    require_user_principal(authenticated_user)?;

    let api_users = repository::list_api_users_for_owner(&state.db, authenticated_user.owner_user_id).await?;
    let mut output = Vec::with_capacity(api_users.len());

    for api_user in api_users {
        output.push(build_api_user_record(state, authenticated_user.principal_id, api_user).await?);
    }

    Ok(output)
}

pub async fn get_api_user(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
    api_user_id: Uuid,
) -> AppResult<ApiUserRecord> {
    require_user_principal(authenticated_user)?;

    let api_user = repository::find_api_user_by_id(&state.db, api_user_id)
        .await?
        .filter(|api_user| api_user.user_id == authenticated_user.owner_user_id)
        .ok_or_else(|| AppError::not_found("api user not found"))?;

    build_api_user_record(state, authenticated_user.principal_id, api_user).await
}

pub async fn create_api_user(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
    command: CreateApiUserCommand,
) -> AppResult<ApiUserRecord> {
    require_user_principal(authenticated_user)?;
    validate_auth_key(&command.auth_key)?;
    let kek_public_key = normalize_kek_public_key(&command.kek_public_key)?;
    validate_encrypted_blob(&command.encrypted_label, "encryptedLabel")?;
    let label_deks = map_wrapped_deks(&command.encrypted_label_deks)?;

    if repository::find_api_user_by_id(&state.db, command.api_user_id)
        .await?
        .is_some()
    {
        return Err(AppError::conflict("an api user already exists for this id"));
    }

    let linked_principals = repository::list_linked_principals_for_owner(&state.db, authenticated_user.owner_user_id).await?;
    let owner_principal = linked_principals
        .iter()
        .find(|principal| principal.principal.principal_id == authenticated_user.owner_user_id)
        .ok_or_else(|| AppError::internal("missing owner principal metadata"))?;

    validate_label_deks(
        &label_deks,
        authenticated_user.owner_user_id,
        command.api_user_id,
        &owner_principal.latest_kek.kek_public_key,
        &kek_public_key,
    )?;

    let now = Utc::now().fixed_offset();
    let transaction = state
        .db
        .begin()
        .await
        .map_err(|_| AppError::internal("failed to start the api user transaction"))?;

    let api_user = repository::insert_api_user(
        &transaction,
        repository::NewApiUserRecord {
            id: command.api_user_id,
            owner_user_id: authenticated_user.owner_user_id,
            username: generate_api_username(command.api_user_id),
            auth_key_hash: hash_auth_key(&command.auth_key),
            label_algorithm: command.encrypted_label.algorithm.trim().to_owned(),
            label_ciphertext_hex: command
                .encrypted_label
                .ciphertext_hex
                .trim()
                .to_ascii_lowercase(),
            label_nonce_hex: command.encrypted_label.nonce_hex.trim().to_ascii_lowercase(),
            label_version: command.encrypted_label.version,
            created_at: now,
            updated_at: now,
        },
    )
    .await?;

    repository::insert_kek_metadata(&transaction, api_user.id, kek_public_key.clone(), 1, now).await?;
    notes::repository::upsert_wrapped_deks(
        &transaction,
        label_deks
            .into_iter()
            .map(|wrapped_dek| notes::repository::ResourceWrappedDek {
                resource_id: api_user.id,
                wrapped_dek,
            })
            .collect(),
        now,
        now,
    )
    .await?;

    transaction
        .commit()
        .await
        .map_err(|_| AppError::internal("failed to commit the api user transaction"))?;

    build_api_user_record(state, authenticated_user.principal_id, api_user).await
}

pub async fn delete_api_user(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
    api_user_id: Uuid,
) -> AppResult<()> {
    require_user_principal(authenticated_user)?;

    let api_user = repository::find_api_user_by_id(&state.db, api_user_id)
        .await?
        .filter(|api_user| api_user.user_id == authenticated_user.owner_user_id)
        .ok_or_else(|| AppError::not_found("api user not found"))?;

    let transaction = state
        .db
        .begin()
        .await
        .map_err(|_| AppError::internal("failed to start the api user deletion transaction"))?;

    delete_api_user_records(&transaction, api_user.id).await?;

    transaction
        .commit()
        .await
        .map_err(|_| AppError::internal("failed to commit the api user deletion transaction"))?;

    Ok(())
}

pub async fn delete_account(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
) -> AppResult<()> {
    require_user_principal(authenticated_user)?;

    let transaction = state
        .db
        .begin()
        .await
        .map_err(|_| AppError::internal("failed to start the account deletion transaction"))?;

    let api_users = repository::list_api_users_for_owner(&transaction, authenticated_user.owner_user_id).await?;

    for api_user in api_users {
        delete_api_user_records(&transaction, api_user.id).await?;
    }

    notes::repository::delete_notes_for_owner(&transaction, authenticated_user.owner_user_id).await?;
    notes::repository::delete_wrapped_deks_linked_to_principal(
        &transaction,
        authenticated_user.owner_user_id,
    )
    .await?;
    repository::delete_kek_metadata_for_user(&transaction, authenticated_user.owner_user_id).await?;
    repository::delete_user(&transaction, authenticated_user.owner_user_id).await?;

    transaction
        .commit()
        .await
        .map_err(|_| AppError::internal("failed to commit the account deletion transaction"))?;

    Ok(())
}

pub async fn provision_api_user_deks(
    state: &AppState,
    authenticated_user: &AuthenticatedUser,
    api_user_id: Uuid,
    commands: Vec<ProvisionApiUserDekCommand>,
) -> AppResult<ApiUserRecord> {
    require_user_principal(authenticated_user)?;

    let api_user = repository::find_api_user_by_id(&state.db, api_user_id)
        .await?
        .filter(|api_user| api_user.user_id == authenticated_user.owner_user_id)
        .ok_or_else(|| AppError::not_found("api user not found"))?;
    let latest_kek = repository::list_kek_metadata_for_user(&state.db, api_user.id)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| AppError::internal("missing kek metadata for the api user"))?;
    let valid_note_ids = notes::repository::list_note_ids_for_owner(&state.db, authenticated_user.owner_user_id)
        .await?
        .into_iter()
        .collect::<std::collections::HashSet<_>>();

    let wrapped_deks = commands
        .into_iter()
        .map(|command| {
            if !valid_note_ids.contains(&command.resource_id) {
                return Err(AppError::validation("resourceId must reference a note owned by the account"));
            }

            let wrapped_dek = map_wrapped_dek(&command.wrapped_dek)?;

            if wrapped_dek.user_id != api_user.id {
                return Err(AppError::validation("wrappedDeks.userId must match the provisioned api user"));
            }

            if wrapped_dek.kek_public_key != latest_kek.kek_public_key {
                return Err(AppError::validation("wrappedDeks.kekId must match the api user's latest KEK id"));
            }

            Ok(notes::repository::ResourceWrappedDek {
                resource_id: command.resource_id,
                wrapped_dek,
            })
        })
        .collect::<AppResult<Vec<_>>>()?;

    let now = Utc::now().fixed_offset();
    notes::repository::upsert_wrapped_deks(&state.db, wrapped_deks, now, now).await?;

    build_api_user_record(state, authenticated_user.principal_id, api_user).await
}

async fn build_auth_session(
    state: &AppState,
    owner_user: &entity::Model,
    current_principal: repository::PrincipalRecord,
    kek_metadatas: Vec<kek_metadata_entity::Model>,
) -> AppResult<AuthSession> {
    let linked_principals = repository::list_linked_principals_for_owner(&state.db, owner_user.id)
        .await?
        .into_iter()
        .map(map_linked_principal)
        .collect::<AppResult<Vec<_>>>()?;

    Ok(AuthSession {
        current_principal: map_principal_summary(&current_principal),
        kek_metadatas: kek_metadatas.into_iter().map(map_kek_metadata).collect(),
        linked_principals,
        token: issue_token(state, &current_principal, owner_user, TokenType::Access)?,
        refresh_token: issue_token(state, &current_principal, owner_user, TokenType::Refresh)?,
        user_id: owner_user.id,
        email: owner_user.email.clone(),
    })
}

async fn delete_api_user_records<C>(db: &C, api_user_id: Uuid) -> AppResult<()>
where
    C: ConnectionTrait,
{
    notes::repository::delete_wrapped_deks_linked_to_principal(db, api_user_id).await?;
    repository::delete_kek_metadata_for_user(db, api_user_id).await?;
    repository::delete_api_user(db, api_user_id).await?;

    Ok(())
}

async fn build_api_user_record(
    state: &AppState,
    current_principal_id: Uuid,
    api_user: api_user_entity::Model,
) -> AppResult<ApiUserRecord> {
    let latest_kek = repository::list_kek_metadata_for_user(&state.db, api_user.id)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| AppError::internal("missing kek metadata for the api user"))?;
    let encrypted_label_dek = notes::repository::find_wrapped_dek(&state.db, api_user.id, current_principal_id)
        .await?
        .ok_or_else(|| AppError::internal("missing label dek for the current principal"))?;
    let label_provisioned = notes::repository::find_wrapped_dek(&state.db, api_user.id, api_user.id)
        .await?
        .is_some();
    let note_ids = notes::repository::list_note_ids_for_owner(&state.db, api_user.user_id).await?;
    let pending_note_ids = notes::repository::list_missing_note_ids_for_principal(&state.db, api_user.user_id, api_user.id)
        .await?;
    let total_resource_count = note_ids.len() as u64 + 1;
    let pending_resource_count = pending_note_ids.len() as u64 + if label_provisioned { 0 } else { 1 };
    let completed_resource_count = total_resource_count.saturating_sub(pending_resource_count);

    Ok(ApiUserRecord {
        created_at: api_user.created_at.to_rfc3339(),
        encrypted_label: notes::service::StoredEncryptedBlob {
            algorithm: api_user.label_algorithm,
            ciphertext_hex: api_user.label_ciphertext_hex,
            nonce_hex: api_user.label_nonce_hex,
            version: api_user.label_version,
        },
        encrypted_label_dek: notes::service::StoredWrappedDek {
            algorithm: encrypted_label_dek.algorithm,
            kem_ciphertext_hex: encrypted_label_dek.kem_ciphertext_hex,
            kek_public_key: encrypted_label_dek.kek_public_key,
            nonce_hex: encrypted_label_dek.nonce_hex,
            user_id: encrypted_label_dek.user_id,
            version: encrypted_label_dek.version,
            wrapped_dek_hex: encrypted_label_dek.wrapped_dek_hex,
        },
        id: api_user.id,
        latest_kek_epoch_version: latest_kek.kek_epoch_version,
        latest_kek_public_key: latest_kek.kek_public_key,
        provisioning: ApiUserProvisioningStatus {
            completed_resource_count,
            pending_note_ids,
            pending_resource_count,
            total_resource_count,
        },
        updated_at: api_user.updated_at.to_rfc3339(),
        username: api_user.username,
    })
}

fn issue_token(
    state: &AppState,
    current_principal: &repository::PrincipalRecord,
    owner_user: &entity::Model,
    token_type: TokenType,
) -> AppResult<String> {
    let ttl_minutes = match token_type {
        TokenType::Access => state.config.jwt_ttl_minutes,
        TokenType::Refresh => state.config.jwt_refresh_ttl_minutes,
    };
    let expires_at = Utc::now()
        .checked_add_signed(chrono::Duration::minutes(ttl_minutes))
        .ok_or_else(|| AppError::internal("failed to calculate the session expiry"))?;
    let claims = Claims {
        sub: current_principal.principal_id.to_string(),
        owner_user_id: current_principal.owner_user_id.to_string(),
        email: owner_user.email.clone(),
        principal_kind: current_principal.kind,
        token_type,
        exp: expires_at.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )
    .map_err(|_| AppError::internal("failed to issue the session token"))
}

fn normalize_email(email: &str) -> AppResult<String> {
    let normalized = email.trim().to_ascii_lowercase();
    if normalized.is_empty() || !normalized.contains('@') {
        return Err(AppError::bad_request("a valid email address is required"));
    }

    Ok(normalized)
}

fn normalize_username(username: &str) -> AppResult<String> {
    let normalized = username.trim().to_ascii_lowercase();

    if normalized.is_empty() {
        return Err(AppError::bad_request("a valid username is required"));
    }

    Ok(normalized)
}

fn validate_auth_key(auth_key: &str) -> AppResult<()> {
    if auth_key.trim().len() < 32 {
        return Err(AppError::bad_request(
            "authKey must be a non-empty derived key string",
        ));
    }

    Ok(())
}

fn assert_auth_key_matches(auth_key: &str, auth_key_hash: &str) -> AppResult<()> {
    let supplied_hash = hash_auth_key(auth_key);
    if supplied_hash
        .as_bytes()
        .ct_eq(auth_key_hash.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(AppError::unauthorized("invalid credentials"));
    }

    Ok(())
}

fn normalize_auth_salt(auth_salt: &str) -> AppResult<String> {
    const AUTH_SALT_BYTES: usize = 16;

    let normalized = auth_salt.trim().to_ascii_lowercase();
    let decoded = hex::decode(&normalized)
        .map_err(|_| AppError::bad_request("saltHex must be a valid hexadecimal string"))?;

    if decoded.len() != AUTH_SALT_BYTES {
        return Err(AppError::bad_request(
            "saltHex must contain a 16-byte password salt",
        ));
    }

    Ok(normalized)
}

fn normalize_kek_public_key(kek_public_key: &str) -> AppResult<String> {
    const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1184;

    let normalized = kek_public_key.trim().to_ascii_lowercase();
    let decoded = hex::decode(&normalized)
        .map_err(|_| AppError::bad_request("kekId must be a valid hexadecimal string"))?;

    if decoded.len() != ML_KEM_768_PUBLIC_KEY_BYTES {
        return Err(AppError::bad_request(
            "kekId must contain an ML-KEM-768 public key",
        ));
    }

    Ok(normalized)
}

fn hash_auth_key(auth_key: &str) -> String {
    hex::encode(Sha512::digest(auth_key.as_bytes()))
}

fn map_kek_metadata(metadata: kek_metadata_entity::Model) -> KekMetadata {
    KekMetadata {
        kek_epoch_version: metadata.kek_epoch_version,
        kek_public_key: metadata.kek_public_key,
    }
}

fn map_principal_summary(principal: &repository::PrincipalRecord) -> PrincipalSummary {
    PrincipalSummary {
        id: principal.principal_id,
        kind: principal.kind,
        email: principal.email.clone(),
        username: principal.username.clone(),
    }
}

fn map_linked_principal(
    linked_principal: repository::LinkedPrincipalRecord,
) -> AppResult<LinkedPrincipal> {
    Ok(LinkedPrincipal {
        id: linked_principal.principal.principal_id,
        kind: linked_principal.principal.kind,
        email: linked_principal.principal.email,
        username: linked_principal.principal.username,
        latest_kek_epoch_version: linked_principal.latest_kek.kek_epoch_version,
        latest_kek_public_key: linked_principal.latest_kek.kek_public_key,
    })
}

fn require_user_principal(authenticated_user: &AuthenticatedUser) -> AppResult<()> {
    if authenticated_user.principal_kind != PrincipalKind::User {
        return Err(AppError::bad_request("this action requires a primary user session"));
    }

    Ok(())
}

fn generate_api_username(api_user_id: Uuid) -> String {
    let compact = api_user_id.simple().to_string();
    format!("api-{}", &compact[..16])
}

fn validate_encrypted_blob(
    payload: &notes::service::SaveEncryptedBlobCommand,
    field_name: &str,
) -> AppResult<()> {
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

fn map_wrapped_deks(
    payloads: &[notes::service::SaveWrappedDekCommand],
) -> AppResult<Vec<notes::repository::WrappedDek>> {
    payloads.iter().map(map_wrapped_dek).collect()
}

fn map_wrapped_dek(
    payload: &notes::service::SaveWrappedDekCommand,
) -> AppResult<notes::repository::WrappedDek> {
    if payload.algorithm.trim() != "ml-kem-768-encapsulated+xsalsa20-poly1305" {
        return Err(AppError::validation(
            "wrappedDeks.algorithm must be ml-kem-768-encapsulated+xsalsa20-poly1305",
        ));
    }

    if payload.version != 3 {
        return Err(AppError::validation("wrappedDeks.version must be 3"));
    }

    normalize_kek_public_key(&payload.kek_public_key)?;
    normalize_hex_field(&payload.wrapped_dek_hex, "wrappedDeks.wrappedDekHex")?;
    normalize_hex_field(&payload.nonce_hex, "wrappedDeks.nonceHex")?;
    normalize_exact_hex_field(&payload.kem_ciphertext_hex, "wrappedDeks.kemCiphertextHex", 1088)?;

    Ok(notes::repository::WrappedDek {
        algorithm: payload.algorithm.trim().to_owned(),
        kem_ciphertext_hex: payload.kem_ciphertext_hex.trim().to_ascii_lowercase(),
        kek_public_key: payload.kek_public_key.trim().to_ascii_lowercase(),
        nonce_hex: payload.nonce_hex.trim().to_ascii_lowercase(),
        user_id: payload.user_id,
        version: payload.version,
        wrapped_dek_hex: payload.wrapped_dek_hex.trim().to_ascii_lowercase(),
    })
}

fn validate_label_deks(
    wrapped_deks: &[notes::repository::WrappedDek],
    owner_user_id: Uuid,
    api_user_id: Uuid,
    owner_kek_public_key: &str,
    api_user_kek_public_key: &str,
) -> AppResult<()> {
    if wrapped_deks.len() != 2 {
        return Err(AppError::validation(
            "encryptedLabelDeks must contain exactly the owner and api user wraps",
        ));
    }

    let owner_wrapped_dek = wrapped_deks
        .iter()
        .find(|wrapped_dek| wrapped_dek.user_id == owner_user_id)
        .ok_or_else(|| AppError::validation("encryptedLabelDeks must contain the owner wrap"))?;
    let api_wrapped_dek = wrapped_deks
        .iter()
        .find(|wrapped_dek| wrapped_dek.user_id == api_user_id)
        .ok_or_else(|| AppError::validation("encryptedLabelDeks must contain the api user wrap"))?;

    if owner_wrapped_dek.kek_public_key != owner_kek_public_key {
        return Err(AppError::validation(
            "encryptedLabelDeks owner wrap must target the owner's latest KEK id",
        ));
    }

    if api_wrapped_dek.kek_public_key != api_user_kek_public_key {
        return Err(AppError::validation(
            "encryptedLabelDeks api user wrap must target the api user's KEK id",
        ));
    }

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

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let result = (|| {
            let authorization_header = parts
                .headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| AppError::unauthorized("missing bearer token"))?;

            let token = authorization_header
                .strip_prefix("Bearer ")
                .or_else(|| authorization_header.strip_prefix("bearer "))
                .ok_or_else(|| AppError::unauthorized("missing bearer token"))?;

            authenticate_access_token(state, token)
        })();

        ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        response::IntoResponse,
    };

    fn test_state() -> AppState {
        let (note_events, _) = tokio::sync::broadcast::channel(1);

        AppState {
            config: crate::config::Config {
                bind_addr: "127.0.0.1:4000".parse().expect("bind addr should parse"),
                database_url: "postgres://example.invalid/backend".to_owned(),
                jwt_secret: "test-secret".to_owned(),
                jwt_ttl_minutes: 15,
                jwt_refresh_ttl_minutes: 60,
            },
            db: sea_orm::DatabaseConnection::Disconnected,
            note_events,
        }
    }

    fn encode_test_token(token_type: TokenType) -> String {
        let state = test_state();

        encode(
            &Header::default(),
            &Claims {
                sub: Uuid::new_v4().to_string(),
                owner_user_id: Uuid::new_v4().to_string(),
                email: "person@example.com".to_owned(),
                principal_kind: PrincipalKind::User,
                token_type,
                exp: (Utc::now().timestamp() + 60) as usize,
            },
            &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        )
        .expect("test token should encode")
    }

    async fn assert_error_response(error: AppError, status: StatusCode, message: &str) {
        let response = error.into_response();

        assert_eq!(response.status(), status);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        let payload: serde_json::Value =
            serde_json::from_slice(&body).expect("response body should be valid json");

        assert_eq!(payload, serde_json::json!({ "error": message }));
    }

    #[test]
    fn normalize_email_trims_and_lowercases() {
        let normalized = normalize_email("  USER@Example.COM  ").expect("email should normalize");

        assert_eq!(normalized, "user@example.com");
    }

    #[tokio::test]
    async fn normalize_email_rejects_missing_at_symbol() {
        let error = normalize_email("not-an-email").expect_err("email should be rejected");

        assert_error_response(
            error,
            StatusCode::BAD_REQUEST,
            "a valid email address is required",
        )
        .await;
    }

    #[test]
    fn validate_auth_key_accepts_32_character_key() {
        let auth_key = "a".repeat(32);

        validate_auth_key(&auth_key).expect("32-character auth key should be accepted");
    }

    #[tokio::test]
    async fn validate_auth_key_rejects_short_key() {
        let error = validate_auth_key("short-key").expect_err("short key should be rejected");

        assert_error_response(
            error,
            StatusCode::BAD_REQUEST,
            "authKey must be a non-empty derived key string",
        )
        .await;
    }

    #[test]
    fn normalize_auth_salt_trims_and_lowercases() {
        let normalized = normalize_auth_salt("  AABBCCDDEEFF00112233445566778899  ")
            .expect("salt should normalize");

        assert_eq!(normalized, "aabbccddeeff00112233445566778899");
    }

    #[tokio::test]
    async fn normalize_auth_salt_rejects_invalid_hex() {
        let error = normalize_auth_salt("not-hex").expect_err("invalid hex should be rejected");

        assert_error_response(
            error,
            StatusCode::BAD_REQUEST,
            "saltHex must be a valid hexadecimal string",
        )
        .await;
    }

    #[tokio::test]
    async fn normalize_auth_salt_rejects_wrong_byte_length() {
        let error = normalize_auth_salt("aabbccdd").expect_err("short salt should be rejected");

        assert_error_response(
            error,
            StatusCode::BAD_REQUEST,
            "saltHex must contain a 16-byte password salt",
        )
        .await;
    }

    #[test]
    fn hash_auth_key_returns_sha512_hex_digest() {
        let auth_key = "client-derived-auth-key-material";

        assert_eq!(
            hash_auth_key(auth_key),
            "54f2b8147b5dc3528ac08a67f6f3c1bd4e04a738d3e1652f721b9a550a5c2e193b00f033f4d8a1ca102810c4a8e03d105b3a979045d34918a6df35947da3238b"
        );
    }

    #[tokio::test]
    async fn extractor_requires_bearer_token_header() {
        let mut parts = Request::builder()
            .uri("/")
            .body(Body::empty())
            .expect("request should build")
            .into_parts()
            .0;
        let state = test_state();

        let error = AuthenticatedUser::from_request_parts(&mut parts, &state)
            .await
            .expect_err("missing header should be rejected");

        assert_error_response(error, StatusCode::UNAUTHORIZED, "missing bearer token").await;
    }

    #[tokio::test]
    async fn authenticate_access_token_rejects_refresh_tokens() {
        let state = test_state();
        let token = encode_test_token(TokenType::Refresh);

        let error = authenticate_access_token(&state, &token)
            .expect_err("refresh token should not satisfy access auth");

        assert_error_response(error, StatusCode::UNAUTHORIZED, "an access token is required").await;
    }

    #[tokio::test]
    async fn authenticate_refresh_token_rejects_access_tokens() {
        let state = test_state();
        let token = encode_test_token(TokenType::Access);

        let error = authenticate_refresh_token(&state, &token)
            .expect_err("access token should not satisfy refresh auth");

        assert_error_response(error, StatusCode::UNAUTHORIZED, "a refresh token is required").await;
    }
}
