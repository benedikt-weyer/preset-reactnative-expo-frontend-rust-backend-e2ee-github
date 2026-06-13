use axum::{
    http::StatusCode,
    extract::{Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    domains::{
        auth::{service, AuthenticatedUser, PrincipalKind},
        notes::service as notes_service,
    },
    error::AppResult,
};

pub fn router() -> Router<AppState> {
    Router::new()
    .route("/linked-principals", get(linked_principals))
        .route("/kek-status", get(kek_status))
        .route("/refresh", post(refresh))
        .route("/salt", post(salt))
        .route("/login", post(login))
    .route("/api-users/login", post(api_user_login))
    .route("/api-users", get(list_api_users).post(create_api_user))
    .route("/api-users/{api_user_id}", get(get_api_user).delete(delete_api_user))
    .route("/api-users/{api_user_id}/provision", post(provision_api_user_deks))
        .route("/account", delete(delete_account))
        .route("/rotate-password", post(rotate_password))
        .route("/register", post(register))
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailRequest {
    email: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    email: String,
    auth_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshTokenRequest {
    refresh_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiUserLoginRequest {
    username: String,
    auth_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    email: String,
    auth_key: String,
    kek_public_key: String,
    salt_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotatePasswordRequest {
    kek_public_key: String,
    new_auth_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApiUserRequest {
    id: Uuid,
    auth_key: String,
    encrypted_label: EncryptedBlobRequest,
    encrypted_label_deks: Vec<WrappedDekRequest>,
    kek_public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionApiUserDeksRequest {
    wrapped_deks: Vec<ProvisionWrappedDekRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionWrappedDekRequest {
    resource_id: Uuid,
    wrapped_dek: WrappedDekRequest,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    current_principal: PrincipalResponse,
    kek_metadatas: Vec<KekMetadataResponse>,
    linked_principals: Vec<LinkedPrincipalResponse>,
    token: String,
    refresh_token: String,
    user: UserResponse,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    id: Uuid,
    email: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalResponse {
    id: Uuid,
    kind: PrincipalKind,
    email: Option<String>,
    username: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkedPrincipalResponse {
    id: Uuid,
    kind: PrincipalKind,
    email: Option<String>,
    username: Option<String>,
    latest_kek_epoch_version: i32,
    latest_kek_public_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaltResponse {
    kek_metadatas: Vec<KekMetadataResponse>,
    salt_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KekMetadataResponse {
    kek_epoch_version: i32,
    kek_public_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KekMigrationStatusResponse {
    all_deks_use_latest_kek: bool,
    latest_kek_dek_count: u64,
    latest_kek_epoch_version: i32,
    latest_kek_public_key: String,
    pending_dek_count: u64,
    total_dek_count: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedBlobRequest {
    algorithm: String,
    ciphertext_hex: String,
    nonce_hex: String,
    version: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedDekRequest {
    algorithm: String,
    kem_ciphertext_hex: String,
    kek_public_key: String,
    nonce_hex: String,
    user_id: Uuid,
    version: i32,
    wrapped_dek_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedBlobResponse {
    algorithm: String,
    ciphertext_hex: String,
    nonce_hex: String,
    version: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedDekResponse {
    algorithm: String,
    kem_ciphertext_hex: String,
    kek_public_key: String,
    nonce_hex: String,
    user_id: Uuid,
    version: i32,
    wrapped_dek_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiUserProvisioningResponse {
    completed_resource_count: u64,
    pending_note_ids: Vec<Uuid>,
    pending_resource_count: u64,
    total_resource_count: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiUserResponse {
    created_at: String,
    encrypted_label: EncryptedBlobResponse,
    encrypted_label_dek: WrappedDekResponse,
    id: Uuid,
    latest_kek_epoch_version: i32,
    latest_kek_public_key: String,
    provisioning: ApiUserProvisioningResponse,
    updated_at: String,
    username: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> AppResult<Json<AuthResponse>> {
    let session = service::register(
        &state,
        service::RegisterCommand {
            email: payload.email,
            auth_key: payload.auth_key,
            kek_public_key: payload.kek_public_key,
            salt_hex: payload.salt_hex,
        },
    )
    .await?;

    Ok(Json(map_auth_response(session)))
}

pub async fn salt(
    State(state): State<AppState>,
    Json(payload): Json<EmailRequest>,
) -> AppResult<Json<SaltResponse>> {
    let salt_material = service::salt(&state, &payload.email).await?;

    Ok(Json(SaltResponse {
        kek_metadatas: salt_material
            .kek_metadatas
            .into_iter()
            .map(map_kek_metadata_response)
            .collect(),
        salt_hex: salt_material.salt_hex,
    }))
}

pub async fn api_user_login(
    State(state): State<AppState>,
    Json(payload): Json<ApiUserLoginRequest>,
) -> AppResult<Json<AuthResponse>> {
    let session = service::login_api_user(
        &state,
        service::ApiUserLoginCommand {
            username: payload.username,
            auth_key: payload.auth_key,
        },
    )
    .await?;

    Ok(Json(map_auth_response(session)))
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<Json<AuthResponse>> {
    let session = service::login(
        &state,
        service::LoginCommand {
            email: payload.email,
            auth_key: payload.auth_key,
        },
    )
    .await?;

    Ok(Json(map_auth_response(session)))
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> AppResult<Json<AuthResponse>> {
    let session = service::refresh_session(&state, &payload.refresh_token).await?;

    Ok(Json(map_auth_response(session)))
}

pub async fn rotate_password(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<RotatePasswordRequest>,
) -> AppResult<Json<AuthResponse>> {
    let session = service::rotate_password(
        &state,
        &authenticated_user,
        service::RotatePasswordCommand {
            kek_public_key: payload.kek_public_key,
            new_auth_key: payload.new_auth_key,
        },
    )
    .await?;

    Ok(Json(map_auth_response(session)))
}

pub async fn kek_status(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<KekMigrationStatusResponse>> {
    Ok(Json(map_kek_migration_status_response(
        service::get_kek_migration_status(&state, &authenticated_user).await?,
    )))
}

pub async fn linked_principals(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<Vec<LinkedPrincipalResponse>>> {
    Ok(Json(
        service::list_linked_principals(&state, &authenticated_user)
            .await?
            .into_iter()
            .map(map_linked_principal_response)
            .collect(),
    ))
}

pub async fn list_api_users(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<Vec<ApiUserResponse>>> {
    Ok(Json(
        service::list_api_users(&state, &authenticated_user)
            .await?
            .into_iter()
            .map(map_api_user_response)
            .collect(),
    ))
}

pub async fn get_api_user(
    State(state): State<AppState>,
    Path(api_user_id): Path<Uuid>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<Json<ApiUserResponse>> {
    Ok(Json(map_api_user_response(
        service::get_api_user(&state, &authenticated_user, api_user_id).await?,
    )))
}

pub async fn create_api_user(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<CreateApiUserRequest>,
) -> AppResult<Json<ApiUserResponse>> {
    Ok(Json(map_api_user_response(
        service::create_api_user(
            &state,
            &authenticated_user,
            service::CreateApiUserCommand {
                api_user_id: payload.id,
                auth_key: payload.auth_key,
                encrypted_label: map_blob_request(payload.encrypted_label),
                encrypted_label_deks: payload
                    .encrypted_label_deks
                    .into_iter()
                    .map(map_wrapped_dek_request)
                    .collect(),
                kek_public_key: payload.kek_public_key,
            },
        )
        .await?,
    )))
}

pub async fn delete_api_user(
    State(state): State<AppState>,
    Path(api_user_id): Path<Uuid>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<StatusCode> {
    service::delete_api_user(&state, &authenticated_user, api_user_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_account(
    State(state): State<AppState>,
    authenticated_user: AuthenticatedUser,
) -> AppResult<StatusCode> {
    service::delete_account(&state, &authenticated_user).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn provision_api_user_deks(
    State(state): State<AppState>,
    Path(api_user_id): Path<Uuid>,
    authenticated_user: AuthenticatedUser,
    Json(payload): Json<ProvisionApiUserDeksRequest>,
) -> AppResult<Json<ApiUserResponse>> {
    Ok(Json(map_api_user_response(
        service::provision_api_user_deks(
            &state,
            &authenticated_user,
            api_user_id,
            payload
                .wrapped_deks
                .into_iter()
                .map(|wrapped_dek| service::ProvisionApiUserDekCommand {
                    resource_id: wrapped_dek.resource_id,
                    wrapped_dek: map_wrapped_dek_request(wrapped_dek.wrapped_dek),
                })
                .collect(),
        )
        .await?,
    )))
}

fn map_auth_response(session: service::AuthSession) -> AuthResponse {
    AuthResponse {
        current_principal: map_principal_response(session.current_principal),
        kek_metadatas: session
            .kek_metadatas
            .into_iter()
            .map(map_kek_metadata_response)
            .collect(),
        linked_principals: session
            .linked_principals
            .into_iter()
            .map(map_linked_principal_response)
            .collect(),
        token: session.token,
        refresh_token: session.refresh_token,
        user: UserResponse {
            id: session.user_id,
            email: session.email,
        },
    }
}

fn map_kek_metadata_response(metadata: service::KekMetadata) -> KekMetadataResponse {
    KekMetadataResponse {
        kek_epoch_version: metadata.kek_epoch_version,
        kek_public_key: metadata.kek_public_key,
    }
}

fn map_principal_response(principal: service::PrincipalSummary) -> PrincipalResponse {
    PrincipalResponse {
        id: principal.id,
        kind: principal.kind,
        email: principal.email,
        username: principal.username,
    }
}

fn map_linked_principal_response(
    principal: service::LinkedPrincipal,
) -> LinkedPrincipalResponse {
    LinkedPrincipalResponse {
        id: principal.id,
        kind: principal.kind,
        email: principal.email,
        username: principal.username,
        latest_kek_epoch_version: principal.latest_kek_epoch_version,
        latest_kek_public_key: principal.latest_kek_public_key,
    }
}

fn map_kek_migration_status_response(
    status: service::KekMigrationStatus,
) -> KekMigrationStatusResponse {
    KekMigrationStatusResponse {
        all_deks_use_latest_kek: status.all_deks_use_latest_kek,
        latest_kek_dek_count: status.latest_kek_dek_count,
        latest_kek_epoch_version: status.latest_kek_epoch_version,
        latest_kek_public_key: status.latest_kek_public_key,
        pending_dek_count: status.pending_dek_count,
        total_dek_count: status.total_dek_count,
    }
}

fn map_blob_request(payload: EncryptedBlobRequest) -> notes_service::SaveEncryptedBlobCommand {
    notes_service::SaveEncryptedBlobCommand {
        algorithm: payload.algorithm,
        ciphertext_hex: payload.ciphertext_hex,
        nonce_hex: payload.nonce_hex,
        version: payload.version,
    }
}

fn map_wrapped_dek_request(payload: WrappedDekRequest) -> notes_service::SaveWrappedDekCommand {
    notes_service::SaveWrappedDekCommand {
        algorithm: payload.algorithm,
        kem_ciphertext_hex: payload.kem_ciphertext_hex,
        kek_public_key: payload.kek_public_key,
        nonce_hex: payload.nonce_hex,
        user_id: payload.user_id,
        version: payload.version,
        wrapped_dek_hex: payload.wrapped_dek_hex,
    }
}

fn map_blob_response(blob: notes_service::StoredEncryptedBlob) -> EncryptedBlobResponse {
    EncryptedBlobResponse {
        algorithm: blob.algorithm,
        ciphertext_hex: blob.ciphertext_hex,
        nonce_hex: blob.nonce_hex,
        version: blob.version,
    }
}

fn map_wrapped_dek_response(blob: notes_service::StoredWrappedDek) -> WrappedDekResponse {
    WrappedDekResponse {
        algorithm: blob.algorithm,
        kem_ciphertext_hex: blob.kem_ciphertext_hex,
        kek_public_key: blob.kek_public_key,
        nonce_hex: blob.nonce_hex,
        user_id: blob.user_id,
        version: blob.version,
        wrapped_dek_hex: blob.wrapped_dek_hex,
    }
}

fn map_api_user_response(api_user: service::ApiUserRecord) -> ApiUserResponse {
    ApiUserResponse {
        created_at: api_user.created_at,
        encrypted_label: map_blob_response(api_user.encrypted_label),
        encrypted_label_dek: map_wrapped_dek_response(api_user.encrypted_label_dek),
        id: api_user.id,
        latest_kek_epoch_version: api_user.latest_kek_epoch_version,
        latest_kek_public_key: api_user.latest_kek_public_key,
        provisioning: ApiUserProvisioningResponse {
            completed_resource_count: api_user.provisioning.completed_resource_count,
            pending_note_ids: api_user.provisioning.pending_note_ids,
            pending_resource_count: api_user.provisioning.pending_resource_count,
            total_resource_count: api_user.provisioning.total_resource_count,
        },
        updated_at: api_user.updated_at,
        username: api_user.username,
    }
}
