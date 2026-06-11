use axum::{extract::State, routing::post, Json, Router};
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    db::entity::user,
    error::{AppError, AppResult},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthRequest {
    email: String,
    auth_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    token: String,
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
struct Claims {
    sub: String,
    email: String,
    exp: usize,
}

async fn register(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> AppResult<Json<AuthResponse>> {
    let email = normalize_email(&payload.email)?;
    validate_auth_key(&payload.auth_key)?;

    let existing_user = user::Entity::find()
        .filter(user::Column::Email.eq(email.clone()))
        .one(&state.db)
        .await
        .map_err(|_| AppError::internal("failed to query the database"))?;

    if existing_user.is_some() {
        return Err(AppError::conflict("an account already exists for this email"));
    }

    let new_user = user::ActiveModel {
        id: Set(Uuid::new_v4()),
        email: Set(email),
        auth_key_hash: Set(hash_auth_key(&payload.auth_key)),
        created_at: Set(Utc::now().fixed_offset()),
    }
    .insert(&state.db)
    .await
    .map_err(|_| AppError::internal("failed to create the account"))?;

    Ok(Json(AuthResponse {
        token: issue_token(&state, &new_user)?,
        user: UserResponse {
            id: new_user.id,
            email: new_user.email,
        },
    }))
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> AppResult<Json<AuthResponse>> {
    let email = normalize_email(&payload.email)?;
    validate_auth_key(&payload.auth_key)?;

    let user = user::Entity::find()
        .filter(user::Column::Email.eq(email))
        .one(&state.db)
        .await
        .map_err(|_| AppError::internal("failed to query the database"))?
        .ok_or_else(|| AppError::unauthorized("invalid email or auth key"))?;

    let supplied_hash = hash_auth_key(&payload.auth_key);
    if supplied_hash
        .as_bytes()
        .ct_eq(user.auth_key_hash.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(AppError::unauthorized("invalid email or auth key"));
    }

    Ok(Json(AuthResponse {
        token: issue_token(&state, &user)?,
        user: UserResponse {
            id: user.id,
            email: user.email,
        },
    }))
}

fn issue_token(state: &AppState, user: &user::Model) -> AppResult<String> {
    let expires_at = Utc::now()
        .checked_add_signed(chrono::Duration::hours(state.config.jwt_ttl_hours))
        .ok_or_else(|| AppError::internal("failed to calculate the session expiry"))?;
    let claims = Claims {
        sub: user.id.to_string(),
        email: user.email.clone(),
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

fn validate_auth_key(auth_key: &str) -> AppResult<()> {
    if auth_key.trim().len() < 32 {
        return Err(AppError::bad_request(
            "authKey must be a non-empty derived key string",
        ));
    }

    Ok(())
}

fn hash_auth_key(auth_key: &str) -> String {
    hex::encode(Sha512::digest(auth_key.as_bytes()))
}
