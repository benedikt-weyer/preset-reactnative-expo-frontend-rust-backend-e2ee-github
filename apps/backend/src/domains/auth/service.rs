use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::future::ready;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    domains::auth::{entity, repository},
    error::{AppError, AppResult},
};

pub struct RegisterCommand {
    pub email: String,
    pub auth_key: String,
    pub salt_hex: String,
}

pub struct LoginCommand {
    pub email: String,
    pub auth_key: String,
}

pub struct AuthSession {
    pub token: String,
    pub refresh_token: String,
    pub user_id: Uuid,
    pub email: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Claims {
    sub: String,
    email: String,
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
    pub user_id: Uuid,
}

pub async fn register(state: &AppState, command: RegisterCommand) -> AppResult<AuthSession> {
    let email = normalize_email(&command.email)?;
    validate_auth_key(&command.auth_key)?;
    let auth_salt = normalize_auth_salt(&command.salt_hex)?;

    if repository::find_user_by_email(&state.db, &email).await?.is_some() {
        return Err(AppError::conflict("an account already exists for this email"));
    }

    let new_user = repository::insert_user(
        &state.db,
        email,
        hash_auth_key(&command.auth_key),
        auth_salt,
        Utc::now().fixed_offset(),
    )
    .await?;

    build_auth_session(state, &new_user)
}

pub async fn salt(state: &AppState, email: &str) -> AppResult<String> {
    let email = normalize_email(email)?;

    let user = repository::find_user_by_email(&state.db, &email)
        .await?
        .ok_or_else(|| AppError::unauthorized("invalid email or password"))?;

    let auth_salt = user
        .auth_salt
        .ok_or_else(|| AppError::unauthorized("invalid email or password"))?;

    normalize_auth_salt(&auth_salt)
}

pub async fn login(state: &AppState, command: LoginCommand) -> AppResult<AuthSession> {
    let email = normalize_email(&command.email)?;
    validate_auth_key(&command.auth_key)?;

    let user = repository::find_user_by_email(&state.db, &email)
        .await?
        .ok_or_else(|| AppError::unauthorized("invalid email or auth key"))?;

    let supplied_hash = hash_auth_key(&command.auth_key);
    if supplied_hash
        .as_bytes()
        .ct_eq(user.auth_key_hash.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(AppError::unauthorized("invalid email or auth key"));
    }

    build_auth_session(state, &user)
}

fn build_auth_session(state: &AppState, user: &entity::Model) -> AppResult<AuthSession> {
    Ok(AuthSession {
        token: issue_token(state, user, TokenType::Access)?,
        refresh_token: issue_token(state, user, TokenType::Refresh)?,
        user_id: user.id,
        email: user.email.clone(),
    })
}

fn issue_token(state: &AppState, user: &entity::Model, token_type: TokenType) -> AppResult<String> {
    let ttl_minutes = match token_type {
        TokenType::Access => state.config.jwt_ttl_minutes,
        TokenType::Refresh => state.config.jwt_refresh_ttl_minutes,
    };
    let expires_at = Utc::now()
        .checked_add_signed(chrono::Duration::minutes(ttl_minutes))
        .ok_or_else(|| AppError::internal("failed to calculate the session expiry"))?;
    let claims = Claims {
        sub: user.id.to_string(),
        email: user.email.clone(),
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

fn validate_auth_key(auth_key: &str) -> AppResult<()> {
    if auth_key.trim().len() < 32 {
        return Err(AppError::bad_request(
            "authKey must be a non-empty derived key string",
        ));
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

fn hash_auth_key(auth_key: &str) -> String {
    hex::encode(Sha512::digest(auth_key.as_bytes()))
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

            let token_data = decode::<Claims>(
                token,
                &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
                &Validation::default(),
            )
            .map_err(|_| AppError::unauthorized("invalid bearer token"))?;

            if token_data.claims.token_type != TokenType::Access {
                return Err(AppError::unauthorized("an access token is required"));
            }

            Ok(Self {
                user_id: Uuid::parse_str(&token_data.claims.sub)
                    .map_err(|_| AppError::unauthorized("invalid bearer token"))?,
            })
        })();

        ready(result)
    }
}