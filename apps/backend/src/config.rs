use std::{env, net::SocketAddr};

use crate::error::{AppError, AppResult};

#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_ttl_hours: i64,
}

impl Config {
    pub fn from_env() -> AppResult<Self> {
        let host = env::var("BACKEND_HOST").unwrap_or_else(|_| "0.0.0.0".to_owned());
        let port = env::var("BACKEND_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(4000);
        let bind_addr = format!("{host}:{port}")
            .parse()
            .map_err(|_| AppError::internal("failed to parse BACKEND_HOST/BACKEND_PORT"))?;

        let database_url = env::var("DATABASE_URL").map_err(|_| {
            AppError::internal("DATABASE_URL must be set before the backend can start")
        })?;

        let jwt_secret = env::var("JWT_SECRET")
            .unwrap_or_else(|_| "dev-only-secret-change-me".to_owned());
        let jwt_ttl_hours = env::var("JWT_TTL_HOURS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(24);

        Ok(Self {
            bind_addr,
            database_url,
            jwt_secret,
            jwt_ttl_hours,
        })
    }
}
use std::{env, net::SocketAddr};

use crate::error::AppError;

pub struct AppConfig {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub jwt_secret: String,
    pub token_ttl_seconds: i64,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, AppError> {
        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_owned());
        let port = env::var("PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(3000);
        let bind_addr = format!("{host}:{port}")
            .parse::<SocketAddr>()
            .map_err(|error| AppError::Config(format!("invalid HOST/PORT combination: {error}")))?;

        let database_url = env::var("DATABASE_URL")
            .map_err(|_| AppError::Config("DATABASE_URL is required".to_owned()))?;

        let jwt_secret = env::var("JWT_SECRET")
            .unwrap_or_else(|_| "local-development-only-secret-change-me".to_owned());

        let token_ttl_seconds = env::var("JWT_TTL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(86_400);

        Ok(Self {
            bind_addr,
            database_url,
            jwt_secret,
            token_ttl_seconds,
        })
    }
}
