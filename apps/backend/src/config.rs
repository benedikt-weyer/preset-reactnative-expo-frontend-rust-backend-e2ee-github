use std::{env, net::SocketAddr};

use crate::error::{AppError, AppResult};

#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_ttl_minutes: i64,
    pub jwt_refresh_ttl_minutes: i64,
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

        let jwt_secret =
            env::var("JWT_SECRET").unwrap_or_else(|_| "dev-only-secret-change-me".to_owned());
        let jwt_ttl_minutes = read_i64_env_with_legacy("JWT_TTL_MINUTES", "JWT_TTL_HOURS", 24 * 60);
        let jwt_refresh_ttl_minutes = read_i64_env_with_legacy(
            "JWT_REFRESH_TTL_MINUTES",
            "JWT_REFRESH_TTL_HOURS",
            24 * 60 * 30,
        );

        Ok(Self {
            bind_addr,
            database_url,
            jwt_secret,
            jwt_ttl_minutes,
            jwt_refresh_ttl_minutes,
        })
    }
}

fn read_i64_env_with_legacy(primary_key: &str, legacy_key: &str, default_value: i64) -> i64 {
    env::var(primary_key)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .or_else(|| {
            env::var(legacy_key)
                .ok()
                .and_then(|value| value.parse::<i64>().ok())
                .map(|value| value * 60)
        })
        .unwrap_or(default_value)
}
