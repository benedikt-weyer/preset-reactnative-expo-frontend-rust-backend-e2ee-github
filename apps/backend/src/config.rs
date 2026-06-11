use std::{env, net::SocketAddr};

use crate::error::{AppError, AppResult};

#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_ttl_hours: i64,
    pub jwt_refresh_ttl_hours: i64,
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
        let jwt_refresh_ttl_hours = env::var("JWT_REFRESH_TTL_HOURS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(24 * 30);

        Ok(Self {
            bind_addr,
            database_url,
            jwt_secret,
            jwt_ttl_hours,
            jwt_refresh_ttl_hours,
        })
    }
}
