use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::errors::Error as JwtError;
use sea_orm::DbErr;
use serde::Serialize;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug)]
pub struct AppError {
    message: String,
    status: StatusCode,
}

impl AppError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: StatusCode::BAD_REQUEST,
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: StatusCode::CONFLICT,
        }
    }

    pub fn config(message: impl Into<String>) -> Self {
        Self::internal(message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: StatusCode::NOT_FOUND,
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: StatusCode::UNAUTHORIZED,
        }
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self::bad_request(message)
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = Json(ErrorBody {
            error: self.message,
        });

        (self.status, body).into_response()
    }
}

impl From<DbErr> for AppError {
    fn from(error: DbErr) -> Self {
        Self::internal(format!("database error: {error}"))
    }
}

impl From<JwtError> for AppError {
    fn from(error: JwtError) -> Self {
        Self::internal(format!("token error: {error}"))
    }
}
