use serde::{Deserialize, Serialize};

pub mod api_user_entity;
pub mod controller;
pub mod entity;
pub mod kek_metadata_entity;
pub mod repository;
pub mod service;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
	User,
	ApiUser,
}

pub use controller::router;
pub use service::AuthenticatedUser;
