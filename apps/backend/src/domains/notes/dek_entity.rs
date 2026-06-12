use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "deks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub resource_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    pub kek_public_key: String,
    pub algorithm: String,
    pub kem_ciphertext_hex: String,
    pub wrapped_dek_hex: String,
    pub nonce_hex: String,
    pub version: i32,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}