use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "kek_metadata")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub kek_id: String,
    pub user_id: Uuid,
    pub kek_epoch_version: i32,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}