mod m20260611_000001_create_users;
mod m20260611_000002_add_user_auth_salt;
mod m20260611_000003_create_notes;
mod m20260612_000003_create_api_users;
mod m20260612_000004_create_deks;
mod m20260612_000005_create_kek_metadata;

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260611_000001_create_users::Migration),
            Box::new(m20260611_000002_add_user_auth_salt::Migration),
            Box::new(m20260611_000003_create_notes::Migration),
            Box::new(m20260612_000003_create_api_users::Migration),
            Box::new(m20260612_000005_create_kek_metadata::Migration),
            Box::new(m20260612_000004_create_deks::Migration),
        ]
    }
}
