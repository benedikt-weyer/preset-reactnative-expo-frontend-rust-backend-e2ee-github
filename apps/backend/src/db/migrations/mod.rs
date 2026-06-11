mod m20260611_000001_create_users;
mod m20260611_000002_add_user_auth_salt;
mod m20260611_000003_create_encrypted_notes;

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260611_000001_create_users::Migration),
            Box::new(m20260611_000002_add_user_auth_salt::Migration),
            Box::new(m20260611_000003_create_encrypted_notes::Migration),
        ]
    }
}
