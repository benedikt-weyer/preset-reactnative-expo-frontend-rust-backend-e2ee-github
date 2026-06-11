use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(EncryptedNotes::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(EncryptedNotes::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(EncryptedNotes::UserId).uuid().not_null().unique_key())
                    .col(ColumnDef::new(EncryptedNotes::Algorithm).string().not_null())
                    .col(ColumnDef::new(EncryptedNotes::CiphertextHex).text().not_null())
                    .col(ColumnDef::new(EncryptedNotes::NonceHex).string().not_null())
                    .col(ColumnDef::new(EncryptedNotes::Version).integer().not_null())
                    .col(
                        ColumnDef::new(EncryptedNotes::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(EncryptedNotes::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-encrypted-notes-user-id")
                            .from(EncryptedNotes::Table, EncryptedNotes::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(EncryptedNotes::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum EncryptedNotes {
    Table,
    Id,
    UserId,
    Algorithm,
    CiphertextHex,
    NonceHex,
    Version,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}