use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Deks::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Deks::ResourceId).uuid().not_null())
                    .col(ColumnDef::new(Deks::UserId).uuid().not_null())
                    .col(ColumnDef::new(Deks::KekPublicKey).text().not_null())
                    .col(ColumnDef::new(Deks::Algorithm).string().not_null())
                    .col(ColumnDef::new(Deks::KemCiphertextHex).text().not_null())
                    .col(ColumnDef::new(Deks::WrappedDekHex).text().not_null())
                    .col(ColumnDef::new(Deks::NonceHex).string().not_null())
                    .col(ColumnDef::new(Deks::Version).integer().not_null())
                    .col(
                        ColumnDef::new(Deks::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Deks::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-deks-kek-id")
                            .from(Deks::Table, Deks::KekPublicKey)
                            .to(KekMetadata::Table, KekMetadata::KekPublicKey)
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-deks-resource-id-user-id")
                            .col(Deks::ResourceId)
                            .col(Deks::UserId),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-deks-user-id-updated-at")
                    .table(Deks::Table)
                    .col(Deks::UserId)
                    .col(Deks::UpdatedAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Deks::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Deks {
    Table,
    ResourceId,
    UserId,
    KekPublicKey,
    Algorithm,
    KemCiphertextHex,
    WrappedDekHex,
    NonceHex,
    Version,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum KekMetadata {
    Table,
    KekPublicKey,
}