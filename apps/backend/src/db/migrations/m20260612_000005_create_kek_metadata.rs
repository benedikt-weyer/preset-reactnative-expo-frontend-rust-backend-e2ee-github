use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(KekMetadata::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(KekMetadata::KekId).uuid().not_null().primary_key())
                    .col(ColumnDef::new(KekMetadata::UserId).uuid().not_null())
                    .col(ColumnDef::new(KekMetadata::KekEpochVersion).integer().not_null())
                    .col(
                        ColumnDef::new(KekMetadata::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-kek-metadata-user-id")
                            .from(KekMetadata::Table, KekMetadata::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-kek-metadata-user-id-epoch")
                    .table(KekMetadata::Table)
                    .col(KekMetadata::UserId)
                    .col(KekMetadata::KekEpochVersion)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(KekMetadata::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum KekMetadata {
    Table,
    KekId,
    UserId,
    KekEpochVersion,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}