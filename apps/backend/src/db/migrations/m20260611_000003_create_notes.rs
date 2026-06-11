use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Notes::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Notes::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Notes::UserId).uuid().not_null())
                    .col(ColumnDef::new(Notes::Algorithm).string().not_null())
                    .col(ColumnDef::new(Notes::CiphertextHex).text().not_null())
                    .col(ColumnDef::new(Notes::NonceHex).string().not_null())
                    .col(ColumnDef::new(Notes::Version).integer().not_null())
                    .col(
                        ColumnDef::new(Notes::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Notes::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-notes-user-id")
                            .from(Notes::Table, Notes::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-notes-user-id-updated-at")
                    .table(Notes::Table)
                    .col(Notes::UserId)
                    .col(Notes::UpdatedAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Notes::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Notes {
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
