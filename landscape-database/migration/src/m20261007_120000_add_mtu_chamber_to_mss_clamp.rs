//! Let an interface carry the settings for the IPv6 Packet Too Big chamber.
//!
//! The chamber belongs to the interface it guards, and the MSS clamp service is
//! already that interface's owner, so the settings live on its row. Nullable so
//! every existing row stays valid and means "no chamber" - the divert is off
//! until an operator asks for it, which is the only safe default for a feature
//! that changes where packets go.

use sea_orm_migration::prelude::*;

use crate::tables::mss_clamp::MssClampServiceConfigs;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(MssClampServiceConfigs::Table)
                    .add_column(ColumnDef::new(MssClampServiceConfigs::MtuChamber).json().null())
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(MssClampServiceConfigs::Table)
                    .drop_column(MssClampServiceConfigs::MtuChamber)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
