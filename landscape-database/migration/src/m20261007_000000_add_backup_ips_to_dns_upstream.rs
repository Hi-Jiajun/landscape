//! Persist the backup resolver addresses on a DNS upstream.
//!
//! The architecture pairs a domestic ISP resolver with a public backup, and a rule
//! binds one upstream - so the pairing has to live on the upstream. Without a
//! column the field would only exist in memory and would not survive a restart.

use sea_orm_migration::prelude::*;

use crate::tables::dns_rule::DNSUpstreamConfigs;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(DNSUpstreamConfigs::Table)
                    .add_column(
                        ColumnDef::new(DNSUpstreamConfigs::BackupIps)
                            .json()
                            .null()
                            .default(Expr::value("[]")),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(DNSUpstreamConfigs::Table)
                    .drop_column(DNSUpstreamConfigs::BackupIps)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
