use sea_orm_migration::prelude::*;

#[derive(Iden)]
pub enum MssClampServiceConfigs {
    Table,
    IfaceName,
    Enable,
    ClampSize,
    /// The IPv6 Packet Too Big chamber for this interface, or NULL for none.
    MtuChamber,
    UpdateAt,
}
