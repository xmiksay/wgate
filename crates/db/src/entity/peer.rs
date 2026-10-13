use sea_orm::entity::prelude::*;
use sea_orm::prelude::IpNetwork;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "peer")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub device_id: i64,
    pub network_id: i64,
    pub public_key: String,
    /// `server` or `pasted`.
    pub key_source: String,
    #[sea_orm(column_type = "Inet")]
    pub ip: IpNetwork,
    pub created_at: DateTimeWithTimeZone,
    pub revoked_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
