use sea_orm::entity::prelude::*;
use sea_orm::prelude::IpNetwork;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "network")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub tenant_id: i64,
    pub block_id: i64,
    pub slug: String,
    pub name: String,
    #[sea_orm(column_type = "Cidr")]
    pub cidr: IpNetwork,
    pub port: i32,
    pub mesh: bool,
    pub disabled_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
