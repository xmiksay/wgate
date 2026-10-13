use sea_orm::entity::prelude::*;
use sea_orm::prelude::IpNetwork;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "inbound")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub network_id: i64,
    #[sea_orm(column_type = "Cidr")]
    pub source: IpNetwork,
    pub proto: String,
    pub port_from: Option<i32>,
    pub port_to: Option<i32>,
    pub comment: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
