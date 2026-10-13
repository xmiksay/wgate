use sea_orm::entity::prelude::*;
use sea_orm::prelude::IpNetwork;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "ceiling")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub tenant_id: i64,
    pub proto: String,
    #[sea_orm(column_type = "Cidr")]
    pub dst: IpNetwork,
    pub port_from: Option<i32>,
    pub port_to: Option<i32>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
