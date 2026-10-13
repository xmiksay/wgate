use sea_orm::entity::prelude::*;
use sea_orm::prelude::IpNetwork;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "peer_route")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub peer_id: i64,
    pub active: bool,
    #[sea_orm(column_type = "Cidr")]
    pub cidr: IpNetwork,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
