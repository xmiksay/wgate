use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "federation")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub from_network_id: i64,
    pub to_network_id: i64,
    pub proto: String,
    pub port_from: Option<i32>,
    pub port_to: Option<i32>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
