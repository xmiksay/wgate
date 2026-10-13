use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "audit")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub at: DateTimeWithTimeZone,
    pub actor_user_id: Option<i64>,
    pub action: String,
    pub target: String,
    pub detail: Json,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
