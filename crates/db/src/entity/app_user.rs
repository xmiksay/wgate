use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "app_user")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub tenant_id: Option<i64>,
    pub email: String,
    pub oidc_sub: Option<String>,
    pub role: String,
    pub disabled_at: Option<DateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
