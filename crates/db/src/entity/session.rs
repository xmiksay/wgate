use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "session")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub token_hash: Vec<u8>,
    pub user_id: i64,
    pub csrf: String,
    pub created_at: DateTimeWithTimeZone,
    pub seen_at: DateTimeWithTimeZone,
    pub expires_at: DateTimeWithTimeZone,
    /// `full`, `totp` or `enrol`: only `full` may use the API.
    pub stage: String,
    /// `password`, `password_totp` or `oidc`.
    pub method: String,
    /// The provider of an `oidc` session (and only of one).
    pub provider_id: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
