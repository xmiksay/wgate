use sea_orm::entity::prelude::*;

#[derive(Clone, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "oidc_provider")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// `None`: a global provider.
    pub tenant_id: Option<i64>,
    pub name: String,
    /// Verbatim, as the provider's discovery names itself.
    pub issuer: String,
    pub client_id: String,
    /// Sealed with the row as associated data (the server's `seal`); never sent out.
    pub client_secret: Vec<u8>,
    pub link_by_email: bool,
    pub disabled_at: Option<DateTimeWithTimeZone>,
}

/// Without the sealed secret: nothing logs even its ciphertext.
impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("oidc_provider::Model")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("name", &self.name)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("link_by_email", &self.link_by_email)
            .field("disabled_at", &self.disabled_at)
            .finish_non_exhaustive()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
