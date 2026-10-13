//! Schema migrations, applied by `wgate migrate` before the units restart.

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(Init)]
    }
}

#[derive(DeriveMigrationName)]
struct Init;

#[async_trait::async_trait]
impl MigrationTrait for Init {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0001_init.sql"))
            .await?;
        Ok(())
    }
}
