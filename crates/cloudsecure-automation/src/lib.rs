use cloudsecure_types::{AppCatalogEntry, SarifReport};
use serde::{de::DeserializeOwned, Serialize};

/// Receipt emitted after every successful state mutation command.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CommandReceipt {
    pub command_name: String,
    pub records_affected: usize,
    pub execution_ms: u64,
    pub state_hash: String,
}

/// Universal 4-way control contract implemented by every CloudSecure application.
pub trait CloudSecureAppEngine: Send + Sync + 'static {
    type Command: Serialize + DeserializeOwned + Clone + Send + Sync;
    type StateSnapshot: Serialize + DeserializeOwned + Clone + Send + Sync;
    type Error: std::error::Error + Send + Sync + 'static;

    fn app_metadata(&self) -> AppCatalogEntry;
    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error>;
    fn snapshot(&self) -> Self::StateSnapshot;
    fn export_sarif(&self) -> SarifReport;
}
