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

/// Generic undo/redo state snapshot ledger.
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct CommandHistory<S> {
    undo_stack: Vec<S>,
    redo_stack: Vec<S>,
    max_history: usize,
}

impl<S: Clone> CommandHistory<S> {
    pub fn new(max_history: usize) -> Self {
        Self {
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            max_history: if max_history == 0 { 50 } else { max_history },
        }
    }

    pub fn record_state(&mut self, state: S) {
        if self.undo_stack.len() >= self.max_history {
            self.undo_stack.remove(0);
        }
        self.undo_stack.push(state);
        self.redo_stack.clear();
    }

    pub fn undo(&mut self, current: S) -> Option<S> {
        let prev = self.undo_stack.pop()?;
        self.redo_stack.push(current);
        Some(prev)
    }

    pub fn redo(&mut self, current: S) -> Option<S> {
        let next = self.redo_stack.pop()?;
        self.undo_stack.push(current);
        Some(next)
    }

    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }
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

    fn undo(&mut self) -> Result<Option<CommandReceipt>, Self::Error> {
        Ok(None)
    }

    fn redo(&mut self) -> Result<Option<CommandReceipt>, Self::Error> {
        Ok(None)
    }
}
