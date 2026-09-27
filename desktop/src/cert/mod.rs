mod dns;
mod issue;
mod model;
mod store;

pub use issue::{issue, IssueRequest, IssueStep, ISSUE_TIMEOUT};
pub use model::{Provider, Vendor};
pub use store::Store;

use crate::config_bridge;
use anyhow::Result;
use std::sync::{Mutex, OnceLock};

static STORE: OnceLock<Mutex<Store>> = OnceLock::new();

pub fn store() -> &'static Mutex<Store> {
    STORE.get_or_init(|| {
        let s = Store::open(config_bridge::data_dir()).expect("open cert store");
        Mutex::new(s)
    })
}

pub fn with_store<R>(f: impl FnOnce(&Store) -> Result<R>) -> Result<R> {
    let guard = store().lock().unwrap_or_else(|e| e.into_inner());
    f(&guard)
}
