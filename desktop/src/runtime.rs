use orbien_client::{ClientHandle, ClientStatus, ReloadOutcome};
use std::sync::OnceLock;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("orbien-client")
            .build()
            .expect("failed to create orbien client runtime")
    })
}

pub fn handle() -> ClientHandle {
    static HANDLE: OnceLock<ClientHandle> = OnceLock::new();
    HANDLE.get_or_init(ClientHandle::new).clone()
}

pub fn status() -> ClientStatus {
    handle().status()
}

pub fn take_last_error() -> Option<String> {
    handle().take_last_error()
}

pub fn drain_logs() -> Vec<String> {
    handle().drain_logs()
}

pub fn tunnel_remotes_if_changed(
    since_gen: u64,
) -> Option<(u64, std::collections::HashMap<String, String>)> {
    handle().tunnel_remotes_if_changed(since_gen)
}

pub fn start(cfg: orbien_client::ClientConfig, path: std::path::PathBuf) -> anyhow::Result<()> {
    let h = handle();
    if h.status().is_active() {
        anyhow::bail!("client already running");
    }
    let _guard = runtime().enter();
    h.start(cfg, path)
}

pub fn reload_async(
    cfg: orbien_client::ClientConfig,
    path: std::path::PathBuf,
    on_done: impl FnOnce(anyhow::Result<ReloadOutcome>) + Send + 'static,
) {
    runtime().spawn(async move {
        let result = handle().reload(cfg, path).await;
        let _ = slint::invoke_from_event_loop(move || on_done(result));
    });
}

pub fn spawn<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    runtime().spawn(fut);
}

pub fn stop_async(on_done: impl FnOnce() + Send + 'static) {
    let h = handle();
    runtime().spawn(async move {
        h.stop().await;
        let _ = slint::invoke_from_event_loop(move || on_done());
    });
}
