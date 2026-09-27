use orbien_client::ClientHandle;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

pub struct ClientUiLogLayer {
    handle: ClientHandle,
}

impl ClientUiLogLayer {
    pub fn new(handle: ClientHandle) -> Self {
        Self { handle }
    }
}

impl<S> Layer<S> for ClientUiLogLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let level = *meta.level();
        if level > Level::INFO {
            return;
        }
        let target = meta.target();
        if !(target.starts_with("orbien_client")
            || target.starts_with("orbien_core")
            || target.starts_with("orbien_desktop"))
        {
            return;
        }

        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        let Some(line) = visitor.into_line(level) else {
            return;
        };
        self.handle.push_log(line);
    }
}

#[derive(Default)]
struct FieldVisitor {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl FieldVisitor {
    fn into_line(self, level: Level) -> Option<String> {
        let msg = self.message.unwrap_or_default();
        let msg = msg.trim();
        if msg.is_empty() && self.fields.is_empty() {
            return None;
        }
        let prefix = match level {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN ",
            Level::INFO => "INFO ",
            _ => return None,
        };
        let mut out = String::with_capacity(64 + msg.len());
        out.push_str(prefix);
        out.push(' ');
        if !msg.is_empty() {
            out.push_str(msg);
        }
        for (k, v) in self.fields {
            if k == "log.target" || k == "log.module_path" || k == "log.file" || k == "log.line" {
                continue;
            }
            if out.ends_with(' ') {
            } else {
                out.push(' ');
            }
            out.push_str(&k);
            out.push('=');
            out.push_str(&v);
        }
        Some(out)
    }
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.push(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field.name(), value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field.name(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field.name(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field.name(), value.to_string());
    }
}

impl FieldVisitor {
    fn push(&mut self, name: &str, value: String) {
        if name == "message" {
            self.message = Some(value.trim_matches('"').to_string());
        } else {
            self.fields
                .push((name.to_string(), value.trim_matches('"').to_string()));
        }
    }
}
