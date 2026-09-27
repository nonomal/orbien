use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    ZhCn,
    EnUs,
}

impl Locale {
    pub fn from_index(i: i32) -> Self {
        if i == 1 {
            Self::EnUs
        } else {
            Self::ZhCn
        }
    }
}

fn table(locale: Locale) -> &'static HashMap<&'static str, &'static str> {
    match locale {
        Locale::ZhCn => ZH.get_or_init(|| parse(include_str!("../i18n/zh_CN.properties"))),
        Locale::EnUs => EN.get_or_init(|| parse(include_str!("../i18n/en_US.properties"))),
    }
}

static ZH: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
static EN: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

fn parse(raw: &'static str) -> HashMap<&'static str, &'static str> {
    let mut map = HashMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        map.insert(key.trim(), value.trim());
    }
    map
}

fn msg(locale: Locale, key: &str) -> String {
    table(locale).get(key).copied().unwrap_or(key).to_string()
}

fn msg_fmt(locale: Locale, key: &str, replacements: &[(&str, &str)]) -> String {
    let mut s = msg(locale, key);
    for (from, to) in replacements {
        s = s.replace(from, to);
    }
    s
}

pub fn running_label_zero(locale: Locale) -> String {
    msg(locale, "msg.running-label-zero")
}

pub fn tunnel_name_required(locale: Locale) -> String {
    msg(locale, "msg.tunnel-name-required")
}

pub fn tunnel_domain_required(locale: Locale) -> String {
    msg(locale, "msg.tunnel-domain-required")
}

pub fn tunnel_local_port_required(locale: Locale) -> String {
    msg(locale, "msg.tunnel-local-port-required")
}

pub fn tunnel_remote_port_required(locale: Locale) -> String {
    msg(locale, "msg.tunnel-remote-port-required")
}

pub fn tunnel_local_port_invalid(locale: Locale) -> String {
    msg(locale, "msg.tunnel-local-port-invalid")
}

pub fn tunnel_remote_port_invalid(locale: Locale) -> String {
    msg(locale, "msg.tunnel-remote-port-invalid")
}

pub fn tunnel_name_exists(locale: Locale) -> String {
    msg(locale, "msg.tunnel-name-exists")
}

pub fn tunnel_persist_failed(locale: Locale, err: &str) -> String {
    msg_fmt(locale, "msg.tunnel-persist-failed", &[("{err}", err)])
}

pub fn tunnel_plugin_username_required(locale: Locale) -> String {
    msg(locale, "msg.tunnel-plugin-username-required")
}

pub fn tunnel_plugin_password_required(locale: Locale) -> String {
    msg(locale, "msg.tunnel-plugin-password-required")
}

pub fn cert_saved(locale: Locale) -> String {
    msg(locale, "cert-saved")
}

pub fn cert_deleted(locale: Locale) -> String {
    msg(locale, "cert-deleted")
}

pub fn cert_applied(locale: Locale) -> String {
    msg(locale, "cert-applied")
}

pub fn cert_in_use(locale: Locale) -> String {
    msg(locale, "cert-in-use")
}

pub fn cert_need_key(locale: Locale) -> String {
    msg(locale, "cert-need-key")
}

pub fn cert_domains_required(locale: Locale) -> String {
    msg(locale, "cert-domains-required")
}

pub fn cert_key_name_required(locale: Locale) -> String {
    msg(locale, "cert-key-name-required")
}

pub fn cert_secret_required(locale: Locale) -> String {
    msg(locale, "cert-secret-required")
}

pub fn cert_issue_failed(locale: Locale, err: &str) -> String {
    msg_fmt(locale, "cert-issue-failed", &[("{err}", err)])
}

pub fn cert_issue_timeout(locale: Locale) -> String {
    msg(locale, "cert-issue-timeout")
}

pub fn cert_issue_cancelled(locale: Locale) -> String {
    msg(locale, "cert-issue-cancelled")
}

pub fn tunnel_copied(locale: Locale) -> String {
    msg(locale, "msg.tunnel-copied")
}

pub fn tunnel_copy_failed(locale: Locale) -> String {
    msg(locale, "msg.tunnel-copy-failed")
}

pub fn config_addr_required(locale: Locale) -> String {
    msg(locale, "msg.config-addr-required")
}

pub fn config_port_required(locale: Locale) -> String {
    msg(locale, "msg.config-port-required")
}

pub fn config_port_invalid(locale: Locale) -> String {
    msg(locale, "msg.config-port-invalid")
}

pub fn config_saved(locale: Locale) -> String {
    msg(locale, "msg.config-saved")
}

pub fn config_saved_applied(locale: Locale) -> String {
    msg(locale, "msg.config-saved-applied")
}

pub fn config_saved_reconnecting(locale: Locale) -> String {
    msg(locale, "msg.config-saved-reconnecting")
}

pub fn reload_failed(locale: Locale, err: &str) -> String {
    msg_fmt(locale, "msg.reload-failed", &[("{err}", err)])
}

pub fn reload_partial(locale: Locale) -> String {
    msg(locale, "msg.reload-partial")
}

pub fn config_persist_failed(locale: Locale, err: &str) -> String {
    msg_fmt(locale, "msg.config-persist-failed", &[("{err}", err)])
}

pub fn config_reset(locale: Locale) -> String {
    msg(locale, "msg.config-reset")
}

pub fn client_started(locale: Locale) -> String {
    msg(locale, "msg.client-started")
}

pub fn client_stopped(locale: Locale) -> String {
    msg(locale, "msg.client-stopped")
}

pub fn client_start_failed(locale: Locale, err: &str) -> String {
    msg_fmt(locale, "msg.client-start-failed", &[("{err}", err)])
}

pub fn client_stopped_error(locale: Locale, err: &str) -> String {
    msg_fmt(locale, "msg.client-stopped-error", &[("{err}", err)])
}

pub fn format_uptime(locale: Locale, secs: u64) -> String {
    if secs < 60 {
        msg_fmt(
            locale,
            "msg.uptime-seconds",
            &[("{secs}", &secs.to_string())],
        )
    } else {
        msg_fmt(
            locale,
            "msg.uptime-minutes",
            &[
                ("{mins}", &(secs / 60).to_string()),
                ("{secs}", &(secs % 60).to_string()),
            ],
        )
    }
}
