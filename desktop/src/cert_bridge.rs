use crate::cert::{self, IssueStep, Provider, Vendor};
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

pub struct IssueProgress {
    ui: slint::Weak<crate::AppWindow>,
    last: AtomicI32,
}

impl IssueProgress {
    pub fn new(ui: slint::Weak<crate::AppWindow>) -> Arc<Self> {
        Arc::new(Self {
            ui,
            last: AtomicI32::new(-1),
        })
    }

    pub fn report(self: &Arc<Self>, step: IssueStep) {
        let step_i = step as i32;
        let prev = self.last.fetch_max(step_i, Ordering::Relaxed);
        if prev >= step_i {
            return;
        }
        let ui = self.ui.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui.upgrade() {
                if ui.get_cert_issuing() {
                    ui.set_cert_issue_step(step_i);
                }
            }
        });
    }
}

pub fn refresh(ui: &crate::AppWindow) {
    let (certs, keys) = match (
        cert::with_store(|s| s.list_certs()),
        cert::with_store(|s| s.list_providers()),
    ) {
        (Ok(c), Ok(k)) => (c, k),
        (Err(e), _) | (_, Err(e)) => {
            tracing::warn!(error = %e, "cert: refresh failed");
            (Vec::new(), Vec::new())
        }
    };

    let providers = keys;
    let cert_rows: Vec<crate::CertRow> = certs
        .iter()
        .map(|c| {
            let provider_name = providers
                .iter()
                .find(|p| p.id == c.provider_id)
                .map(|p| format!("{} · {}", p.name, vendor_label(p.vendor)))
                .unwrap_or_default();
            crate::CertRow {
                id: c.id.clone().into(),
                domains: c.domains.join(", ").into(),
                not_after: display_not_after(&c.not_after).into(),
                provider_id: c.provider_id.clone().into(),
                provider_name: provider_name.into(),
                expired: is_expired(&c.not_after),
            }
        })
        .collect();

    let key_rows: Vec<crate::KeyRow> = providers
        .iter()
        .map(|p| {
            let mask = cert::with_store(|s| s.get_secret(&p.id))
                .ok()
                .flatten()
                .map(|s| mask_secret(&s))
                .unwrap_or_else(|| "••••••••".into());
            crate::KeyRow {
                id: p.id.clone().into(),
                name: p.name.clone().into(),
                vendor: vendor_label(p.vendor).into(),
                vendor_index: p.vendor.index(),
                access_key_id: p.access_key_id.clone().into(),
                secret_mask: mask.into(),
            }
        })
        .collect();

    let key_labels: Vec<slint::SharedString> = key_rows
        .iter()
        .map(|k| format!("{} · {}", k.name, k.vendor).into())
        .collect();

    let lib_labels: Vec<slint::SharedString> = cert_rows
        .iter()
        .map(|c| format!("{} ({})", c.domains, c.not_after).into())
        .collect();

    ui.set_cert_rows(slint::ModelRc::new(slint::VecModel::from(cert_rows)));
    ui.set_key_rows(slint::ModelRc::new(slint::VecModel::from(key_rows)));
    ui.set_cert_key_labels(slint::ModelRc::new(slint::VecModel::from(key_labels)));
    ui.set_cert_library_labels(slint::ModelRc::new(slint::VecModel::from(lib_labels)));
}

pub fn resolve_library_paths(cert_id: &str) -> Result<(String, String)> {
    cert::with_store(|s| {
        let _ = s
            .get_cert(cert_id)?
            .ok_or_else(|| anyhow::anyhow!("cert not found"))?;
        Ok((
            s.cert_pem_path(cert_id).display().to_string(),
            s.key_pem_path(cert_id).display().to_string(),
        ))
    })
}

pub fn find_library_index(cert_file: &str, key_file: &str) -> Option<i32> {
    let certs = cert::with_store(|s| s.list_certs()).ok()?;
    for (i, c) in certs.iter().enumerate() {
        let (cp, kp) = cert::with_store(|s| {
            Ok((
                s.cert_pem_path(&c.id).display().to_string(),
                s.key_pem_path(&c.id).display().to_string(),
            ))
        })
        .ok()?;
        if paths_eq(cert_file, &cp) && paths_eq(key_file, &kp) {
            return Some(i as i32);
        }
    }
    None
}

pub fn library_cert_id_at(index: i32) -> Option<String> {
    let certs = cert::with_store(|s| s.list_certs()).ok()?;
    certs.get(index as usize).map(|c| c.id.clone())
}

pub fn cert_paths_used_by_tunnels(cert_id: &str, tunnels: &[crate::TunnelRow]) -> bool {
    let Ok((cp, kp)) = resolve_library_paths(cert_id) else {
        return false;
    };
    tunnels.iter().any(|t| {
        t.plugin_tls_term
            && paths_eq(t.plugin_cert_file.as_str(), &cp)
            && paths_eq(t.plugin_key_file.as_str(), &kp)
    })
}

pub fn save_provider(
    id: &str,
    name: &str,
    vendor_index: i32,
    access_key_id: &str,
    secret: &str,
) -> Result<()> {
    let vendor =
        Vendor::from_index(vendor_index).ok_or_else(|| anyhow::anyhow!("invalid vendor"))?;
    let provider = Provider {
        id: id.to_string(),
        name: name.trim().to_string(),
        vendor,
        access_key_id: access_key_id.trim().to_string(),
    };
    let secret_opt = if secret.trim().is_empty() {
        None
    } else {
        Some(secret.trim())
    };
    cert::with_store(|s| {
        s.upsert_provider(provider, secret_opt)?;
        Ok(())
    })
}

pub fn delete_provider(id: &str) -> Result<()> {
    cert::with_store(|s| s.delete_provider(id))
}

pub fn delete_cert(id: &str) -> Result<()> {
    cert::with_store(|s| s.delete_cert(id))
}

fn vendor_label(v: Vendor) -> &'static str {
    match v {
        Vendor::Cloudflare => "Cloudflare",
        Vendor::Aliyun => "Aliyun",
        Vendor::Tencent => "Tencent",
    }
}

fn mask_secret(s: &str) -> String {
    const HEAD: usize = 4;
    const TAIL: usize = 4;
    const MID: &str = "••••••••";
    let chars: Vec<char> = s.trim().chars().collect();
    if chars.len() <= HEAD + TAIL {
        return MID.into();
    }
    let head: String = chars[..HEAD].iter().collect();
    let tail: String = chars[chars.len() - TAIL..].iter().collect();
    format!("{head}{MID}{tail}")
}

fn is_expired(not_after: &str) -> bool {
    parse_time(not_after)
        .map(|t| t < Utc::now())
        .unwrap_or(false)
}

fn display_not_after(not_after: &str) -> String {
    parse_time(not_after)
        .map(|t| t.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| not_after.to_string())
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
        .or_else(|| {
            chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
                .ok()
                .and_then(|d| d.and_hms_opt(0, 0, 0))
                .map(|n| DateTime::<Utc>::from_naive_utc_and_offset(n, Utc))
        })
}

fn paths_eq(a: &str, b: &str) -> bool {
    let na = std::path::Path::new(a.trim());
    let nb = std::path::Path::new(b.trim());
    na == nb
}
