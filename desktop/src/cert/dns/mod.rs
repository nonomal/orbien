mod aliyun;
mod cloudflare;
mod tencent;

use crate::cert::model::{Provider, Vendor};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;

#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn upsert_txt(&self, host: &str, value: &str) -> Result<String>;
    async fn delete_txt(&self, record_id: &str) -> Result<()>;
}

pub fn build_provider(provider: &Provider, secret: &str) -> Result<Box<dyn DnsProvider>> {
    let secret = secret.trim();
    if secret.is_empty() {
        bail!("dns secret is empty");
    }
    match provider.vendor {
        Vendor::Cloudflare => Ok(Box::new(cloudflare::CloudflareDns::new(secret)?)),
        Vendor::Aliyun => {
            if provider.access_key_id.trim().is_empty() {
                bail!("accessKeyId is required for aliyun");
            }
            Ok(Box::new(aliyun::AliyunDns::new(
                &provider.access_key_id,
                secret,
            )?))
        }
        Vendor::Tencent => {
            if provider.access_key_id.trim().is_empty() {
                bail!("secretId is required for tencent");
            }
            Ok(Box::new(tencent::TencentDns::new(
                &provider.access_key_id,
                secret,
            )?))
        }
    }
}

pub fn challenge_name(domain: &str) -> String {
    format!("_acme-challenge.{domain}")
}

pub async fn wait_txt_propagated(
    host: &str,
    expected: &str,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<()> {
    let host = host.trim_end_matches('.');
    let expected = expected.trim().trim_matches('"');
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()?;
    let endpoints = [
        format!("https://dns.alidns.com/resolve?name={host}&type=TXT"),
        format!("https://doh.pub/dns-query?name={host}&type=TXT"),
        format!("https://cloudflare-dns.com/dns-query?name={host}&type=TXT"),
    ];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(150);
    let mut attempt = 0u32;
    loop {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            anyhow::bail!("cancelled");
        }
        attempt += 1;
        for url in &endpoints {
            match fetch_txt_answers(&client, url).await {
                Ok(answers) if answers.iter().any(|a| a.trim_matches('"') == expected) => {
                    tracing::info!(%host, attempt, "acme: dns txt visible");
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(error = %e, %url, "acme: doh lookup failed");
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "DNS TXT for {host} not visible after 150s (value may not have propagated)"
            );
        }
        if attempt == 1 || attempt % 5 == 0 {
            tracing::info!(%host, attempt, "acme: waiting dns txt propagation");
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

async fn fetch_txt_answers(client: &reqwest::Client, url: &str) -> Result<Vec<String>> {
    let resp = client
        .get(url)
        .header("Accept", "application/dns-json")
        .send()
        .await
        .context("doh request")?
        .error_for_status()
        .context("doh status")?
        .json::<serde_json::Value>()
        .await
        .context("doh json")?;
    let mut out = Vec::new();
    if let Some(arr) = resp.get("Answer").and_then(|v| v.as_array()) {
        for a in arr {
            if a.get("type").and_then(|t| t.as_u64()) != Some(16) {
                continue;
            }
            if let Some(data) = a.get("data").and_then(|d| d.as_str()) {
                out.push(data.to_string());
            }
        }
    }
    Ok(out)
}
