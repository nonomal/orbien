use super::DnsProvider;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

pub struct CloudflareDns {
    token: String,
    client: reqwest::Client,
}

impl CloudflareDns {
    pub fn new(token: &str) -> Result<Self> {
        Ok(Self {
            token: token.to_string(),
            client: reqwest::Client::new(),
        })
    }

    async fn find_zone(&self, domain: &str) -> Result<(String, String)> {
        let mut name = domain.trim_end_matches('.').to_string();
        loop {
            let url =
                format!("https://api.cloudflare.com/client/v4/zones?name={name}&status=active");
            let resp: CfResp<Vec<CfZone>> = self
                .client
                .get(&url)
                .bearer_auth(&self.token)
                .send()
                .await
                .context("cloudflare list zones")?
                .json()
                .await
                .context("cloudflare zones json")?;
            if !resp.success {
                bail!("cloudflare zones error: {:?}", resp.errors);
            }
            if let Some(z) = resp.result.into_iter().next() {
                return Ok((z.id, z.name));
            }
            if let Some((_, rest)) = name.split_once('.') {
                name = rest.to_string();
            } else {
                break;
            }
        }
        Err(anyhow!("cloudflare zone not found for {domain}"))
    }
}

#[async_trait]
impl DnsProvider for CloudflareDns {
    async fn upsert_txt(&self, host: &str, value: &str) -> Result<String> {
        let host = host.trim_end_matches('.');
        let (zone_id, zone_name) = self.find_zone(host).await?;
        let relative = if host == zone_name {
            "@".to_string()
        } else if let Some(prefix) = host.strip_suffix(&format!(".{zone_name}")) {
            prefix.to_string()
        } else {
            host.to_string()
        };

        let list_url = format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=TXT&name={host}"
        );
        let listed: CfResp<Vec<CfRecord>> = self
            .client
            .get(&list_url)
            .bearer_auth(&self.token)
            .send()
            .await
            .context("cloudflare list txt")?
            .json()
            .await
            .context("cloudflare list txt json")?;

        if let Some(existing) = listed
            .result
            .iter()
            .find(|r| r.content.trim_matches('"') == value)
        {
            return Ok(format!("{zone_id}:{}", existing.id));
        }

        let body = json!({
            "type": "TXT",
            "name": relative,
            "content": value,
            "ttl": 120,
        });
        let create_url =
            format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records");
        let created: CfResp<CfRecord> = self
            .client
            .post(&create_url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .context("cloudflare create txt")?
            .json()
            .await
            .context("cloudflare create txt json")?;
        if !created.success {
            bail!("cloudflare create txt failed: {:?}", created.errors);
        }
        tracing::info!(%host, "cert: cloudflare txt upserted");
        Ok(format!("{zone_id}:{}", created.result.id))
    }

    async fn delete_txt(&self, record_id: &str) -> Result<()> {
        let Some((zone_id, id)) = record_id.split_once(':') else {
            bail!("invalid cloudflare record id");
        };
        let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{id}");
        let resp: CfResp<serde_json::Value> = self
            .client
            .delete(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .context("cloudflare delete txt")?
            .json()
            .await
            .context("cloudflare delete txt json")?;
        if !resp.success {
            tracing::warn!(?resp.errors, "cert: cloudflare delete txt failed");
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct CfResp<T> {
    success: bool,
    #[serde(default)]
    result: T,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct CfZone {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize, Default)]
struct CfRecord {
    #[serde(default)]
    id: String,
    #[serde(default)]
    content: String,
}
