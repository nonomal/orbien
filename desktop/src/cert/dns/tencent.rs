use super::DnsProvider;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub struct TencentDns {
    secret_id: String,
    secret_key: String,
    client: reqwest::Client,
}

impl TencentDns {
    pub fn new(secret_id: &str, secret_key: &str) -> Result<Self> {
        Ok(Self {
            secret_id: secret_id.to_string(),
            secret_key: secret_key.to_string(),
            client: reqwest::Client::new(),
        })
    }

    async fn call(&self, action: &str, payload: serde_json::Value) -> Result<serde_json::Value> {
        let host = "dnspod.tencentcloudapi.com";
        let service = "dnspod";
        let version = "2021-03-23";
        let timestamp = Utc::now().timestamp();
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let body = payload.to_string();
        let hashed_payload = hex::encode(Sha256::digest(body.as_bytes()));

        let canonical_headers = format!(
            "content-type:application/json; charset=utf-8\nhost:{host}\nx-tc-action:{}\n",
            action.to_lowercase()
        );
        let signed_headers = "content-type;host;x-tc-action";
        let canonical_request =
            format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{hashed_payload}");
        let hashed_canonical = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let credential_scope = format!("{date}/{service}/tc3_request");
        let string_to_sign =
            format!("TC3-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{hashed_canonical}");

        let secret_date = hmac_sha256(
            format!("TC3{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let secret_service = hmac_sha256(&secret_date, service.as_bytes());
        let secret_signing = hmac_sha256(&secret_service, b"tc3_request");
        let signature = hex::encode(hmac_sha256(&secret_signing, string_to_sign.as_bytes()));

        let authorization = format!(
            "TC3-HMAC-SHA256 Credential={}/{}, SignedHeaders={signed_headers}, Signature={signature}",
            self.secret_id, credential_scope
        );

        let url = format!("https://{host}");
        let resp = self
            .client
            .post(&url)
            .header("Authorization", authorization)
            .header("Content-Type", "application/json; charset=utf-8")
            .header("Host", host)
            .header("X-TC-Action", action)
            .header("X-TC-Timestamp", timestamp.to_string())
            .header("X-TC-Version", version)
            .body(body)
            .send()
            .await
            .context("tencent dns request")?;
        let text = resp.text().await.context("tencent dns body")?;
        let v: TcResp =
            serde_json::from_str(&text).with_context(|| format!("tencent dns json: {text}"))?;
        if let Some(err) = v.response.error {
            bail!("tencent dns error: {} - {}", err.code, err.message);
        }
        let mut data = v.response.extra;
        data.as_object_mut().map(|m| {
            m.remove("RequestId");
            m.remove("Error");
        });
        Ok(data)
    }

    async fn find_domain(&self, host: &str) -> Result<(u64, String, String)> {
        let host = host.trim_end_matches('.');
        let listed = self
            .call("DescribeDomainList", json!({"Limit": 100, "Offset": 0}))
            .await?;
        let domains = listed
            .get("DomainList")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut name = host.to_string();
        loop {
            for d in &domains {
                let dn = d.get("Name").and_then(|v| v.as_str()).unwrap_or("");
                let id = d
                    .get("DomainId")
                    .and_then(|v| v.as_u64())
                    .or_else(|| {
                        d.get("DomainId")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse().ok())
                    })
                    .unwrap_or(0);
                if !dn.is_empty() && dn.eq_ignore_ascii_case(&name) {
                    let rr = if host.eq_ignore_ascii_case(&name) {
                        "@".to_string()
                    } else {
                        host.strip_suffix(&format!(".{name}"))
                            .or_else(|| {
                                let lower = name.to_ascii_lowercase();
                                host.strip_suffix(&format!(".{lower}"))
                            })
                            .unwrap_or(host)
                            .to_string()
                    };
                    tracing::info!(%host, domain = %dn, domain_id = id, %rr, "cert: tencent resolve zone");
                    return Ok((id, dn.to_string(), rr));
                }
            }
            if let Some((_, rest)) = name.split_once('.') {
                name = rest.to_string();
            } else {
                break;
            }
        }
        Err(anyhow!("tencent domain not found for {host}"))
    }
}

#[async_trait]
impl DnsProvider for TencentDns {
    async fn upsert_txt(&self, host: &str, value: &str) -> Result<String> {
        let (domain_id, domain, rr) = self.find_domain(host).await?;

        let mut list_body = json!({
            "Domain": domain,
            "Subdomain": rr,
            "RecordType": "TXT",
            "Limit": 100,
        });
        if domain_id > 0 {
            list_body["DomainId"] = json!(domain_id);
        }
        let listed = self.call("DescribeRecordList", list_body).await;
        if let Ok(listed) = listed {
            if let Some(records) = listed.get("RecordList").and_then(|v| v.as_array()) {
                for r in records {
                    let content = r.get("Value").and_then(|v| v.as_str()).unwrap_or("");
                    let id = r.get("RecordId").and_then(|v| v.as_u64()).unwrap_or(0);
                    let record_rr = r.get("Name").and_then(|v| v.as_str()).unwrap_or("");
                    if !record_rr.is_empty() && record_rr != rr {
                        continue;
                    }
                    if content == value && id > 0 {
                        tracing::info!(%host, %id, "cert: tencent txt already present");
                        return Ok(format!("{domain}:{id}"));
                    }
                    if id > 0 {
                        let mut del = json!({
                            "Domain": domain,
                            "RecordId": id,
                        });
                        if domain_id > 0 {
                            del["DomainId"] = json!(domain_id);
                        }
                        let _ = self.call("DeleteRecord", del).await;
                        tracing::info!(%id, "cert: tencent stale txt deleted");
                    }
                }
            }
        }

        let mut create_body = json!({
            "Domain": domain,
            "SubDomain": rr,
            "RecordType": "TXT",
            "RecordLine": "默认",
            "Value": value,
            "TTL": 600,
        });
        if domain_id > 0 {
            create_body["DomainId"] = json!(domain_id);
        }
        let created = self.call("CreateRecord", create_body).await?;
        let id = created
            .get("RecordId")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("tencent missing RecordId"))?;
        tracing::info!(%host, %id, %domain, "cert: tencent txt upserted");
        Ok(format!("{domain}:{id}"))
    }

    async fn delete_txt(&self, record_id: &str) -> Result<()> {
        let (domain, id) = match record_id.split_once(':') {
            Some((d, i)) => (
                d.to_string(),
                i.parse::<u64>().context("tencent record id")?,
            ),
            None => {
                bail!("tencent record id missing domain prefix");
            }
        };
        self.call(
            "DeleteRecord",
            json!({
                "Domain": domain,
                "RecordId": id,
            }),
        )
        .await
        .context("tencent delete txt")?;
        Ok(())
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[derive(Debug, Deserialize)]
struct TcResp {
    #[serde(rename = "Response")]
    response: TcResponse,
}

#[derive(Debug, Deserialize)]
struct TcResponse {
    #[serde(rename = "Error")]
    error: Option<TcError>,
    #[serde(flatten)]
    extra: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct TcError {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}
