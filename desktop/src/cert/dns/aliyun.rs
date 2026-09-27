use super::DnsProvider;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha1::Sha1;
use std::collections::BTreeMap;
use uuid::Uuid;

type HmacSha1 = Hmac<Sha1>;

const ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub struct AliyunDns {
    access_key_id: String,
    access_key_secret: String,
    client: reqwest::Client,
}

impl AliyunDns {
    pub fn new(access_key_id: &str, access_key_secret: &str) -> Result<Self> {
        Ok(Self {
            access_key_id: access_key_id.to_string(),
            access_key_secret: access_key_secret.to_string(),
            client: reqwest::Client::new(),
        })
    }

    fn sign(&self, params: &BTreeMap<String, String>) -> String {
        let canonical: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
            .collect::<Vec<_>>()
            .join("&");
        let string_to_sign = format!("GET&{}&{}", enc("/"), enc(&canonical));
        let mut mac = HmacSha1::new_from_slice(format!("{}&", self.access_key_secret).as_bytes())
            .expect("hmac");
        mac.update(string_to_sign.as_bytes());
        B64.encode(&mac.finalize().into_bytes())
    }

    async fn call(&self, mut params: BTreeMap<String, String>) -> Result<serde_json::Value> {
        params.insert("Format".into(), "JSON".into());
        params.insert("Version".into(), "2015-01-09".into());
        params.insert("AccessKeyId".into(), self.access_key_id.clone());
        params.insert("SignatureMethod".into(), "HMAC-SHA1".into());
        params.insert(
            "Timestamp".into(),
            Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        );
        params.insert("SignatureVersion".into(), "1.0".into());
        params.insert("SignatureNonce".into(), Uuid::new_v4().to_string());
        let signature = self.sign(&params);
        params.insert("Signature".into(), signature);

        let query: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
            .collect::<Vec<_>>()
            .join("&");
        let url = format!("https://alidns.aliyuncs.com/?{query}");
        let text = self
            .client
            .get(&url)
            .send()
            .await
            .context("aliyun dns request")?
            .text()
            .await
            .context("aliyun dns body")?;
        let v: serde_json::Value =
            serde_json::from_str(&text).with_context(|| format!("aliyun dns json: {text}"))?;
        if v.get("Code").is_some() {
            bail!("aliyun dns error: {text}");
        }
        Ok(v)
    }

    async fn find_domain(&self, host: &str) -> Result<(String, String)> {
        let host = host.trim_end_matches('.');
        let mut name = host.to_string();
        loop {
            let mut params = BTreeMap::new();
            params.insert("Action".into(), "DescribeDomainInfo".into());
            params.insert("DomainName".into(), name.clone());
            match self.call(params).await {
                Ok(_) => {
                    let rr = if host == name {
                        "@".to_string()
                    } else {
                        host.strip_suffix(&format!(".{name}"))
                            .unwrap_or(host)
                            .to_string()
                    };
                    return Ok((name, rr));
                }
                Err(_) => {
                    if let Some((_, rest)) = name.split_once('.') {
                        name = rest.to_string();
                    } else {
                        break;
                    }
                }
            }
        }
        Err(anyhow!("aliyun domain not found for {host}"))
    }
}

#[async_trait]
impl DnsProvider for AliyunDns {
    async fn upsert_txt(&self, host: &str, value: &str) -> Result<String> {
        let (domain, rr) = self.find_domain(host).await?;
        tracing::info!(%host, %domain, %rr, "cert: aliyun resolve zone");

        let mut params = BTreeMap::new();
        params.insert("Action".into(), "DescribeDomainRecords".into());
        params.insert("DomainName".into(), domain.clone());
        params.insert("RRKeyWord".into(), rr.clone());
        params.insert("Type".into(), "TXT".into());
        let listed = self.call(params).await?;
        let records = domain_records(&listed);
        for r in &records {
            let content = r.get("Value").and_then(|v| v.as_str()).unwrap_or("");
            let id = r.get("RecordId").and_then(|v| v.as_str()).unwrap_or("");
            let record_rr = r.get("RR").and_then(|v| v.as_str()).unwrap_or("");
            if record_rr != rr || id.is_empty() {
                continue;
            }
            if content == value {
                tracing::info!(%host, %id, "cert: aliyun txt already present");
                return Ok(id.to_string());
            }
            let mut del = BTreeMap::new();
            del.insert("Action".into(), "DeleteDomainRecord".into());
            del.insert("RecordId".into(), id.to_string());
            let _ = self.call(del).await;
            tracing::info!(%id, "cert: aliyun stale txt deleted");
        }

        let mut params = BTreeMap::new();
        params.insert("Action".into(), "AddDomainRecord".into());
        params.insert("DomainName".into(), domain);
        params.insert("RR".into(), rr);
        params.insert("Type".into(), "TXT".into());
        params.insert("Value".into(), value.to_string());
        params.insert("TTL".into(), "600".into());
        let created = self.call(params).await?;
        let id = created
            .get("RecordId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("aliyun missing RecordId"))?
            .to_string();
        tracing::info!(%host, %id, "cert: aliyun txt upserted");
        Ok(id)
    }

    async fn delete_txt(&self, record_id: &str) -> Result<()> {
        let mut params = BTreeMap::new();
        params.insert("Action".into(), "DeleteDomainRecord".into());
        params.insert("RecordId".into(), record_id.to_string());
        self.call(params).await.context("aliyun delete txt")?;
        Ok(())
    }
}

fn domain_records(listed: &serde_json::Value) -> Vec<serde_json::Value> {
    match listed.pointer("/DomainRecords/Record") {
        Some(serde_json::Value::Array(arr)) => arr.clone(),
        Some(obj) if obj.is_object() => vec![obj.clone()],
        _ => Vec::new(),
    }
}

fn enc(s: &str) -> String {
    utf8_percent_encode(s, ENCODE_SET).to_string()
}
