use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Vendor {
    Cloudflare,
    Aliyun,
    Tencent,
}

impl Vendor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::Aliyun => "aliyun",
            Self::Tencent => "tencent",
        }
    }

    pub fn from_index(i: i32) -> Option<Self> {
        match i {
            0 => Some(Self::Aliyun),
            1 => Some(Self::Tencent),
            2 => Some(Self::Cloudflare),
            _ => None,
        }
    }

    pub fn index(self) -> i32 {
        match self {
            Self::Aliyun => 0,
            Self::Tencent => 1,
            Self::Cloudflare => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub vendor: Vendor,
    #[serde(default, rename = "accessKeyId")]
    pub access_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderFile {
    #[serde(default)]
    pub providers: Vec<Provider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cert {
    pub id: String,
    pub domains: Vec<String>,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "notAfter")]
    pub not_after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertFile {
    #[serde(default)]
    pub certs: Vec<Cert>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretsFile {
    #[serde(default)]
    pub secrets: std::collections::HashMap<String, String>,
}
