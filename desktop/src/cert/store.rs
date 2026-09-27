use super::model::{Cert, CertFile, Provider, ProviderFile, SecretsFile};
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub struct Store {
    root: PathBuf,
}

impl Clone for Store {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
        }
    }
}

impl Store {
    pub fn open(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(root.join("certs")).context("create certs dir")?;
        fs::create_dir_all(root.join("acme")).context("create acme dir")?;
        Ok(Self { root })
    }

    fn providers_path(&self) -> PathBuf {
        self.root.join("providers.json")
    }

    fn secrets_path(&self) -> PathBuf {
        self.root.join("secrets.json")
    }

    fn certs_index_path(&self) -> PathBuf {
        self.root.join("certs").join("index.json")
    }

    pub fn cert_dir(&self, id: &str) -> PathBuf {
        self.root.join("certs").join(id)
    }

    pub fn cert_pem_path(&self, id: &str) -> PathBuf {
        self.cert_dir(id).join("fullchain.pem")
    }

    pub fn key_pem_path(&self, id: &str) -> PathBuf {
        self.cert_dir(id).join("privkey.pem")
    }

    pub fn acme_account_path(&self) -> PathBuf {
        self.root.join("acme").join("account.json")
    }

    #[allow(dead_code)]
    pub fn acme_staging_account_path(&self) -> PathBuf {
        self.root.join("acme").join("account-staging.json")
    }

    pub fn list_providers(&self) -> Result<Vec<Provider>> {
        Ok(self.load_providers()?.providers)
    }

    pub fn list_certs(&self) -> Result<Vec<Cert>> {
        Ok(self.load_certs()?.certs)
    }

    pub fn get_provider(&self, id: &str) -> Result<Option<Provider>> {
        Ok(self.list_providers()?.into_iter().find(|p| p.id == id))
    }

    pub fn get_cert(&self, id: &str) -> Result<Option<Cert>> {
        Ok(self.list_certs()?.into_iter().find(|c| c.id == id))
    }

    pub fn get_secret(&self, provider_id: &str) -> Result<Option<String>> {
        let file = self.load_secrets()?;
        Ok(file.secrets.get(provider_id).cloned())
    }

    pub fn upsert_provider(
        &self,
        mut provider: Provider,
        secret: Option<&str>,
    ) -> Result<Provider> {
        if provider.name.trim().is_empty() {
            bail!("name is required");
        }
        let mut file = self.load_providers()?;
        if provider.id.is_empty() {
            provider.id = new_id("p");
            if secret.map(|s| s.trim().is_empty()).unwrap_or(true) {
                bail!("secret is required");
            }
            file.providers.push(provider.clone());
        } else if let Some(slot) = file.providers.iter_mut().find(|p| p.id == provider.id) {
            *slot = provider.clone();
        } else {
            bail!("provider not found");
        }

        if let Some(s) = secret {
            let s = s.trim();
            if !s.is_empty() {
                let mut secrets = self.load_secrets()?;
                secrets.secrets.insert(provider.id.clone(), s.to_string());
                self.save_secrets(&secrets)?;
            }
        }
        self.save_providers(&file)?;
        tracing::info!(id = %provider.id, vendor = %provider.vendor.as_str(), "cert: provider saved");
        Ok(provider)
    }

    pub fn delete_provider(&self, id: &str) -> Result<()> {
        let mut file = self.load_providers()?;
        let before = file.providers.len();
        file.providers.retain(|p| p.id != id);
        if file.providers.len() == before {
            bail!("provider not found");
        }
        self.save_providers(&file)?;
        let mut secrets = self.load_secrets()?;
        secrets.secrets.remove(id);
        self.save_secrets(&secrets)?;
        tracing::info!(%id, "cert: provider deleted");
        Ok(())
    }

    pub fn add_cert(&self, cert: Cert, fullchain_pem: &str, key_pem: &str) -> Result<()> {
        let dir = self.cert_dir(&cert.id);
        fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
        let cert_path = self.cert_pem_path(&cert.id);
        let key_path = self.key_pem_path(&cert.id);
        fs::write(&cert_path, fullchain_pem)
            .with_context(|| format!("write {}", cert_path.display()))?;
        fs::write(&key_path, key_pem).with_context(|| format!("write {}", key_path.display()))?;
        set_private_mode(&key_path)?;

        let mut file = self.load_certs()?;
        file.certs.retain(|c| c.id != cert.id);
        file.certs.insert(0, cert.clone());
        self.save_certs(&file)?;
        tracing::info!(
            id = %cert.id,
            domains = ?cert.domains,
            "cert: certificate saved"
        );
        Ok(())
    }

    pub fn delete_cert(&self, id: &str) -> Result<()> {
        let mut file = self.load_certs()?;
        let before = file.certs.len();
        file.certs.retain(|c| c.id != id);
        if file.certs.len() == before {
            bail!("cert not found");
        }
        self.save_certs(&file)?;
        let dir = self.cert_dir(id);
        if dir.exists() {
            let _ = fs::remove_dir_all(&dir);
        }
        tracing::info!(%id, "cert: certificate deleted");
        Ok(())
    }

    fn load_providers(&self) -> Result<ProviderFile> {
        read_json_or_default(&self.providers_path())
    }

    fn save_providers(&self, file: &ProviderFile) -> Result<()> {
        write_json_atomic(&self.providers_path(), file)
    }

    fn load_certs(&self) -> Result<CertFile> {
        read_json_or_default(&self.certs_index_path())
    }

    fn save_certs(&self, file: &CertFile) -> Result<()> {
        write_json_atomic(&self.certs_index_path(), file)
    }

    fn load_secrets(&self) -> Result<SecretsFile> {
        read_json_or_default(&self.secrets_path())
    }

    fn save_secrets(&self, file: &SecretsFile) -> Result<()> {
        write_json_atomic(&self.secrets_path(), file)?;
        set_private_mode(&self.secrets_path())?;
        Ok(())
    }
}

pub fn new_id(prefix: &str) -> String {
    format!(
        "{prefix}_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    )
}

fn read_json_or_default<T: serde::de::DeserializeOwned + Default>(path: &Path) -> Result<T> {
    if !path.exists() {
        return Ok(T::default());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(T::default());
    }
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn write_json_atomic<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(value).context("serialize json")?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &raw).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

fn set_private_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    #[cfg(windows)]
    {
        let _ = path;
    }
    Ok(())
}
