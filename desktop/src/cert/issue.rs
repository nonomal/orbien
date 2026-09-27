use super::dns::{self, DnsProvider};
use super::model::Cert;
use super::store::{self, Store};
use anyhow::{bail, Context, Result};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const ISSUE_TIMEOUT: Duration = Duration::from_secs(360);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum IssueStep {
    Prepare = 0,
    Order = 1,
    DnsWrite = 2,
    DnsWait = 3,
    Validate = 4,
    Finalize = 5,
    Cleanup = 6,
}

pub struct IssueRequest {
    pub domains: Vec<String>,
    pub provider_id: String,
}

struct PendingTxt {
    host: String,
    value: String,
    record_id: String,
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        bail!("cancelled");
    }
    Ok(())
}

async fn until_cancel<T, E>(
    cancel: &AtomicBool,
    fut: impl Future<Output = Result<T, E>>,
) -> Result<T>
where
    E: Into<anyhow::Error>,
{
    tokio::pin!(fut);
    loop {
        tokio::select! {
            biased;
            r = &mut fut => return r.map_err(Into::into),
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                check_cancel(cancel)?;
            }
        }
    }
}

pub async fn issue(
    store: &Store,
    req: IssueRequest,
    cancel: Arc<AtomicBool>,
    mut on_step: impl FnMut(IssueStep) + Send,
) -> Result<Cert> {
    let domains: Vec<String> = req
        .domains
        .iter()
        .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    if domains.is_empty() {
        bail!("domains is required");
    }
    for d in &domains {
        if d.contains('*') || d.contains(' ') || !d.contains('.') {
            bail!("invalid domain: {d}");
        }
    }

    let provider = store
        .get_provider(&req.provider_id)?
        .ok_or_else(|| anyhow::anyhow!("provider not found"))?;
    let secret = store
        .get_secret(&req.provider_id)?
        .ok_or_else(|| anyhow::anyhow!("provider secret not found"))?;
    let dns = dns::build_provider(&provider, &secret)?;

    tracing::info!(domains = ?domains, provider = %provider.id, "acme: issue start");

    on_step(IssueStep::Prepare);
    check_cancel(&cancel)?;
    let account = load_or_create_account(store).await?;
    check_cancel(&cancel)?;

    on_step(IssueStep::Order);
    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("acme new_order")?;
    check_cancel(&cancel)?;

    on_step(IssueStep::DnsWrite);
    let mut pending: Vec<PendingTxt> = Vec::new();
    let result = async {
        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                check_cancel(&cancel)?;
                let mut authz = result.context("acme authorizations")?;
                match authz.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    other => bail!("unexpected authorization status: {other:?}"),
                }

                let challenge = authz
                    .challenge(ChallengeType::Dns01)
                    .ok_or_else(|| anyhow::anyhow!("dns-01 challenge missing"))?;

                let identifier = challenge.identifier().to_string();
                let value = challenge.key_authorization().dns_value();
                let host = dns::challenge_name(&identifier);
                tracing::info!(%host, "acme: upsert dns txt");
                let record_id = dns.upsert_txt(&host, &value).await?;
                tracing::info!(%host, %record_id, "acme: dns txt upserted");
                pending.push(PendingTxt {
                    host,
                    value,
                    record_id,
                });
            }
        }

        on_step(IssueStep::DnsWait);
        for p in &pending {
            check_cancel(&cancel)?;
            dns::wait_txt_propagated(&p.host, &p.value, &cancel)
                .await
                .context("wait dns propagation")?;
        }

        on_step(IssueStep::Validate);
        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                check_cancel(&cancel)?;
                let mut authz = result.context("acme authorizations")?;
                if authz.status == AuthorizationStatus::Valid {
                    continue;
                }
                let Some(mut challenge) = authz.challenge(ChallengeType::Dns01) else {
                    continue;
                };
                challenge
                    .set_ready()
                    .await
                    .context("acme set_challenge_ready")?;
            }
        }

        let status = until_cancel(
            &cancel,
            order.poll_ready(&RetryPolicy::new().timeout(Duration::from_secs(180))),
        )
        .await
        .context("acme poll_ready")?;
        if status != OrderStatus::Ready {
            bail!("acme order not ready: {status:?}");
        }
        check_cancel(&cancel)?;

        on_step(IssueStep::Finalize);
        let private_key_pem = until_cancel(&cancel, order.finalize())
            .await
            .context("acme finalize")?;
        let cert_chain_pem = until_cancel(
            &cancel,
            order.poll_certificate(&RetryPolicy::new().timeout(Duration::from_secs(120))),
        )
        .await
        .context("acme certificate")?;

        let not_after = (chrono::Utc::now() + chrono::Duration::days(90))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let cert = Cert {
            id: store::new_id("c"),
            domains,
            provider_id: req.provider_id,
            not_after,
        };
        store.add_cert(cert.clone(), &cert_chain_pem, &private_key_pem)?;
        tracing::info!(id = %cert.id, "acme: issue ok");
        Ok(cert)
    }
    .await;

    let record_ids: Vec<String> = pending.iter().map(|p| p.record_id.clone()).collect();
    if !record_ids.is_empty() {
        on_step(IssueStep::Cleanup);
        cleanup_dns(dns.as_ref(), &record_ids).await;
    }
    result
}

async fn cleanup_dns(dns: &dyn DnsProvider, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    tracing::info!(count = ids.len(), "acme: cleanup dns txt");
    for id in ids {
        match dns.delete_txt(id).await {
            Ok(()) => tracing::info!(record = %id, "acme: dns txt deleted"),
            Err(e) => tracing::warn!(error = %e, record = %id, "acme: cleanup txt failed"),
        }
    }
}

async fn load_or_create_account(store: &Store) -> Result<Account> {
    let path = store.acme_account_path();
    let directory_url = LetsEncrypt::Production.url().to_owned();

    let builder = Account::builder().context("acme account builder")?;

    if path.exists() {
        let raw = std::fs::read_to_string(&path).context("read acme account")?;
        let creds: instant_acme::AccountCredentials =
            serde_json::from_str(&raw).context("parse acme account")?;
        let account = builder
            .from_credentials(creds)
            .await
            .context("acme from_credentials")?;
        tracing::info!("acme: production account loaded");
        return Ok(account);
    }

    let (account, creds) = builder
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
        .await
        .context("acme create account")?;

    let raw = serde_json::to_string_pretty(&creds).context("serialize acme account")?;
    std::fs::write(&path, raw).context("write acme account")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
    }
    tracing::info!("acme: production account created");
    Ok(account)
}
