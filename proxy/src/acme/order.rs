//! The account at the CA and the order of one certificate (RFC 8555 sections 7.1 to 7.4).
//!
//! `Session::open` reads the directory and makes (or finds) the account with `termsOfServiceAgreed` and the contact
//! address; from then on every message names the account by its URL. Each message carries a nonce: the one of the last
//! answer (every answer has a `Replay-Nonce`), or one fetched from `newNonce` when there is none. A `badNonce` is
//! answered by signing again with the nonce that came with it, once.
//!
//! `Session::issue` orders the hosts, answers the `http-01` challenge of each authorization that is pending (the file
//! of the key authorization is put in place first, then the challenge is told to go on, then the authorization is
//! looked at until it is valid or invalid, with the pause that `Retry-After` says), waits for the order to be ready,
//! sends the request for the certificate, waits for the order to be valid, and downloads the chain. The tokens, the
//! URLs and the names in what the CA says are checked before they are used. The caller bounds the whole time.

use http::header::LOCATION;
use serde::Deserialize;
use serde_json::json;
use tokio::time::sleep;

use super::Failure;
use super::client::{Client, Reply, Url, problem};
use super::files::Challenges;
use super::jws::{self, Signer};
use super::key::Key;

const BAD_NONCE: &str = "urn:ietf:params:acme:error:badNonce";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

#[derive(Deserialize)]
struct Order {
    status: String,
    #[serde(default)]
    authorizations: Vec<String>,
    finalize: Option<String>,
    certificate: Option<String>,
}

#[derive(Deserialize)]
struct Authorization {
    identifier: Identifier,
    status: String,
    #[serde(default)]
    challenges: Vec<Challenge>,
    #[serde(default)]
    wildcard: bool,
}

#[derive(Deserialize)]
struct Identifier {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

#[derive(Deserialize)]
struct Challenge {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    #[serde(default)]
    token: String,
    error: Option<ProblemDocument>,
}

#[derive(Deserialize)]
struct ProblemDocument {
    #[serde(rename = "type", default)]
    kind: String,
}

/// `reply` if its status is one of `statuses`, else the failure it stands for.
fn expect(reply: Reply, statuses: &[u16]) -> Result<Reply, Failure> {
    if statuses.contains(&reply.status) {
        Ok(reply)
    } else {
        Err(reply.refused())
    }
}

/// An authorization the CA does not accept: the problem its challenge reports, if there is one.
fn rejected(authorization: &Authorization) -> Failure {
    authorization
        .challenges
        .iter()
        .find_map(|challenge| challenge.error.as_ref().filter(|e| !e.kind.is_empty()))
        .map_or(
            Failure::Text("the CA did not accept the authorization"),
            |error| problem(&error.kind),
        )
}

/// The account at the CA, and what it takes to talk to it.
pub struct Session {
    client: Client,
    key: Key,
    new_nonce: Url,
    new_order: Url,
    /// The URL of the account; none until the account is made.
    account: Option<String>,
    /// The nonce of the last answer.
    nonce: Option<String>,
}

impl Session {
    /// Reads the directory at `directory` and makes the account for `key` with the contact address `email`.
    pub async fn open(
        client: Client,
        key: Key,
        directory: &str,
        email: &str,
    ) -> Result<Session, Failure> {
        let reply = expect(client.get(&Url::parse(directory)?).await?, &[200])?;
        let directory: Directory = reply.json()?;
        let new_account = Url::parse(&directory.new_account)?;
        let mut session = Session {
            client,
            key,
            new_nonce: Url::parse(&directory.new_nonce)?,
            new_order: Url::parse(&directory.new_order)?,
            account: None,
            nonce: None,
        };
        let payload = json!({"termsOfServiceAgreed": true, "contact": [format!("mailto:{email}")]});
        let reply = session
            .post(&new_account, payload.to_string().as_bytes())
            .await?;
        let reply = expect(reply, &[200, 201])?;
        let account = reply
            .header(LOCATION.as_str())
            .ok_or("the CA gave no URL for the account")?;
        session.account = Some(Url::parse(account)?.as_str().to_owned());
        Ok(session)
    }

    /// A nonce: the one that the last answer gave, or a new one.
    async fn nonce(&mut self) -> Result<String, Failure> {
        if let Some(nonce) = self.nonce.take() {
            return Ok(nonce);
        }
        let reply = expect(self.client.head(&self.new_nonce).await?, &[200, 204])?;
        reply
            .nonce()
            .ok_or_else(|| "the CA gave no usable nonce".into())
    }

    /// Signs `payload` for `url` and posts it. An empty payload asks for the resource.
    async fn post(&mut self, url: &Url, payload: &[u8]) -> Result<Reply, Failure> {
        let mut again = true;
        loop {
            let nonce = self.nonce().await?;
            let signer = match &self.account {
                Some(account) => Signer::Kid(account),
                None => Signer::Jwk,
            };
            let message = jws::sign(&self.key, signer, &nonce, url.as_str(), payload)?;
            let reply = self.client.post(url, message).await?;
            self.nonce = reply.nonce();
            if again && reply.status == 400 && reply.problem_type().as_deref() == Some(BAD_NONCE) {
                again = false;
                continue;
            }
            return Ok(reply);
        }
    }

    /// The authorization at `url`, and how long to wait before looking again.
    async fn authorization(
        &mut self,
        url: &Url,
    ) -> Result<(Authorization, std::time::Duration), Failure> {
        let reply = expect(self.post(url, b"").await?, &[200])?;
        Ok((reply.json()?, reply.retry_after()))
    }

    /// Makes the authorization at `url` valid, if it is not: the file of the challenge, the word to the CA, and the
    /// wait.
    async fn authorize(
        &mut self,
        url: &Url,
        hosts: &[String],
        challenges: &mut Challenges,
    ) -> Result<(), Failure> {
        let (authorization, _) = self.authorization(url).await?;
        let name = &authorization.identifier;
        if name.kind != "dns"
            || authorization.wildcard
            || !hosts
                .iter()
                .any(|host| host.eq_ignore_ascii_case(&name.value))
        {
            return Err("the CA made an authorization for a name that was not asked for".into());
        }
        match authorization.status.as_str() {
            "valid" => return Ok(()),
            "pending" => {}
            _ => return Err(rejected(&authorization)),
        }
        let challenge = authorization
            .challenges
            .iter()
            .find(|challenge| challenge.kind == "http-01")
            .ok_or("the CA offers no http-01 challenge")?;
        let challenge_url = Url::parse(&challenge.url)?;
        challenges.put(
            &challenge.token,
            &jws::key_authorization(&challenge.token, &self.key),
        )?;
        expect(self.post(&challenge_url, b"{}").await?, &[200])?;
        loop {
            let (authorization, pause) = self.authorization(url).await?;
            match authorization.status.as_str() {
                "valid" => return Ok(()),
                "pending" | "processing" => sleep(pause).await,
                _ => return Err(rejected(&authorization)),
            }
        }
    }

    /// Looks at the order at `url` until its status is `wanted`. An order that has become invalid, or has a status
    /// that the order of events does not have, is a failure.
    async fn wait_for(&mut self, url: &Url, wanted: &str) -> Result<Order, Failure> {
        loop {
            let reply = expect(self.post(url, b"").await?, &[200])?;
            let pause = reply.retry_after();
            let order: Order = reply.json()?;
            if order.status == wanted {
                return Ok(order);
            }
            match order.status.as_str() {
                "pending" | "ready" | "processing" => sleep(pause).await,
                _ => return Err("the CA made the order invalid".into()),
            }
        }
    }

    /// Orders a certificate for `hosts` with the request `csr` (base64, URL-safe) and gives the chain of PEM that the CA
    /// made. The files of the challenges are put in `challenges`, which the caller empties.
    pub async fn issue(
        &mut self,
        hosts: &[String],
        csr: &str,
        challenges: &mut Challenges,
    ) -> Result<Vec<u8>, Failure> {
        let identifiers: Vec<_> = hosts
            .iter()
            .map(|host| json!({"type": "dns", "value": host}))
            .collect();
        let new_order = self.new_order.clone();
        let payload = json!({"identifiers": identifiers}).to_string();
        let reply = expect(self.post(&new_order, payload.as_bytes()).await?, &[201])?;
        let order_url = Url::parse(
            reply
                .header(LOCATION.as_str())
                .ok_or("the CA gave no URL for the order")?,
        )?;
        let order: Order = reply.json()?;
        if order.authorizations.len() > hosts.len() {
            return Err("the CA asks for more authorizations than there are hosts".into());
        }
        for authorization in &order.authorizations {
            self.authorize(&Url::parse(authorization)?, hosts, challenges)
                .await?;
        }
        let order = self.wait_for(&order_url, "ready").await?;
        let finalize = Url::parse(
            order
                .finalize
                .as_deref()
                .ok_or("the order has no URL to finish it")?,
        )?;
        let payload = json!({"csr": csr}).to_string();
        expect(self.post(&finalize, payload.as_bytes()).await?, &[200])?;
        let order = self.wait_for(&order_url, "valid").await?;
        let certificate = Url::parse(
            order
                .certificate
                .as_deref()
                .ok_or("the order has no URL for the certificate")?,
        )?;
        let reply = expect(self.post(&certificate, b"").await?, &[200])?;
        Ok(reply.body)
    }
}

#[cfg(test)]
mod tests;
