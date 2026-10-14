//! Every request wgate makes to an OIDC provider (discovery, its keys, the token
//! exchange): admins name the URLs (and a provider names the next ones), so none of
//! them may reach into the hub's own networks. A host must resolve to public
//! addresses only (an IP literal likewise), unless they are in `oidc_allow_private`
//! (an internal Keycloak); plain `http` only into that list. The addresses checked
//! are the ones connected to (the resolver filters them), so a name cannot be
//! rebound in between to a private address. Answers are capped at [`MAX_BODY`];
//! redirects are not followed, and no proxy is used (a proxy would resolve the name
//! itself, past the filter), whatever `HTTPS_PROXY` says.
//!
//! Residue: plain `http` to a name is checked on what the name resolves to before the
//! request, and resolved again to connect (filtered to public or listed addresses):
//! a name rebound in between may take a plain-http request to a public address,
//! never to a private one outside the list.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ipnet::IpNet;
use openidconnect::reqwest;
use openidconnect::reqwest::dns::{Addrs, Name, Resolve, Resolving};
use openidconnect::{AsyncHttpClient, HttpRequest, HttpResponse};
use url::Url;

/// Discovery documents, key sets and token answers are a few KiB.
pub const MAX_BODY: usize = 1 << 20;

/// Not on the internet: what no provider URL may reach unless allowed.
const NOT_PUBLIC: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/96",
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/23",
    "2001:db8::/32",
    "3fff::/20",
    "2002::/16",
    "fc00::/7",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
];

/// `e` and its sources, for the log: what the provider (or the checks here) said.
pub fn chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        out.push_str(": ");
        out.push_str(&c.to_string());
        cause = c.source();
    }
    out
}

/// The well-known NAT64 prefix: such an address reaches the IPv4 address in its last
/// 32 bits.
const NAT64: &str = "64:ff9b::/96";

pub fn public(ip: IpAddr) -> bool {
    // An IPv4-mapped IPv6 address is its IPv4 address, and so is a NAT64 one.
    let ip = ip.to_canonical();
    if let IpAddr::V6(v6) = ip
        && NAT64.parse::<IpNet>().is_ok_and(|n| n.contains(&ip))
    {
        let [.., a, b, c, d] = v6.octets();
        return public(IpAddr::from([a, b, c, d]));
    }
    !NOT_PUBLIC
        .iter()
        .filter_map(|n| n.parse::<IpNet>().ok())
        .any(|n| n.contains(&ip))
}

#[derive(Clone, Default)]
struct Allow(Arc<Vec<IpNet>>);

impl Allow {
    fn listed(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.0.iter().any(|n| n.contains(&ip))
    }

    fn reachable(&self, ip: IpAddr) -> bool {
        public(ip) || self.listed(ip)
    }
}

impl Resolve for Allow {
    fn resolve(&self, name: Name) -> Resolving {
        let allow = self.clone();
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let found: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|a| allow.reachable(a.ip()))
                .collect();
            if found.is_empty() {
                return Err(format!("{host} resolves to no address a provider may have").into());
            }
            let addrs: Addrs = Box::new(found.into_iter());
            Ok(addrs)
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("refused: {0}")]
    Refused(String),
    #[error("an answer over {MAX_BODY} bytes")]
    TooLarge,
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error(transparent)]
    Http(#[from] openidconnect::http::Error),
}

/// The HTTP client for providers.
#[derive(Clone)]
pub struct Outbound {
    client: reqwest::Client,
    allow: Allow,
}

impl Outbound {
    pub fn new(allow_private: Vec<IpNet>) -> anyhow::Result<Self> {
        let allow = Allow(Arc::new(allow_private));
        let client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .dns_resolver(Arc::new(allow.clone()))
            // A provider that hangs must not hold the discovery lock forever.
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self { client, allow })
    }

    /// Whether `url` may be asked at all, before anything connects.
    async fn check(&self, url: &Url) -> Result<(), Error> {
        let refused = |why: &str| Err(Error::Refused(format!("{url}: {why}")));
        let https = match url.scheme() {
            "https" => true,
            "http" => false,
            _ => return refused("neither https nor http"),
        };
        let ips: Vec<IpAddr> = match url.host() {
            Some(url::Host::Ipv4(a)) => vec![a.into()],
            Some(url::Host::Ipv6(a)) => vec![a.into()],
            // The resolver checks what a name resolves to; plain http needs all of it
            // in the list.
            Some(url::Host::Domain(_)) if https => return Ok(()),
            Some(url::Host::Domain(d)) => tokio::net::lookup_host((d, 0))
                .await
                .map_err(|e| Error::Refused(format!("{url}: {e}")))?
                .map(|a| a.ip())
                .collect(),
            None => return refused("no host"),
        };
        let ok = |ip: &IpAddr| {
            if https {
                self.allow.reachable(*ip)
            } else {
                self.allow.listed(*ip)
            }
        };
        if ips.is_empty() || !ips.iter().all(ok) {
            return refused(if https {
                "not a public address (see oidc_allow_private)"
            } else {
                "plain http outside oidc_allow_private"
            });
        }
        Ok(())
    }

    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, Error> {
        let request: reqwest::Request = request.try_into()?;
        self.check(request.url()).await?;
        let mut response = self.client.execute(request).await?;
        let mut builder = openidconnect::http::Response::builder().status(response.status());
        for (name, value) in response.headers() {
            builder = builder.header(name, value);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(Error::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(builder.body(body)?)
    }
}

impl<'c> AsyncHttpClient<'c> for Outbound {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send + Sync + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(self.send(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_are_public() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.19.9.11",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::808:808",
            "3fff::1",
        ] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "142.250.1.1",
            "2a00:1450::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(public(ip.parse().unwrap()), "{ip}");
        }
        assert!(NOT_PUBLIC.iter().all(|n| n.parse::<IpNet>().is_ok()));
    }

    #[tokio::test]
    async fn urls_are_checked_before_anything_connects() {
        let none = Outbound::new(vec![]).unwrap();
        let lan = Outbound::new(vec!["10.0.0.0/8".parse().unwrap()]).unwrap();
        let url = |s: &str| Url::parse(s).unwrap();
        for bad in [
            "https://127.0.0.1/x",
            "https://[::1]/x",
            "https://[::ffff:10.0.0.1]/x",
            "https://169.254.169.254/latest",
            "http://8.8.8.8/x",
            "http://localhost/x",
            "ftp://8.8.8.8/x",
        ] {
            assert!(none.check(&url(bad)).await.is_err(), "{bad}");
        }
        for bad in [
            "https://0x7f.1/",
            "https://127.1/",
            "https://[::127.0.0.1]/",
        ] {
            assert!(none.check(&url(bad)).await.is_err(), "{bad}");
        }
        assert!(none.check(&url("https://8.8.8.8/x")).await.is_ok());
        assert!(lan.check(&url("http://10.1.1.1/x")).await.is_ok());
        assert!(lan.check(&url("https://10.1.1.1/x")).await.is_ok());
        assert!(lan.check(&url("http://192.168.1.1/x")).await.is_err());
        assert!(lan.check(&url("http://8.8.8.8/x")).await.is_err());
    }

    #[tokio::test]
    async fn the_resolver_drops_private_addresses() {
        use std::str::FromStr;
        let name = || Name::from_str("localhost").unwrap();
        assert!(Allow::default().resolve(name()).await.is_err());
        let lo = Allow(Arc::new(vec![
            "127.0.0.0/8".parse().unwrap(),
            "::1/128".parse().unwrap(),
        ]));
        let found: Vec<SocketAddr> = lo.resolve(name()).await.unwrap().collect();
        assert!(!found.is_empty() && found.iter().all(|a| a.ip().is_loopback()));
    }

    const CHILD: &str = "WGATE_PROXY_CHILD";

    /// A proxy from the environment is never used: a request for an internal name
    /// fails here and never reaches the proxy, which would resolve it unfiltered. The
    /// environment is the child process's own (see the test below), so no other test
    /// sees it.
    #[test]
    fn proxies_from_the_environment_are_ignored() {
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let at = format!("http://{}", proxy.local_addr().unwrap());
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "auth::outbound::tests::through_a_proxy_env",
            ])
            .env(CHILD, "1")
            .env("HTTPS_PROXY", &at)
            .env("HTTP_PROXY", &at)
            .env("ALL_PROXY", &at)
            .env("https_proxy", &at)
            .env("http_proxy", &at)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "the child did not run or failed: {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        proxy.set_nonblocking(true).unwrap();
        assert!(
            proxy
                .accept()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock),
            "the proxy was asked"
        );
    }

    #[tokio::test]
    #[ignore = "run by proxies_from_the_environment_are_ignored, with a proxy env"]
    async fn through_a_proxy_env() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        let out = Outbound::new(vec![]).unwrap();
        let request = openidconnect::http::Request::get("https://localhost:9/x")
            .body(Vec::new())
            .unwrap();
        let err = out.send(request).await.unwrap_err();
        let why = chain(&err);
        assert!(
            why.contains("resolves to no address a provider may have"),
            "not the resolver's refusal: {why}"
        );
    }
}
