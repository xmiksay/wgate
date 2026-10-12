//! Rendering of a device's WireGuard client config.

use std::fmt::Write;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::rights::RuleSet;

pub struct ClientConfig<'a> {
    pub address: Ipv4Addr,
    /// `None` when the user brought their own key pair.
    pub private_key: Option<&'a str>,
    pub hub_public_key: &'a str,
    pub endpoint: SocketAddrV4,
    pub rights: &'a RuleSet,
}

/// `AllowedIPs` is the union of the rights' destinations, so the client only routes
/// what the hub would let through anyway. No DNS is pushed.
pub fn render_client_config(c: &ClientConfig) -> String {
    let mut out = String::from("[Interface]\n");
    match c.private_key {
        Some(key) => {
            let _ = writeln!(out, "PrivateKey = {key}");
        }
        None => out.push_str("# PrivateKey = <the private key of the public key you registered>\n"),
    }
    let _ = write!(
        out,
        "Address = {}/32\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\n",
        c.address, c.hub_public_key, c.endpoint
    );
    let allowed: Vec<String> = c
        .rights
        .destinations()
        .iter()
        .map(|n| n.to_string())
        .collect();
    // An empty `AllowedIPs =` does not parse everywhere; no line means no routes.
    if !allowed.is_empty() {
        let _ = writeln!(out, "AllowedIPs = {}", allowed.join(", "));
    }
    out.push_str("PersistentKeepalive = 25\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::golden::assert_golden;
    use crate::rule::Rule;

    const HUB_PK: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

    fn rights() -> RuleSet {
        let rules: Vec<Rule> = [
            "tcp 172.16.16.1/32 6443",
            "icmp 172.19.9.10/32",
            "icmp 172.19.9.11/32",
            "icmp 172.19.9.12/32",
        ]
        .iter()
        .map(|r| r.parse().unwrap())
        .collect();
        RuleSet::from_rules(&rules)
    }

    fn config<'a>(rights: &'a RuleSet, private_key: Option<&'a str>) -> ClientConfig<'a> {
        ClientConfig {
            address: Ipv4Addr::new(10, 50, 1, 2),
            private_key,
            hub_public_key: HUB_PK,
            endpoint: "37.205.11.119:51831".parse().unwrap(),
            rights,
        }
    }

    #[test]
    fn server_generated_key_golden() {
        let r = rights();
        let key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        assert_golden(
            "client-server-key.conf",
            &render_client_config(&config(&r, Some(key))),
        );
    }

    #[test]
    fn pasted_key_golden() {
        let r = rights();
        assert_golden(
            "client-pasted-key.conf",
            &render_client_config(&config(&r, None)),
        );
    }

    #[test]
    fn no_rights_means_no_allowed_ips() {
        let r = RuleSet::new();
        assert!(!render_client_config(&config(&r, None)).contains("AllowedIPs"));
    }
}
