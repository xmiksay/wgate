//! Rendering of a device's WireGuard client config.

use std::fmt::Write;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::rights::RuleSet;
use crate::rule::Service;

pub struct ClientConfig<'a> {
    pub address: Ipv4Addr,
    /// The network's hub address, source of the hub's ICMP errors.
    pub hub_address: Ipv4Addr,
    /// `None` when the user brought their own key pair.
    pub private_key: Option<&'a str>,
    pub hub_public_key: &'a str,
    /// `host:port`, as the client dials it.
    pub endpoint: &'a str,
    /// What the endpoint's host resolves to: never routed into the tunnel (that would
    /// loop the handshake).
    pub endpoint_ips: &'a [Ipv4Addr],
    /// Resolvers for the client; none = no `DNS` line.
    pub dns: &'a [Ipv4Addr],
    /// What the device may open.
    pub outbound: &'a RuleSet,
    /// Who may open connections to the device; their replies must route back.
    pub inbound: &'a RuleSet,
}

/// `AllowedIPs` is the union of the outbound destinations and the inbound sources,
/// so the client only routes what the hub would let through anyway, plus the hub
/// address (else the client would drop the hub's ICMP errors). The endpoint is
/// left out: routing it into the tunnel would loop the handshake.
///
/// Inbound sources are routed into the tunnel so replies reach them; a broad source
/// (e.g. `0.0.0.0/0`) therefore makes the tunnel a full tunnel.
pub fn render_client_config(c: &ClientConfig) -> String {
    let mut out = String::from("[Interface]\n");
    match c.private_key {
        Some(key) => {
            let _ = writeln!(out, "PrivateKey = {key}");
        }
        None => out.push_str("# PrivateKey = <the private key of the public key you registered>\n"),
    }
    let _ = writeln!(out, "Address = {}/32", c.address);
    if !c.dns.is_empty() {
        let dns: Vec<String> = c.dns.iter().map(Ipv4Addr::to_string).collect();
        let _ = writeln!(out, "DNS = {}", dns.join(", "));
    }
    let _ = write!(
        out,
        "\n[Peer]\nPublicKey = {}\nEndpoint = {}\n",
        c.hub_public_key, c.endpoint
    );
    let hub = RuleSet::for_nets(&[Ipv4Net::from(c.hub_address)], Service::Icmp);
    let allowed: Vec<String> = c
        .outbound
        .union(c.inbound)
        .union(&hub)
        .addresses(
            &c.endpoint_ips
                .iter()
                .map(|ip| Ipv4Net::from(*ip))
                .collect::<Vec<_>>(),
        )
        .iter()
        .map(|n| n.to_string())
        .collect();
    let _ = writeln!(out, "AllowedIPs = {}", allowed.join(", "));
    out.push_str("PersistentKeepalive = 25\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{assert_golden, rule_set};

    const HUB_PK: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

    fn rights() -> RuleSet {
        rule_set(&[
            "tcp 172.16.16.1/32 6443",
            "icmp 172.19.9.10/32",
            "icmp 172.19.9.11/32",
            "icmp 172.19.9.12/32",
        ])
    }

    const NONE: &RuleSet = &RuleSet::new();
    const ENDPOINT_IPS: &[Ipv4Addr] = &[Ipv4Addr::new(37, 205, 11, 119)];

    fn config<'a>(outbound: &'a RuleSet, private_key: Option<&'a str>) -> ClientConfig<'a> {
        ClientConfig {
            address: Ipv4Addr::new(10, 50, 1, 2),
            hub_address: Ipv4Addr::new(10, 50, 1, 1),
            private_key,
            hub_public_key: HUB_PK,
            endpoint: "vpn.mmik.cz:51831",
            endpoint_ips: ENDPOINT_IPS,
            dns: &[],
            outbound,
            inbound: NONE,
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
    fn endpoint_is_never_routed_into_the_tunnel() {
        let r = rule_set(&["tcp 37.205.11.118/31 443"]);
        let out = render_client_config(&config(&r, None));
        assert!(
            out.contains("AllowedIPs = 10.50.1.1/32, 37.205.11.118/32\n"),
            "{out}"
        );
    }

    #[test]
    fn inbound_sources_are_routed_back() {
        let out_rights = rule_set(&["tcp 10.50.2.0/24 22"]);
        let inbound = rule_set(&["tcp 10.244.0.0/16 8080"]);
        let c = ClientConfig {
            inbound: &inbound,
            ..config(&out_rights, None)
        };
        let out = render_client_config(&c);
        assert!(
            out.contains("AllowedIPs = 10.50.1.1/32, 10.50.2.0/24, 10.244.0.0/16\n"),
            "{out}"
        );
    }

    #[test]
    fn dns_is_pushed_when_the_network_has_some() {
        let r = RuleSet::new();
        let dns = [Ipv4Addr::new(10, 50, 1, 1), Ipv4Addr::new(1, 1, 1, 1)];
        let c = ClientConfig {
            dns: &dns,
            ..config(&r, None)
        };
        let out = render_client_config(&c);
        assert!(
            out.contains("Address = 10.50.1.2/32\nDNS = 10.50.1.1, 1.1.1.1\n"),
            "{out}"
        );
        assert!(!render_client_config(&config(&r, None)).contains("DNS"));
    }

    #[test]
    fn no_rights_route_only_the_hub_address() {
        let r = RuleSet::new();
        let out = render_client_config(&config(&r, None));
        assert!(out.contains("AllowedIPs = 10.50.1.1/32\n"), "{out}");
    }
}
