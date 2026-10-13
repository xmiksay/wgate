//! What the kernel's `table inet wgate` holds, from `nft -j`: the networks registered
//! in the `from_net` dispatch map (interface → `jump n<id>_from`) and the addresses in
//! an interval set.

use std::net::Ipv4Addr;

use anyhow::Context;
use ipnet::{Ipv4Net, Ipv4Subnets};
use serde_json::Value;
use wgate_core::{Id, network_of_chain};

/// (interface, network id) for every registered network.
pub fn parse(json: &str) -> anyhow::Result<Vec<(String, Id)>> {
    let v: Value = serde_json::from_str(json).context("nft -j")?;
    let mut out = Vec::new();
    for item in v["nftables"].as_array().context("no nftables array")? {
        let Some(elems) = item["map"]["elem"].as_array() else {
            continue;
        };
        for e in elems {
            // One element that is not wgate's (added by hand) must not hide the rest.
            let parsed = e[0]
                .as_str()
                .zip(e[1]["jump"]["target"].as_str().and_then(network_of_chain));
            match parsed {
                Some((iface, id)) => out.push((iface.to_owned(), id)),
                None => tracing::warn!(element = %e, "unknown from_net element skipped"),
            }
        }
    }
    Ok(out)
}

/// The addresses of an interval set (`nft -j list set …`), as networks.
pub fn parse_ranges(json: &str) -> anyhow::Result<Vec<Ipv4Net>> {
    let v: Value = serde_json::from_str(json).context("nft -j")?;
    let addr = |v: &Value| -> anyhow::Result<Ipv4Addr> {
        v.as_str()
            .context("set element")?
            .parse()
            .context("set element")
    };
    let mut out = Vec::new();
    for item in v["nftables"].as_array().context("no nftables array")? {
        for e in item["set"]["elem"].as_array().into_iter().flatten() {
            if let Some(p) = e.get("prefix") {
                let len = p["len"].as_u64().context("prefix length")?;
                out.push(Ipv4Net::new(addr(&p["addr"])?, u8::try_from(len)?)?.trunc());
            } else if let Some(r) = e.get("range") {
                out.extend(Ipv4Subnets::new(addr(&r[0])?, addr(&r[1])?, 0));
            } else {
                out.push(Ipv4Net::from(addr(e)?));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_registered_networks() {
        let json = r#"{"nftables": [{"metainfo": {"version": "1.1.7", "json_schema_version": 1}}, {"map": {"family": "inet", "name": "from_net", "table": "wgate", "type": "ifname", "handle": 3, "map": "verdict", "elem": [["wg-a", {"jump": {"target": "n1_from"}}], ["wg-bb", {"jump": {"target": "n12_from"}}]]}}]}"#;
        assert_eq!(
            parse(json).unwrap(),
            [("wg-a".into(), 1), ("wg-bb".into(), 12)]
        );
        let empty =
            r#"{"nftables": [{"metainfo": {}}, {"map": {"name": "from_net", "map": "verdict"}}]}"#;
        assert!(parse(empty).unwrap().is_empty());
        let odd = r#"{"nftables": [{"map": {"name": "from_net", "elem": [["wg-x", "accept"], ["wg-a", {"jump": {"target": "n1_from"}}]]}}]}"#;
        assert_eq!(parse(odd).unwrap(), [("wg-a".into(), 1)]);
    }

    #[test]
    fn parses_set_ranges() {
        let json = r#"{"nftables": [{"metainfo": {"version": "1.1.7"}}, {"set": {"name": "tenant_space", "flags": ["interval"], "elem": [{"prefix": {"addr": "10.50.0.0", "len": 16}}, "10.60.0.1", {"range": ["10.70.0.0", "10.70.0.5"]}]}}]}"#;
        let nets: Vec<String> = parse_ranges(json)
            .unwrap()
            .iter()
            .map(Ipv4Net::to_string)
            .collect();
        assert_eq!(
            nets,
            [
                "10.50.0.0/16",
                "10.60.0.1/32",
                "10.70.0.0/30",
                "10.70.0.4/31"
            ]
        );
    }
}
