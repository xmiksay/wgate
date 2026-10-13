//! Which networks the agent has registered: the `from_net` dispatch map
//! (`nft -j list map inet wgate from_net`), interface → `jump n<id>_from`.

use anyhow::Context;
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
            let iface = e[0].as_str().context("map key")?;
            let target = e[1]["jump"]["target"].as_str().context("map verdict")?;
            let id = network_of_chain(target).with_context(|| format!("chain {target}"))?;
            out.push((iface.to_owned(), id));
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
    }
}
