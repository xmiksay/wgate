//! Routes to routed LANs, marked with wgate's own route protocol so only those are
//! touched.

use anyhow::Context;
use ipnet::Ipv4Net;
use serde::Deserialize;

/// The `proto` of the routes the agent owns (any free number; 150 is unassigned).
pub const PROTO: &str = "150";

#[derive(Deserialize)]
struct Route {
    dst: String,
}

/// The destinations of `ip -j route show dev <if> proto 150`.
pub fn parse(json: &str) -> anyhow::Result<Vec<Ipv4Net>> {
    let routes: Vec<Route> = serde_json::from_str(json).context("ip -j route")?;
    Ok(routes
        .iter()
        .filter_map(|r| {
            // A host route prints without its prefix length.
            let dst = if r.dst.contains('/') {
                r.dst.clone()
            } else {
                format!("{}/32", r.dst)
            };
            let parsed = dst.parse::<Ipv4Net>().ok();
            if parsed.is_none() {
                // Not a LAN wgate routes (a `default` someone added): not ours to
                // touch, and no reason to lose sight of the rest.
                tracing::warn!(dst = %r.dst, "route skipped");
            }
            parsed
        })
        .collect())
}

/// (to add, to delete)
pub fn diff(current: &[Ipv4Net], desired: &[Ipv4Net]) -> (Vec<Ipv4Net>, Vec<Ipv4Net>) {
    let add = desired
        .iter()
        .filter(|d| !current.contains(d))
        .copied()
        .collect();
    let del = current
        .iter()
        .filter(|c| !desired.contains(c))
        .copied()
        .collect();
    (add, del)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(s: &[&str]) -> Vec<Ipv4Net> {
        s.iter().map(|n| n.parse().unwrap()).collect()
    }

    #[test]
    fn parses_and_diffs() {
        let json = r#"[{"dst":"192.168.1.0/24","scope":"link","flags":[]},{"dst":"10.9.9.9","scope":"link","flags":[]}]"#;
        let current = parse(json).unwrap();
        assert_eq!(current, nets(&["192.168.1.0/24", "10.9.9.9/32"]));
        let (add, del) = diff(&current, &nets(&["192.168.1.0/24", "192.168.2.0/24"]));
        assert_eq!(add, nets(&["192.168.2.0/24"]));
        assert_eq!(del, nets(&["10.9.9.9/32"]));
        assert!(parse("[]").unwrap().is_empty());
        let odd = r#"[{"dst":"default","flags":[]},{"dst":"192.168.1.0/24","flags":[]}]"#;
        assert_eq!(parse(odd).unwrap(), nets(&["192.168.1.0/24"]));
    }
}
