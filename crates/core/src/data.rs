//! The desired state as data (the agent's cache of the last one loaded): every value
//! goes back through its validating constructor when read, so a cache can never hold
//! what the database could not.

use std::str::FromStr;

use ipnet::{Ipv4Net, Ipv4Subnets};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::net::Slug;
use crate::rights::RuleSet;
use crate::rule::{PortRange, Rule, Service};

impl Serialize for Slug {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Slug {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Slug::from_str(&String::deserialize(d)?).map_err(D::Error::custom)
    }
}

impl Serialize for PortRange {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (self.from(), self.to()).serialize(s)
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (from, to) = <(u16, u16)>::deserialize(d)?;
        PortRange::new(from, to).map_err(D::Error::custom)
    }
}

/// A rule as `(net, service)`.
#[derive(Serialize, Deserialize)]
struct RuleData {
    net: Ipv4Net,
    service: Service,
}

impl Serialize for Rule {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        RuleData {
            net: self.net(),
            service: self.service(),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Rule {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = RuleData::deserialize(d)?;
        Rule::new(r.service.proto(), r.net, r.service.ports()).map_err(D::Error::custom)
    }
}

/// A rule set as the rules that cover exactly its elements.
impl Serialize for RuleSet {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let rules: Vec<Rule> = self
            .elements()
            .into_iter()
            .flat_map(|e| {
                Ipv4Subnets::new(e.addrs.lo, e.addrs.hi, 0)
                    .map(move |net| Rule::from_parts(net, e.service))
            })
            .collect();
        rules.serialize(s)
    }
}

impl<'de> Deserialize<'de> for RuleSet {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(RuleSet::from_rules(&Vec::<Rule>::deserialize(d)?))
    }
}

#[cfg(test)]
mod tests {
    use crate::compile::tests::state;
    use crate::{DesiredState, compile, render_all};

    #[test]
    fn a_state_read_back_compiles_to_the_same_rules() {
        let state = state();
        let json = serde_json::to_string(&state).unwrap();
        let back: DesiredState = serde_json::from_str(&json).unwrap();
        assert_eq!(render_all(&compile(&back)), render_all(&compile(&state)));
    }

    #[test]
    fn what_is_read_is_validated() {
        assert!(serde_json::from_str::<crate::Slug>(r#""Not A Slug""#).is_err());
        assert!(serde_json::from_str::<crate::PortRange>("[0, 5]").is_err());
        let host_bits = r#"{"net": "10.0.0.1/8", "service": "Icmp"}"#;
        assert!(serde_json::from_str::<crate::Rule>(host_bits).is_err());
    }
}
