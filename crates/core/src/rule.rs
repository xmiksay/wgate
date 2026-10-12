//! A single allow rule: `proto + dst CIDR + port range`.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Proto {
    type Err = RuleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "icmp" => Ok(Self::Icmp),
            _ => Err(RuleError::Parse(format!("unknown protocol `{s}`"))),
        }
    }
}

/// Inclusive port range, `from <= to`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortRange {
    from: u16,
    to: u16,
}

impl PortRange {
    pub fn new(from: u16, to: u16) -> Result<Self, RuleError> {
        if from == 0 {
            return Err(RuleError::PortZero);
        }
        if from > to {
            return Err(RuleError::InvertedPorts { from, to });
        }
        Ok(Self { from, to })
    }

    pub fn single(port: u16) -> Self {
        Self {
            from: port,
            to: port,
        }
    }

    /// From a port span of a `RuleSet`, which only ever holds spans built from valid
    /// ranges, so the casts cannot truncate.
    pub(crate) fn from_span(lo: u32, hi: u32) -> Self {
        debug_assert!(0 < lo && lo <= hi && hi <= u32::from(u16::MAX));
        Self {
            from: lo as u16,
            to: hi as u16,
        }
    }

    pub fn from(self) -> u16 {
        self.from
    }

    pub fn to(self) -> u16 {
        self.to
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.from == self.to {
            write!(f, "{}", self.from)
        } else {
            write!(f, "{}-{}", self.from, self.to)
        }
    }
}

impl FromStr for PortRange {
    type Err = RuleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let port = |p: &str| {
            p.parse::<u16>()
                .map_err(|_| RuleError::Parse(format!("invalid port `{p}`")))
        };
        match s.split_once('-') {
            Some((from, to)) => Self::new(port(from)?, port(to)?),
            None => Ok(Self::single(port(s)?)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    #[error("icmp rules take no ports")]
    PortsOnIcmp,
    #[error("{0} rules need a port range")]
    MissingPorts(Proto),
    #[error("port 0 is not a service port")]
    PortZero,
    #[error("port range {from}-{to} is inverted")]
    InvertedPorts { from: u16, to: u16 },
    #[error("{0} has host bits set; did you mean {1}?")]
    HostBits(Ipv4Net, Ipv4Net),
    #[error("{0}")]
    Parse(String),
}

/// Valid by construction: tcp/udp carry ports, icmp does not, and `dst` is a network
/// address (no host bits).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rule {
    proto: Proto,
    dst: Ipv4Net,
    ports: Option<PortRange>,
}

impl Rule {
    pub fn new(proto: Proto, dst: Ipv4Net, ports: Option<PortRange>) -> Result<Self, RuleError> {
        match (proto, ports) {
            (Proto::Icmp, Some(_)) => return Err(RuleError::PortsOnIcmp),
            (Proto::Tcp | Proto::Udp, None) => return Err(RuleError::MissingPorts(proto)),
            _ => {}
        }
        if dst != dst.trunc() {
            return Err(RuleError::HostBits(dst, dst.trunc()));
        }
        Ok(Self { proto, dst, ports })
    }

    pub fn proto(&self) -> Proto {
        self.proto
    }

    pub fn dst(&self) -> Ipv4Net {
        self.dst
    }

    pub fn ports(&self) -> Option<PortRange> {
        self.ports
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.proto, self.dst)?;
        match self.ports {
            Some(p) => write!(f, " {p}"),
            None => Ok(()),
        }
    }
}

/// `tcp 172.16.16.1/32 6443`, `udp 10.0.0.0/8 1000-2000`, `icmp 172.19.9.10`
/// (a bare address means /32).
impl FromStr for Rule {
    type Err = RuleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split_whitespace();
        let (Some(proto), Some(dst)) = (parts.next(), parts.next()) else {
            return Err(RuleError::Parse(format!(
                "expected `proto dst [ports]`, got `{s}`"
            )));
        };
        let dst = match dst.parse::<Ipv4Net>() {
            Ok(net) => net,
            Err(_) => dst
                .parse::<Ipv4Addr>()
                .map(Ipv4Net::from)
                .map_err(|_| RuleError::Parse(format!("invalid destination `{dst}`")))?,
        };
        let ports = parts.next().map(str::parse).transpose()?;
        if let Some(extra) = parts.next() {
            return Err(RuleError::Parse(format!("unexpected `{extra}`")));
        }
        Self::new(proto.parse()?, dst, ports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_displays_round_trip() {
        for s in [
            "tcp 172.16.16.1/32 6443",
            "udp 10.0.0.0/8 1000-2000",
            "icmp 172.19.9.10/32",
        ] {
            assert_eq!(s.parse::<Rule>().map(|r| r.to_string()), Ok(s.to_owned()));
        }
    }

    #[test]
    fn protocol_is_case_insensitive() {
        assert_eq!(
            "TCP 10.0.0.0/8 80".parse::<Rule>().map(|r| r.proto()),
            Ok(Proto::Tcp)
        );
    }

    #[test]
    fn bare_address_is_host_route() {
        let r: Rule = "icmp 172.19.9.10".parse().unwrap();
        assert_eq!(r.dst().prefix_len(), 32);
    }

    #[test]
    fn rejects_invalid_rules() {
        let err = |s: &str| s.parse::<Rule>().unwrap_err();
        assert_eq!(err("icmp 10.0.0.0/8 80"), RuleError::PortsOnIcmp);
        assert_eq!(err("tcp 10.0.0.0/8"), RuleError::MissingPorts(Proto::Tcp));
        assert_eq!(
            err("tcp 10.0.0.0/8 90-80"),
            RuleError::InvertedPorts { from: 90, to: 80 }
        );
        assert!(matches!(err("tcp 10.0.0.5/8 80"), RuleError::HostBits(..)));
        assert_eq!(err("tcp 10.0.0.0/8 0-80"), RuleError::PortZero);
        assert!(matches!(err("sctp 10.0.0.0/8 80"), RuleError::Parse(_)));
        assert!(matches!(
            err("tcp 10.0.0.0/8 80 extra"),
            RuleError::Parse(_)
        ));
        assert!(matches!(err("tcp 10.0.0.0/33 80"), RuleError::Parse(_)));
        assert!(matches!(err("tcp"), RuleError::Parse(_)));
        assert!(matches!(err("tcp 10.0.0.0/8 70000"), RuleError::Parse(_)));
    }
}
