//! A single allow rule: `proto + CIDR + port range`. The CIDR is the destination for
//! outbound rights and the source for inbound grants.

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

    /// Every service port.
    pub const ALL: Self = Self {
        from: 1,
        to: u16::MAX,
    };

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
        // u16::from_str also takes `+80`; only plain digits round-trip through Display.
        let port = |p: &str| {
            p.bytes()
                .all(|b| b.is_ascii_digit())
                .then(|| p.parse::<u16>().ok())
                .flatten()
                .ok_or_else(|| RuleError::Parse(format!("invalid port `{p}`")))
        };
        match s.split_once('-') {
            Some((from, to)) => Self::new(port(from)?, port(to)?),
            None => port(s).and_then(|p| Self::new(p, p)),
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

/// What a rule allows on its destination. Ports exist exactly for tcp and udp.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Service {
    Tcp(PortRange),
    Udp(PortRange),
    Icmp,
}

impl Service {
    pub fn new(proto: Proto, ports: Option<PortRange>) -> Result<Self, RuleError> {
        match (proto, ports) {
            (Proto::Tcp, Some(p)) => Ok(Self::Tcp(p)),
            (Proto::Udp, Some(p)) => Ok(Self::Udp(p)),
            (Proto::Icmp, None) => Ok(Self::Icmp),
            (Proto::Icmp, Some(_)) => Err(RuleError::PortsOnIcmp),
            (Proto::Tcp | Proto::Udp, None) => Err(RuleError::MissingPorts(proto)),
        }
    }

    pub fn proto(self) -> Proto {
        match self {
            Self::Tcp(_) => Proto::Tcp,
            Self::Udp(_) => Proto::Udp,
            Self::Icmp => Proto::Icmp,
        }
    }

    pub fn ports(self) -> Option<PortRange> {
        match self {
            Self::Tcp(p) | Self::Udp(p) => Some(p),
            Self::Icmp => None,
        }
    }
}

/// `proto net [ports]`, shared by rules (CIDR) and rule-set elements (ranges).
pub(crate) fn fmt_rule(
    f: &mut fmt::Formatter<'_>,
    service: Service,
    net: impl fmt::Display,
) -> fmt::Result {
    write!(f, "{} {net}", service.proto())?;
    match service.ports() {
        Some(p) => write!(f, " {p}"),
        None => Ok(()),
    }
}

/// Valid by construction: `net` is a network address (no host bits) and the
/// service carries ports exactly when it is tcp/udp.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rule {
    net: Ipv4Net,
    service: Service,
}

impl Rule {
    pub fn new(proto: Proto, net: Ipv4Net, ports: Option<PortRange>) -> Result<Self, RuleError> {
        let service = Service::new(proto, ports)?;
        if net != net.trunc() {
            return Err(RuleError::HostBits(net, net.trunc()));
        }
        Ok(Self { net, service })
    }

    /// From an already valid service; `net` is truncated to its network address.
    pub fn from_parts(net: Ipv4Net, service: Service) -> Self {
        Self {
            net: net.trunc(),
            service,
        }
    }

    pub fn net(&self) -> Ipv4Net {
        self.net
    }

    pub fn service(&self) -> Service {
        self.service
    }

    pub fn proto(&self) -> Proto {
        self.service.proto()
    }

    pub fn ports(&self) -> Option<PortRange> {
        self.service.ports()
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_rule(f, self.service, self.net)
    }
}

/// `tcp 172.16.16.1/32 6443`, `udp 10.0.0.0/8 1000-2000`, `icmp 172.19.9.10`
/// (a bare address means /32).
impl FromStr for Rule {
    type Err = RuleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split_whitespace();
        let (Some(proto), Some(net)) = (parts.next(), parts.next()) else {
            return Err(RuleError::Parse(format!(
                "expected `proto net [ports]`, got `{s}`"
            )));
        };
        let net = match net.parse::<Ipv4Net>() {
            Ok(net) => net,
            Err(_) => net
                .parse::<Ipv4Addr>()
                .map(Ipv4Net::from)
                .map_err(|_| RuleError::Parse(format!("invalid network `{net}`")))?,
        };
        let ports = parts.next().map(str::parse).transpose()?;
        if let Some(extra) = parts.next() {
            return Err(RuleError::Parse(format!("unexpected `{extra}`")));
        }
        Self::new(proto.parse()?, net, ports)
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
        assert_eq!(r.net().prefix_len(), 32);
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
        assert_eq!(err("tcp 10.0.0.0/8 0"), RuleError::PortZero);
        assert!(matches!(err("tcp 10.0.0.0/8 +80"), RuleError::Parse(_)));
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
