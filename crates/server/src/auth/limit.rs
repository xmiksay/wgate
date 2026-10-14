//! Login attempts per client: at most [`PER_MINUTE`] a minute from one address (an
//! IPv6 /64), [`PER_SITE_MINUTE`] from one IPv6 /48, in memory (one server process).
//! Who the client is: the TCP peer, or, when the peer is a trusted proxy, the
//! right-most `X-Forwarded-For` hop no trusted proxy added.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use ipnet::IpNet;

pub const PER_MINUTE: u32 = 20;
/// From one IPv6 /48 (a site: 65 536 /64 clients) a minute, so one site cannot fill
/// the hashing slots with fresh /64s.
pub const PER_SITE_MINUTE: u32 = 100;
const WINDOW: Duration = Duration::from_secs(60);
/// Clients tracked at once (a few MiB). A newcomer to a full table evicts the oldest
/// window: the heap stays bounded and nobody is refused for want of room.
const MAX_CLIENTS: usize = 65_536;

/// A fixed window per client, from its first attempt, and one per IPv6 site.
#[derive(Default)]
pub struct Limiter {
    client: Mutex<Windows>,
    site: Mutex<Windows>,
    /// Database lookups a full site may cost a minute (whether a client is known).
    lookups: Mutex<Windows>,
}

#[derive(Default)]
struct Windows {
    by_client: HashMap<IpAddr, (Instant, u32)>,
    /// Window starts in order (`Instant`s only grow); an entry whose client has since
    /// started a newer window is stale and skipped.
    order: VecDeque<(Instant, IpAddr)>,
}

impl Windows {
    /// Drops the front of `order`: its client too, unless that started a newer window.
    fn pop_oldest(&mut self) {
        if let Some((start, key)) = self.order.pop_front()
            && self.by_client.get(&key).is_some_and(|(s, _)| *s == start)
        {
            self.by_client.remove(&key);
        }
    }

    /// How long `key` must wait if its window is already used up; changes nothing.
    fn full(&self, key: IpAddr, limit: u32, now: Instant) -> Option<Duration> {
        let (start, count) = self.by_client.get(&key)?;
        let elapsed = now.saturating_duration_since(*start);
        (elapsed < WINDOW && *count >= limit).then(|| WINDOW - elapsed)
    }

    fn count(&mut self, key: IpAddr, limit: u32, now: Instant) -> Result<(), Duration> {
        // Amortized: each window is pushed once and popped once.
        while self
            .order
            .front()
            .is_some_and(|(start, _)| now.saturating_duration_since(*start) >= WINDOW)
        {
            self.pop_oldest();
        }
        if let Some((start, count)) = self.by_client.get_mut(&key) {
            if *count >= limit {
                return Err(WINDOW.saturating_sub(now.saturating_duration_since(*start)));
            }
            *count += 1;
            return Ok(());
        }
        while self.by_client.len() >= MAX_CLIENTS {
            self.pop_oldest();
        }
        self.by_client.insert(key, (now, 1));
        self.order.push_back((now, key));
        Ok(())
    }
}

fn lock(m: &Mutex<Windows>) -> std::sync::MutexGuard<'_, Windows> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Limiter {
    /// Counts one attempt of the client; `Err` is how long until it may try again.
    pub fn check(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        lock(&self.client).count(bucket(ip), PER_MINUTE, now)
    }

    /// How long the client must wait if it has used up its attempts, without counting
    /// one (so a refused client costs its site nothing).
    pub fn client_full(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        lock(&self.client).full(bucket(ip), PER_MINUTE, now)
    }

    /// Counts one attempt of an IPv6 client's /48 (IPv4 has none: its clients are
    /// single addresses already).
    pub fn check_site(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        match site(ip) {
            Some(key) => lock(&self.site).count(key, PER_SITE_MINUTE, now),
            None => Ok(()),
        }
    }

    /// Whether a site over its limit may still ask the database if this client is
    /// known: [`PER_SITE_MINUTE`] times a minute, so a full site cannot flood it.
    pub fn may_look_up(&self, ip: IpAddr, now: Instant) -> bool {
        site(ip).is_some_and(|key| lock(&self.lookups).count(key, PER_SITE_MINUTE, now).is_ok())
    }
}

fn site(ip: IpAddr) -> Option<IpAddr> {
    match bucket(ip) {
        IpAddr::V4(_) => None,
        IpAddr::V6(v6) => {
            let s = v6.segments();
            Some(IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0)))
        }
    }
}

/// Who counts as one client, here and in the per-client lockout. One host holds a
/// whole IPv6 /64: counting single addresses there would count nothing.
pub fn bucket(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// The client behind `peer`. Only a trusted proxy's `X-Forwarded-For` counts, read
/// from the right: each trusted hop vouches for the address left of it, the first
/// untrusted one is the client (a client can prepend anything, never append).
pub fn client_ip(peer: SocketAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|n| n.contains(&canonical(*ip)));
    let mut client = canonical(peer.ip());
    if !is_trusted(&client) {
        return client;
    }
    let hops: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .collect();
    for hop in hops.iter().rev() {
        // Garbage from a trusted hop: the hop that sent it is the best we know.
        let Some(ip) = parse_hop(hop.trim()) else {
            break;
        };
        client = ip;
        if !is_trusted(&ip) {
            break;
        }
    }
    client
}

fn parse_hop(hop: &str) -> Option<IpAddr> {
    hop.parse::<IpAddr>()
        .or_else(|_| hop.parse::<SocketAddr>().map(|s| s.ip()))
        .ok()
        .map(canonical)
}

/// An IPv4 peer of a dual-stack listener arrives as `::ffff:a.b.c.d`.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn twenty_a_minute_per_client() {
        let l = Limiter::default();
        let t0 = Instant::now();
        for _ in 0..PER_MINUTE {
            assert!(l.check(ip("192.0.2.1"), t0).is_ok());
        }
        let wait = l.check(ip("192.0.2.1"), t0 + Duration::from_secs(10));
        assert_eq!(wait, Err(Duration::from_secs(50)));
        // Others are not held up; an IPv4 client over IPv6 is the same client.
        assert!(l.check(ip("192.0.2.2"), t0).is_ok());
        assert!(l.check(ip("::ffff:192.0.2.1"), t0).is_err());
        assert!(l.check(ip("192.0.2.1"), t0 + WINDOW).is_ok());
    }

    #[test]
    fn an_ipv6_host_is_its_64() {
        let l = Limiter::default();
        let t0 = Instant::now();
        for i in 0..PER_MINUTE {
            assert!(l.check(ip(&format!("2001:db8::{i:x}")), t0).is_ok());
        }
        assert!(l.check(ip("2001:db8::ffff:1"), t0).is_err());
        assert!(l.check(ip("2001:db8:0:1::1"), t0).is_ok());
    }

    #[test]
    fn an_ipv6_site_has_100_a_minute() {
        let l = Limiter::default();
        let t0 = Instant::now();
        for i in 0..PER_SITE_MINUTE {
            let fresh = ip(&format!("2001:db8:0:{i:x}::1"));
            assert!(l.check(fresh, t0).is_ok(), "a /64 of its own");
            assert!(l.check_site(fresh, t0).is_ok());
        }
        assert!(l.check_site(ip("2001:db8:0:ffff::1"), t0).is_err());
        assert!(l.check_site(ip("2001:db8:1::1"), t0).is_ok(), "another /48");
        // IPv4 has no site.
        for _ in 0..1000 {
            assert!(l.check_site(ip("192.0.2.1"), t0).is_ok());
        }
        assert!(l.check_site(ip("2001:db8:0:ffff::1"), t0 + WINDOW).is_ok());
    }

    #[test]
    fn a_full_site_costs_bounded_lookups_and_no_client_windows() {
        let l = Limiter::default();
        let t0 = Instant::now();
        let mut lookups = 0;
        // As `ClientIp::attempt` asks: the site first, a client window only after it.
        for i in 0..10_000u32 {
            let fresh = ip(&format!("2001:db8:0:{:x}::1", i & 0xffff));
            if l.check_site(fresh, t0).is_err() {
                if l.may_look_up(fresh, t0) {
                    lookups += 1;
                }
                continue;
            }
            assert!(l.check(fresh, t0).is_ok());
        }
        assert_eq!(lookups, PER_SITE_MINUTE);
        let clients = l.client.lock().unwrap().by_client.len();
        assert_eq!(
            clients, PER_SITE_MINUTE as usize,
            "no window for a refused one"
        );
        assert!(l.may_look_up(ip("2001:db8:0:1::1"), t0 + WINDOW));
        assert!(!l.may_look_up(ip("192.0.2.1"), t0), "IPv4 has no site");
    }

    #[test]
    fn a_client_over_its_own_limit_costs_its_site_nothing() {
        let l = Limiter::default();
        let t0 = Instant::now();
        let one = ip("2001:db8:0:1::1");
        // As `ClientIp::attempt` asks.
        for _ in 0..101 {
            if l.client_full(one, t0).is_some() {
                continue;
            }
            assert!(l.check_site(one, t0).is_ok());
            assert!(l.check(one, t0).is_ok());
        }
        assert!(l.client_full(one, t0).is_some());
        let other = ip("2001:db8:0:2::1");
        for _ in 0..PER_SITE_MINUTE - PER_MINUTE {
            assert!(l.check_site(other, t0).is_ok());
        }
        assert!(l.check_site(other, t0).is_err());
        assert!(l.lookups.lock().unwrap().by_client.is_empty());
    }

    #[test]
    fn a_full_table_evicts_the_oldest_window() {
        let l = Limiter::default();
        let t0 = Instant::now();
        for _ in 0..PER_MINUTE {
            assert!(l.check(ip("192.0.2.1"), t0).is_ok());
        }
        for i in 1..MAX_CLIENTS as u32 {
            let t = t0 + Duration::from_millis(1);
            assert!(l.check(IpAddr::V4(i.into()), t).is_ok());
        }
        assert!(l.check(ip("192.0.2.1"), t0).is_err());
        // A newcomer still gets a window: the oldest one (192.0.2.1's) makes room.
        let t = t0 + Duration::from_millis(2);
        assert!(l.check(ip("2001:db8::1"), t).is_ok());
        assert!(l.check(ip("192.0.2.1"), t).is_ok());
        {
            let w = l.client.lock().unwrap();
            assert_eq!(w.by_client.len(), MAX_CLIENTS);
            assert!(w.order.len() <= MAX_CLIENTS + 1);
        }
        // Expired windows go as time passes.
        assert!(l.check(ip("192.0.2.1"), t0 + WINDOW + WINDOW).is_ok());
        let w = l.client.lock().unwrap();
        assert_eq!((w.by_client.len(), w.order.len()), (1, 1));
    }

    fn xff(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn forwarded_for_counts_only_from_a_trusted_proxy() {
        let peer = |s: &str| SocketAddr::new(ip(s), 4000);
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let h = xff(&["198.51.100.7, 10.1.1.1"]);
        // Not from a proxy: the header is the client's own claim.
        assert_eq!(
            client_ip(peer("203.0.113.9"), &h, &trusted),
            ip("203.0.113.9")
        );
        assert_eq!(client_ip(peer("10.2.2.2"), &h, &[]), ip("10.2.2.2"));
        // Through two proxies: the right-most untrusted hop.
        assert_eq!(
            client_ip(peer("10.2.2.2"), &h, &trusted),
            ip("198.51.100.7")
        );
        // A spoofed hop left of the client's real one is ignored.
        let h = xff(&["1.1.1.1", "198.51.100.7"]);
        assert_eq!(
            client_ip(peer("10.2.2.2"), &h, &trusted),
            ip("198.51.100.7")
        );
        // No header, garbage, or only proxies: the last address we can vouch for.
        assert_eq!(
            client_ip(peer("10.2.2.2"), &xff(&[]), &trusted),
            ip("10.2.2.2")
        );
        let h = xff(&["198.51.100.7, junk"]);
        assert_eq!(client_ip(peer("10.2.2.2"), &h, &trusted), ip("10.2.2.2"));
        let h = xff(&["10.3.3.3"]);
        assert_eq!(client_ip(peer("10.2.2.2"), &h, &trusted), ip("10.3.3.3"));
        let h = xff(&["198.51.100.7:5555"]);
        assert_eq!(
            client_ip(peer("10.2.2.2"), &h, &trusted),
            ip("198.51.100.7")
        );
        // A mapped IPv4 peer is matched as IPv4.
        let h = xff(&["198.51.100.7"]);
        assert_eq!(
            client_ip(peer("::ffff:10.2.2.2"), &h, &trusted),
            ip("198.51.100.7")
        );
    }
}
