//! Live TCP streams (`py::STREAM`) and when their echoes arrived.

use std::time::{Duration, Instant};

use super::netns::py::STREAM;
use super::netns::{Background, Netns};

/// What must be cut off, within this of the API call returning.
pub const CUT: Duration = Duration::from_secs(1);
/// The stream echoes every 100 ms; a longer silence means it stalled.
pub const STALL: Duration = Duration::from_millis(500);

/// One echo connection, "ok" every 100 ms for a minute; returns once it is up.
pub fn stream(from: &Netns, host: &str, port: u16) -> Background {
    let s = from.spawn(&["python3", "-c", STREAM, host, &port.to_string(), "60"]);
    assert_eq!(s.expect_line("stream is up"), "ok");
    s
}

/// Drains `s` and panics unless it echoed within `STALL`: alive right now, so a
/// cut measured from here is the next call's doing.
pub fn assert_alive(s: &Background, what: &str) {
    let mut last = None;
    while let Ok((t, _)) = s.lines.try_recv() {
        last = Some(t);
    }
    if last.is_none_or(|t| t.elapsed() > STALL) {
        assert!(s.lines.recv_timeout(STALL).is_ok(), "{what} is not alive");
    }
}

/// When each line of `s` arrived, up to `until` (lines already queued included).
pub fn lines_until(s: &Background, until: Instant) -> Vec<Instant> {
    let mut at = vec![];
    while let Ok((t, _)) = s
        .lines
        .recv_timeout(until.saturating_duration_since(Instant::now()))
    {
        at.push(t);
    }
    at
}

/// Panics unless `s` (alive before `since`) went silent within `CUT` of it and
/// stayed so for another `CUT`.
pub fn assert_cut(s: &Background, since: Instant, what: &str) {
    let at = lines_until(s, since + CUT * 2);
    let late: Vec<Duration> = at
        .iter()
        .filter(|t| **t >= since + CUT)
        .map(|t| t.duration_since(since))
        .collect();
    assert!(late.is_empty(), "{what} ran on: echoes after {late:?}");
}

/// Panics if `s` went silent for `STALL` or more between `from` and `until`.
pub fn assert_flowing(s: &Background, from: Instant, until: Instant, what: &str) {
    let at = lines_until(s, until);
    let mut prev = from;
    for t in at.iter().chain([&until]) {
        let gap = t.saturating_duration_since(prev);
        assert!(gap < STALL, "{what} stalled for {gap:?}");
        prev = prev.max(*t);
    }
}
