//! Canonical interval maps over `u32`, the engine behind [`crate::RuleSet`].

/// Inclusive span `lo..=hi` carrying a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Span<V> {
    pub lo: u32,
    pub hi: u32,
    pub val: V,
}

/// Disjoint spans kept canonical: sorted, non-overlapping, and touching spans with
/// equal values merged. Canonical form makes structural equality semantic equality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IntervalMap<V> {
    spans: Vec<Span<V>>,
}

impl<V> IntervalMap<V> {
    pub const fn empty() -> Self {
        Self { spans: Vec::new() }
    }
}

impl<V> Default for IntervalMap<V> {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Op {
    Union,
    Intersect,
    Difference,
}

/// Values that combine pointwise under a set operation; `None` = empty.
pub(crate) trait SetValue: Clone + PartialEq + Sized {
    fn apply(op: Op, a: Option<&Self>, b: Option<&Self>) -> Option<Self>;
}

/// A plain set: a point is either in it or not.
impl SetValue for () {
    fn apply(op: Op, a: Option<&()>, b: Option<&()>) -> Option<()> {
        let (a, b) = (a.is_some(), b.is_some());
        let keep = match op {
            Op::Union => a || b,
            Op::Intersect => a && b,
            Op::Difference => a && !b,
        };
        keep.then_some(())
    }
}

/// Nested maps (a plane: address → port set) combine recursively.
impl<V: SetValue> SetValue for IntervalMap<V> {
    fn apply(op: Op, a: Option<&Self>, b: Option<&Self>) -> Option<Self> {
        let empty = Self::default();
        let out = a.unwrap_or(&empty).op(b.unwrap_or(&empty), op);
        (!out.is_empty()).then_some(out)
    }
}

impl<V: SetValue> IntervalMap<V> {
    pub fn single(lo: u32, hi: u32, val: V) -> Self {
        debug_assert!(lo <= hi);
        Self {
            spans: vec![Span { lo, hi, val }],
        }
    }

    pub fn spans(&self) -> &[Span<V>] {
        &self.spans
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    pub fn get(&self, x: u32) -> Option<&V> {
        let i = self.spans.partition_point(|s| s.hi < x);
        self.spans.get(i).filter(|s| s.lo <= x).map(|s| &s.val)
    }

    /// Sweeps the union of both maps' boundaries; between two consecutive cuts
    /// both maps are constant, so one `apply` per elementary span is exact.
    pub fn op(&self, other: &Self, op: Op) -> Self {
        let mut cuts: Vec<u64> = self
            .spans
            .iter()
            .chain(&other.spans)
            .flat_map(|s| [u64::from(s.lo), u64::from(s.hi) + 1])
            .collect();
        cuts.sort_unstable();
        cuts.dedup();

        let mut out = Self::default();
        for (&lo, &next) in cuts.iter().zip(cuts.iter().skip(1)) {
            // Every cut except the last is some span's `lo` or `hi + 1` with a larger
            // cut after it, so both values fit in u32.
            let (lo, hi) = (lo as u32, (next - 1) as u32);
            if let Some(val) = V::apply(op, self.get(lo), other.get(lo)) {
                out.push(lo, hi, val);
            }
        }
        out
    }

    /// Appends a span right of all existing ones, merging when it touches an equal value.
    pub(crate) fn push(&mut self, lo: u32, hi: u32, val: V) {
        if let Some(last) = self.spans.last_mut()
            && u64::from(last.hi) + 1 == u64::from(lo)
            && last.val == val
        {
            last.hi = hi;
            return;
        }
        self.spans.push(Span { lo, hi, val });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Set = IntervalMap<()>;

    fn set(spans: &[(u32, u32)]) -> Set {
        spans.iter().fold(Set::default(), |acc, &(lo, hi)| {
            acc.op(&Set::single(lo, hi, ()), Op::Union)
        })
    }

    fn pairs(s: &Set) -> Vec<(u32, u32)> {
        s.spans().iter().map(|s| (s.lo, s.hi)).collect()
    }

    #[test]
    fn union_merges_overlapping_and_touching() {
        assert_eq!(pairs(&set(&[(5, 10), (8, 20), (21, 30)])), [(5, 30)]);
        assert_eq!(pairs(&set(&[(1, 2), (4, 5)])), [(1, 2), (4, 5)]);
    }

    #[test]
    fn intersect_and_difference() {
        let a = set(&[(0, 100)]);
        let b = set(&[(10, 20), (50, 60)]);
        assert_eq!(pairs(&a.op(&b, Op::Intersect)), [(10, 20), (50, 60)]);
        assert_eq!(
            pairs(&a.op(&b, Op::Difference)),
            [(0, 9), (21, 49), (61, 100)]
        );
        assert!(b.op(&a, Op::Difference).is_empty());
    }

    #[test]
    fn handles_u32_extremes() {
        let all = set(&[(0, u32::MAX)]);
        let top = set(&[(u32::MAX, u32::MAX)]);
        assert_eq!(pairs(&all.op(&top, Op::Difference)), [(0, u32::MAX - 1)]);
        assert_eq!(all.get(u32::MAX), Some(&()));
    }

    #[test]
    fn get_finds_containing_span() {
        let s = set(&[(10, 20), (30, 40)]);
        assert!(s.get(9).is_none());
        assert!(s.get(10).is_some());
        assert!(s.get(25).is_none());
        assert!(s.get(40).is_some());
        assert!(s.get(41).is_none());
    }

    #[test]
    fn nested_maps_merge_equal_neighbours() {
        let ports = |lo, hi| Set::single(lo, hi, ());
        let a = IntervalMap::single(0, 9, ports(80, 80));
        let b = IntervalMap::single(10, 19, ports(80, 80));
        let c = IntervalMap::single(5, 14, ports(443, 443));
        let u = a.op(&b, Op::Union);
        assert_eq!(u.spans().len(), 1);
        let u = u.op(&c, Op::Union);
        // 0-4 {80}, 5-14 {80,443}, 15-19 {80}
        assert_eq!(u.spans().len(), 3);
        assert_eq!(pairs(&u.spans()[1].val), [(80, 80), (443, 443)]);
    }
}
