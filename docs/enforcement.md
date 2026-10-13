# Enforcement on the hub

Part of [design.md](design.md).

## `table inet wgate`

Owned by the agent; it never touches the other tables. The table is a **base**, its
**SNAT** rule and one **fragment per network**, each applied as its own atomic `nft -f`
transaction, network by network (one network's transaction never touches another's
rules; a broken SNAT setting never holds back the spoof guard). Every pass re-applies
all of them: idempotent, and any drift is repaired within a pass. The exact
rendering is the golden file `crates/core/tests/golden/ruleset.nft` (base + every
fragment); in short:

```nft
table inet wgate {
  # base: global sets, the dispatch maps, the hooks
  set tenant_space { pool + routed LANs of compiled peers }
  map ingress / from_net / to_net { wg-<slug> : jump n<id>_ingress / _from / _to }

  prerouting (raw): non-wg ingress claiming a tenant source → drop;
                    a wg-* without its ingress entry (unknown, or an entry lost) →
                    drop; iifname vmap @ingress
  input:    a wg-* without its from_net entry → drop; iifname vmap @from_net
  forward:  a wg-* without its from_net / to_net entry → drop;
            iifname vmap @from_net; oifname vmap @to_net
  output:   a local packet with a tenant-space source that is no hub address → drop;
            a wg-* without its to_net entry → drop; hub ICMP errors for a tracked
            flow accept; oifname vmap @to_net
  (the "without its entry" drops fail closed: a map entry lost to a hand edit or a
  removal halfway never lets an interface through unchecked)
  postrouting: ip saddr @tenant_space ip daddr { node_cidrs − tenant space } snat ip to 172.19.9.10

  # fragment of network <id> (only its own peers; sender side + receiver side)
  set n<id>_peers        { addrs(peer) }
  set n<id>_allow        { peer . dst . proto . dport }       # outbound
  set n<id>_allow_icmp   { peer . dst }
  set n<id>_inbound      { src . peer . proto . dport }       # inbound
  set n<id>_inbound_icmp { src . peer }
  chain n<id>_ingress { ip saddr != @n<id>_peers drop }       # sources pinned to wg-<slug>
  chain n<id>_from {   # a packet from a member
    ct direction original  fwd @n<id>_allow return
    ct direction reply     rev @n<id>_inbound return
    drop }
  chain n<id>_to {     # a packet to a member
    ct direction original  fwd @n<id>_inbound return
    ct direction reply     rev @n<id>_allow return
    drop }
  #   fwd = ip saddr . ip daddr . meta l4proto . th dport, rev = the tuple swapped;
  #   each pair also has an icmp rule against the *_icmp sets
}
```

- Every packet from a member passes its network's `_from` chain, every packet to a
  member its network's `_to` chain; device → device across networks passes both (the
  opener's outbound right and the target's inbound right). The chains `return` on
  success so the other side's check still runs; base chains have policy accept and
  never see a tenant packet that both sides did not allow.
- A network fragment creates its chains and sets if missing, flushes and refills them
  and registers its interface in the maps; removing a network deletes its map entries
  and then its chains and sets (a chain still referenced by a map cannot be deleted).
- **Elements must be disjoint.** nft rejects an interval element that overlaps an
  existing one ("File exists"), even when one contains the other. `core` therefore
  keeps rights in a canonical disjoint form (`RuleSet`) and renders them as
  non-overlapping boxes, e.g. `tcp 10.0.0.0/8 80-90` + `tcp 10.1.0.0/16 85-100`
  become three elements. Peer addresses are globally unique (pool + unique routed
  subnets), so elements of different peers never overlap. The inet family needs
  `snat ip to`.
- **SNAT matches the whole tenant space** (pool blocks and routed LANs), not only
  peer addresses: a hub process that binds a hub address (`10.50.x.1`) to reach the
  node networks is translated to the SNAT source as well.
- **Every packet to or from a peer is checked against the current sets**, in both
  directions, with no `ct state established` shortcut. On vpsFree LXC the host owns
  conntrack (`conntrack -D` may not work), so revocation must not depend on clearing
  it; conntrack only picks which check applies (`ct direction`). Untracked or invalid
  packets hit the drops.
- **No related-ICMP shortcut**: ICMP errors can carry payload and match flows that
  outlive a revocation, so they pass only where the icmp sets allow the host pair.
  Only ICMP errors the hub itself generates for a tracked flow go out unchecked.
  Trade-off: PMTU/unreachable errors from hosts a peer has no icmp right to are
  dropped; keep tunnel MTUs at the WireGuard default.
- **A peer's addresses are believed only on its own network's interface**
  (`@ingress`); WireGuard additionally drops packets whose source is outside the
  sending peer's `AllowedIPs` (its /32 + routed subnets). So neither a peer nor a
  leftover or misconfigured `wg-*` interface can pose as another peer. A tenant source
  arriving on any other interface, or sent by a local socket, is spoofed and dropped.
- Rules apply to hub-local addresses too (input/output hooks); that is how
  `tcp 172.16.16.1/32 6443` reaches the k8s API. A broad ceiling (e.g. `0.0.0.0/0`)
  therefore also opens the hub's own services on those ports. Keep ceilings specific.
- A peer whose network is outside the pool or overlaps an older network, whose
  address is not a peer address of its network, or that claims an address an older
  peer already holds, is left out of the sets (fail closed) and reported; the older
  holder keeps working. The DB constraints should make this impossible.
- Inbound grants take sources outside tenant space only, plus hub addresses; an
  in-pool source is clipped away.
- A drop in any base chain is final, so iptables' `-i wg0 -j ACCEPT` (wg-quick) does
  not affect us.
- Role `firewall` (ansible) adds `iifname "wg-*" accept` to its input chain and
  `iifname/oifname "wg-*" accept` to its forward chain, leaving the decision to this
  table. The public ports `udp 51800–51899` go into `firewall_public_udp`.
