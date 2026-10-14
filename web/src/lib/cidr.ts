// IPv4 only, like the pool: enough to pick the block a suggested range lies in.

function parse(cidr: string): { net: number; len: number } | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr.trim())
  if (!m) return null
  const octets = m.slice(1, 5).map(Number)
  const len = Number(m[5])
  if (octets.some((o) => o > 255) || len > 32) return null
  const addr = octets.reduce((a, o) => a * 256 + o, 0)
  const size = 2 ** (32 - len)
  return { net: addr - (addr % size), len }
}

/** Whether `inner` lies inside `outer`. */
export function cidrContains(outer: string, inner: string): boolean {
  const o = parse(outer)
  const i = parse(inner)
  if (!o || !i || i.len < o.len) return false
  const size = 2 ** (32 - o.len)
  return i.net - (i.net % size) === o.net
}
