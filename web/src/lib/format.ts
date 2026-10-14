import type { ServiceBody } from '../api/types'

/** `tcp 443`, `udp 1000–2000`, `icmp`, `tcp (all ports)`. */
export function serviceText(s: ServiceBody): string {
  if (s.proto === 'icmp') return 'icmp'
  if (s.port_from == null) return `${s.proto} (all ports)`
  if (s.port_to == null || s.port_to === s.port_from) return `${s.proto} ${s.port_from}`
  return `${s.proto} ${s.port_from}–${s.port_to}`
}

export function timeText(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

/** `a, b c` → `['a', 'b', 'c']`: lists typed into one field. */
export function splitList(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean)
}
