import type { components } from './schema'

type S = components['schemas']

export type AuditEntry = S['AuditEntry']
export type Block = S['Block']
export type Ceiling = S['Ceiling']
export type ConfigOut = S['ConfigOut']
export type Device = S['Device']
export type Federation = S['Federation']
export type Inbound = S['Inbound']
export type Network = S['Network']
export type Peer = S['Peer']
export type PeerCreated = S['PeerCreated']
export type Rendered = S['Rendered']
export type RuleOut = S['RuleOut']
export type ServiceBody = S['ServiceBody']
export type Session = S['Session']
export type Status = S['Status']
export type Tenant = S['Tenant']
export type User = S['User']

export const PROTOS = ['tcp', 'udp', 'icmp'] as const
export const TENANT_ROLES = ['tenant_admin', 'user'] as const

/** A device as a peer form offers it: `label` names the owner too. */
export interface DeviceChoice {
  id: number
  name: string
  label: string
}
