import type { components } from './schema'

type S = components['schemas']

export type AccountLink = S['AccountLink']
export type AuditEntry = S['AuditEntry']
export type Block = S['Block']
export type Ceiling = S['Ceiling']
export type ConfigOut = S['ConfigOut']
export type Device = S['Device']
export type Federation = S['Federation']
export type Identity = S['Identity']
export type Inbound = S['Inbound']
export type LinkInfo = S['LinkInfo']
export type LinkableProvider = S['LinkableProvider']
export type LoginOptions = S['LoginOptions']
export type Network = S['Network']
export type Peer = S['Peer']
export type PeerCreated = S['PeerCreated']
export type Provider = S['Provider']
export type ProviderCreate = S['ProviderCreate']
export type ProviderOption = S['ProviderOption']
export type ProviderUpdate = S['ProviderUpdate']
export type RecoveryCodes = S['RecoveryCodes']
export type Rendered = S['Rendered']
export type Role = S['Role']
export type RuleOut = S['RuleOut']
export type ServiceBody = S['ServiceBody']
export type Session = S['Session']
export type Stage = S['Stage']
export type Status = S['Status']
export type Tenant = S['Tenant']
export type TotpLogin = S['TotpLogin']
export type TotpSetup = S['TotpSetup']
export type User = S['User']

export const PROTOS = ['tcp', 'udp', 'icmp'] as const
export const TENANT_ROLES = ['tenant_admin', 'user'] as const

/** Local passwords, counted in code points like the server does. */
export const PASSWORD_MIN = 12
export const PASSWORD_MAX = 256

/** A device as a peer form offers it: `label` names the owner too. */
export interface DeviceChoice {
  id: number
  name: string
  label: string
}
