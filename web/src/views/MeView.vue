<script setup lang="ts">
import { storeToRefs } from 'pinia'
import type { Role } from '../api/types'
import PasswordChange from '../components/me/PasswordChange.vue'
import TotpManage from '../components/me/TotpManage.vue'
import TotpSetup from '../components/me/TotpSetup.vue'
import UiSection from '../components/UiSection.vue'
import { useSessionStore } from '../stores/session'

const sessionStore = useSessionStore()
const { session, isAdmin } = storeToRefs(sessionStore)

const roles: Record<Role, string> = {
  global_admin: 'Global admin',
  tenant_admin: 'Tenant admin',
  user: 'User',
}

/** `has_password` and `totp_enabled` live in the session: reload it after a change. */
const reload = () => sessionStore.load()
</script>

<template>
  <template v-if="session">
    <UiSection title="Profile">
      <dl class="grid max-w-sm grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt class="muted">
          Email
        </dt>
        <dd>{{ session.email }}</dd>
        <dt class="muted">
          Role
        </dt>
        <dd>{{ roles[session.role] }}</dd>
      </dl>
    </UiSection>
    <UiSection title="Two-factor sign-in">
      <p
        v-if="!session.has_password"
        class="muted max-w-prose"
      >
        Two-factor protects password logins, and this account has none: it signs in
        through a provider, whose own second factor applies.
      </p>
      <TotpManage
        v-else-if="session.totp_enabled"
        :email="session.email"
        :admin="isAdmin"
        @removed="reload"
      />
      <template v-else>
        <p class="muted max-w-prose">
          Off: a password alone signs you in. With it on, a login also asks for a code
          from an authenticator app.
        </p>
        <TotpSetup
          :email="session.email"
          @done="reload"
        />
      </template>
    </UiSection>
    <PasswordChange
      v-if="session.has_password"
      :email="session.email"
    />
    <UiSection
      v-else
      title="Password"
    >
      <p class="muted max-w-prose">
        This account has no password: it signs in through a provider. An admin can send
        you an invite link to set one.
      </p>
    </UiSection>
  </template>
</template>
