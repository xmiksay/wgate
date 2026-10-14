<script setup lang="ts">
import { storeToRefs } from 'pinia'
import type { Role } from '../api/types'
import PasswordChange from '../components/me/PasswordChange.vue'
import UiSection from '../components/UiSection.vue'
import { useSessionStore } from '../stores/session'

const { session } = storeToRefs(useSessionStore())

const roles: Record<Role, string> = {
  global_admin: 'Global admin',
  tenant_admin: 'Tenant admin',
  user: 'User',
}
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
    <PasswordChange :email="session.email" />
  </template>
</template>
