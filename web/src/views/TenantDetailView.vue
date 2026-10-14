<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { api, call } from '../api/client'
import type { Block, Tenant } from '../api/types'
import ConfirmButton from '../components/ConfirmButton.vue'
import ErrorNote from '../components/ErrorNote.vue'
import UiButton from '../components/UiButton.vue'
import UiSection from '../components/UiSection.vue'
import TenantBlocks from '../components/tenant/TenantBlocks.vue'
import TenantCeilings from '../components/tenant/TenantCeilings.vue'
import TenantNetworks from '../components/tenant/TenantNetworks.vue'
import UserList from '../components/UserList.vue'
import { useLoad } from '../composables/useLoad'
import { useSubmit } from '../composables/useSubmit'
import { useSessionStore } from '../stores/session'

const props = defineProps<{ id: number }>()
const router = useRouter()
const { isGlobal } = storeToRefs(useSessionStore())
const path = { params: { path: { id: props.id } } }

const tenant = useLoad(() => call(api.GET('/tenants/{id}', path)), null as Tenant | null)
const blocks = useLoad(() => call(api.GET('/tenants/{id}/blocks', path)), [] as Block[])
const { busy, error, run } = useSubmit()
const name = ref('')

watch(
  () => tenant.data?.name,
  (n) => (name.value = n ?? ''),
)

async function update(body: { name?: string; disabled?: boolean }) {
  let next: Tenant | undefined
  if (await run(async () => (next = await call(api.PATCH('/tenants/{id}', { ...path, body }))))) {
    tenant.data = next ?? null
  }
}

async function remove() {
  if (await run(() => call(api.DELETE('/tenants/{id}', path)))) await router.push('/tenants')
}
</script>

<template>
  <ErrorNote :error="tenant.error" />
  <template v-if="tenant.data">
    <UiSection :title="`Tenant ${tenant.data.name}`">
      <template
        v-if="isGlobal"
        #actions
      >
        <ConfirmButton
          v-if="!tenant.data.disabled"
          label="Disable"
          message="Disabling cuts every network of this tenant off at once. Addresses stay reserved; enabling restores it."
          confirm-label="Disable"
          :disabled="busy"
          @confirm="update({ disabled: true })"
        />
        <UiButton
          v-else
          :disabled="busy"
          @click="update({ disabled: false })"
        >
          Enable
        </UiButton>
        <ConfirmButton
          label="Delete"
          :message="`Delete tenant ${tenant.data.name} with all its blocks, networks, users and peers? This cannot be undone.`"
          confirm-label="Delete tenant"
          :disabled="busy"
          @confirm="remove"
        />
      </template>
      <p class="muted">
        Slug <span class="mono">{{ tenant.data.slug }}</span> ·
        {{ tenant.data.disabled ? 'disabled' : 'active' }}
      </p>
      <form
        v-if="isGlobal"
        class="flex gap-2"
        @submit.prevent="update({ name: name.trim() })"
      >
        <input
          v-model="name"
          class="input max-w-xs"
          aria-label="Name"
          required
        >
        <UiButton
          type="submit"
          :disabled="busy || name.trim() === tenant.data.name"
        >
          Rename
        </UiButton>
      </form>
      <ErrorNote :error="error" />
    </UiSection>

    <TenantBlocks
      :tenant-id="id"
      :blocks="blocks.data"
      :error="blocks.error"
      :editable="isGlobal"
      @changed="blocks.reload()"
    />
    <TenantNetworks
      :tenant-id="id"
      :blocks="blocks.data"
    />
    <TenantCeilings
      :tenant-id="id"
      :editable="isGlobal"
    />
    <UserList :tenant-id="id" />
  </template>
</template>
