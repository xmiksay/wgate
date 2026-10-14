<script setup lang="ts">
import { ref, watch } from 'vue'
import { api, call } from '../../api/client'
import type { Network } from '../../api/types'
import { useSubmit } from '../../composables/useSubmit'
import { splitList } from '../../lib/format'
import ConfirmButton from '../ConfirmButton.vue'
import ErrorNote from '../ErrorNote.vue'
import UiButton from '../UiButton.vue'
import UiField from '../UiField.vue'
import UiSection from '../UiSection.vue'

const props = defineProps<{ network: Network }>()
const emit = defineEmits<{ updated: [Network]; deleted: [tenantId: number] }>()

const { busy, error, run } = useSubmit()
const name = ref('')
const mesh = ref(false)
const dns = ref('')

watch(
  () => props.network,
  (n) => {
    name.value = n.name
    mesh.value = n.mesh
    dns.value = n.dns.join(', ')
  },
  { immediate: true },
)

const path = () => ({ params: { path: { id: props.network.id } } })

async function update(body: { name?: string; mesh?: boolean; dns?: string[]; disabled?: boolean }) {
  let next: Network | undefined
  if (await run(async () => (next = await call(api.PATCH('/networks/{id}', { ...path(), body }))))) {
    if (next) emit('updated', next)
  }
}

function save() {
  return update({ name: name.value.trim(), mesh: mesh.value, dns: splitList(dns.value) })
}

async function remove() {
  if (await run(() => call(api.DELETE('/networks/{id}', path())))) {
    emit('deleted', props.network.tenant_id)
  }
}
</script>

<template>
  <UiSection :title="`Network ${network.name}`">
    <template #actions>
      <RouterLink
        :to="`/tenants/${network.tenant_id}`"
        class="link self-center text-sm"
      >
        Tenant
      </RouterLink>
      <ConfirmButton
        v-if="!network.disabled"
        label="Disable"
        message="Disabling takes the interface down at once. Addresses stay reserved; enabling restores it."
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
        :message="`Delete network ${network.name} with all its peers, rules and grants? This cannot be undone.`"
        confirm-label="Delete network"
        :disabled="busy"
        @confirm="remove"
      />
    </template>
    <dl class="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[auto_1fr]">
      <dt class="muted">
        Interface
      </dt>
      <dd class="mono">
        wg-{{ network.slug }} · UDP {{ network.port }} ·
        {{ network.disabled ? 'disabled' : 'active' }}
      </dd>
      <dt class="muted">
        Range
      </dt>
      <dd class="mono">
        {{ network.cidr }}
      </dd>
      <dt class="muted">
        Hub key
      </dt>
      <dd class="mono break-all">
        {{ network.hub_public_key ?? 'not published yet (the agent has not brought the network up)' }}
      </dd>
    </dl>
    <form
      class="grid gap-3 sm:grid-cols-4 sm:items-end"
      @submit.prevent="save"
    >
      <UiField label="Name">
        <input
          v-model="name"
          class="input"
          required
        >
      </UiField>
      <UiField
        label="DNS"
        hint="Hosts pushed to clients; empty: none"
      >
        <input
          v-model="dns"
          class="input mono"
        >
      </UiField>
      <label class="flex items-center gap-2 text-sm">
        <input
          v-model="mesh"
          type="checkbox"
        >
        Mesh (members reach each other)
      </label>
      <div>
        <UiButton
          type="submit"
          variant="primary"
          :disabled="busy"
        >
          Save
        </UiButton>
      </div>
    </form>
    <ErrorNote :error="error" />
  </UiSection>
</template>
