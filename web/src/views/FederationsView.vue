<script setup lang="ts">
import { computed, ref } from 'vue'
import { api, call } from '../api/client'
import type { Federation, Network, Tenant } from '../api/types'
import ConfirmButton from '../components/ConfirmButton.vue'
import ErrorNote from '../components/ErrorNote.vue'
import ServiceFields from '../components/ServiceFields.vue'
import UiButton from '../components/UiButton.vue'
import UiField from '../components/UiField.vue'
import UiSection from '../components/UiSection.vue'
import UiTable from '../components/UiTable.vue'
import { useLoad } from '../composables/useLoad'
import { useSubmit } from '../composables/useSubmit'
import { serviceText } from '../lib/format'

const federations = useLoad(() => call(api.GET('/federations')), [] as Federation[])
const networks = useLoad(() => call(api.GET('/networks')), [] as Network[])
const tenants = useLoad(() => call(api.GET('/tenants')), [] as Tenant[])

const { busy, error, run } = useSubmit()
const from = ref<number | null>(null)
const to = ref<number | null>(null)
const proto = ref('tcp')
const portFrom = ref<number | null>(null)
const portTo = ref<number | null>(null)

const tenantsById = computed(() => new Map(tenants.data.map((t) => [t.id, t])))
const networksById = computed(() => new Map(networks.data.map((n) => [n.id, n])))

function networkText(id: number): string {
  const n = networksById.value.get(id)
  if (!n) return `network #${id}`
  return `${tenantsById.value.get(n.tenant_id)?.slug ?? `#${n.tenant_id}`} / ${n.name}`
}

// Federation links two different tenants.
const targets = computed(() => {
  const source = from.value === null ? undefined : networksById.value.get(from.value)
  return networks.data.filter((n) => !source || n.tenant_id !== source.tenant_id)
})

async function add() {
  const f = from.value
  const t = to.value
  if (f === null || t === null) return
  const body = {
    from_network_id: f,
    to_network_id: t,
    proto: proto.value,
    port_from: portFrom.value,
    port_to: portTo.value,
  }
  if (await run(() => call(api.POST('/federations', { body })))) await federations.reload()
}

async function remove(id: number) {
  if (await run(() => call(api.DELETE('/federations/{id}', { params: { path: { id } } })))) {
    await federations.reload()
  }
}
</script>

<template>
  <UiSection title="Federations (cross-tenant access)">
    <ErrorNote :error="federations.error ?? networks.error ?? tenants.error" />
    <UiTable :empty="!federations.loading && !federations.data.length">
      <template #head>
        <th>From</th>
        <th>To</th>
        <th>Service</th>
        <th />
      </template>
      <tr
        v-for="f in federations.data"
        :key="f.id"
      >
        <td>
          <RouterLink
            :to="`/networks/${f.from_network_id}`"
            class="link"
          >
            {{ networkText(f.from_network_id) }}
          </RouterLink>
        </td>
        <td>
          <RouterLink
            :to="`/networks/${f.to_network_id}`"
            class="link"
          >
            {{ networkText(f.to_network_id) }}
          </RouterLink>
        </td>
        <td>{{ serviceText(f) }}</td>
        <td class="text-right">
          <ConfirmButton
            label="Delete"
            :message="`Delete the federation ${networkText(f.from_network_id)} → ${networkText(f.to_network_id)}? Access ends at once.`"
            confirm-label="Delete"
            :disabled="busy"
            @confirm="remove(f.id)"
          />
        </td>
      </tr>
    </UiTable>

    <form
      class="grid gap-3 sm:grid-cols-5 sm:items-end"
      @submit.prevent="add"
    >
      <UiField label="From (opens)">
        <select
          v-model="from"
          class="input"
          required
        >
          <option
            v-for="n in networks.data"
            :key="n.id"
            :value="n.id"
          >
            {{ networkText(n.id) }}
          </option>
        </select>
      </UiField>
      <UiField label="To">
        <select
          v-model="to"
          class="input"
          required
        >
          <option
            v-for="n in targets"
            :key="n.id"
            :value="n.id"
          >
            {{ networkText(n.id) }}
          </option>
        </select>
      </UiField>
      <ServiceFields
        v-model:proto="proto"
        v-model:port-from="portFrom"
        v-model:port-to="portTo"
      />
      <div>
        <UiButton
          type="submit"
          variant="primary"
          :disabled="busy"
        >
          Add federation
        </UiButton>
      </div>
    </form>
    <ErrorNote :error="error" />
  </UiSection>
</template>
