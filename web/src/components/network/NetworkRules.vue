<script setup lang="ts">
import { computed, ref } from 'vue'
import { api, call } from '../../api/client'
import type { Network, RuleOut } from '../../api/types'
import { useLoad } from '../../composables/useLoad'
import { useSubmit } from '../../composables/useSubmit'
import { serviceText } from '../../lib/format'
import ConfirmButton from '../ConfirmButton.vue'
import ErrorNote from '../ErrorNote.vue'
import ServiceFields from '../ServiceFields.vue'
import UiButton from '../UiButton.vue'
import UiField from '../UiField.vue'
import UiSection from '../UiSection.vue'
import UiTable from '../UiTable.vue'

const props = defineProps<{ network: Network }>()
const path = { params: { path: { id: props.network.id } } }

const rules = useLoad(() => call(api.GET('/networks/{id}/rules', path)), [] as RuleOut[])
const siblings = useLoad(
  () => call(api.GET('/networks', { params: { query: { tenant_id: props.network.tenant_id } } })),
  [] as Network[],
)
const targets = computed(() => siblings.data.filter((n) => n.id !== props.network.id))

const { busy, error, run } = useSubmit()
const kind = ref<'network' | 'external'>('network')
const target = ref<number | null>(null)
const dst = ref('')
const proto = ref('tcp')
const portFrom = ref<number | null>(null)
const portTo = ref<number | null>(null)
const comment = ref('')

function targetText(r: RuleOut): string {
  if (r.dst) return r.dst
  const n = siblings.data.find((s) => s.id === r.target_network_id)
  return n ? `network ${n.name}` : `network #${r.target_network_id}`
}

async function add() {
  const body = {
    proto: proto.value,
    port_from: portFrom.value,
    port_to: portTo.value,
    comment: comment.value.trim(),
    dst: kind.value === 'external' ? dst.value.trim() : null,
    target_network_id: kind.value === 'network' ? target.value : null,
  }
  if (await run(() => call(api.POST('/networks/{id}/rules', { ...path, body })))) {
    comment.value = ''
    await rules.reload()
  }
}

async function remove(id: number) {
  if (await run(() => call(api.DELETE('/rules/{id}', { params: { path: { id } } })))) {
    await rules.reload()
  }
}
</script>

<template>
  <UiSection title="Rules (what this network's peers may open)">
    <ErrorNote :error="rules.error" />
    <UiTable :empty="!rules.loading && !rules.data.length">
      <template #head>
        <th>To</th>
        <th>Service</th>
        <th>Comment</th>
        <th />
      </template>
      <tr
        v-for="r in rules.data"
        :key="r.id"
      >
        <td :class="{ mono: !!r.dst }">
          <RouterLink
            v-if="r.target_network_id != null"
            :to="`/networks/${r.target_network_id}`"
            class="link"
          >
            {{ targetText(r) }}
          </RouterLink>
          <template v-else>
            {{ targetText(r) }}
          </template>
        </td>
        <td>{{ serviceText(r) }}</td>
        <td>{{ r.comment }}</td>
        <td class="text-right">
          <ConfirmButton
            label="Delete"
            :message="`Delete the rule to ${targetText(r)} (${serviceText(r)})? Access ends at once.`"
            confirm-label="Delete"
            :disabled="busy"
            @confirm="remove(r.id)"
          />
        </td>
      </tr>
    </UiTable>

    <form
      class="grid gap-3 sm:grid-cols-4 sm:items-end"
      @submit.prevent="add"
    >
      <UiField label="To">
        <select
          v-model="kind"
          class="input"
        >
          <option value="network">
            another network of the tenant
          </option>
          <option value="external">
            an external destination
          </option>
        </select>
      </UiField>
      <UiField
        v-if="kind === 'network'"
        label="Network"
      >
        <select
          v-model="target"
          class="input"
          required
        >
          <option
            v-for="n in targets"
            :key="n.id"
            :value="n.id"
          >
            {{ n.name }} ({{ n.cidr }})
          </option>
        </select>
      </UiField>
      <UiField
        v-else
        label="Destination CIDR"
        hint="Must lie within the tenant's ceiling"
      >
        <input
          v-model="dst"
          class="input mono"
          required
        >
      </UiField>
      <ServiceFields
        v-model:proto="proto"
        v-model:port-from="portFrom"
        v-model:port-to="portTo"
      />
      <UiField label="Comment">
        <input
          v-model="comment"
          class="input"
        >
      </UiField>
      <div>
        <UiButton
          type="submit"
          variant="primary"
          :disabled="busy"
        >
          Add rule
        </UiButton>
      </div>
    </form>
    <ErrorNote :error="error" />
  </UiSection>
</template>
