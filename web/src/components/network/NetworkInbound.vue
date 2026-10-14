<script setup lang="ts">
import { ref } from 'vue'
import { api, call } from '../../api/client'
import type { Inbound, Network } from '../../api/types'
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
import WarningList from '../WarningList.vue'

const props = defineProps<{ network: Network }>()
const path = { params: { path: { id: props.network.id } } }

const grants = useLoad(() => call(api.GET('/networks/{id}/inbound', path)), [] as Inbound[])
const { busy, error, run } = useSubmit()
const source = ref('')
const proto = ref('tcp')
const portFrom = ref<number | null>(null)
const portTo = ref<number | null>(null)
const comment = ref('')
const warnings = ref<string[]>([])

async function add() {
  warnings.value = []
  const body = {
    source: source.value.trim(),
    proto: proto.value,
    port_from: portFrom.value,
    port_to: portTo.value,
    comment: comment.value.trim(),
  }
  const ok = await run(async () => {
    const made = await call(api.POST('/networks/{id}/inbound', { ...path, body }))
    warnings.value = made.warnings
  })
  if (ok) {
    source.value = ''
    comment.value = ''
    await grants.reload()
  }
}

async function remove(id: number) {
  if (await run(() => call(api.DELETE('/inbound/{id}', { params: { path: { id } } })))) {
    await grants.reload()
  }
}
</script>

<template>
  <UiSection title="Inbound grants (sources outside the pool)">
    <ErrorNote :error="grants.error" />
    <UiTable :empty="!grants.loading && !grants.data.length">
      <template #head>
        <th>Source</th>
        <th>Service</th>
        <th>Comment</th>
        <th />
      </template>
      <tr
        v-for="g in grants.data"
        :key="g.id"
      >
        <td class="mono">
          {{ g.source }}
        </td>
        <td>{{ serviceText(g) }}</td>
        <td>{{ g.comment }}</td>
        <td class="text-right">
          <ConfirmButton
            label="Delete"
            :message="`Delete the grant from ${g.source} (${serviceText(g)})? Access ends at once.`"
            confirm-label="Delete"
            :disabled="busy"
            @confirm="remove(g.id)"
          />
        </td>
      </tr>
    </UiTable>

    <form
      class="grid gap-3 sm:grid-cols-5 sm:items-end"
      @submit.prevent="add"
    >
      <UiField label="Source CIDR">
        <input
          v-model="source"
          class="input mono"
          placeholder="10.244.0.0/16"
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
          Add grant
        </UiButton>
      </div>
    </form>
    <WarningList :warnings="warnings" />
    <ErrorNote :error="error" />
  </UiSection>
</template>
