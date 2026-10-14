<script setup lang="ts">
import { ref } from 'vue'
import { api, call } from '../../api/client'
import type { Ceiling } from '../../api/types'
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

const props = defineProps<{ tenantId: number; editable: boolean }>()
const path = { params: { path: { id: props.tenantId } } }

const ceilings = useLoad(() => call(api.GET('/tenants/{id}/ceilings', path)), [] as Ceiling[])
const { busy, error, run } = useSubmit()
const dst = ref('')
const proto = ref('tcp')
const portFrom = ref<number | null>(null)
const portTo = ref<number | null>(null)

async function add() {
  const body = { dst: dst.value.trim(), proto: proto.value, port_from: portFrom.value, port_to: portTo.value }
  if (await run(() => call(api.POST('/tenants/{id}/ceilings', { ...path, body })))) {
    dst.value = ''
    await ceilings.reload()
  }
}

async function remove(id: number) {
  if (await run(() => call(api.DELETE('/ceilings/{id}', { params: { path: { id } } })))) {
    await ceilings.reload()
  }
}
</script>

<template>
  <UiSection title="Ceiling (external destinations the tenant's rules may reach)">
    <ErrorNote :error="ceilings.error" />
    <UiTable :empty="!ceilings.loading && !ceilings.data.length">
      <template #head>
        <th>Destination</th>
        <th>Service</th>
        <th />
      </template>
      <tr
        v-for="c in ceilings.data"
        :key="c.id"
      >
        <td class="mono">
          {{ c.dst }}
        </td>
        <td>{{ serviceText(c) }}</td>
        <td class="text-right">
          <ConfirmButton
            v-if="editable"
            label="Delete"
            :message="`Delete the ceiling ${c.dst} ${serviceText(c)}? Rules relying on it stop reaching it at once.`"
            confirm-label="Delete"
            :disabled="busy"
            @confirm="remove(c.id)"
          />
        </td>
      </tr>
    </UiTable>
    <form
      v-if="editable"
      class="grid gap-3 sm:grid-cols-5 sm:items-end"
      @submit.prevent="add"
    >
      <UiField label="Destination CIDR">
        <input
          v-model="dst"
          class="input mono"
          placeholder="172.16.16.1/32"
          required
        >
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
          Add
        </UiButton>
      </div>
    </form>
    <ErrorNote :error="error" />
  </UiSection>
</template>
