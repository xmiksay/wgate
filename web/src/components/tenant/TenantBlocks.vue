<script setup lang="ts">
import { ref, watch } from 'vue'
import { api, call, type ApiError } from '../../api/client'
import type { Block } from '../../api/types'
import { useSubmit } from '../../composables/useSubmit'
import ConfirmButton from '../ConfirmButton.vue'
import ErrorNote from '../ErrorNote.vue'
import UiButton from '../UiButton.vue'
import UiField from '../UiField.vue'
import UiSection from '../UiSection.vue'
import UiTable from '../UiTable.vue'

const props = defineProps<{
  tenantId: number
  blocks: Block[]
  error: ApiError | null
  editable: boolean
}>()
const emit = defineEmits<{ changed: [] }>()

const { busy, error: writeError, run } = useSubmit()
const prefix = ref(24)
const cidr = ref('')
const hint = ref('')

async function suggest() {
  hint.value = ''
  try {
    const s = await call(api.GET('/free-block', { params: { query: { prefix: prefix.value } } }))
    cidr.value = s.free ?? ''
    if (!s.free) hint.value = `No free /${prefix.value} in the pool.`
  } catch {
    hint.value = 'No suggestion: type a range.'
  }
}

watch(prefix, suggest, { immediate: props.editable })

async function add() {
  const ok = await run(() =>
    call(
      api.POST('/tenants/{id}/blocks', {
        params: { path: { id: props.tenantId } },
        body: { cidr: cidr.value.trim() },
      }),
    ),
  )
  if (ok) {
    emit('changed')
    await suggest()
  }
}

async function remove(id: number) {
  if (await run(() => call(api.DELETE('/blocks/{id}', { params: { path: { id } } })))) {
    emit('changed')
  }
}
</script>

<template>
  <UiSection title="Blocks">
    <ErrorNote :error="error" />
    <UiTable :empty="!blocks.length">
      <template #head>
        <th>Range</th>
        <th />
      </template>
      <tr
        v-for="b in blocks"
        :key="b.id"
      >
        <td class="mono">
          {{ b.cidr }}
        </td>
        <td class="text-right">
          <ConfirmButton
            v-if="editable"
            label="Delete"
            :message="`Delete block ${b.cidr}? Its networks and their peers go with it.`"
            confirm-label="Delete block"
            :disabled="busy"
            @confirm="remove(b.id)"
          />
        </td>
      </tr>
    </UiTable>
    <form
      v-if="editable"
      class="grid gap-3 sm:grid-cols-[8rem_1fr_auto] sm:items-end"
      @submit.prevent="add"
    >
      <UiField label="Prefix length">
        <input
          v-model.number="prefix"
          type="number"
          min="8"
          max="30"
          class="input"
        >
      </UiField>
      <UiField
        label="Range"
        :hint="hint || 'Suggested from the free pool; editable'"
      >
        <input
          v-model="cidr"
          class="input mono"
          required
        >
      </UiField>
      <div>
        <UiButton
          type="submit"
          variant="primary"
          :disabled="busy"
        >
          Add block
        </UiButton>
      </div>
    </form>
    <ErrorNote :error="writeError" />
  </UiSection>
</template>
