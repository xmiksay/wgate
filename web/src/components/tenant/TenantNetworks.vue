<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api, call } from '../../api/client'
import type { Block, Network } from '../../api/types'
import { useLoad } from '../../composables/useLoad'
import { useSubmit } from '../../composables/useSubmit'
import { useSuggestion } from '../../composables/useSuggestion'
import { cidrContains } from '../../lib/cidr'
import { splitList } from '../../lib/format'
import ErrorNote from '../ErrorNote.vue'
import UiButton from '../UiButton.vue'
import UiField from '../UiField.vue'
import UiSection from '../UiSection.vue'
import UiTable from '../UiTable.vue'

const props = defineProps<{ tenantId: number; blocks: Block[] }>()
const router = useRouter()

const networks = useLoad(
  () => call(api.GET('/networks', { params: { query: { tenant_id: props.tenantId } } })),
  [] as Network[],
)
const { busy, error, run } = useSubmit()
const name = ref('')
const slug = ref('')
const prefix = ref(26)
const range = useSuggestion('')
const block = useSuggestion<number | null>(null)
const portField = useSuggestion<number | null>(null)
const { value: cidr } = range
const { value: blockId } = block
const { value: port } = portField
const mesh = ref(false)
const dns = ref('')
const hints = ref({ cidr: '', port: '' })

const blockHint = computed(() =>
  props.blocks.length ? 'The block the range lies in' : 'The tenant has no block yet',
)

/** Inside the block the user picked, else anywhere in the tenant's blocks. */
async function suggestRange() {
  const t = range.ticket()
  const chosen = block.edited() ? props.blocks.find((b) => b.id === blockId.value) : undefined
  hints.value.cidr = ''
  try {
    const s = await call(
      api.GET('/tenants/{id}/free-range', {
        params: {
          path: { id: props.tenantId },
          query: { prefix: prefix.value, block_id: chosen?.id },
        },
      }),
    )
    if (range.offer(s.free ?? '', t) && !s.free) {
      hints.value.cidr = `No free /${prefix.value} in ${chosen ? chosen.cidr : "the tenant's blocks"}.`
    }
  } catch {
    if (range.current(t)) hints.value.cidr = 'No suggestion: type a range.'
  }
}

async function suggestPort() {
  const t = portField.ticket()
  hints.value.port = ''
  try {
    const s = await call(api.GET('/free-port'))
    if (portField.offer(s.free ?? null, t) && s.free == null) hints.value.port = 'No free port left.'
  } catch {
    if (portField.current(t)) hints.value.port = 'No suggestion: type a port.'
  }
}

// A new block may free a range; a block the user picks narrows the suggestion.
watch([prefix, () => props.blocks], suggestRange, { immediate: true })
watch(blockId, () => {
  if (block.edited()) void suggestRange()
})
void suggestPort()

// Follows the range (the block holding it) until the user picks one.
watch(
  [cidr, () => props.blocks],
  () => {
    const holder = props.blocks.find((b) => cidrContains(b.cidr, cidr.value)) ?? props.blocks[0]
    block.offer(holder?.id ?? null)
  },
  { immediate: true },
)

async function create() {
  const block = blockId.value
  const p = port.value
  if (block === null || p === null) return
  let made: Network | undefined
  const ok = await run(async () => {
    made = await call(
      api.POST('/networks', {
        body: {
          tenant_id: props.tenantId,
          block_id: block,
          name: name.value.trim(),
          slug: slug.value.trim(),
          cidr: cidr.value.trim(),
          port: p,
          mesh: mesh.value,
          dns: splitList(dns.value),
        },
      }),
    )
  })
  if (ok && made) await router.push(`/networks/${made.id}`)
}
</script>

<template>
  <UiSection title="Networks">
    <ErrorNote :error="networks.error" />
    <UiTable :empty="!networks.loading && !networks.data.length">
      <template #head>
        <th>Name</th>
        <th>Interface</th>
        <th>Range</th>
        <th>Port</th>
        <th>Mesh</th>
        <th>State</th>
      </template>
      <tr
        v-for="n in networks.data"
        :key="n.id"
      >
        <td>
          <RouterLink
            :to="`/networks/${n.id}`"
            class="link"
          >
            {{ n.name }}
          </RouterLink>
        </td>
        <td class="mono">
          wg-{{ n.slug }}
        </td>
        <td class="mono">
          {{ n.cidr }}
        </td>
        <td>{{ n.port }}</td>
        <td>{{ n.mesh ? 'on' : 'off' }}</td>
        <td>{{ n.disabled ? 'disabled' : 'active' }}</td>
      </tr>
    </UiTable>

    <h3 class="pt-2 text-sm font-semibold">
      New network
    </h3>
    <form
      class="grid gap-3 sm:grid-cols-4 sm:items-end"
      @submit.prevent="create"
    >
      <UiField label="Name">
        <input
          v-model="name"
          class="input"
          required
        >
      </UiField>
      <UiField
        label="Slug"
        hint="Interface wg-<slug>; a-z, 0-9, -; up to 11"
      >
        <input
          v-model="slug"
          class="input mono"
          maxlength="11"
          required
        >
      </UiField>
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
        :hint="hints.cidr || 'Suggested; editable'"
      >
        <input
          v-model="cidr"
          class="input mono"
          required
          @input="range.touch()"
        >
      </UiField>
      <UiField
        label="Block"
        :hint="blockHint"
      >
        <select
          v-model="blockId"
          class="input"
          required
          @change="block.touch()"
        >
          <option
            v-for="b in blocks"
            :key="b.id"
            :value="b.id"
          >
            {{ b.cidr }}
          </option>
        </select>
      </UiField>
      <UiField
        label="UDP port"
        :hint="hints.port || 'Suggested; editable'"
      >
        <input
          v-model.number="port"
          type="number"
          min="1"
          max="65535"
          class="input"
          required
          @input="portField.touch()"
        >
      </UiField>
      <UiField
        label="DNS (optional)"
        hint="Hosts pushed to clients"
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
          :disabled="busy || blockId === null"
        >
          Create network
        </UiButton>
      </div>
    </form>
    <ErrorNote :error="error" />
  </UiSection>
</template>
