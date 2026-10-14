<script setup lang="ts">
import { api, call } from '../api/client'
import type { Peer } from '../api/types'
import { useSubmit } from '../composables/useSubmit'
import ConfirmButton from './ConfirmButton.vue'
import ErrorNote from './ErrorNote.vue'
import PeerConfigButton from './PeerConfigButton.vue'
import PeerRoutes from './PeerRoutes.vue'
import UiTable from './UiTable.vue'

/** `subject` is the first column: the device on a network's page, the network on a user's. */
const props = defineProps<{
  peers: Peer[]
  subjectLabel: string
  subject: (p: Peer) => { text: string; to?: string }
  fileName: (p: Peer) => string
}>()
const emit = defineEmits<{ changed: [] }>()

const { busy, error, run } = useSubmit()

async function revoke(id: number) {
  if (await run(() => call(api.POST('/peers/{id}/revoke', { params: { path: { id } } })))) {
    emit('changed')
  }
}

async function remove(id: number) {
  if (await run(() => call(api.DELETE('/peers/{id}', { params: { path: { id } } })))) {
    emit('changed')
  }
}

const label = (p: Peer) => `${props.subject(p).text} (${p.ip})`
</script>

<template>
  <ErrorNote :error="error" />
  <UiTable :empty="!peers.length">
    <template #head>
      <th>{{ subjectLabel }}</th>
      <th>Address</th>
      <th>Key</th>
      <th>Routed LANs</th>
      <th>State</th>
      <th />
    </template>
    <tr
      v-for="p in peers"
      :key="p.id"
      :class="{ 'opacity-60': p.revoked }"
    >
      <td>
        <RouterLink
          v-if="subject(p).to"
          :to="subject(p).to ?? ''"
          class="link"
        >
          {{ subject(p).text }}
        </RouterLink>
        <template v-else>
          {{ subject(p).text }}
        </template>
      </td>
      <td class="mono">
        {{ p.ip }}
      </td>
      <td
        class="mono"
        :title="p.public_key"
      >
        {{ p.public_key.slice(0, 10) }}… ({{ p.key_source }})
      </td>
      <td>
        <PeerRoutes
          :peer="p"
          @changed="emit('changed')"
        />
      </td>
      <td>{{ p.revoked ? 'revoked' : 'active' }}</td>
      <td>
        <div class="flex flex-wrap justify-end gap-2">
          <template v-if="!p.revoked">
            <PeerConfigButton
              :peer="p"
              :file-name="fileName(p)"
            />
            <ConfirmButton
              label="Revoke"
              :message="`Revoke ${label(p)}? Its tunnel stops at once; its address, key and LANs are freed.`"
              confirm-label="Revoke"
              :disabled="busy"
              @confirm="revoke(p.id)"
            />
          </template>
          <ConfirmButton
            label="Delete"
            :message="`Delete ${label(p)} for good?`"
            confirm-label="Delete"
            :disabled="busy"
            @confirm="remove(p.id)"
          />
        </div>
      </td>
    </tr>
  </UiTable>
</template>
