<script setup lang="ts">
import { ref } from 'vue'
import { api, call } from '../api/client'
import type { Peer } from '../api/types'
import { useSubmit } from '../composables/useSubmit'
import ConfirmButton from './ConfirmButton.vue'
import ErrorNote from './ErrorNote.vue'
import UiButton from './UiButton.vue'

const props = defineProps<{ peer: Peer }>()
const emit = defineEmits<{ changed: [] }>()

const { busy, error, run } = useSubmit()
const cidr = ref('')

async function add() {
  const ok = await run(() =>
    call(
      api.POST('/peers/{id}/routes', {
        params: { path: { id: props.peer.id } },
        body: { cidr: cidr.value.trim() },
      }),
    ),
  )
  if (ok) {
    cidr.value = ''
    emit('changed')
  }
}

async function remove(id: number) {
  if (await run(() => call(api.DELETE('/routes/{id}', { params: { path: { id } } })))) {
    emit('changed')
  }
}
</script>

<template>
  <div class="space-y-1">
    <div
      v-for="r in peer.routes"
      :key="r.id"
      class="flex items-center gap-2"
    >
      <span class="mono">{{ r.cidr }}</span>
      <ConfirmButton
        label="Remove"
        :message="`Remove the routed LAN ${r.cidr}? Its hosts lose this peer's access at once.`"
        confirm-label="Remove"
        :disabled="busy"
        @confirm="remove(r.id)"
      />
    </div>
    <form
      v-if="!peer.revoked"
      class="flex gap-1"
      @submit.prevent="add"
    >
      <input
        v-model="cidr"
        class="input w-36"
        placeholder="LAN, e.g. 192.168.1.0/24"
        aria-label="Routed LAN"
        required
      >
      <UiButton
        type="submit"
        :disabled="busy"
      >
        Add
      </UiButton>
    </form>
    <ErrorNote :error="error" />
  </div>
</template>
