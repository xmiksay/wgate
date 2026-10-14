<script setup lang="ts">
import { computed, ref } from 'vue'
import { api, call } from '../api/client'
import type { ConfigOut, Peer } from '../api/types'
import { useSubmit } from '../composables/useSubmit'
import { SECRET_GUARD, downloadText } from '../lib/conf'
import ConfigReveal from './ConfigReveal.vue'
import ConfirmButton from './ConfirmButton.vue'
import ErrorNote from './ErrorNote.vue'
import UiButton from './UiButton.vue'
import UiDialog from './UiDialog.vue'

const props = defineProps<{ peer: Peer; fileName: string }>()
const emit = defineEmits<{ changed: [] }>()

const { busy, error, run } = useSubmit()
// The config may hold a private key: it lives here only while the dialog is open.
const result = ref<ConfigOut | null>(null)
const open = ref(false)
const guard = computed(() =>
  result.value?.config && props.peer.key_source === 'server' ? SECRET_GUARD : undefined,
)

async function fetchConfig() {
  let out: ConfigOut | null = null
  const ok = await run(async () => {
    out = await call(api.POST('/peers/{id}/config', { params: { path: { id: props.peer.id } } }))
  })
  if (!ok && error.value?.status === 409) {
    error.value.message = 'The peer changed meanwhile (its key or the hub). Try again.'
  }
  return out as ConfigOut | null
}

async function rotate() {
  result.value = await fetchConfig()
  open.value = result.value !== null
  // The peer's public key changed with it.
  if (result.value?.config) emit('changed')
}

async function downloadPasted() {
  const out = await fetchConfig()
  if (out?.config) downloadText(props.fileName, out.config.config)
  else if (out) {
    result.value = out
    open.value = true
  }
}

function close() {
  open.value = false
  result.value = null
}
</script>

<template>
  <div class="space-y-1">
    <ConfirmButton
      v-if="peer.key_source === 'server'"
      label="New config (replaces the current one)"
      message="This makes a new key pair for the peer. The device's current config stops working at once; it needs the new one."
      confirm-label="Make a new config"
      variant="secondary"
      :disabled="busy"
      @confirm="rotate"
    />
    <UiButton
      v-else
      :disabled="busy"
      @click="downloadPasted"
    >
      Download config
    </UiButton>
    <ErrorNote :error="error" />
    <UiDialog
      :open="open"
      title="Peer config"
      :guard="guard"
      @update:open="(v) => !v && close()"
    >
      <ConfigReveal
        v-if="result"
        :config="result.config"
        :warnings="result.warnings"
        :file-name="fileName"
        :secret="peer.key_source === 'server'"
      />
      <template #actions="{ close: requestClose }">
        <UiButton @click="requestClose">
          Close
        </UiButton>
      </template>
    </UiDialog>
  </div>
</template>
