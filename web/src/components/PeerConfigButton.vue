<script setup lang="ts">
import { ref } from 'vue'
import { api, call } from '../api/client'
import type { ConfigOut, Peer } from '../api/types'
import { useSubmit } from '../composables/useSubmit'
import { downloadText } from '../lib/conf'
import ConfigReveal from './ConfigReveal.vue'
import ConfirmButton from './ConfirmButton.vue'
import ErrorNote from './ErrorNote.vue'
import UiButton from './UiButton.vue'
import UiDialog from './UiDialog.vue'

const props = defineProps<{ peer: Peer; fileName: string }>()

const { busy, error, run } = useSubmit()
// The config may hold a private key: it lives here only while the dialog is open.
const result = ref<ConfigOut | null>(null)
const open = ref(false)

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
      @update:open="(v) => !v && close()"
    >
      <ConfigReveal
        v-if="result"
        :config="result.config"
        :warnings="result.warnings"
        :file-name="fileName"
        :secret="peer.key_source === 'server'"
      />
      <template #actions>
        <UiButton @click="close">
          Close
        </UiButton>
      </template>
    </UiDialog>
  </div>
</template>
