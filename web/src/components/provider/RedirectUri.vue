<script setup lang="ts">
import { ref } from 'vue'
import UiButton from '../UiButton.vue'

// The server's own is `<public_url>/auth/callback`: the same as long as the UI is
// opened at the public URL.
const uri = `${window.location.origin}/auth/callback`
const note = ref('')

async function copy() {
  try {
    await navigator.clipboard.writeText(uri)
    note.value = 'Copied.'
  } catch {
    note.value = 'Copying is blocked here: select the URI instead.'
  }
}
</script>

<template>
  <div class="space-y-1 text-sm">
    <p class="muted">
      Register this redirect URI at the provider (the same for every provider):
    </p>
    <div class="flex flex-wrap items-center gap-2">
      <span class="mono rounded bg-slate-100 px-2 py-1 break-all select-all dark:bg-slate-800">
        {{ uri }}
      </span>
      <UiButton @click="copy">
        Copy
      </UiButton>
      <span class="muted">{{ note }}</span>
    </div>
  </div>
</template>
