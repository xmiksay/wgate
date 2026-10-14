<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import type { AccountLink } from '../../api/types'
import { useSecretGuard } from '../../composables/useSecretGuard'
import { timeText } from '../../lib/format'
import UiButton from '../UiButton.vue'
import UiDialog from '../UiDialog.vue'

/** Shown while mounted: render it only while there is a link to show. */
const props = defineProps<{ link: AccountLink; title: string; email: string }>()
const emit = defineEmits<{ close: [] }>()

const open = ref(true)
const copied = ref(false)
const note = ref('')

// Copied counts as kept: only a link never taken off the screen asks before closing.
const guard = computed(() =>
  copied.value ? undefined : 'The link is shown only once; close anyway?',
)
useSecretGuard(guard)

watch(open, (o) => {
  if (!o) emit('close')
})

async function copy() {
  try {
    await navigator.clipboard.writeText(props.link.url)
    copied.value = true
    note.value = 'Copied.'
  } catch {
    note.value = 'Copying is blocked here: select the link instead.'
  }
}
</script>

<template>
  <UiDialog
    v-model:open="open"
    :title="title"
    :guard="guard"
  >
    <p class="text-sm">
      Send this link to {{ email }} yourself (wgate sends no mail). It works once, until
      {{ timeText(link.expires_at) }}; a newer link replaces it.
    </p>
    <p class="text-sm font-medium text-amber-700 dark:text-amber-300">
      Shown only now: wgate keeps only its hash.
    </p>
    <p class="mono rounded bg-slate-100 p-3 text-sm break-all select-all dark:bg-slate-800">
      {{ link.url }}
    </p>
    <div class="flex flex-wrap items-center gap-2">
      <UiButton
        variant="primary"
        @click="copy"
      >
        Copy link
      </UiButton>
      <span class="muted">{{ note }}</span>
    </div>
    <template #actions="{ close }">
      <UiButton @click="close">
        Close
      </UiButton>
    </template>
  </UiDialog>
</template>
