<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useSecretGuard } from '../../composables/useSecretGuard'
import { downloadText } from '../../lib/conf'
import UiButton from '../UiButton.vue'
import UiDialog from '../UiDialog.vue'

/** Shown while mounted: render it only while there are codes to show. */
const props = defineProps<{ codes: string[]; email: string }>()
const emit = defineEmits<{ close: [] }>()

const open = ref(true)
const saved = ref(false)
const copied = ref('')
const text = computed(() => props.codes.join('\n') + '\n')

const guard = computed(() =>
  saved.value ? undefined : 'The recovery codes are shown only once; close anyway?',
)
useSecretGuard(guard)

watch(open, (o) => {
  if (!o) emit('close')
})

async function copy() {
  try {
    await navigator.clipboard.writeText(text.value)
    copied.value = 'Copied.'
  } catch {
    copied.value = 'Copying is blocked here: select the codes instead.'
  }
}

function download() {
  const header = `wgate recovery codes for ${props.email}\nEach works once.\n\n`
  downloadText('wgate-recovery-codes.txt', header + text.value)
}
</script>

<template>
  <UiDialog
    v-model:open="open"
    title="Your recovery codes"
    :guard="guard"
  >
    <p class="text-sm">
      Each code signs you in once in place of an authenticator code, if you lose the
      device. Keep them somewhere safe, apart from it.
    </p>
    <p class="text-sm font-medium text-amber-700 dark:text-amber-300">
      Shown only now: wgate keeps only their hashes.
    </p>
    <ol
      class="mono grid list-inside list-decimal grid-cols-1 gap-x-6 gap-y-1 rounded bg-slate-100 p-3 text-sm select-all sm:grid-cols-2 dark:bg-slate-800"
    >
      <li
        v-for="c in codes"
        :key="c"
      >
        {{ c }}
      </li>
    </ol>
    <div class="flex flex-wrap items-center gap-2">
      <UiButton @click="download">
        Download .txt
      </UiButton>
      <UiButton @click="copy">
        Copy
      </UiButton>
      <span class="muted">{{ copied }}</span>
    </div>
    <label class="flex items-center gap-2 text-sm">
      <input
        v-model="saved"
        type="checkbox"
      >
      I have saved these codes
    </label>
    <template #actions="{ close }">
      <UiButton
        variant="primary"
        :disabled="!saved"
        @click="close"
      >
        Done
      </UiButton>
    </template>
  </UiDialog>
</template>
