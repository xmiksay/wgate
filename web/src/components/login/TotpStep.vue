<script setup lang="ts">
import { computed, nextTick, ref, useTemplateRef } from 'vue'
import UiButton from '../UiButton.vue'
import UiField from '../UiField.vue'
import { useSubmit } from '../../composables/useSubmit'
import { useSessionStore } from '../../stores/session'

defineProps<{ email: string }>()
/** Done is the session turning `full`, which unmounts this step: no event for it. */
const emit = defineEmits<{ back: [] }>()

const sessionStore = useSessionStore()
const { busy, error, run } = useSubmit()
const recovery = ref(false)
const value = ref('')
const input = useTemplateRef<HTMLInputElement>('input')

const code = computed(() => value.value.replace(/\s+/g, ''))
const shown = computed(() => {
  const e = error.value
  if (!e) return ''
  // Every refusal is the same 401, as for the password.
  if (e.status !== 401) return e.message
  return recovery.value ? 'Wrong or already used recovery code.' : 'Wrong code.'
})

async function toggle() {
  recovery.value = !recovery.value
  value.value = ''
  error.value = null
  await nextTick()
  input.value?.focus()
}

async function submit() {
  if (!code.value || busy.value) return
  const body = recovery.value ? { recovery_code: code.value } : { code: code.value }
  if (!(await run(() => sessionStore.verify(body)))) {
    value.value = ''
    input.value?.focus()
  }
}
</script>

<template>
  <div class="space-y-3">
    <div class="flex items-center justify-between gap-2 text-sm">
      <span class="truncate font-medium">{{ email }}</span>
      <button
        type="button"
        class="link shrink-0"
        :disabled="busy"
        @click="emit('back')"
      >
        start over
      </button>
    </div>
    <p
      v-if="shown"
      role="alert"
      class="rounded bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-950 dark:text-red-200"
    >
      {{ shown }}
    </p>
    <form
      class="space-y-3"
      @submit.prevent="submit"
    >
      <UiField
        v-if="!recovery"
        label="Code from your authenticator app"
      >
        <input
          ref="input"
          v-model="value"
          name="code"
          inputmode="numeric"
          autocomplete="one-time-code"
          pattern="[0-9 ]*"
          maxlength="7"
          class="input mono text-center tracking-widest"
          required
          autofocus
        >
      </UiField>
      <UiField
        v-else
        label="Recovery code"
        hint="One of the codes saved when two-factor was set up; each works once"
      >
        <input
          ref="input"
          v-model="value"
          name="recovery_code"
          autocomplete="off"
          autocapitalize="characters"
          spellcheck="false"
          placeholder="ABCD-EFGH-IJKL-MNOP"
          class="input mono"
          required
        >
      </UiField>
      <UiButton
        type="submit"
        variant="primary"
        class="w-full"
        :disabled="busy || !code"
      >
        {{ busy ? 'Checking…' : 'Verify' }}
      </UiButton>
      <p
        v-if="busy"
        role="status"
        class="muted"
      >
        Checking the code; this can take up to half a minute.
      </p>
    </form>
    <button
      type="button"
      class="link text-sm"
      :disabled="busy"
      @click="toggle"
    >
      {{ recovery ? 'Use the authenticator app instead' : 'Use a recovery code instead' }}
    </button>
  </div>
</template>
