<script setup lang="ts">
import { computed, ref, useTemplateRef } from 'vue'
import { api, call } from '../../api/client'
import { PASSWORD_MAX, PASSWORD_MIN } from '../../api/types'
import ErrorNote from '../ErrorNote.vue'
import UiButton from '../UiButton.vue'
import UiField from '../UiField.vue'
import UiSection from '../UiSection.vue'
import { useSubmit } from '../../composables/useSubmit'

defineProps<{ email: string }>()

const { busy, error, run } = useSubmit()
const currentInput = useTemplateRef<HTMLInputElement>('currentInput')
const current = ref('')
const next = ref('')
const repeat = ref('')
const changed = ref(false)

// Code points, as the server counts them (not UTF-16 units).
const length = computed(() => [...next.value].length)
const problem = computed(() => {
  if (!next.value) return ''
  if (length.value < PASSWORD_MIN || length.value > PASSWORD_MAX) {
    return `A password has ${PASSWORD_MIN} to ${PASSWORD_MAX} characters.`
  }
  if (repeat.value && repeat.value !== next.value) return 'The new passwords differ.'
  return ''
})
const ready = computed(
  () => current.value !== '' && next.value !== '' && next.value === repeat.value && !problem.value,
)

async function submit() {
  if (!ready.value || busy.value) return
  changed.value = false
  const body = { current: current.value, new: next.value }
  if (await run(() => call(api.POST('/me/password', { body })))) {
    current.value = next.value = repeat.value = ''
    changed.value = true
  } else if (error.value?.status === 422 || error.value?.status === 429) {
    current.value = ''
    currentInput.value?.focus()
  }
}
</script>

<template>
  <UiSection title="Change password">
    <form
      class="max-w-sm space-y-3"
      @submit.prevent="submit"
    >
      <p class="muted">
        Signing in only through a provider? Such an account has no password to change
        here; an admin sets one with <code class="mono">wgate user password &lt;email&gt;</code>.
      </p>
      <!-- For password managers: the account the new password belongs to. -->
      <input
        :value="email"
        type="email"
        name="username"
        autocomplete="username"
        class="sr-only"
        tabindex="-1"
        aria-hidden="true"
        readonly
      >
      <UiField label="Current password">
        <input
          ref="currentInput"
          v-model="current"
          type="password"
          autocomplete="current-password"
          class="input"
          required
        >
      </UiField>
      <UiField
        label="New password"
        :hint="`${PASSWORD_MIN} to ${PASSWORD_MAX} characters`"
      >
        <input
          v-model="next"
          type="password"
          autocomplete="new-password"
          class="input"
          required
        >
      </UiField>
      <UiField label="Repeat the new password">
        <input
          v-model="repeat"
          type="password"
          autocomplete="new-password"
          class="input"
          required
        >
      </UiField>
      <p
        v-if="problem"
        class="text-sm text-amber-800 dark:text-amber-300"
      >
        {{ problem }}
      </p>
      <ErrorNote :error="error" />
      <p
        v-if="changed"
        role="status"
        class="rounded bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200"
      >
        Password changed; other sessions were signed out.
      </p>
      <UiButton
        type="submit"
        variant="primary"
        :disabled="busy || !ready"
      >
        Change password
      </UiButton>
    </form>
  </UiSection>
</template>
