<script setup lang="ts">
import { computed, ref } from 'vue'
import { auth, call } from '../api/client'
import { PASSWORD_MAX, PASSWORD_MIN, type LinkInfo } from '../api/types'
import ErrorNote from '../components/ErrorNote.vue'
import UiButton from '../components/UiButton.vue'
import UiField from '../components/UiField.vue'
import { useLoad } from '../composables/useLoad'
import { useNewPassword } from '../composables/useNewPassword'
import { useSubmit } from '../composables/useSubmit'

const props = defineProps<{ token: string }>()

const path = { params: { path: { token: props.token } } }
const link = useLoad(() => call(auth.GET('/auth/account/{token}', path)), null as LinkInfo | null)
const { busy, error, run } = useSubmit()
const { next, repeat, problem, ready, clear } = useNewPassword()
const done = ref(false)

/** Any dead link (unknown, used, expired, replaced) is the same 404. */
const dead = computed(() => link.error?.status === 404 || error.value?.status === 404)
const title = computed(() =>
  link.data?.purpose === 'reset' ? 'Reset your password' : 'Set your password',
)

async function submit() {
  if (!ready.value || busy.value) return
  const body = { password: next.value }
  if (await run(() => call(auth.POST('/auth/account/{token}', { ...path, body })))) {
    clear()
    done.value = true
  }
}
</script>

<template>
  <div
    class="mx-auto mt-16 max-w-sm space-y-4 rounded-lg border border-slate-200 bg-white p-6 dark:border-slate-700 dark:bg-slate-900"
  >
    <h1 class="text-center text-xl font-semibold">
      {{ dead || !link.data ? 'wgate' : title }}
    </h1>
    <p
      v-if="dead"
      role="alert"
      class="text-sm"
    >
      This link is invalid or has expired. Ask an admin for a new one.
    </p>
    <ErrorNote
      v-else-if="link.error"
      :error="link.error"
    />
    <div
      v-else-if="done"
      role="status"
      class="space-y-3 text-sm"
    >
      <p>
        Your password is set{{ link.data?.purpose === 'reset' ? ' and your other sessions ended' : '' }}.
      </p>
      <RouterLink
        to="/login"
        class="link"
      >
        Sign in
      </RouterLink>
    </div>
    <form
      v-else-if="link.data"
      class="space-y-3"
      @submit.prevent="submit"
    >
      <p class="text-sm">
        For <span class="font-medium">{{ link.data.email }}</span>
      </p>
      <!-- For password managers: the account the new password belongs to. -->
      <input
        :value="link.data.email"
        type="email"
        name="username"
        autocomplete="username"
        class="sr-only"
        tabindex="-1"
        aria-hidden="true"
        readonly
      >
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
          autofocus
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
      <UiButton
        type="submit"
        variant="primary"
        class="w-full"
        :disabled="busy || !ready"
      >
        {{ title }}
      </UiButton>
    </form>
    <p
      v-else
      class="muted text-center"
    >
      Loading…
    </p>
  </div>
</template>
