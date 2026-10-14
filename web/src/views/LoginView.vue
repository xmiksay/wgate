<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { storeToRefs } from 'pinia'
import UiButton from '../components/UiButton.vue'
import { useSessionStore } from '../stores/session'

const { problem } = storeToRefs(useSessionStore())
const route = useRoute()

// Why the server's /auth/callback sent the browser back here.
const refusals: Record<string, string> = {
  forbidden: 'This account is not a global admin.',
  expired: 'The sign-in expired or was started in another browser; try again.',
  failed: 'Signing in failed; try again, or check the server log.',
}
const shown = computed(() => {
  const error = route.query.error
  return (typeof error === 'string' && refusals[error]) || problem.value
})

function signIn() {
  // A full navigation: the server sends the browser to the IdP and back to `/`.
  window.location.assign('/auth/login')
}
</script>

<template>
  <div
    class="mx-auto mt-16 max-w-sm space-y-4 rounded-lg border border-slate-200 bg-white p-6 text-center dark:border-slate-700 dark:bg-slate-900"
  >
    <h1 class="text-xl font-semibold">
      wgate
    </h1>
    <p class="muted">
      WireGuard gateway portal
    </p>
    <p
      v-if="shown"
      role="alert"
      class="rounded bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-950 dark:text-red-200"
    >
      {{ shown }}
    </p>
    <UiButton
      variant="primary"
      @click="signIn"
    >
      Sign in
    </UiButton>
  </div>
</template>
