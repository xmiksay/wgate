<script setup lang="ts">
import { computed, nextTick, ref, useTemplateRef, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import type { ProviderOption } from '../api/types'
import UiButton from '../components/UiButton.vue'
import UiField from '../components/UiField.vue'
import TotpStep from '../components/login/TotpStep.vue'
import { useSubmit } from '../composables/useSubmit'
import { takeRoute } from '../lib/resume'
import { useSessionStore } from '../stores/session'

const sessionStore = useSessionStore()
const { problem, session, signedIn } = storeToRefs(sessionStore)
const route = useRoute()
const router = useRouter()
const { busy, error, run } = useSubmit()

// Why the server sent the browser back here from a provider login.
const refusals: Record<string, string> = {
  forbidden: 'This account is not a global admin.',
  expired: 'The sign-in expired or was started in another browser; try again.',
  failed: 'Signing in failed; try again, or check the server log.',
  cancelled: 'Sign-in was cancelled or refused at the identity provider.',
  unavailable: 'That sign-in provider is not configured.',
}

const email = ref('')
const password = ref('')
/** Set once the email is in: the second step, with what the server offers for it. */
const providers = ref<ProviderOption[] | null>(null)
const passwordInput = useTemplateRef<HTMLInputElement>('passwordInput')
const emailInput = useTemplateRef<HTMLInputElement>('emailInput')

const shown = computed(() => {
  const e = error.value
  // Every refused login is the same 401: the server tells nothing about the account.
  if (e) return e.status === 401 ? 'Wrong email or password.' : e.message
  const why = route.query.error
  return (typeof why === 'string' && refusals[why]) || problem.value
})

async function next() {
  const address = email.value.trim()
  if (!address || busy.value) return
  let offered: ProviderOption[] = []
  if (await run(async () => (offered = (await sessionStore.options(address)).providers))) {
    email.value = address
    providers.value = offered
    await nextTick()
    passwordInput.value?.focus()
  }
}

async function change() {
  providers.value = null
  password.value = ''
  error.value = null
  await nextTick()
  emailInput.value?.focus()
}

/** The password was right, and the account has TOTP on: its code is next. */
const waitingForCode = computed(() => session.value?.stage === 'totp')

// Whichever step finished the login (the code step is gone by then): move on.
watch(signedIn, async (yes) => {
  // The guard sends `/` home; a route remembered before the login goes first.
  if (yes) await router.push(takeRoute() ?? '/')
})

async function signIn() {
  if (!password.value || busy.value) return
  if (await run(() => sessionStore.signIn(email.value, password.value))) {
    password.value = ''
    // `totp`: this page shows the code step. `enrol` keeps the remembered route for later.
    if (session.value?.stage === 'enrol') await router.push({ name: 'enrol' })
  } else if (error.value?.status === 401) {
    password.value = ''
    passwordInput.value?.focus()
  }
}

async function startOver() {
  if (await run(() => sessionStore.logout())) await change()
}

function viaProvider(p: ProviderOption) {
  // A full navigation: the server sends the browser to the provider and back to `/`.
  window.location.assign(`/auth/oidc/${encodeURIComponent(p.id)}`)
}
</script>

<template>
  <div
    class="mx-auto mt-16 max-w-sm space-y-4 rounded-lg border border-slate-200 bg-white p-6 dark:border-slate-700 dark:bg-slate-900"
  >
    <div class="text-center">
      <h1 class="text-xl font-semibold">
        wgate
      </h1>
      <p class="muted">
        WireGuard gateway portal
      </p>
    </div>
    <p
      v-if="shown"
      role="alert"
      class="rounded bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-950 dark:text-red-200"
    >
      {{ shown }}
    </p>

    <TotpStep
      v-if="waitingForCode && session"
      :email="session.email"
      @back="startOver"
    />
    <form
      v-else-if="!providers"
      class="space-y-3"
      @submit.prevent="next"
    >
      <UiField label="Email">
        <input
          ref="emailInput"
          v-model="email"
          type="email"
          name="username"
          autocomplete="username"
          class="input"
          required
          autofocus
        >
      </UiField>
      <UiButton
        type="submit"
        variant="primary"
        class="w-full"
        :disabled="busy || !email.trim()"
      >
        Continue
      </UiButton>
    </form>

    <template v-else>
      <div class="flex items-center justify-between gap-2 text-sm">
        <span class="truncate font-medium">{{ email }}</span>
        <button
          type="button"
          class="link shrink-0"
          :disabled="busy"
          @click="change"
        >
          change
        </button>
      </div>
      <form
        class="space-y-3"
        @submit.prevent="signIn"
      >
        <!-- For password managers: the account this password belongs to. -->
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
        <UiField label="Password">
          <input
            ref="passwordInput"
            v-model="password"
            type="password"
            name="password"
            autocomplete="current-password"
            class="input"
            required
          >
        </UiField>
        <UiButton
          type="submit"
          variant="primary"
          class="w-full"
          :disabled="busy || !password"
        >
          Sign in
        </UiButton>
      </form>
      <div
        v-if="providers.length"
        class="space-y-2 border-t border-slate-200 pt-3 dark:border-slate-700"
      >
        <UiButton
          v-for="p in providers"
          :key="p.id"
          class="w-full"
          :disabled="busy"
          @click="viaProvider(p)"
        >
          Sign in with {{ p.name }}
        </UiButton>
      </div>
    </template>
  </div>
</template>
