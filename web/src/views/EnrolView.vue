<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useRouter } from 'vue-router'
import TotpSetup from '../components/me/TotpSetup.vue'
import UiSection from '../components/UiSection.vue'
import { takeRoute } from '../lib/resume'
import { useSessionStore } from '../stores/session'

const sessionStore = useSessionStore()
const { session } = storeToRefs(sessionStore)
const router = useRouter()

async function done() {
  // The confirm made the session `full` already; the guard needs to see it.
  await sessionStore.load()
  await router.push(takeRoute() ?? '/')
}
</script>

<template>
  <UiSection
    v-if="session"
    title="Set up two-factor sign-in"
  >
    <p class="max-w-prose text-sm">
      Admin accounts need a second factor: set up an authenticator app before going on.
      You have 30 minutes; log out to do it later.
    </p>
    <TotpSetup
      :email="session.email"
      immediate
      @done="done"
    />
  </UiSection>
</template>
