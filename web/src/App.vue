<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { asApiError, type ApiError } from './api/client'
import ErrorNote from './components/ErrorNote.vue'
import StatusBar from './components/StatusBar.vue'
import UiButton from './components/UiButton.vue'
import { useSessionStore } from './stores/session'
import { useStatusStore } from './stores/status'

const router = useRouter()
const sessionStore = useSessionStore()
const statusStore = useStatusStore()
const { session, isGlobal, isAdmin } = storeToRefs(sessionStore)
const logoutError = ref<ApiError | null>(null)

// Plain users have no /status to poll (it is a 403 for them).
watch(
  isAdmin,
  (admin) => {
    if (admin) statusStore.start()
    else statusStore.stop()
  },
  { immediate: true },
)

const nav = computed(() => {
  const s = session.value
  if (!s || !isAdmin.value) return []
  if (isGlobal.value) {
    return [
      { to: '/tenants', label: 'Tenants' },
      { to: '/users', label: 'Users' },
      { to: '/federations', label: 'Federations' },
      { to: '/audit', label: 'Audit' },
    ]
  }
  return [
    { to: `/tenants/${s.tenant_id}`, label: 'Tenant' },
    { to: '/users', label: 'Users' },
  ]
})

async function logout() {
  logoutError.value = null
  try {
    await sessionStore.logout()
    await router.push({ name: 'login' })
  } catch (e) {
    logoutError.value = asApiError(e)
  }
}
</script>

<template>
  <header
    class="sticky top-0 z-10 border-b border-slate-200 bg-white/95 px-4 py-2 dark:border-slate-700 dark:bg-slate-900/95"
  >
    <div class="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2">
      <RouterLink
        to="/"
        class="text-lg font-semibold"
      >
        wgate
      </RouterLink>
      <nav
        v-if="session"
        class="flex gap-4 text-sm"
      >
        <RouterLink
          v-for="item in nav"
          :key="item.to"
          :to="item.to"
          class="text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white"
          active-class="font-semibold text-slate-900 dark:text-white"
        >
          {{ item.label }}
        </RouterLink>
      </nav>
      <!-- A login waiting for its code starts over from the login page instead. -->
      <div
        v-if="session && session.stage !== 'totp'"
        class="ml-auto flex items-center gap-3"
      >
        <RouterLink
          to="/me"
          class="muted hover:text-slate-900 dark:hover:text-white"
          active-class="font-semibold text-slate-900 dark:text-white"
          title="Your profile"
        >
          {{ session.email }}
        </RouterLink>
        <UiButton @click="logout">
          Log out
        </UiButton>
      </div>
    </div>
    <div
      v-if="session"
      class="mx-auto max-w-6xl space-y-1 pt-1"
    >
      <StatusBar v-if="isAdmin" />
      <ErrorNote :error="logoutError" />
    </div>
  </header>
  <main class="mx-auto max-w-6xl space-y-4 p-4">
    <RouterView :key="$route.path" />
  </main>
</template>
