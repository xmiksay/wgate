import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import { hooks } from './api/client'
import { rememberRoute } from './lib/resume'
import { router } from './router'
import { useSessionStore } from './stores/session'
import { useStatusStore } from './stores/status'
import './style.css'

const app = createApp(App).use(createPinia()).use(router)

// The session ended under us (expired, or ended elsewhere): log in again, then resume.
hooks.unauthorized = () => {
  rememberRoute(router.currentRoute.value.fullPath)
  useSessionStore().clear()
  void router.push({ name: 'login' })
}
// E.g. a password session from before TOTP was mandatory: set it up, then resume.
hooks.totpRequired = async () => {
  const store = useSessionStore()
  await store.load()
  if (store.session?.stage !== 'enrol') return
  rememberRoute(router.currentRoute.value.fullPath)
  await router.push({ name: 'enrol' })
}
hooks.wrote = () => useStatusStore().wrote()

app.mount('#app')
