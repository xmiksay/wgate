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
hooks.wrote = () => useStatusStore().wrote()

app.mount('#app')
