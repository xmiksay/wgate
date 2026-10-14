import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { ApiError, api, asApiError, call, setCsrf } from '../api/client'
import type { Session } from '../api/types'

export const useSessionStore = defineStore('session', () => {
  const session = ref<Session | null>(null)
  const loaded = ref(false)
  /** Why there is no session, shown on the login page (none for a plain 401). */
  const problem = ref('')

  const isGlobal = computed(() => session.value?.role === 'global_admin')

  async function load() {
    try {
      const s = await call(api.GET('/session'))
      session.value = s
      setCsrf(s.csrf)
      problem.value = ''
    } catch (e) {
      clear()
      const err = asApiError(e)
      if (err.status === 403) problem.value = 'This account is not a global admin.'
      else if (err.status !== 401) problem.value = err.message
    }
    loaded.value = true
  }

  function clear() {
    session.value = null
    setCsrf('')
  }

  /** Ends the session on the server; throws (keeping it) when that failed. */
  async function logout() {
    let res: Response
    try {
      res = await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' })
    } catch {
      throw new ApiError(0, 'network', 'The server cannot be reached.')
    }
    if (!res.ok) throw new ApiError(res.status, 'http', `Logout failed (HTTP ${res.status}).`)
    clear()
  }

  return { session, loaded, problem, isGlobal, load, clear, logout }
})
