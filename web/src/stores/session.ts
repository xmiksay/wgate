import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { ApiError, api, asApiError, auth, call, setCsrf } from '../api/client'
import type { LoginOptions, Session, TotpLogin } from '../api/types'

export const useSessionStore = defineStore('session', () => {
  const session = ref<Session | null>(null)
  const loaded = ref(false)
  /** Why there is no session, shown on the login page (none for a plain 401). */
  const problem = ref('')

  /** The login is done: a `totp` or `enrol` session may only finish it. */
  const signedIn = computed(() => session.value?.stage === 'full')
  const isGlobal = computed(() => signedIn.value && session.value?.role === 'global_admin')
  /** Plain users may only use their own profile: every admin route is a 403 for them. */
  const isAdmin = computed(() => signedIn.value && session.value?.role !== 'user')

  async function load() {
    try {
      const s = await call(api.GET('/session'))
      session.value = s
      setCsrf(s.csrf)
      problem.value = ''
    } catch (e) {
      clear()
      const err = asApiError(e)
      if (err.status !== 401) problem.value = err.message
    }
    loaded.value = true
  }

  /** Which ways to sign in the login page offers for `email`. */
  function options(email: string): Promise<LoginOptions> {
    return call(auth.POST('/auth/options', { body: { email } }))
  }

  /** Signs in with a local password and loads the new session; throws when refused. */
  async function signIn(email: string, password: string) {
    await call(auth.POST('/auth/password', { body: { email, password } }))
    await load()
    if (!session.value) throw new ApiError(0, 'session', problem.value || 'Signing in failed.')
  }

  /**
   * The second step of a password login (`stage` totp); throws when refused. A failure
   * reloads the session: a lockout or the 5 minutes running out ends it.
   */
  async function verify(body: TotpLogin) {
    // The `auth` client sends no CSRF token on its own; this endpoint checks it.
    const headers = { 'X-CSRF-Token': session.value?.csrf ?? '' }
    try {
      await call(auth.POST('/auth/totp', { body, headers }))
    } catch (e) {
      await load()
      if (!session.value) problem.value = 'The sign-in ended (expired, or too many tries): start again.'
      throw e
    }
    await load()
    if (!signedIn.value) throw new ApiError(0, 'session', problem.value || 'Signing in failed.')
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

  return {
    session,
    loaded,
    problem,
    signedIn,
    isGlobal,
    isAdmin,
    load,
    options,
    signIn,
    verify,
    clear,
    logout,
  }
})
