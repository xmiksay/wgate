import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, asApiError, call } from '../api/client'
import type { Status } from '../api/types'

const SLOW_MS = 5000
const FAST_MS = 1000
/** How long after one of our own writes we watch the agent closely. */
const FAST_FOR_MS = 30_000

export const useStatusStore = defineStore('status', () => {
  const status = ref<Status | null>(null)
  const problem = ref('')

  let running = false
  let busy = false
  let fastUntil = 0
  let timer: ReturnType<typeof setTimeout> | undefined
  // Bumped by stop(): a poll from before it must not land or reschedule.
  let generation = 0

  function schedule(ms: number) {
    clearTimeout(timer)
    timer = running ? setTimeout(tick, ms) : undefined
  }

  async function tick() {
    timer = undefined
    // Paused while hidden; `visibilitychange` restarts it.
    if (!running || busy || document.hidden) return
    const mine = generation
    busy = true
    try {
      const s = await call(api.GET('/status'))
      if (mine !== generation) return
      status.value = s
      problem.value = ''
    } catch (e) {
      if (mine === generation) problem.value = asApiError(e).message
    } finally {
      if (mine === generation) {
        busy = false
        schedule(Date.now() < fastUntil ? FAST_MS : SLOW_MS)
      }
    }
  }

  function onVisibility() {
    if (!document.hidden && !busy) schedule(0)
  }

  function start() {
    if (running) return
    running = true
    document.addEventListener('visibilitychange', onVisibility)
    schedule(0)
  }

  function stop() {
    generation++
    running = false
    busy = false
    document.removeEventListener('visibilitychange', onVisibility)
    schedule(0)
    status.value = null
    problem.value = ''
  }

  /** After a write of ours: poll at once, then every second for a while. */
  function wrote() {
    fastUntil = Date.now() + FAST_FOR_MS
    // A poll in flight reschedules itself at the fast rate when it finishes.
    if (!busy) schedule(0)
  }

  return { status, problem, start, stop, wrote }
})
