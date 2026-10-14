import { reactive, ref, type Ref } from 'vue'
import { asApiError, type ApiError } from '../api/client'

/** Loads at once unless `immediate` is false; `reload` after a change. */
export function useLoad<T>(load: () => Promise<T>, initial: T, { immediate = true } = {}) {
  const data = ref(initial) as Ref<T>
  const error = ref<ApiError | null>(null)
  const loading = ref(false)
  let seq = 0

  async function reload() {
    // Only the latest call lands: an older one finishing late must not overwrite it.
    const mine = ++seq
    loading.value = true
    try {
      const result = await load()
      if (mine !== seq) return
      data.value = result
      error.value = null
    } catch (e) {
      if (mine === seq) error.value = asApiError(e)
    } finally {
      if (mine === seq) loading.value = false
    }
  }

  if (immediate) void reload()
  return reactive({ data, error, loading, reload })
}
