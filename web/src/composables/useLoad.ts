import { reactive, ref, type Ref } from 'vue'
import { asApiError, type ApiError } from '../api/client'

/** Loads at once; `reload` after a change. */
export function useLoad<T>(load: () => Promise<T>, initial: T) {
  const data = ref(initial) as Ref<T>
  const error = ref<ApiError | null>(null)
  const loading = ref(false)

  async function reload() {
    loading.value = true
    try {
      data.value = await load()
      error.value = null
    } catch (e) {
      error.value = asApiError(e)
    } finally {
      loading.value = false
    }
  }

  void reload()
  return reactive({ data, error, loading, reload })
}
