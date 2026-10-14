import { ref } from 'vue'
import { asApiError, type ApiError } from '../api/client'

/** One form's write: `busy` while it runs, the server's refusal in `error`. */
export function useSubmit() {
  const busy = ref(false)
  const error = ref<ApiError | null>(null)

  /** Whether the write went through; results travel through the closure. */
  async function run(write: () => Promise<unknown>): Promise<boolean> {
    busy.value = true
    error.value = null
    try {
      await write()
      return true
    } catch (e) {
      error.value = asApiError(e)
      return false
    } finally {
      busy.value = false
    }
  }

  return { busy, error, run }
}
