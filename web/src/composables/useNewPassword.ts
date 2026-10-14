import { computed, ref } from 'vue'
import { PASSWORD_MAX, PASSWORD_MIN } from '../api/types'

/** A new password typed twice: what is wrong with it, and whether it may be sent. */
export function useNewPassword() {
  const next = ref('')
  const repeat = ref('')

  // Code points, as the server counts them (not UTF-16 units).
  const length = computed(() => [...next.value].length)
  const problem = computed(() => {
    if (!next.value) return ''
    if (length.value < PASSWORD_MIN || length.value > PASSWORD_MAX) {
      return `A password has ${PASSWORD_MIN} to ${PASSWORD_MAX} characters.`
    }
    if (repeat.value && repeat.value !== next.value) return 'The new passwords differ.'
    return ''
  })
  const ready = computed(() => next.value !== '' && next.value === repeat.value && !problem.value)

  function clear() {
    next.value = repeat.value = ''
  }

  return { next, repeat, problem, ready, clear }
}
