import { ref, type Ref } from 'vue'

/**
 * A form field prefilled from a `free-*` endpoint: a new suggestion replaces the field
 * only while it is empty or still holds the previous suggestion, never what was typed.
 */
export function useSuggestion<T>(empty: T) {
  const value = ref(empty) as Ref<T>
  let last: T = empty

  function offer(suggested: T) {
    if (value.value === empty || value.value === last) value.value = suggested
    last = suggested
  }

  function reset() {
    value.value = empty
    last = empty
  }

  return { value, offer, reset }
}
