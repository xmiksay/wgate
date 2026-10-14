import { ref, type Ref } from 'vue'

/**
 * A form field prefilled from a `free-*` endpoint. Suggestions fill it until the user
 * edits it (`touch()`, bound to the field's input); after that, until `reset()`, it is
 * theirs. A request takes a `ticket()`; only the latest ticket's answer may land.
 */
export function useSuggestion<T>(empty: T) {
  const value = ref(empty) as Ref<T>
  let touched = false
  let seq = 0

  const ticket = () => ++seq
  const current = (t: number) => t === seq

  /** Whether the answer was still current (a touched field keeps its value either way). */
  function offer(suggested: T, t?: number): boolean {
    if (t !== undefined && !current(t)) return false
    if (!touched) value.value = suggested
    return true
  }

  const touch = () => {
    touched = true
  }

  /** The user chose the value themselves. */
  const edited = () => touched

  /** Empties the field, hands it back to suggestions, drops answers on their way. */
  function reset() {
    seq++
    touched = false
    value.value = empty
  }

  return { value, ticket, current, offer, touch, edited, reset }
}
