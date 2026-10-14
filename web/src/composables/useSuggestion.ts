import { ref, type Ref } from 'vue'

/**
 * A form field prefilled from a `free-*` endpoint: a new suggestion replaces the field
 * only while it is empty or still holds the previous suggestion, never what was typed.
 * Each request takes a `ticket()`; only the latest ticket's answer may land.
 */
export function useSuggestion<T>(empty: T) {
  const value = ref(empty) as Ref<T>
  let last: T = empty
  let seq = 0

  const ticket = () => ++seq
  const current = (t: number) => t === seq

  /** Whether the answer was still current (it may still leave a typed value alone). */
  function offer(suggested: T, t: number): boolean {
    if (!current(t)) return false
    if (value.value === empty || value.value === last) value.value = suggested
    last = suggested
    return true
  }

  /** The user chose this value themselves. */
  const edited = () => value.value !== empty && value.value !== last

  /** Takes back the last suggestion if the field still holds it. */
  function withdraw() {
    if (value.value === last) value.value = empty
    last = empty
  }

  /** Empties the field and drops every answer still on its way. */
  function reset() {
    seq++
    value.value = empty
    last = empty
  }

  return { value, ticket, current, offer, edited, withdraw, reset }
}
