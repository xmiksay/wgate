import { onBeforeUnmount, watch, type Ref } from 'vue'
import { onBeforeRouteLeave, onBeforeRouteUpdate } from 'vue-router'

/**
 * While `question` is set (a one-time secret is on screen), leaving the page or the
 * route asks first. Call it from a component rendered inside the RouterView.
 */
export function useSecretGuard(question: Ref<string | undefined>) {
  const ask = () => !question.value || window.confirm(question.value)
  onBeforeRouteLeave(ask)
  // `/networks/1` → `/networks/2` reuses the route record: no leave guard runs.
  onBeforeRouteUpdate(ask)

  function onBeforeUnload(e: BeforeUnloadEvent) {
    e.preventDefault()
    e.returnValue = ''
  }

  const stop = watch(
    question,
    (q) => {
      if (q) window.addEventListener('beforeunload', onBeforeUnload)
      else window.removeEventListener('beforeunload', onBeforeUnload)
    },
    { immediate: true },
  )

  onBeforeUnmount(() => {
    stop()
    window.removeEventListener('beforeunload', onBeforeUnload)
  })
}
