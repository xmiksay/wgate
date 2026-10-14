<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import UiButton from './UiButton.vue'

/** `guard`: while set, closing needs a confirm with this question (e.g. a one-time secret). */
const props = defineProps<{ title: string; guard?: string }>()
const open = defineModel<boolean>('open', { required: true })
const dialog = ref<HTMLDialogElement>()
const confirming = ref(false)

function sync() {
  const d = dialog.value
  confirming.value = false
  if (!d) return
  if (open.value && !d.open) d.showModal()
  else if (!open.value && d.open) d.close()
}

watch(open, sync)
onMounted(sync)

/** For the slot's own Close/Cancel buttons. */
function close() {
  if (props.guard) confirming.value = true
  else open.value = false
}

function onCancel(e: Event) {
  if (!props.guard) return
  e.preventDefault()
  confirming.value = true
}

function onClose() {
  if (!open.value) return
  // Browsers may close anyway on a repeated Esc despite preventDefault: reopen.
  if (props.guard) {
    dialog.value?.showModal()
    confirming.value = true
  } else {
    open.value = false
  }
}
</script>

<template>
  <dialog
    ref="dialog"
    class="m-auto w-full max-w-2xl rounded-lg border border-slate-300 bg-white p-0 text-slate-900 shadow-xl backdrop:bg-black/50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
    @cancel="onCancel"
    @close="onClose"
  >
    <div
      v-if="open"
      class="space-y-4 p-5"
    >
      <h2 class="text-lg font-semibold">
        {{ title }}
      </h2>
      <slot />
      <div
        v-if="confirming && guard"
        role="alert"
        class="flex flex-wrap items-center justify-end gap-2 rounded border border-amber-300 bg-amber-50 p-2 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-100"
      >
        <span class="mr-auto">{{ guard }}</span>
        <UiButton @click="confirming = false">
          Keep open
        </UiButton>
        <UiButton
          variant="danger"
          @click="open = false"
        >
          Close anyway
        </UiButton>
      </div>
      <div
        v-else
        class="flex justify-end gap-2"
      >
        <slot
          name="actions"
          :close="close"
        />
      </div>
    </div>
  </dialog>
</template>
