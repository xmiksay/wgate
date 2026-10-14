<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'

defineProps<{ title: string }>()
const open = defineModel<boolean>('open', { required: true })
const dialog = ref<HTMLDialogElement>()

function sync() {
  const d = dialog.value
  if (!d) return
  if (open.value && !d.open) d.showModal()
  else if (!open.value && d.open) d.close()
}

watch(open, sync)
onMounted(sync)
</script>

<template>
  <dialog
    ref="dialog"
    class="m-auto w-full max-w-2xl rounded-lg border border-slate-300 bg-white p-0 text-slate-900 shadow-xl backdrop:bg-black/50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
    @close="open = false"
  >
    <div
      v-if="open"
      class="space-y-4 p-5"
    >
      <h2 class="text-lg font-semibold">
        {{ title }}
      </h2>
      <slot />
      <div class="flex justify-end gap-2">
        <slot name="actions" />
      </div>
    </div>
  </dialog>
</template>
