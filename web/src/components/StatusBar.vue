<script setup lang="ts">
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import { useStatusStore } from '../stores/status'
import { timeText } from '../lib/format'

const { status, problem } = storeToRefs(useStatusStore())

const applied = computed(() => {
  const s = status.value
  return s != null && s.applied_revision != null && s.applied_revision >= s.revision
})
const appliedAt = computed(() =>
  status.value?.applied_at ? `applied ${timeText(status.value.applied_at)}` : undefined,
)
</script>

<template>
  <div>
    <div class="flex flex-wrap items-center gap-2 text-xs">
      <span
        v-if="problem"
        class="text-red-700 dark:text-red-400"
      >status unavailable: {{ problem }}</span>
      <span
        v-else-if="!status"
        class="muted"
      >status …</span>
      <template v-else>
        <span
          v-if="applied"
          class="rounded bg-emerald-100 px-2 py-0.5 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-200"
          :title="appliedAt"
        >applied (rev {{ status.revision }})</span>
        <span
          v-else
          class="rounded bg-amber-100 px-2 py-0.5 text-amber-900 dark:bg-amber-900 dark:text-amber-100"
          :title="appliedAt"
        >pending (rev {{ status.applied_revision ?? '–' }} → {{ status.revision }})</span>
        <span
          v-if="status.failing"
          class="rounded bg-red-100 px-2 py-0.5 text-red-800 dark:bg-red-900 dark:text-red-100"
        >agent failing</span>
      </template>
    </div>
    <pre
      v-if="status?.error"
      class="mono mt-1 max-h-32 overflow-auto rounded bg-red-50 p-2 whitespace-pre-wrap text-red-800 dark:bg-red-950 dark:text-red-200"
    >{{ status.error }}</pre>
  </div>
</template>
