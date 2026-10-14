<script setup lang="ts">
import type { ApiError } from '../api/client'

defineProps<{ error: ApiError | null }>()
</script>

<template>
  <div
    v-if="error"
    role="alert"
    class="rounded border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200"
  >
    <p>{{ error.message }}</p>
    <template v-if="error.uncovered.length">
      <p class="mt-1">
        Not covered by the tenant's ceiling:
      </p>
      <ul class="mono list-inside list-disc">
        <li
          v-for="u in error.uncovered"
          :key="u"
        >
          {{ u }}
        </li>
      </ul>
    </template>
  </div>
</template>
