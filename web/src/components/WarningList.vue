<script setup lang="ts">
defineProps<{ warnings: string[] }>()
</script>

<template>
  <ul
    v-if="warnings.length"
    class="space-y-1 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
  >
    <li
      v-for="w in warnings"
      :key="w"
    >
      {{ w }}
    </li>
  </ul>
</template>
