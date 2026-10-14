<script setup lang="ts">
defineProps<{ label: string; hint?: string }>()
</script>

<template>
  <label class="block space-y-1">
    <span class="text-xs font-medium text-slate-600 dark:text-slate-300">{{ label }}</span>
    <slot />
    <span
      v-if="hint"
      class="block text-xs text-slate-500 dark:text-slate-400"
    >{{ hint }}</span>
  </label>
</template>
