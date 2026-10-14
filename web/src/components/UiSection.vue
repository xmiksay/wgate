<script setup lang="ts">
defineProps<{ title: string }>()
</script>

<template>
  <section
    class="space-y-3 rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900"
  >
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h2 class="font-semibold">
        {{ title }}
      </h2>
      <div class="flex gap-2">
        <slot name="actions" />
      </div>
    </div>
    <slot />
  </section>
</template>
