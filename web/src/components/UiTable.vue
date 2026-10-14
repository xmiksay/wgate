<script setup lang="ts">
defineProps<{ empty?: boolean }>()
</script>

<template>
  <div class="overflow-x-auto">
    <table
      class="w-full text-left text-sm [&_td]:border-t [&_td]:border-slate-200 [&_td]:px-2 [&_td]:py-1.5 [&_td]:align-top dark:[&_td]:border-slate-700 [&_th]:px-2 [&_th]:py-1 [&_th]:text-xs [&_th]:font-medium [&_th]:text-slate-500 dark:[&_th]:text-slate-400"
    >
      <thead>
        <tr>
          <slot name="head" />
        </tr>
      </thead>
      <tbody>
        <slot />
      </tbody>
    </table>
    <p
      v-if="empty"
      class="muted px-2 py-2"
    >
      None yet.
    </p>
  </div>
</template>
