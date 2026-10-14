<script setup lang="ts">
const { variant = 'secondary', type = 'button' } = defineProps<{
  variant?: 'primary' | 'secondary' | 'danger'
  type?: 'button' | 'submit'
  disabled?: boolean
}>()

const look = {
  primary: 'bg-sky-700 text-white hover:bg-sky-800 dark:bg-sky-600 dark:hover:bg-sky-500',
  secondary:
    'border border-slate-300 bg-white hover:bg-slate-100 dark:border-slate-600 dark:bg-slate-800 dark:hover:bg-slate-700',
  danger: 'bg-red-700 text-white hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-500',
}
</script>

<template>
  <button
    :type="type"
    :disabled="disabled"
    class="rounded px-3 py-1 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50"
    :class="look[variant]"
  >
    <slot />
  </button>
</template>
