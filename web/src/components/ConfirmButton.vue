<script setup lang="ts">
import { ref } from 'vue'
import UiButton from './UiButton.vue'
import UiDialog from './UiDialog.vue'

const { confirmLabel = 'Confirm', variant = 'danger' } = defineProps<{
  label: string
  message: string
  confirmLabel?: string
  variant?: 'secondary' | 'danger'
  disabled?: boolean
}>()
const emit = defineEmits<{ confirm: [] }>()
const open = ref(false)

function confirm() {
  open.value = false
  emit('confirm')
}
</script>

<template>
  <UiButton
    :variant="variant"
    :disabled="disabled"
    @click="open = true"
  >
    {{ label }}
  </UiButton>
  <UiDialog
    v-model:open="open"
    :title="label"
  >
    <p class="text-sm">
      {{ message }}
    </p>
    <template #actions>
      <UiButton @click="open = false">
        Cancel
      </UiButton>
      <UiButton
        variant="danger"
        @click="confirm"
      >
        {{ confirmLabel }}
      </UiButton>
    </template>
  </UiDialog>
</template>
