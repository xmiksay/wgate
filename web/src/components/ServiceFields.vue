<script setup lang="ts">
import { watch } from 'vue'
import { PROTOS } from '../api/types'
import UiField from './UiField.vue'

const proto = defineModel<string>('proto', { required: true })
const portFrom = defineModel<number | null>('portFrom', { required: true })
const portTo = defineModel<number | null>('portTo', { required: true })

watch(proto, (p) => {
  if (p === 'icmp') {
    portFrom.value = null
    portTo.value = null
  }
})

function port(v: string): number | null {
  return v === '' ? null : Number(v)
}
</script>

<template>
  <UiField label="Protocol">
    <select
      v-model="proto"
      class="input"
    >
      <option
        v-for="p in PROTOS"
        :key="p"
        :value="p"
      >
        {{ p }}
      </option>
    </select>
  </UiField>
  <template v-if="proto !== 'icmp'">
    <UiField
      label="Port from"
      hint="Empty: all ports"
    >
      <input
        :value="portFrom ?? ''"
        type="number"
        min="1"
        max="65535"
        class="input"
        @input="portFrom = port(($event.target as HTMLInputElement).value)"
      >
    </UiField>
    <UiField
      label="Port to"
      hint="Empty: just the first"
    >
      <input
        :value="portTo ?? ''"
        type="number"
        min="1"
        max="65535"
        class="input"
        @input="portTo = port(($event.target as HTMLInputElement).value)"
      >
    </UiField>
  </template>
</template>
