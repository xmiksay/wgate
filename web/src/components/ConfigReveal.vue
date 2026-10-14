<script setup lang="ts">
import { computed, ref } from 'vue'
import type { Rendered } from '../api/types'
import { downloadText, svgDataUrl } from '../lib/conf'
import UiButton from './UiButton.vue'
import WarningList from './WarningList.vue'

const props = defineProps<{
  config: Rendered | null | undefined
  warnings: string[]
  fileName: string
  /** It carries a private key (a server-made key pair). */
  secret: boolean
}>()

const copied = ref('')
const qr = computed(() => (props.config?.qr_svg ? svgDataUrl(props.config.qr_svg) : null))

async function copy() {
  if (!props.config) return
  try {
    await navigator.clipboard.writeText(props.config.config)
    copied.value = 'Copied.'
  } catch {
    copied.value = 'Copying is blocked here: select the text instead.'
  }
}

function download() {
  if (props.config) downloadText(props.fileName, props.config.config)
}
</script>

<template>
  <div class="space-y-3">
    <WarningList :warnings="warnings" />
    <template v-if="config">
      <p
        v-if="secret"
        class="text-sm font-medium text-amber-700 dark:text-amber-300"
      >
        Shown only now: wgate does not keep the device's private key.
      </p>
      <div class="flex flex-col gap-4 sm:flex-row">
        <pre
          class="mono max-h-80 flex-1 overflow-auto rounded bg-slate-100 p-3 select-all dark:bg-slate-800"
        >{{ config.config }}</pre>
        <img
          v-if="qr"
          :src="qr"
          alt="QR code of the config"
          class="size-56 self-start rounded bg-white p-2"
        >
        <p
          v-else
          class="muted sm:w-56"
        >
          The config is too long for a QR code: import the file instead.
        </p>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <UiButton
          variant="primary"
          @click="download"
        >
          Download .conf
        </UiButton>
        <UiButton @click="copy">
          Copy
        </UiButton>
        <span class="muted">{{ copied }}</span>
      </div>
    </template>
  </div>
</template>
