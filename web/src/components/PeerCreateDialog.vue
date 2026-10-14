<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { api, call } from '../api/client'
import type { DeviceChoice, Network, PeerCreated } from '../api/types'
import { useSecretGuard } from '../composables/useSecretGuard'
import { useSubmit } from '../composables/useSubmit'
import { useSuggestion } from '../composables/useSuggestion'
import { SECRET_GUARD, confFileName } from '../lib/conf'
import { splitList } from '../lib/format'
import ConfigReveal from './ConfigReveal.vue'
import ErrorNote from './ErrorNote.vue'
import UiButton from './UiButton.vue'
import UiDialog from './UiDialog.vue'
import UiField from './UiField.vue'

const props = defineProps<{ network: Network; devices: DeviceChoice[] }>()
const open = defineModel<boolean>('open', { required: true })
const emit = defineEmits<{ created: [] }>()

const { busy, error, run } = useSubmit()
const deviceId = ref<number | null>(null)
const address = useSuggestion('')
const { value: ip } = address
const ipHint = ref('')
const keyMode = ref<'server' | 'pasted'>('server')
const publicKey = ref('')
const routes = ref('')
// Holds the private key of a server-made pair: dropped as soon as the dialog closes.
const created = ref<PeerCreated | null>(null)

const guard = computed(() =>
  created.value?.config && created.value.peer.key_source === 'server' ? SECRET_GUARD : undefined,
)

useSecretGuard(guard)

const deviceName = computed(
  () => props.devices.find((d) => d.id === created.value?.peer.device_id)?.name ?? 'peer',
)

async function suggestIp() {
  const t = address.ticket()
  ipHint.value = ''
  try {
    const s = await call(
      api.GET('/networks/{id}/free-ip', { params: { path: { id: props.network.id } } }),
    )
    if (address.offer(s.free ?? '', t) && !s.free) ipHint.value = 'The network has no free address.'
  } catch {
    if (address.current(t)) ipHint.value = 'No suggestion: type an address.'
  }
}

function reset() {
  created.value = null
  error.value = null
  deviceId.value = props.devices[0]?.id ?? null
  address.reset()
  keyMode.value = 'server'
  publicKey.value = ''
  routes.value = ''
}

watch(open, (isOpen) => {
  reset()
  if (isOpen) void suggestIp()
})

async function submit() {
  const device = deviceId.value
  if (device === null) return
  let out: PeerCreated | null = null
  const ok = await run(async () => {
    out = await call(
      api.POST('/peers', {
        body: {
          device_id: device,
          network_id: props.network.id,
          ip: ip.value.trim(),
          public_key: keyMode.value === 'pasted' ? publicKey.value.trim() : null,
          routes: splitList(routes.value),
        },
      }),
    )
  })
  if (ok) {
    created.value = out
    emit('created')
  }
}
</script>

<template>
  <UiDialog
    v-model:open="open"
    :title="created ? 'Peer added' : `Add a peer to ${network.name}`"
    :guard="guard"
  >
    <ConfigReveal
      v-if="created"
      :config="created.config"
      :warnings="created.warnings"
      :file-name="confFileName(network.slug, deviceName)"
      :secret="created.peer.key_source === 'server'"
    />
    <form
      v-else
      id="peer-create"
      class="grid gap-3 sm:grid-cols-2"
      @submit.prevent="submit"
    >
      <UiField label="Device">
        <select
          v-model="deviceId"
          class="input"
          required
        >
          <option
            v-for="d in devices"
            :key="d.id"
            :value="d.id"
          >
            {{ d.label }}
          </option>
        </select>
      </UiField>
      <UiField
        label="Address"
        :hint="ipHint || `Inside ${network.cidr}`"
      >
        <input
          v-model="ip"
          class="input mono"
          required
        >
      </UiField>
      <fieldset class="space-y-1 sm:col-span-2">
        <legend class="text-xs font-medium text-slate-600 dark:text-slate-300">
          Key
        </legend>
        <label class="flex items-center gap-2 text-sm">
          <input
            v-model="keyMode"
            type="radio"
            value="server"
          >
          wgate makes the key pair (the config is shown once)
        </label>
        <label class="flex items-center gap-2 text-sm">
          <input
            v-model="keyMode"
            type="radio"
            value="pasted"
          >
          The device has its own key: paste its public key
        </label>
        <input
          v-if="keyMode === 'pasted'"
          v-model="publicKey"
          class="input mono"
          placeholder="Base64 public key"
          aria-label="Public key"
          required
        >
      </fieldset>
      <UiField
        class="sm:col-span-2"
        label="Routed LANs (optional)"
        hint="For a router: the subnets behind it, separated by spaces or commas"
      >
        <input
          v-model="routes"
          class="input mono"
          placeholder="192.168.1.0/24"
        >
      </UiField>
      <p
        v-if="!devices.length"
        class="muted sm:col-span-2"
      >
        No devices to add: create one on a user's page first.
      </p>
    </form>
    <ErrorNote :error="error" />
    <template #actions="{ close }">
      <UiButton @click="close">
        {{ created ? 'Close' : 'Cancel' }}
      </UiButton>
      <UiButton
        v-if="!created"
        type="submit"
        form="peer-create"
        variant="primary"
        :disabled="busy || deviceId === null"
      >
        Add peer
      </UiButton>
    </template>
  </UiDialog>
</template>
