<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { api, call } from '../../api/client'
import type { Device, Network, Peer } from '../../api/types'
import { useLoad } from '../../composables/useLoad'
import { useSubmit } from '../../composables/useSubmit'
import { confFileName } from '../../lib/conf'
import ConfirmButton from '../ConfirmButton.vue'
import ErrorNote from '../ErrorNote.vue'
import PeerTable from '../PeerTable.vue'
import UiButton from '../UiButton.vue'
import UiSection from '../UiSection.vue'

const props = defineProps<{ userId: number }>()

const devices = useLoad(
  () => call(api.GET('/devices', { params: { query: { user_id: props.userId } } })),
  [] as Device[],
)
const peers = useLoad(async () => {
  const lists = await Promise.all(
    devices.data.map((d) =>
      call(api.GET('/peers', { params: { query: { device_id: d.id } } })),
    ),
  )
  return lists.flat()
}, [] as Peer[])
const networks = useLoad(() => call(api.GET('/networks')), [] as Network[])

const { busy, error, run } = useSubmit()
const newName = ref('')
const renaming = ref<number | null>(null)
const rename = ref('')

const networksById = computed(() => new Map(networks.data.map((n) => [n.id, n])))
const peersOf = (id: number) => peers.data.filter((p) => p.device_id === id)

// The peers follow the devices they belong to.
watch(() => devices.data, () => peers.reload())

async function add() {
  const body = { user_id: props.userId, name: newName.value.trim() }
  if (await run(() => call(api.POST('/devices', { body })))) {
    newName.value = ''
    await devices.reload()
  }
}

function startRename(d: Device) {
  renaming.value = d.id
  rename.value = d.name
}

async function saveName(id: number) {
  const body = { name: rename.value.trim() }
  if (await run(() => call(api.PATCH('/devices/{id}', { params: { path: { id } }, body })))) {
    renaming.value = null
    await devices.reload()
  }
}

async function remove(id: number) {
  if (await run(() => call(api.DELETE('/devices/{id}', { params: { path: { id } } })))) {
    await devices.reload()
  }
}

const subject = (p: Peer) => {
  const n = networksById.value.get(p.network_id)
  return { text: n ? n.name : `network #${p.network_id}`, to: `/networks/${p.network_id}` }
}
const fileNameFor = (d: Device) => (p: Peer) =>
  confFileName(networksById.value.get(p.network_id)?.slug ?? `n${p.network_id}`, d.name)
</script>

<template>
  <UiSection title="Devices">
    <ErrorNote :error="devices.error ?? peers.error ?? networks.error" />
    <p
      v-if="!devices.loading && !devices.data.length"
      class="muted"
    >
      No devices yet.
    </p>
    <div
      v-for="d in devices.data"
      :key="d.id"
      class="space-y-2 border-t border-slate-200 pt-3 dark:border-slate-700"
    >
      <div class="flex flex-wrap items-center gap-2">
        <form
          v-if="renaming === d.id"
          class="flex gap-2"
          @submit.prevent="saveName(d.id)"
        >
          <input
            v-model="rename"
            class="input"
            aria-label="Device name"
            required
          >
          <UiButton
            type="submit"
            :disabled="busy"
          >
            Save
          </UiButton>
          <UiButton @click="renaming = null">
            Cancel
          </UiButton>
        </form>
        <template v-else>
          <h3 class="font-medium">
            {{ d.name }}
          </h3>
          <UiButton @click="startRename(d)">
            Rename
          </UiButton>
        </template>
        <ConfirmButton
          label="Delete"
          :message="`Delete device ${d.name}? Its peers in every network are cut off and removed.`"
          confirm-label="Delete device"
          :disabled="busy"
          @confirm="remove(d.id)"
        />
      </div>
      <PeerTable
        :peers="peersOf(d.id)"
        subject-label="Network"
        :subject="subject"
        :file-name="fileNameFor(d)"
        @changed="peers.reload()"
      />
    </div>
    <form
      class="flex gap-2 border-t border-slate-200 pt-3 dark:border-slate-700"
      @submit.prevent="add"
    >
      <input
        v-model="newName"
        class="input max-w-xs"
        placeholder="Device name, e.g. laptop"
        aria-label="New device name"
        required
      >
      <UiButton
        type="submit"
        variant="primary"
        :disabled="busy"
      >
        Add device
      </UiButton>
    </form>
    <p class="muted">
      Add a device to a network from the network's page.
    </p>
    <ErrorNote :error="error" />
  </UiSection>
</template>
