<script setup lang="ts">
import { computed, ref } from 'vue'
import { api, call } from '../../api/client'
import type { Device, DeviceChoice, Network, Peer, User } from '../../api/types'
import { useLoad } from '../../composables/useLoad'
import { confFileName } from '../../lib/conf'
import ErrorNote from '../ErrorNote.vue'
import PeerCreateDialog from '../PeerCreateDialog.vue'
import PeerTable from '../PeerTable.vue'
import UiButton from '../UiButton.vue'
import UiSection from '../UiSection.vue'

const props = defineProps<{ network: Network }>()

const peers = useLoad(
  () => call(api.GET('/peers', { params: { query: { network_id: props.network.id } } })),
  [] as Peer[],
)
const devices = useLoad(() => call(api.GET('/devices')), [] as Device[])
const users = useLoad(() => call(api.GET('/users')), [] as User[])
const adding = ref(false)

const usersById = computed(() => new Map(users.data.map((u) => [u.id, u])))
const devicesById = computed(() => new Map(devices.data.map((d) => [d.id, d])))

function deviceText(id: number): string {
  const d = devicesById.value.get(id)
  if (!d) return `device #${id}`
  const owner = usersById.value.get(d.user_id)
  return owner ? `${d.name} (${owner.email})` : d.name
}

// Devices of the network's tenant, or of a global admin.
const choices = computed<DeviceChoice[]>(() =>
  devices.data
    .filter((d) => {
      const owner = usersById.value.get(d.user_id)
      if (!owner || owner.disabled) return false
      return owner.tenant_id == null || owner.tenant_id === props.network.tenant_id
    })
    .map((d) => ({ id: d.id, name: d.name, label: deviceText(d.id) })),
)

const subject = (p: Peer) => {
  const d = devicesById.value.get(p.device_id)
  return { text: deviceText(p.device_id), to: d ? `/users/${d.user_id}` : undefined }
}
const fileName = (p: Peer) =>
  confFileName(props.network.slug, devicesById.value.get(p.device_id)?.name ?? `peer${p.id}`)
</script>

<template>
  <UiSection title="Peers">
    <template #actions>
      <UiButton
        variant="primary"
        @click="adding = true"
      >
        Add peer
      </UiButton>
    </template>
    <ErrorNote :error="peers.error ?? devices.error ?? users.error" />
    <PeerTable
      :peers="peers.data"
      subject-label="Device"
      :subject="subject"
      :file-name="fileName"
      @changed="peers.reload()"
    />
    <PeerCreateDialog
      v-model:open="adding"
      :network="network"
      :devices="choices"
      @created="peers.reload()"
    />
  </UiSection>
</template>
