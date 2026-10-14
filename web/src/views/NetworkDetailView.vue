<script setup lang="ts">
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { api, call } from '../api/client'
import type { Network } from '../api/types'
import ErrorNote from '../components/ErrorNote.vue'
import NetworkInbound from '../components/network/NetworkInbound.vue'
import NetworkPeers from '../components/network/NetworkPeers.vue'
import NetworkRules from '../components/network/NetworkRules.vue'
import NetworkSettings from '../components/network/NetworkSettings.vue'
import { useLoad } from '../composables/useLoad'
import { useSessionStore } from '../stores/session'

const props = defineProps<{ id: number }>()
const router = useRouter()
const { isGlobal } = storeToRefs(useSessionStore())

const network = useLoad(
  () => call(api.GET('/networks/{id}', { params: { path: { id: props.id } } })),
  null as Network | null,
)

async function deleted(tenantId: number) {
  await router.push(`/tenants/${tenantId}`)
}
</script>

<template>
  <ErrorNote :error="network.error" />
  <template v-if="network.data">
    <NetworkSettings
      :network="network.data"
      @updated="(n) => (network.data = n)"
      @deleted="deleted"
    />
    <NetworkPeers :network="network.data" />
    <NetworkRules :network="network.data" />
    <NetworkInbound
      v-if="isGlobal"
      :network="network.data"
    />
  </template>
</template>
