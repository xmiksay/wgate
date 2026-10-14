<script setup lang="ts">
import { computed } from 'vue'
import { api, call } from '../../api/client'
import type { Provider } from '../../api/types'
import { useLoad } from '../../composables/useLoad'
import ErrorNote from '../ErrorNote.vue'
import UiSection from '../UiSection.vue'

const props = defineProps<{ tenantId: number }>()

const providers = useLoad(() => call(api.GET('/providers')), [] as Provider[])
const own = computed(() => providers.data.filter((p) => p.tenant_id === props.tenantId))
</script>

<template>
  <UiSection title="Sign-in providers">
    <template #actions>
      <RouterLink
        :to="{ path: '/providers', query: { tenant: tenantId } }"
        class="link self-center text-sm"
      >
        Manage
      </RouterLink>
    </template>
    <ErrorNote :error="providers.error" />
    <p
      v-if="!providers.loading && !providers.error && !own.length"
      class="muted"
    >
      None of its own: its accounts sign in with a password or a global provider.
    </p>
    <ul
      v-else
      class="space-y-1 text-sm"
    >
      <li
        v-for="p in own"
        :key="p.id"
      >
        <span class="font-medium">{{ p.name }}</span>
        <span class="muted">
          · {{ p.disabled ? 'disabled' : 'enabled' }} · {{ p.identities ?? 0 }} linked
        </span>
      </li>
    </ul>
  </UiSection>
</template>
