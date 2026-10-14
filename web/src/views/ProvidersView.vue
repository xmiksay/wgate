<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute } from 'vue-router'
import { storeToRefs } from 'pinia'
import { api, call } from '../api/client'
import type { Provider, Tenant } from '../api/types'
import ConfirmButton from '../components/ConfirmButton.vue'
import ErrorNote from '../components/ErrorNote.vue'
import ProviderDialog from '../components/provider/ProviderDialog.vue'
import RedirectUri from '../components/provider/RedirectUri.vue'
import UiButton from '../components/UiButton.vue'
import UiSection from '../components/UiSection.vue'
import UiTable from '../components/UiTable.vue'
import { useLoad } from '../composables/useLoad'
import { useSubmit } from '../composables/useSubmit'
import { useSessionStore } from '../stores/session'

const route = useRoute()
const { session, isGlobal } = storeToRefs(useSessionStore())
const providers = useLoad(() => call(api.GET('/providers')), [] as Provider[])
// A tenant admin's list holds their own tenant only.
const tenants = useLoad(() => call(api.GET('/tenants')), [] as Tenant[])
const { busy, error, run } = useSubmit()

const dialogOpen = ref(false)
const editing = ref<Provider | null>(null)
/** What the last write did to accounts' ways in. */
const notice = ref('')

function strandedNotice(n: number) {
  notice.value = n
    ? `${n} ${n === 1 ? 'account is' : 'accounts are'} left without a way to sign in: send them an invite link (on the user's page).`
    : ''
}

/** `?tenant=<id>`: that tenant's providers only (linked from the tenant's page). */
const tenantFilter = computed(() => {
  const t = Number(route.query.tenant)
  return Number.isInteger(t) && t > 0 ? t : null
})
const shown = computed(() =>
  tenantFilter.value === null
    ? providers.data
    : providers.data.filter((p) => p.tenant_id === tenantFilter.value),
)

const tenantNames = computed(() => new Map(tenants.data.map((t) => [t.id, t.name])))
function scope(p: Provider): string {
  if (p.tenant_id == null) return 'global'
  return tenantNames.value.get(p.tenant_id) ?? `tenant #${p.tenant_id}`
}

function edit(p: Provider | null) {
  notice.value = ''
  editing.value = p
  dialogOpen.value = true
}

function deleteMessage(p: Provider): string {
  const n = p.identities ?? 0
  return (
    `Delete ${p.name}? Its ${n} linked ${n === 1 ? 'identity goes' : 'identities go'}, ` +
    'and every session signed in through it ends. An account left without another way ' +
    'in needs an invite link. This cannot be undone.'
  )
}

async function remove(id: number) {
  notice.value = ''
  let stranded = 0
  const ok = await run(async () => {
    stranded = (await call(api.DELETE('/providers/{id}', { params: { path: { id } } }))).stranded
  })
  if (ok) {
    strandedNotice(stranded)
    await providers.reload()
  }
}

async function saved(stranded: number) {
  strandedNotice(stranded)
  await providers.reload()
}
</script>

<template>
  <UiSection title="Sign-in providers (OpenID Connect)">
    <template #actions>
      <UiButton
        variant="primary"
        @click="edit(null)"
      >
        Add provider
      </UiButton>
    </template>
    <RedirectUri />
    <p
      v-if="tenantFilter !== null"
      class="muted"
    >
      Showing {{ tenantNames.get(tenantFilter) ?? `tenant #${tenantFilter}` }}'s providers ·
      <RouterLink
        to="/providers"
        class="link"
      >
        show all
      </RouterLink>
    </p>
    <p
      v-if="!isGlobal"
      class="muted max-w-prose"
    >
      Global providers are a global admin's: shown here by name, as your users can link
      them.
    </p>
    <ErrorNote :error="providers.error ?? tenants.error" />
    <UiTable :empty="!providers.loading && !shown.length">
      <template #head>
        <th>Name</th>
        <th>For</th>
        <th>Issuer</th>
        <th>Client ID</th>
        <th>Link by email</th>
        <th>Status</th>
        <th>Identities</th>
        <th />
      </template>
      <tr
        v-for="p in shown"
        :key="p.id"
      >
        <td class="font-medium">
          {{ p.name }}
        </td>
        <td>{{ scope(p) }}</td>
        <td class="mono break-all">
          {{ p.issuer ?? '—' }}
        </td>
        <td class="mono break-all">
          {{ p.client_id ?? '—' }}
        </td>
        <td>{{ p.tenant_id == null ? (p.link_by_email ? 'yes' : 'no') : '—' }}</td>
        <td>{{ p.disabled ? 'disabled' : 'enabled' }}</td>
        <td>{{ p.identities ?? '—' }}</td>
        <td class="whitespace-nowrap text-right">
          <template v-if="p.managed">
            <UiButton
              class="mr-2"
              :disabled="busy"
              @click="edit(p)"
            >
              Edit
            </UiButton>
            <ConfirmButton
              label="Delete"
              :message="deleteMessage(p)"
              confirm-label="Delete provider"
              :disabled="busy"
              @confirm="remove(p.id)"
            />
          </template>
          <span
            v-else
            class="muted"
          >read-only</span>
        </td>
      </tr>
    </UiTable>
    <ErrorNote :error="error" />
    <p
      v-if="notice"
      role="status"
      class="rounded bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-950 dark:text-amber-100"
    >
      {{ notice }}
    </p>
    <ProviderDialog
      v-model:open="dialogOpen"
      :provider="editing"
      :tenants="tenants.data"
      :is-global="isGlobal"
      :default-tenant="isGlobal ? tenantFilter : (session?.tenant_id ?? null)"
      @saved="saved"
    />
  </UiSection>
</template>
