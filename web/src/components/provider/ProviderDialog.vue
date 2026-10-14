<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { api, call } from '../../api/client'
import type { Provider, ProviderCreate, ProviderUpdate, Tenant } from '../../api/types'
import { useSubmit } from '../../composables/useSubmit'
import ErrorNote from '../ErrorNote.vue'
import UiButton from '../UiButton.vue'
import UiDialog from '../UiDialog.vue'
import UiField from '../UiField.vue'

/**
 * Creates a provider (`provider` null) or edits one the caller manages. A new one
 * goes to `defaultTenant` (null: global); a global admin may pick from `tenants`.
 */
const props = defineProps<{
  provider: Provider | null
  tenants: Tenant[]
  isGlobal: boolean
  defaultTenant: number | null
}>()
const open = defineModel<boolean>('open', { required: true })
/** `stranded`: accounts an update left without a way in (disabling, a new issuer). */
const emit = defineEmits<{ saved: [stranded: number] }>()

const { busy, error, run } = useSubmit()
const name = ref('')
const issuer = ref('')
const clientId = ref('')
const secret = ref('')
const tenantId = ref<number | null>(null)
const linkByEmail = ref(false)
const disabled = ref(false)

watch(
  open,
  (o) => {
    if (!o) return
    const p = props.provider
    name.value = p?.name ?? ''
    issuer.value = p?.issuer ?? ''
    clientId.value = p?.client_id ?? ''
    secret.value = ''
    tenantId.value = p ? (p.tenant_id ?? null) : props.defaultTenant
    linkByEmail.value = p?.link_by_email ?? false
    disabled.value = p?.disabled ?? false
    error.value = null
  },
  { immediate: true },
)

const editing = computed(() => props.provider !== null)
// As the server rules: only a global admin sets it, and only on a global provider.
const offersLinkByEmail = computed(() => props.isGlobal && tenantId.value === null)
const issuerChanged = computed(
  () => editing.value && issuer.value.trim() !== (props.provider?.issuer ?? ''),
)
const tenantName = computed(
  () => props.tenants.find((t) => t.id === tenantId.value)?.name ?? `#${tenantId.value}`,
)

async function submit() {
  const p = props.provider
  let stranded = 0
  const ok = await run(async () => {
    if (p) {
      const body: ProviderUpdate = {
        name: name.value.trim(),
        issuer: issuer.value.trim(),
        client_id: clientId.value.trim(),
        disabled: disabled.value,
      }
      // Left out, the stored secret stays.
      if (secret.value) body.client_secret = secret.value
      if (offersLinkByEmail.value) body.link_by_email = linkByEmail.value
      const out = await call(api.PATCH('/providers/{id}', { params: { path: { id: p.id } }, body }))
      stranded = out.stranded ?? 0
    } else {
      const body: ProviderCreate = {
        tenant_id: tenantId.value,
        name: name.value.trim(),
        issuer: issuer.value.trim(),
        client_id: clientId.value.trim(),
        client_secret: secret.value,
        link_by_email: offersLinkByEmail.value && linkByEmail.value,
        disabled: disabled.value,
      }
      await call(api.POST('/providers', { body }))
    }
  })
  if (ok) {
    open.value = false
    emit('saved', stranded)
  }
}
</script>

<template>
  <UiDialog
    v-model:open="open"
    :title="provider ? `Edit ${provider.name}` : 'Add a provider'"
  >
    <form
      id="provider-form"
      class="grid gap-3 sm:grid-cols-2"
      autocomplete="off"
      @submit.prevent="submit"
    >
      <UiField
        label="Name"
        hint="On the login button"
      >
        <input
          v-model="name"
          class="input"
          maxlength="64"
          required
        >
      </UiField>
      <UiField
        v-if="!editing && isGlobal"
        label="For"
        hint="A tenant's provider serves only that tenant's accounts"
      >
        <select
          v-model="tenantId"
          class="input"
        >
          <option :value="null">
            Global (any account)
          </option>
          <option
            v-for="t in tenants"
            :key="t.id"
            :value="t.id"
          >
            Tenant {{ t.name }}
          </option>
        </select>
      </UiField>
      <UiField
        v-else
        label="For"
        hint="A provider never moves to another tenant"
      >
        <p class="py-1 text-sm">
          {{ tenantId === null ? 'Global (any account)' : `Tenant ${tenantName}` }}
        </p>
      </UiField>
      <UiField
        class="sm:col-span-2"
        label="Issuer"
        hint="Exactly as the provider's discovery names it (a trailing slash counts); https"
      >
        <input
          v-model="issuer"
          class="input mono"
          type="url"
          placeholder="https://idp.example.com/realms/main"
          required
        >
      </UiField>
      <p
        v-if="issuerChanged"
        class="text-sm text-amber-700 sm:col-span-2 dark:text-amber-300"
      >
        A new issuer deletes the {{ provider?.identities ?? 0 }} identities linked here (a
        subject is only unique per issuer) and ends the sessions made through it. Accounts
        left without another way in need an invite link.
      </p>
      <UiField label="Client ID">
        <input
          v-model="clientId"
          class="input mono"
          required
        >
      </UiField>
      <UiField
        label="Client secret"
        :hint="editing ? 'Write-only: leave empty to keep the stored one' : 'Write-only: never shown again'"
      >
        <input
          v-model="secret"
          class="input mono"
          type="password"
          autocomplete="new-password"
          :required="!editing"
        >
      </UiField>
      <label
        v-if="offersLinkByEmail"
        class="flex items-start gap-2 text-sm sm:col-span-2"
      >
        <input
          v-model="linkByEmail"
          type="checkbox"
          class="mt-1"
        >
        <span>
          Link by email: a first login binds to the account with the same verified
          email (never a global admin's)
        </span>
      </label>
      <label class="flex items-start gap-2 text-sm sm:col-span-2">
        <input
          v-model="disabled"
          type="checkbox"
          class="mt-1"
        >
        <span>
          Disabled: nobody logs in or links through it, and disabling ends the sessions
          made through it
        </span>
      </label>
    </form>
    <ErrorNote :error="error" />
    <template #actions="{ close }">
      <UiButton @click="close">
        Cancel
      </UiButton>
      <UiButton
        type="submit"
        form="provider-form"
        variant="primary"
        :disabled="busy"
      >
        {{ provider ? 'Save' : 'Add provider' }}
      </UiButton>
    </template>
  </UiDialog>
</template>
