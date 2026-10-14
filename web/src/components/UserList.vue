<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { api, call } from '../api/client'
import { TENANT_ROLES, type Tenant, type User } from '../api/types'
import { useLoad } from '../composables/useLoad'
import { signInText } from '../lib/format'
import { useSubmit } from '../composables/useSubmit'
import { useSessionStore } from '../stores/session'
import ErrorNote from './ErrorNote.vue'
import UiButton from './UiButton.vue'
import UiField from './UiField.vue'
import UiSection from './UiSection.vue'
import UiTable from './UiTable.vue'

/** One tenant's users, or (without `tenantId`) everyone the session may see. */
const props = defineProps<{ tenantId?: number; tenants?: Tenant[] }>()
const { isGlobal } = storeToRefs(useSessionStore())

const users = useLoad(
  () => call(api.GET('/users', { params: { query: { tenant_id: props.tenantId } } })),
  [] as User[],
)
const { busy, error, run } = useSubmit()
const email = ref('')
// `null`: a global admin.
const tenantChoice = ref<number | null>(props.tenantId ?? null)
const role = ref<string>('user')

// Admin roles are a global admin's to give; a tenant admin makes plain users only.
const roles = computed<readonly string[]>(() =>
  tenantChoice.value === null ? ['global_admin'] : isGlobal.value ? TENANT_ROLES : ['user'],
)
watch(roles, (r) => {
  if (!r.includes(role.value)) role.value = r[r.length - 1] ?? 'user'
})
watch(
  () => props.tenants,
  (ts) => {
    // A tenant by default: making a global admin is a deliberate choice.
    if (props.tenantId === undefined && tenantChoice.value === null) {
      tenantChoice.value = ts?.[0]?.id ?? null
    }
  },
  { immediate: true },
)

const tenantName = (id: number | null | undefined) =>
  id == null ? '(global)' : (props.tenants?.find((t) => t.id === id)?.name ?? `#${id}`)

async function create() {
  const body = { email: email.value.trim(), role: role.value, tenant_id: tenantChoice.value }
  if (await run(() => call(api.POST('/users', { body })))) {
    email.value = ''
    await users.reload()
  }
}
</script>

<template>
  <UiSection title="Users">
    <ErrorNote :error="users.error" />
    <UiTable :empty="!users.loading && !users.data.length">
      <template #head>
        <th>Email</th>
        <th>Role</th>
        <th v-if="tenantId === undefined">
          Tenant
        </th>
        <th>Sign-in</th>
        <th>State</th>
      </template>
      <tr
        v-for="u in users.data"
        :key="u.id"
      >
        <td>
          <RouterLink
            :to="`/users/${u.id}`"
            class="link"
          >
            {{ u.email }}
          </RouterLink>
        </td>
        <td>{{ u.role }}</td>
        <td v-if="tenantId === undefined">
          {{ tenantName(u.tenant_id) }}
        </td>
        <td>{{ signInText(u) }}</td>
        <td>{{ u.disabled ? 'disabled' : 'active' }}</td>
      </tr>
    </UiTable>

    <form
      class="grid gap-3 sm:grid-cols-4 sm:items-end"
      @submit.prevent="create"
    >
      <UiField label="Email">
        <input
          v-model="email"
          type="email"
          class="input"
          required
        >
      </UiField>
      <UiField
        v-if="tenantId === undefined"
        label="Tenant"
      >
        <select
          v-model="tenantChoice"
          class="input"
        >
          <option
            v-if="isGlobal"
            :value="null"
          >
            (none: a global admin)
          </option>
          <option
            v-for="t in tenants"
            :key="t.id"
            :value="t.id"
          >
            {{ t.name }}
          </option>
        </select>
      </UiField>
      <UiField label="Role">
        <select
          v-model="role"
          class="input"
        >
          <option
            v-for="r in roles"
            :key="r"
            :value="r"
          >
            {{ r }}
          </option>
        </select>
      </UiField>
      <div>
        <UiButton
          type="submit"
          variant="primary"
          :disabled="busy"
        >
          Add user
        </UiButton>
      </div>
    </form>
    <ErrorNote :error="error" />
  </UiSection>
</template>
