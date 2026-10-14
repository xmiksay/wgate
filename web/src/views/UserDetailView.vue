<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { api, call } from '../api/client'
import { TENANT_ROLES, type User } from '../api/types'
import ConfirmButton from '../components/ConfirmButton.vue'
import ErrorNote from '../components/ErrorNote.vue'
import UiButton from '../components/UiButton.vue'
import UiSection from '../components/UiSection.vue'
import UserDevices from '../components/user/UserDevices.vue'
import UserSignIn from '../components/user/UserSignIn.vue'
import { useLoad } from '../composables/useLoad'
import { useSubmit } from '../composables/useSubmit'
import { useSessionStore } from '../stores/session'

const props = defineProps<{ id: number }>()
const router = useRouter()

// There is no GET /users/{id}: the list holds everyone the session may see.
const users = useLoad(() => call(api.GET('/users')), [] as User[])
const user = computed(() => users.data.find((u) => u.id === props.id) ?? null)
const { busy, error, run } = useSubmit()
const role = ref('')
const { isGlobal } = storeToRefs(useSessionStore())
// As the server rules: anything touching an admin account (or an admin role) is a
// global admin's; a tenant admin manages plain users only.
const manageable = computed(() => isGlobal.value || user.value?.role === 'user')

watch(user, (u) => (role.value = u?.role ?? ''), { immediate: true })

const path = { params: { path: { id: props.id } } }

async function update(body: { role?: string; disabled?: boolean }) {
  if (await run(() => call(api.PATCH('/users/{id}', { ...path, body })))) await users.reload()
}

async function remove() {
  if (await run(() => call(api.DELETE('/users/{id}', path)))) await router.push('/users')
}
</script>

<template>
  <ErrorNote :error="users.error" />
  <p
    v-if="!users.loading && !users.error && !user"
    class="muted"
  >
    No such user.
  </p>
  <template v-if="user">
    <UiSection :title="user.email">
      <template #actions>
        <RouterLink
          v-if="user.tenant_id != null"
          :to="`/tenants/${user.tenant_id}`"
          class="link self-center text-sm"
        >
          Tenant
        </RouterLink>
        <ConfirmButton
          v-if="manageable && !user.disabled"
          label="Disable"
          message="Disabling ends their sessions and takes their peers out at once. Enabling restores them."
          confirm-label="Disable"
          :disabled="busy"
          @confirm="update({ disabled: true })"
        />
        <UiButton
          v-else-if="manageable"
          :disabled="busy"
          @click="update({ disabled: false })"
        >
          Enable
        </UiButton>
        <ConfirmButton
          v-if="manageable"
          label="Delete"
          :message="`Delete ${user.email} with their devices and peers? This cannot be undone.`"
          confirm-label="Delete user"
          :disabled="busy"
          @confirm="remove"
        />
      </template>
      <p class="muted">
        {{ user.role }} · {{ user.disabled ? 'disabled' : 'active' }}
      </p>
      <p
        v-if="!manageable"
        class="muted"
      >
        An admin account: only a global admin may change, disable or delete it.
      </p>
      <!-- A tenant admin may only give the role `user`: nothing to choose. -->
      <div
        v-if="isGlobal && user.tenant_id != null"
        class="flex gap-2"
      >
        <select
          v-model="role"
          class="input max-w-xs"
          aria-label="Role"
        >
          <option
            v-for="r in TENANT_ROLES"
            :key="r"
            :value="r"
          >
            {{ r }}
          </option>
        </select>
        <ConfirmButton
          label="Change role"
          :message="`Make ${user.email} ${role}? Their sessions end and their open invite or reset links stop working.`"
          confirm-label="Change role"
          variant="secondary"
          :disabled="busy || role === user.role"
          @confirm="update({ role })"
        />
      </div>
      <ErrorNote :error="error" />
    </UiSection>
    <UserSignIn
      :user="user"
      @changed="users.reload()"
    />
    <UserDevices :user-id="user.id" />
  </template>
</template>
