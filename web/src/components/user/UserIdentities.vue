<script setup lang="ts">
import { computed, ref } from 'vue'
import { api, call } from '../../api/client'
import type { Identity, Provider, User } from '../../api/types'
import { useLoad } from '../../composables/useLoad'
import { useSubmit } from '../../composables/useSubmit'
import { timeText } from '../../lib/format'
import ConfirmButton from '../ConfirmButton.vue'
import ErrorNote from '../ErrorNote.vue'
import UiButton from '../UiButton.vue'
import UiField from '../UiField.vue'
import UiTable from '../UiTable.vue'

/** Only for an account in the caller's reach (as for reset links): the server refuses the rest. */
const props = defineProps<{ user: User }>()

const path = () => ({ params: { path: { id: props.user.id } } })
const identities = useLoad(() => call(api.GET('/users/{id}/identities', path())), [] as Identity[])
const providers = useLoad(() => call(api.GET('/providers')), [] as Provider[])
const { busy, error, run } = useSubmit()
const providerId = ref<number | null>(null)
const subject = ref('')

// As the server rules: a global provider serves anyone, a tenant's only its accounts.
const choices = computed(() => {
  const have = new Set(identities.data.map((i) => i.provider_id))
  return providers.data.filter(
    (p) => (p.tenant_id == null || p.tenant_id === props.user.tenant_id) && !have.has(p.id),
  )
})

async function preLink() {
  const provider_id = providerId.value
  if (provider_id === null) return
  const body = { provider_id, subject: subject.value.trim() }
  if (await run(() => call(api.POST('/users/{id}/identities', { ...path(), body })))) {
    providerId.value = null
    subject.value = ''
    await identities.reload()
  }
}

async function unlink(identity_id: number) {
  const params = { path: { id: props.user.id, identity_id } }
  if (await run(() => call(api.DELETE('/users/{id}/identities/{identity_id}', { params })))) {
    await identities.reload()
  }
}
</script>

<template>
  <div class="space-y-2 border-t border-slate-200 pt-3 dark:border-slate-700">
    <h3 class="text-sm font-medium">
      Linked identities
    </h3>
    <ErrorNote :error="identities.error ?? providers.error" />
    <UiTable :empty="!identities.loading && !identities.error && !identities.data.length">
      <template #head>
        <th>Provider</th>
        <th>Subject</th>
        <th>Linked</th>
        <th />
      </template>
      <tr
        v-for="i in identities.data"
        :key="i.id"
      >
        <td>{{ i.provider_name }}</td>
        <td class="mono break-all">
          {{ i.subject }}
        </td>
        <td>{{ timeText(i.created_at) }}</td>
        <td class="text-right">
          <ConfirmButton
            label="Unlink"
            :message="`Unlink ${user.email}'s ${i.provider_name} identity? Their sessions made through it end.`"
            confirm-label="Unlink"
            :disabled="busy"
            @confirm="unlink(i.id)"
          />
        </td>
      </tr>
    </UiTable>
    <form
      v-if="choices.length"
      class="grid gap-3 sm:grid-cols-[1fr_2fr_auto] sm:items-end"
      @submit.prevent="preLink"
    >
      <UiField label="Provider">
        <select
          v-model="providerId"
          class="input"
          required
        >
          <option
            v-for="p in choices"
            :key="p.id"
            :value="p.id"
          >
            {{ p.name }}{{ p.disabled ? ' (disabled)' : '' }}
          </option>
        </select>
      </UiField>
      <UiField
        label="Subject"
        hint="The provider's subject (sub) for this person: their next login there is this account"
      >
        <input
          v-model="subject"
          class="input mono"
          maxlength="255"
          required
        >
      </UiField>
      <div>
        <UiButton
          type="submit"
          :disabled="busy || providerId === null || !subject.trim()"
        >
          Pre-link
        </UiButton>
      </div>
    </form>
    <ErrorNote :error="error" />
  </div>
</template>
