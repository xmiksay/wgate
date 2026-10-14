<script setup lang="ts">
import { computed, ref } from 'vue'
import { api, asApiError, call, type ApiError } from '../api/client'
import type { AuditEntry, User } from '../api/types'
import ErrorNote from '../components/ErrorNote.vue'
import UiButton from '../components/UiButton.vue'
import UiSection from '../components/UiSection.vue'
import UiTable from '../components/UiTable.vue'
import { useLoad } from '../composables/useLoad'
import { timeText } from '../lib/format'

const PAGE = 50

const users = useLoad(() => call(api.GET('/users')), [] as User[])
const entries = ref<AuditEntry[]>([])
const error = ref<ApiError | null>(null)
const loading = ref(false)
const more = ref(true)

const emails = computed(() => new Map(users.data.map((u) => [u.id, u.email])))
const actor = (id: number | null | undefined) =>
  id == null ? 'system' : (emails.value.get(id) ?? `user #${id}`)

/** The next page: newest first, so older entries have lower ids. */
async function older() {
  loading.value = true
  try {
    const before = entries.value.at(-1)?.id
    const page = await call(api.GET('/audit', { params: { query: { before, limit: PAGE } } }))
    entries.value.push(...page)
    more.value = page.length === PAGE
    error.value = null
  } catch (e) {
    error.value = asApiError(e)
  } finally {
    loading.value = false
  }
}

void older()
</script>

<template>
  <UiSection title="Audit log">
    <ErrorNote :error="error" />
    <UiTable :empty="!loading && !entries.length">
      <template #head>
        <th>When</th>
        <th>Who</th>
        <th>Action</th>
        <th>Target</th>
        <th>Detail</th>
      </template>
      <tr
        v-for="e in entries"
        :key="e.id"
      >
        <td class="whitespace-nowrap">
          {{ timeText(e.at) }}
        </td>
        <td>{{ actor(e.actor_user_id) }}</td>
        <td class="mono">
          {{ e.action }}
        </td>
        <td class="mono">
          {{ e.target }}
        </td>
        <td class="mono break-all">
          {{ JSON.stringify(e.detail) }}
        </td>
      </tr>
    </UiTable>
    <UiButton
      v-if="more"
      :disabled="loading"
      @click="older"
    >
      Older
    </UiButton>
  </UiSection>
</template>
