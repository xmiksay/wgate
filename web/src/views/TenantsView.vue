<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { api, call } from '../api/client'
import type { Tenant } from '../api/types'
import ErrorNote from '../components/ErrorNote.vue'
import UiButton from '../components/UiButton.vue'
import UiField from '../components/UiField.vue'
import UiSection from '../components/UiSection.vue'
import UiTable from '../components/UiTable.vue'
import { useLoad } from '../composables/useLoad'
import { useSubmit } from '../composables/useSubmit'

const router = useRouter()
const tenants = useLoad(() => call(api.GET('/tenants')), [] as Tenant[])
const { busy, error, run } = useSubmit()
const slug = ref('')
const name = ref('')

async function create() {
  let made: Tenant | undefined
  const ok = await run(async () => {
    made = await call(
      api.POST('/tenants', { body: { slug: slug.value.trim(), name: name.value.trim() } }),
    )
  })
  if (ok && made) await router.push(`/tenants/${made.id}`)
}
</script>

<template>
  <UiSection title="Tenants">
    <ErrorNote :error="tenants.error" />
    <UiTable :empty="!tenants.loading && !tenants.data.length">
      <template #head>
        <th>Name</th>
        <th>Slug</th>
        <th>State</th>
      </template>
      <tr
        v-for="t in tenants.data"
        :key="t.id"
      >
        <td>
          <RouterLink
            :to="`/tenants/${t.id}`"
            class="link"
          >
            {{ t.name }}
          </RouterLink>
        </td>
        <td class="mono">
          {{ t.slug }}
        </td>
        <td>{{ t.disabled ? 'disabled' : 'active' }}</td>
      </tr>
    </UiTable>
  </UiSection>

  <UiSection title="New tenant">
    <form
      class="grid gap-3 sm:grid-cols-3 sm:items-end"
      @submit.prevent="create"
    >
      <UiField label="Name">
        <input
          v-model="name"
          class="input"
          required
        >
      </UiField>
      <UiField label="Slug">
        <input
          v-model="slug"
          class="input mono"
          required
        >
      </UiField>
      <div>
        <UiButton
          type="submit"
          variant="primary"
          :disabled="busy"
        >
          Create
        </UiButton>
      </div>
    </form>
    <ErrorNote :error="error" />
  </UiSection>
</template>
