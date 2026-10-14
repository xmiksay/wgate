<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ApiError, api, call } from '../../api/client'
import type { Identity, LinkableProvider } from '../../api/types'
import { useLoad } from '../../composables/useLoad'
import { useSubmit } from '../../composables/useSubmit'
import { timeText } from '../../lib/format'
import ConfirmButton from '../ConfirmButton.vue'
import ErrorNote from '../ErrorNote.vue'
import UiButton from '../UiButton.vue'
import UiSection from '../UiSection.vue'
import UiTable from '../UiTable.vue'

const route = useRoute()
const router = useRouter()
const { busy, error, run } = useSubmit()

const identities = useLoad(() => call(api.GET('/me/identities')), [] as Identity[])
// The enabled providers that serve this account (global ones and its tenant's).
const offered = useLoad(() => call(api.GET('/me/providers')), [] as LinkableProvider[])
const linkable = computed(() => offered.data.filter((p) => !p.linked))

// Why the server sent the browser back here from a link round trip.
const refusals: Record<string, string> = {
  taken: 'That identity is already linked to another account.',
  exists: 'This account already has an identity at that provider.',
  expired: 'Linking expired or was started in another session; try again.',
  forbidden: 'That provider does not serve this account.',
  cancelled: 'Linking was cancelled or refused at the identity provider.',
  unavailable: 'That provider is unavailable: disabled, removed, or not reachable right now.',
  failed: 'Linking failed; try again, or ask an admin to check the server log.',
}
const linkedId = typeof route.query.linked === 'string' ? route.query.linked : null
const why = typeof route.query.error === 'string' ? route.query.error : null
const refused = ref(why ? (refusals[why] ?? refusals.failed) : '')
const linked = ref(linkedId !== null)
if (linkedId !== null || why !== null) void router.replace({ query: {} })

const linkedName = computed(
  () => identities.data.find((i) => String(i.provider_id) === linkedId)?.provider_name,
)

function dismiss() {
  linked.value = false
  refused.value = ''
}

async function link(p: LinkableProvider) {
  dismiss()
  let url = ''
  const ok = await run(async () => {
    const path = { id: p.id }
    url = (await call(api.POST('/me/identities/{id}/link', { params: { path } }))).url
  })
  // A full navigation: the provider sends the browser back to /me.
  if (ok) window.location.assign(url)
  // The client reads every 503 as a busy server; here it is the provider's discovery.
  else if (error.value?.status === 503) {
    error.value = new ApiError(503, 'unavailable', 'That sign-in provider is unavailable right now.')
  }
}

async function unlink(id: number) {
  dismiss()
  if (await run(() => call(api.DELETE('/me/identities/{id}', { params: { path: { id } } })))) {
    await Promise.all([identities.reload(), offered.reload()])
  }
}
</script>

<template>
  <UiSection title="Linked sign-ins">
    <p
      v-if="linked"
      role="status"
      class="rounded bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200"
    >
      Linked{{ linkedName ? ` ${linkedName}` : '' }}: you can now sign in through it.
    </p>
    <p
      v-if="refused"
      role="alert"
      class="rounded bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-950 dark:text-red-200"
    >
      {{ refused }}
    </p>
    <p class="muted max-w-prose">
      Sign in through an identity provider instead of a password. The last way in (no
      password, no other linked sign-in) cannot be unlinked.
    </p>
    <ErrorNote :error="identities.error ?? offered.error" />
    <UiTable :empty="!identities.loading && !identities.data.length">
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
            :message="`Unlink ${i.provider_name}? You can no longer sign in through it, and your other sessions made through it end.`"
            confirm-label="Unlink"
            :disabled="busy"
            @confirm="unlink(i.id)"
          />
        </td>
      </tr>
    </UiTable>
    <div
      v-if="linkable.length"
      class="flex flex-wrap gap-2"
    >
      <UiButton
        v-for="p in linkable"
        :key="p.id"
        :disabled="busy"
        @click="link(p)"
      >
        Link {{ p.name }}
      </UiButton>
    </div>
    <ErrorNote :error="error" />
  </UiSection>
</template>
