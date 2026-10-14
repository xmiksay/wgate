<script setup lang="ts">
import { computed, ref } from 'vue'
import { storeToRefs } from 'pinia'
import { api, call } from '../../api/client'
import type { AccountLink, User } from '../../api/types'
import { useSubmit } from '../../composables/useSubmit'
import { signInText } from '../../lib/format'
import { useSessionStore } from '../../stores/session'
import ConfirmButton from '../ConfirmButton.vue'
import ErrorNote from '../ErrorNote.vue'
import UiButton from '../UiButton.vue'
import UiSection from '../UiSection.vue'
import LinkDialog from './LinkDialog.vue'
import UserIdentities from './UserIdentities.vue'

const props = defineProps<{ user: User }>()
/** The account's sign-in changed: reload it. */
const emit = defineEmits<{ changed: [] }>()

const { session, isGlobal } = storeToRefs(useSessionStore())
const { busy, error, run } = useSubmit()
const shown = ref<{ link: AccountLink; title: string } | null>(null)
const reset = ref(false)

const own = computed(() => props.user.id === session.value?.user_id)
// As the server rules: a tenant admin reaches only plain users (of their tenant, or
// they would not see the account); admin accounts are a global admin's.
const reachable = computed(() => !own.value && (isGlobal.value || props.user.role === 'user'))

const path = () => ({ params: { path: { id: props.user.id } } })

async function makeLink(kind: 'invite' | 'reset') {
  reset.value = false
  await run(async () => {
    const link =
      kind === 'invite'
        ? await call(api.POST('/users/{id}/invite', path()))
        : await call(api.POST('/users/{id}/reset', path()))
    shown.value = { link, title: kind === 'invite' ? 'Invite link' : 'Reset link' }
  })
}

async function resetTotp() {
  reset.value = false
  if (await run(() => call(api.POST('/users/{id}/totp-reset', path())))) {
    reset.value = true
    emit('changed')
  }
}
</script>

<template>
  <UiSection title="Sign-in">
    <template
      v-if="reachable"
      #actions
    >
      <UiButton
        v-if="!user.has_password"
        :disabled="busy"
        @click="makeLink('invite')"
      >
        Invite link
      </UiButton>
      <UiButton
        v-else
        :disabled="busy"
        @click="makeLink('reset')"
      >
        Reset link
      </UiButton>
      <ConfirmButton
        v-if="user.totp_enabled"
        label="Reset two-factor"
        :message="`Turn two-factor sign-in off for ${user.email} and end their sessions? Their next password login sets it up again (an admin's must).`"
        confirm-label="Reset two-factor"
        :disabled="busy"
        @confirm="resetTotp"
      />
    </template>
    <p class="text-sm">
      {{ signInText(user) }}
    </p>
    <p
      v-if="own"
      class="muted max-w-prose"
    >
      This is your account: manage your password, two-factor and linked sign-ins on
      <RouterLink
        to="/me"
        class="link"
      >
        your profile
      </RouterLink>.
    </p>
    <p
      v-else-if="!reachable"
      class="muted max-w-prose"
    >
      Only a global admin manages an admin account's sign-in, linked identities included.
    </p>
    <p
      v-else
      class="muted max-w-prose"
    >
      {{
        user.has_password
          ? 'A reset link sets a new password; following it ends the account\'s sessions.'
          : 'An invite link sets the account\'s first password.'
      }}
      It works once within 24 hours, and a new link voids the account's older ones.
    </p>
    <ErrorNote :error="error" />
    <p
      v-if="reset"
      role="status"
      class="rounded bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200"
    >
      Two-factor is off for {{ user.email }}; their sessions ended.
    </p>
    <!-- A role or tenant change can delete identities: remount to reload them. -->
    <UserIdentities
      v-if="reachable"
      :key="`${user.role}:${user.tenant_id}`"
      :user="user"
    />
    <LinkDialog
      v-if="shown"
      :link="shown.link"
      :title="shown.title"
      :email="user.email"
      @close="shown = null"
    />
  </UiSection>
</template>
