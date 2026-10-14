<script setup lang="ts">
import { ref, useTemplateRef } from 'vue'
import { api, call } from '../../api/client'
import { useSubmit } from '../../composables/useSubmit'
import ErrorNote from '../ErrorNote.vue'
import UiButton from '../UiButton.vue'
import UiField from '../UiField.vue'
import RecoveryCodesDialog from './RecoveryCodesDialog.vue'

/** TOTP is on. `admin`: it may not be removed (the server refuses it too). */
defineProps<{ email: string; admin: boolean }>()
const emit = defineEmits<{ removed: [] }>()

const regen = useSubmit()
const code = ref('')
const codes = ref<string[] | null>(null)
const codeInput = useTemplateRef<HTMLInputElement>('codeInput')

const removal = useSubmit()
const password = ref('')
const passwordInput = useTemplateRef<HTMLInputElement>('passwordInput')

async function regenerate() {
  const body = { code: code.value.replace(/\s+/g, '') }
  if (!body.code || regen.busy.value) return
  let out: string[] = []
  const ok = await regen.run(async () => {
    out = (await call(api.POST('/me/recovery-codes', { body }))).recovery_codes
  })
  code.value = ''
  if (ok) codes.value = out
  else codeInput.value?.focus()
}

async function remove() {
  if (!password.value || removal.busy.value) return
  const body = { password: password.value }
  const ok = await removal.run(() => call(api.DELETE('/me/totp', { body })))
  password.value = ''
  if (ok) emit('removed')
  else passwordInput.value?.focus()
}
</script>

<template>
  <div class="space-y-4">
    <p
      role="status"
      class="text-sm"
    >
      Two-factor sign-in is <strong>on</strong>: a password login also asks for a code
      from your authenticator app.
    </p>

    <form
      class="max-w-sm space-y-2"
      @submit.prevent="regenerate"
    >
      <h3 class="text-sm font-semibold">
        New recovery codes
      </h3>
      <p class="muted">
        Ten new codes; the old ones stop working.
      </p>
      <div class="flex items-end gap-2">
        <UiField
          label="Current code from the app"
          class="flex-1"
        >
          <input
            ref="codeInput"
            v-model="code"
            name="code"
            inputmode="numeric"
            autocomplete="one-time-code"
            pattern="[0-9 ]*"
            maxlength="7"
            class="input mono tracking-widest"
            required
          >
        </UiField>
        <UiButton
          type="submit"
          :disabled="regen.busy.value || !code.trim()"
        >
          {{ regen.busy.value ? 'Checking…' : 'Regenerate' }}
        </UiButton>
      </div>
      <p
        v-if="regen.busy.value"
        role="status"
        class="muted"
      >
        Checking the code; this can take up to half a minute.
      </p>
      <ErrorNote :error="regen.error.value" />
    </form>

    <p
      v-if="admin"
      class="muted max-w-prose"
    >
      Admins must keep two-factor on. Lost the authenticator and the recovery codes?
      Another admin can reset it from your user page (or
      <code class="mono">wgate user totp-reset &lt;email&gt;</code> on the server).
    </p>
    <form
      v-else
      class="max-w-sm space-y-2"
      @submit.prevent="remove"
    >
      <h3 class="text-sm font-semibold">
        Remove two-factor
      </h3>
      <!-- For password managers: the account this password belongs to. -->
      <input
        :value="email"
        type="email"
        name="username"
        autocomplete="username"
        class="sr-only"
        tabindex="-1"
        aria-hidden="true"
        readonly
      >
      <div class="flex items-end gap-2">
        <UiField
          label="Your password"
          class="flex-1"
        >
          <input
            ref="passwordInput"
            v-model="password"
            type="password"
            autocomplete="current-password"
            class="input"
            required
          >
        </UiField>
        <UiButton
          type="submit"
          variant="danger"
          :disabled="removal.busy.value || !password"
        >
          {{ removal.busy.value ? 'Checking…' : 'Remove' }}
        </UiButton>
      </div>
      <ErrorNote :error="removal.error.value" />
    </form>

    <RecoveryCodesDialog
      v-if="codes"
      :codes="codes"
      :email="email"
      @close="codes = null"
    />
  </div>
</template>
