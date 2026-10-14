<script setup lang="ts">
import { computed, nextTick, onMounted, ref, useTemplateRef } from 'vue'
import { api, call } from '../../api/client'
import type { TotpSetup } from '../../api/types'
import { useSubmit } from '../../composables/useSubmit'
import { svgDataUrl } from '../../lib/conf'
import ErrorNote from '../ErrorNote.vue'
import UiButton from '../UiButton.vue'
import UiField from '../UiField.vue'
import RecoveryCodesDialog from './RecoveryCodesDialog.vue'

/**
 * `immediate`: the `enrol` stage, which asks for a secret at once and sends no
 * password (the login just checked it). Otherwise the current password goes first.
 */
const props = defineProps<{ email: string; immediate?: boolean }>()
/** The codes were shown and acknowledged: TOTP is on. */
const emit = defineEmits<{ done: [] }>()

const { busy, error, run } = useSubmit()
const setup = ref<TotpSetup | null>(null)
const code = ref('')
const codes = ref<string[] | null>(null)
const codeInput = useTemplateRef<HTMLInputElement>('codeInput')
const password = ref('')
const passwordInput = useTemplateRef<HTMLInputElement>('passwordInput')

const qr = computed(() => (setup.value ? svgDataUrl(setup.value.qr_svg) : null))
/** The base32 secret, in groups of four, for typing it into an app by hand. */
const secret = computed(() => {
  if (!setup.value) return ''
  let raw: string | null
  try {
    raw = new URL(setup.value.otpauth_uri).searchParams.get('secret')
  } catch {
    return ''
  }
  return raw?.match(/.{1,4}/g)?.join(' ') ?? ''
})

async function start() {
  if (busy.value || (!props.immediate && !password.value)) return
  const body = { password: password.value }
  let out: TotpSetup | null = null
  const ok = await run(async () => {
    out = await call(
      props.immediate ? api.POST('/me/totp/setup') : api.POST('/me/totp/setup', { body }),
    )
  })
  password.value = ''
  if (ok) {
    setup.value = out
    code.value = ''
    await nextTick()
    codeInput.value?.focus()
  } else {
    passwordInput.value?.focus()
  }
}

function cancel() {
  // The server keeps the pending secret until the next setup replaces it: harmless.
  setup.value = null
  code.value = ''
  error.value = null
}

async function confirm() {
  const body = { code: code.value.replace(/\s+/g, '') }
  if (!body.code || busy.value) return
  let out: string[] = []
  const ok = await run(async () => {
    out = (await call(api.POST('/me/totp/confirm', { body }))).recovery_codes
  })
  if (ok) {
    setup.value = null
    codes.value = out
  } else {
    code.value = ''
    codeInput.value?.focus()
  }
}

function closed() {
  codes.value = null
  emit('done')
}

onMounted(() => {
  if (props.immediate) void start()
})
</script>

<template>
  <div class="space-y-3">
    <form
      v-if="!setup && !codes && !immediate"
      class="max-w-sm space-y-2"
      @submit.prevent="start"
    >
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
          variant="primary"
          :disabled="busy || !password"
        >
          {{ busy ? 'Checking…' : 'Set up two-factor' }}
        </UiButton>
      </div>
    </form>
    <template v-if="setup">
      <ol class="list-inside list-decimal space-y-1 text-sm">
        <li>Scan the QR code with an authenticator app (or type in the key below).</li>
        <li>Enter the 6-digit code the app shows.</li>
      </ol>
      <div class="flex flex-col gap-4 sm:flex-row sm:items-start">
        <img
          v-if="qr"
          :src="qr"
          alt="QR code of the authenticator secret"
          class="size-56 shrink-0 rounded bg-white p-2"
        >
        <div class="min-w-0 space-y-2 text-sm">
          <p class="muted">
            Key for typing in by hand (time-based, 6 digits, 30 seconds):
          </p>
          <p class="mono text-sm break-all select-all">
            {{ secret }}
          </p>
          <details>
            <summary class="muted cursor-pointer">
              otpauth URI
            </summary>
            <p class="mono mt-1 break-all select-all">
              {{ setup.otpauth_uri }}
            </p>
          </details>
        </div>
      </div>
      <form
        class="flex max-w-sm items-end gap-2"
        @submit.prevent="confirm"
      >
        <UiField
          label="Code from the app"
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
          variant="primary"
          :disabled="busy || !code.trim()"
        >
          Turn on
        </UiButton>
        <UiButton
          v-if="!immediate"
          :disabled="busy"
          @click="cancel"
        >
          Cancel
        </UiButton>
      </form>
    </template>
    <ErrorNote :error="error" />
    <UiButton
      v-if="immediate && !setup && !codes && error"
      :disabled="busy"
      @click="start"
    >
      Try again
    </UiButton>
    <RecoveryCodesDialog
      v-if="codes"
      :codes="codes"
      :email="email"
      @close="closed"
    />
  </div>
</template>
