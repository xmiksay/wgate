<script setup lang="ts">
import { api, call } from '../api/client'
import type { Tenant } from '../api/types'
import ErrorNote from '../components/ErrorNote.vue'
import UserList from '../components/UserList.vue'
import { useLoad } from '../composables/useLoad'

// Tenant admins see just their own tenant here.
const tenants = useLoad(() => call(api.GET('/tenants')), [] as Tenant[])
</script>

<template>
  <ErrorNote :error="tenants.error" />
  <UserList :tenants="tenants.data" />
</template>
