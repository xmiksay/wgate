import { createRouter, createWebHistory } from 'vue-router'
import { rememberRoute, takeRoute } from './lib/resume'
import { useSessionStore } from './stores/session'
import AuditView from './views/AuditView.vue'
import FederationsView from './views/FederationsView.vue'
import LoginView from './views/LoginView.vue'
import MeView from './views/MeView.vue'
import NetworkDetailView from './views/NetworkDetailView.vue'
import NotFoundView from './views/NotFoundView.vue'
import TenantDetailView from './views/TenantDetailView.vue'
import TenantsView from './views/TenantsView.vue'
import UserDetailView from './views/UserDetailView.vue'
import UsersView from './views/UsersView.vue'

declare module 'vue-router' {
  interface RouteMeta {
    /** Reachable without a session. */
    public?: boolean
    /** For global admins only (the server refuses the rest anyway). */
    global?: boolean
    /** Open to plain users too; every other route is for admins. */
    everyone?: boolean
  }
}

const id = (route: { params: Record<string, unknown> }) => ({ id: Number(route.params.id) })

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: NotFoundView },
    { path: '/login', name: 'login', component: LoginView, meta: { public: true } },
    { path: '/me', component: MeView, meta: { everyone: true } },
    { path: '/tenants', component: TenantsView, meta: { global: true } },
    { path: '/tenants/:id(\\d+)', component: TenantDetailView, props: id },
    { path: '/networks/:id(\\d+)', component: NetworkDetailView, props: id },
    { path: '/users', component: UsersView },
    { path: '/users/:id(\\d+)', component: UserDetailView, props: id },
    { path: '/federations', component: FederationsView, meta: { global: true } },
    { path: '/audit', component: AuditView, meta: { global: true } },
    { path: '/:rest(.*)*', component: NotFoundView },
  ],
})

// The remembered route is for the first navigation after the session loads, only.
let resumeChecked = false

router.beforeEach(async (to) => {
  const store = useSessionStore()
  if (!store.loaded) await store.load()
  const s = store.session
  const home = !store.isAdmin
    ? '/me'
    : store.isGlobal
      ? '/tenants'
      : `/tenants/${s?.tenant_id}`

  if (!s) {
    if (to.meta.public) return true
    rememberRoute(to.fullPath)
    return { name: 'login' }
  }
  if (!resumeChecked) {
    resumeChecked = true
    const resume = takeRoute()
    if (resume && resume !== to.fullPath) return resume
  }
  if (to.meta.public || to.path === '/') return home
  if (!to.meta.everyone && !store.isAdmin) return home
  if (to.meta.global && !store.isGlobal) return home
  return true
})
