import createClient, { type Middleware } from 'openapi-fetch'
import type { paths } from './schema'

/** Every failed call: the server's `ErrorBody`, or `status` 0 when it was not reached. */
export class ApiError extends Error {
  readonly status: number
  readonly error: string
  readonly detail: unknown

  constructor(status: number, error: string, message: string, detail?: unknown) {
    super(message)
    this.status = status
    this.error = error
    this.detail = detail
  }

  /** What no ceiling covers, when a rule is refused for it. */
  get uncovered(): string[] {
    const d = this.detail as { uncovered?: unknown } | null | undefined
    return Array.isArray(d?.uncovered) ? d.uncovered.map(String) : []
  }
}

export function asApiError(e: unknown): ApiError {
  if (e instanceof ApiError) return e
  return new ApiError(0, 'client', e instanceof Error ? e.message : String(e))
}

let csrf = ''

/** Set from `GET /session`; every write sends it back. */
export function setCsrf(token: string) {
  csrf = token
}

/** Wired in main.ts, so this module needs neither the router nor a store. */
export const hooks = {
  unauthorized: () => {},
  wrote: () => {},
}

const middleware: Middleware = {
  onRequest({ request }) {
    if (request.method !== 'GET' && csrf) request.headers.set('X-CSRF-Token', csrf)
    return request
  },
  onResponse({ request, response }) {
    // A 401 from /session itself is the router guard's to handle: it is how we learn
    // there is no session at all.
    if (response.status === 401 && !new URL(request.url).pathname.endsWith('/session')) {
      hooks.unauthorized()
    } else if (response.ok && request.method !== 'GET') {
      hooks.wrote()
    }
    return response
  },
}

export const api = createClient<paths>({ baseUrl: '/api/v1', credentials: 'same-origin' })
api.use(middleware)

/**
 * The login endpoints outside `/api/v1`. No middleware: there is no session to send a
 * CSRF token for yet, and a 401 here is a refused login, not an expired session.
 */
export const auth = createClient<paths>({ baseUrl: '', credentials: 'same-origin' })

interface Result<T> {
  data?: T
  error?: unknown
  response: Response
}

function errorFrom(response: Response, body: unknown): ApiError {
  const status = response.status
  if (status === 429) {
    const secs = Number(response.headers.get('Retry-After'))
    const when = Number.isInteger(secs) && secs > 0 ? `in ${secs} seconds` : 'later'
    return new ApiError(status, 'too_many_attempts', `Too many attempts; try again ${when}.`)
  }
  if (status === 503) {
    return new ApiError(status, 'busy', 'The server is busy; try again in a moment.')
  }
  const b = body as { error?: unknown; message?: unknown; detail?: unknown } | undefined
  if (b && typeof b.error === 'string' && typeof b.message === 'string') {
    return new ApiError(status, b.error, b.message, b.detail)
  }
  return new ApiError(status, 'http', `HTTP ${status}`)
}

/** The response data, or throws an `ApiError`. */
export async function call<T>(request: Promise<Result<T>>): Promise<T> {
  let r: Result<T>
  try {
    r = await request
  } catch {
    throw new ApiError(0, 'network', 'The server cannot be reached.')
  }
  if (!r.response.ok) throw errorFrom(r.response, r.error)
  return r.data as T
}
