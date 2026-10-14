// Where to go back to after the login round trip (the server always lands on `/`).
const KEY = 'wgate.resume'

export function rememberRoute(path: string) {
  if (path === '/' || path.startsWith('/login')) return
  try {
    sessionStorage.setItem(KEY, path)
  } catch {
    // Storage blocked: the user just starts at the home page.
  }
}

/** The remembered in-app path (once), or null. */
export function takeRoute(): string | null {
  let path: string | null
  try {
    path = sessionStorage.getItem(KEY)
    sessionStorage.removeItem(KEY)
  } catch {
    return null
  }
  // Same origin only: `//host` and `/\host` resolve elsewhere.
  if (!path || !path.startsWith('/') || path.includes('\\')) return null
  let url: URL
  try {
    url = new URL(path, location.origin)
  } catch {
    return null
  }
  return url.origin === location.origin ? url.pathname + url.search + url.hash : null
}
