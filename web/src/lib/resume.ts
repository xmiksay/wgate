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

export function takeRoute(): string | null {
  try {
    const path = sessionStorage.getItem(KEY)
    sessionStorage.removeItem(KEY)
    // Only an in-app path, never `//host`.
    return path && path.startsWith('/') && !path.startsWith('//') ? path : null
  } catch {
    return null
  }
}
