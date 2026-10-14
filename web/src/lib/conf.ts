/** An `<img>` source for the server's QR code: never inserted as markup. */
export function svgDataUrl(svg: string): string {
  let bin = ''
  for (const b of new TextEncoder().encode(svg)) bin += String.fromCharCode(b)
  return 'data:image/svg+xml;base64,' + btoa(bin)
}

/**
 * wg-quick names the interface after the file and Linux allows 15 characters, so
 * the name is cut to fit.
 */
export function confFileName(networkSlug: string, deviceName: string): string {
  const base = `${networkSlug}-${deviceName}`.replace(/[^A-Za-z0-9_=+.-]+/g, '-')
  return `${base.slice(0, 15).replace(/-+$/, '')}.conf`
}

export function downloadText(fileName: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
  const a = document.createElement('a')
  a.href = url
  a.download = fileName
  // Firefox and Safari drop a download from a detached anchor or an already revoked URL.
  document.body.append(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const SECRET_GUARD = 'The private key is shown only once; close anyway?'
