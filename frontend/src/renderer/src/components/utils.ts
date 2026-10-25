// Small helpers shared by the backend-connected pages.
export const errMsg = (e: unknown): string => (e instanceof Error ? e.message : String(e))

export const short = (s?: string | null, n = 16): string =>
  !s ? '—' : s.length > n * 2 + 3 ? s.slice(0, n) + '…' + s.slice(-n) : s

export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

export function base64ToBlob(b64: string, type = 'application/pdf'): Blob {
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return new Blob([bytes], { type })
}
