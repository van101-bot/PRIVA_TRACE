// Real SIH26237 backend client (FastAPI + JWT).
// Config comes from frontend/.env (electron-vite only exposes RENDERER_VITE_* to the renderer).
const env = (import.meta as unknown as { env: Record<string, string | undefined> }).env
const API_BASE_URL = env.RENDERER_VITE_API_URL ?? ''

let token: string | null = null

export type Recipient = { recipient_id: string; public_key: string; private_key: string }
// Demo only: server-generated recipient key pair, kept in memory (never persisted).
let lastRecipient: Recipient | null = null
export const getLastRecipient = (): Recipient | null => lastRecipient

// Remembers the newest watermark id so the Investigation / Privacy / Reports / Ledger pages can prefill it.
let lastWatermarkId = ''
export const getLastWatermarkId = (): string => lastWatermarkId

export type LedgerEvent = { event: string; hash: string; status: string; time: string }

export type DecryptResult = {
  watermark_id: string
  zkp_proof: string
  timestamp: string
  watermarked_file: string // base64
}

export type ProvenanceResult = {
  watermark_id: string
  status?: string
  confidence?: number
  known?: boolean
  encrypted_file_id?: string
  document_hash?: string
  decrypted_at?: string
  timestamp?: string
  zkp_verified?: boolean
  signature_valid?: boolean
  ledger_backend?: string
  [key: string]: unknown
}

async function rawRequest(
  path: string,
  init: RequestInit = {},
  auth = true,
  retried = false
): Promise<Response> {
  const headers = new Headers(init.headers)
  if (auth) {
    if (!token) await login()
    headers.set('Authorization', 'Bearer ' + token)
  }
  const res = await fetch(API_BASE_URL + path, { ...init, headers })
  if (res.status === 401 && auth && !retried) {
    token = null // token expired: log in once more
    await login()
    return rawRequest(path, init, true, true)
  }
  if (!res.ok) {
    let detail = ''
    try {
      detail = JSON.stringify((await res.json()).detail ?? '')
    } catch {
      /* body was not JSON */
    }
    throw new Error('API ' + res.status + ' ' + path + ' ' + detail)
  }
  return res
}

async function request(path: string, init: RequestInit = {}, auth = true) {
  return (await rawRequest(path, init, auth)).json()
}

const post = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body)
})

// ---------- auth ----------
function askCred(key: string, label: string): string {
  let v = sessionStorage.getItem(key)
  if (!v) {
    v = window.prompt(label) ?? ''
    if (v) sessionStorage.setItem(key, v)
  }
  return v
}

export async function login(username?: string, password?: string): Promise<boolean> {
  const u = username ?? env.RENDERER_VITE_API_USER ?? askCred('api_user', 'Username')
  const p = password ?? env.RENDERER_VITE_API_PASSWORD ?? askCred('api_pass', 'Password')
  if (!u || !p) throw new Error('No API credentials: set RENDERER_VITE_API_USER and RENDERER_VITE_API_PASSWORD in .env')
  const data = await request('/auth/login', post({ username: u, password: p }), false)
  token = data.access_token
  return true
}

// ---------- health / status ----------
export const checkBackend = () => request('/health', {}, false)
export const getQKDStatus = () => request('/qkd/status')
export const getFabricStatus = () => request('/fabric/status')

// ---------- keys + encrypt ----------
export async function generateRecipientKey(recipientId: string): Promise<Recipient> {
  const r = await request('/keys/generate', post({ recipient_id: recipientId }))
  lastRecipient = { recipient_id: r.recipient_id, public_key: r.public_key, private_key: r.private_key }
  return lastRecipient
}

// returns { encrypted_file_id, document_hash, status }
export async function encryptDocument(
  file: File,
  recipients: { recipient_id: string; public_key: string }[]
) {
  const form = new FormData()
  form.append('file', file)
  form.append('recipients_json', JSON.stringify(recipients))
  return request('/encrypt', { method: 'POST', body: form })
}

// ---------- decrypt: watermark + ZKP + signed record ----------
export async function decryptDocument(
  encryptedFileId: string,
  recipientId: string,
  privateKey: string
): Promise<DecryptResult> {
  const r: DecryptResult = await request(
    '/decrypt',
    post({ encrypted_file_id: encryptedFileId, recipient_id: recipientId, private_key: privateKey })
  )
  lastWatermarkId = r.watermark_id
  return r
}

// ---------- investigation ----------
export async function investigateLeak(file: File): Promise<ProvenanceResult> {
  const form = new FormData()
  form.append('file', file)
  const r: ProvenanceResult = await request('/provenance/trace', { method: 'POST', body: form })
  if (r.watermark_id) lastWatermarkId = r.watermark_id
  return r
}
export const getProvenance = (watermarkId: string): Promise<ProvenanceResult> =>
  request('/provenance/' + encodeURIComponent(watermarkId))
export const verifyAttribution = (
  watermarkId: string
): Promise<{ is_authorized: boolean; zkp_verified: boolean }> =>
  request('/attribute-with-zkp', post({ watermark_id: watermarkId }))

// ---------- ledger ----------
export const getLedgerProof = (watermarkId: string) =>
  request('/ledger/' + encodeURIComponent(watermarkId))
export const anchorOnFabric = (watermarkId: string) =>
  request('/fabric/anchor', post({ watermark_id: watermarkId }))
export const verifyOnFabric = (watermarkId: string) =>
  request('/fabric/verify/' + encodeURIComponent(watermarkId))
export const appendToHashChain = (watermarkId: string) =>
  request('/ledger-chain/append', post({ watermark_id: watermarkId }))
export const verifyHashChain = () => request('/ledger-chain/verify')

// ---------- reports ----------
export async function downloadAttributionReport(watermarkId: string): Promise<Blob> {
  const res = await rawRequest('/generate-attribution-report', post({ watermark_id: watermarkId }))
  return res.blob()
}

// ---------- save helpers (renderer-side download) ----------
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function saveBase64File(base64: string, filename: string): void {
  const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0))
  saveBlob(new Blob([bytes]), filename)
}


// ---------- access log (used by the status/events helpers) ----------
export type AccessLogRow = {
  request_id: string
  method: string
  path: string
  status_code: number
  outcome: string
  created_at: string
  resource?: string | null
  [key: string]: unknown
}
export const getAccessLog = (limit = 50): Promise<AccessLogRow[]> =>
  request('/access-log?limit=' + limit)

// Feeds the dashboard ledger list (same shape App.tsx already expects) from the caller's access log.
export async function getLedgerEvents(): Promise<LedgerEvent[]> {
  const rows: {
    method: string
    path: string
    outcome: string
    created_at: string
    request_id: string
  }[] = await request('/access-log?limit=20')
  return rows.map((r) => ({
    event: r.method + ' ' + r.path,
    hash: r.request_id.slice(0, 8).toUpperCase() + '...',
    status: r.outcome.toUpperCase(),
    time: new Date(r.created_at).toLocaleTimeString()
  }))
}

export type ChainRecord = {
  sequence: number
  event: string | null
  watermark_id: string | null
  own: boolean
  document_hash: string | null
  timestamp: number
  previous_hash: string
  record_hash: string
}
export const getChainRecords = (limit = 20): Promise<ChainRecord[]> =>
  request('/ledger-chain/records?limit=' + limit)
