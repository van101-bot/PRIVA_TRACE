// Turns raw API-call log rows into readable events (shared by Dashboard).
export type Kind = 'encryption' | 'decryption' | 'zkp' | 'investigation' | 'ledger' | 'report' | 'other'

// Calls the pages make about themselves would flood the lists, so they are hidden.
export const NOISE = ['/access-log', '/ledger-chain/verify', '/ledger-chain/records', '/fabric/status', '/auth/', '/health', '/qkd/status']

export function classify(path: string): { kind: Kind; label: string } {
  if (path.startsWith('/keys/generate')) return { kind: 'encryption', label: 'Recipient key generated' }
  if (path.startsWith('/encrypt')) return { kind: 'encryption', label: 'Document encrypted' }
  if (path.startsWith('/decrypt')) return { kind: 'decryption', label: 'Document decrypted + watermarked' }
  if (path.startsWith('/attribute-with-zkp')) return { kind: 'zkp', label: 'ZKP attribution check' }
  if (path.startsWith('/provenance/trace')) return { kind: 'investigation', label: 'Leaked file traced' }
  if (path.startsWith('/provenance')) return { kind: 'investigation', label: 'Provenance lookup' }
  if (path.startsWith('/extract-watermark')) return { kind: 'investigation', label: 'Watermark extracted' }
  if (path.startsWith('/generate-attribution-report')) return { kind: 'report', label: 'Attribution report generated' }
  if (path.startsWith('/ledger-chain/append')) return { kind: 'ledger', label: 'Recorded in hash chain' }
  if (path.startsWith('/fabric/anchor')) return { kind: 'ledger', label: 'Anchored on Fabric' }
  if (path.startsWith('/fabric/verify')) return { kind: 'ledger', label: 'Fabric verification' }
  if (path.startsWith('/ledger/')) return { kind: 'ledger', label: 'Ledger proof read' }
  return { kind: 'other', label: 'Other API call' }
}

export const KIND_ICON: Record<Kind, string> = {
  encryption: 'E',
  decryption: 'D',
  zkp: 'Z',
  investigation: 'I',
  ledger: 'L',
  report: 'R',
  other: '•'
}

export function timeAgo(iso: string): string {
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return s + 's ago'
  if (s < 3600) return Math.floor(s / 60) + 'm ago'
  if (s < 86400) return Math.floor(s / 3600) + 'h ago'
  return Math.floor(s / 86400) + 'd ago'
}
