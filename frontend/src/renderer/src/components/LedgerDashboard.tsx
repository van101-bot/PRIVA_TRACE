import { useEffect, useState } from 'react'
import {
  anchorOnFabric,
  appendToHashChain,
  getAccessLog,
  getChainRecords,
  getFabricStatus,
  getLastWatermarkId,
  verifyHashChain,
  verifyOnFabric
} from '../services/api'
import type { AccessLogRow, ChainRecord } from '../services/api'
import { errMsg, short } from './utils'

type Kind = 'encryption' | 'decryption' | 'zkp' | 'investigation' | 'ledger' | 'report' | 'other'
type Filter = 'all' | Exclude<Kind, 'ledger' | 'other'>
type Chain = {
  valid: boolean
  records_checked: number
  ledger_tip_hash?: string
  reason?: string
  failed_sequence?: number
}

const FILTERS: { key: Filter; label: string }[] = [
  { key: 'all', label: 'All Events' },
  { key: 'encryption', label: 'Encryption' },
  { key: 'decryption', label: 'Decryption' },
  { key: 'zkp', label: 'ZKP' },
  { key: 'investigation', label: 'Investigation' },
  { key: 'report', label: 'Reports' }
]

const NOISE = ['/access-log', '/ledger-chain/verify', '/fabric/status', '/auth/', '/health', '/qkd/status']

function classify(path: string): { kind: Kind; label: string } {
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

export default function LedgerDashboard() {
  const [watermarkId, setWatermarkId] = useState(getLastWatermarkId())
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [failed, setFailed] = useState(false)

  const [rows, setRows] = useState<AccessLogRow[]>([])
  const [chain, setChain] = useState<Chain | null>(null)
  const [fabric, setFabric] = useState<boolean | null>(null)
  const [records, setRecords] = useState<ChainRecord[]>([])
  const [filter, setFilter] = useState<Filter>('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [synced, setSynced] = useState('-')
  const [tick, setTick] = useState(0)

  useEffect(() => {
    let alive = true
    void (async () => {
      const [log, ch, fab, rec] = await Promise.allSettled([
        getAccessLog(100),
        verifyHashChain(),
        getFabricStatus(),
        getChainRecords(20)
      ])
      if (!alive) return
      setRows(log.status === 'fulfilled' ? log.value : [])
      setError(log.status === 'rejected' ? errMsg(log.reason) : null)
      setChain(ch.status === 'fulfilled' ? ch.value : null)
      setFabric(fab.status === 'fulfilled' ? !!fab.value.enabled : null)
      setRecords(rec.status === 'fulfilled' ? rec.value : [])
      setSynced(new Date().toLocaleTimeString())
      setLoading(false)
    })()
    return () => {
      alive = false
    }
  }, [tick])

  const refresh = () => {
    setLoading(true)
    setTick((t) => t + 1)
  }

  const run = async (label: string, job: () => Promise<unknown>) => {
    setBusy(true)
    setMessage(null)
    setFailed(false)
    try {
      const out = await job()
      setMessage(label + ': ' + JSON.stringify(out))
      refresh()
    } catch (e) {
      setFailed(true)
      setMessage(label + ' failed: ' + (e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const id = watermarkId.trim()

  const events = rows
    .filter((r) => !NOISE.some((n) => r.path.startsWith(n)))
    .map((r) => ({ ...r, ...classify(r.path) }))
    .filter((r) => filter === 'all' || r.kind === filter)

  return (
    <section className="content-card large-card">
      <div className="card-title">
        <div>
          <h2>Immutable Ledger Dashboard</h2>
          <p>Signed records, hash chain integrity and your recent cryptographic events.</p>
        </div>
        <span className={'badge ' + (chain?.valid ? 'badge-success' : 'badge-warning')}>
          {chain ? (chain.valid ? 'CHAIN VALID' : 'CHAIN BROKEN') : 'CHAIN UNKNOWN'}
        </span>
      </div>

      <div className="privacy-card" style={{ margin: '16px 0' }}>
        <span className="privacy-label">
          LEDGER ACTIONS - Fabric: {fabric === null ? 'unavailable' : fabric ? 'enabled' : 'disabled'}
        </span>
        <input
          className="text-input"
          placeholder="Watermark ID"
          value={watermarkId}
          onChange={(e) => setWatermarkId(e.target.value)}
        />
        <div className="ledger-toolbar">
          <button className="secondary-button" disabled={busy || !id} onClick={() => run('Hash chain append', () => appendToHashChain(id))}>
            Add to hash chain
          </button>
          <button className="secondary-button" disabled={busy} onClick={() => run('Hash chain check', () => verifyHashChain())}>
            Verify hash chain
          </button>
          <button className="secondary-button" disabled={busy || !id} onClick={() => run('Fabric anchor', () => anchorOnFabric(id))}>
            Anchor on Fabric
          </button>
          <button className="secondary-button" disabled={busy || !id} onClick={() => run('Fabric verify', () => verifyOnFabric(id))}>
            Verify on Fabric
          </button>
        </div>
        {message && (
          <p style={{ color: failed ? '#dc2626' : undefined, wordBreak: 'break-word', fontSize: '0.85rem' }}>{message}</p>
        )}
      </div>

      <div className="ledger-live-bar">
        <div>
          <span className="live-dot"></span>
          <strong>LOCAL HASH CHAIN</strong>
        </div>
        <div className="ledger-sync-info">
          <span>Records: <strong>{chain ? chain.records_checked : '-'}</strong></span>
          <span>Tip: <strong className="mono">{chain?.ledger_tip_hash ? short(chain.ledger_tip_hash, 6) : '-'}</strong></span>
          <span>Last synced: <strong>{synced}</strong></span>
        </div>
      </div>

      {chain && !chain.valid && (
        <div className="error-notice">
          Hash chain failed verification at record #{chain.failed_sequence ?? '?'}
          {chain.reason ? ' (' + chain.reason + ')' : ''}.
        </div>
      )}

      <div className="ledger-toolbar">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            className={'secondary-button' + (filter === f.key ? ' filter-active' : '')}
            onClick={() => setFilter(f.key)}
          >
            {f.label}
          </button>
        ))}
        <button className="secondary-button" onClick={refresh} disabled={loading}>
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {error && <div className="error-notice">{error}</div>}

      <div className="ledger-table">
        <div className="ledger-row ledger-header">
          <span>EVENT</span>
          <span>REFERENCE</span>
          <span>STATUS</span>
          <span>TIME</span>
        </div>
        {events.length === 0 && !loading && (
          <div className="ledger-row">
            <span>No events yet. Encrypt or decrypt a document first.</span>
            <span></span>
            <span></span>
            <span></span>
          </div>
        )}
        {events.map((e) => (
          <div className="ledger-row" key={e.request_id}>
            <span>{e.label}</span>
            <span className="mono">{short(e.resource ?? e.request_id, 6)}</span>
            <span className={e.status_code < 400 ? 'status-ok' : 'status-fail'}>{e.outcome.toUpperCase()}</span>
            <span>{new Date(e.created_at).toLocaleTimeString()}</span>
          </div>
        ))}
      </div>

      <h3 className="chain-heading">Hash chain records (newest first)</h3>
      <div className="ledger-table">
        <div className="ledger-row ledger-header chain-row">
          <span>#</span>
          <span>EVENT</span>
          <span>RECORD HASH</span>
          <span>PREVIOUS HASH</span>
          <span>TIME</span>
        </div>
        {records.length === 0 && !loading && (
          <div className="ledger-row chain-row">
            <span></span>
            <span>No chain records yet. Use "Add to hash chain" above.</span>
            <span></span>
            <span></span>
            <span></span>
          </div>
        )}
        {records.map((r) => (
          <div
            className={'ledger-row chain-row' + (chain && !chain.valid && chain.failed_sequence === r.sequence ? ' chain-broken' : '')}
            key={r.sequence}
            title={r.own && r.watermark_id ? 'Watermark ' + r.watermark_id : 'Another account record (identifier hidden)'}
          >
            <span>{r.sequence}</span>
            <span>{r.event ?? '-'}{r.own ? '' : ' - other account'}</span>
            <span className="mono">{short(r.record_hash, 6)}</span>
            <span className="mono">{short(r.previous_hash, 6)}</span>
            <span>{new Date(r.timestamp * 1000).toLocaleTimeString()}</span>
          </div>
        ))}
      </div>
      <p className="hint">
        Each record stores the hash of the one before it. Changing any past record breaks every hash after it.
      </p>
    </section>
  )
}