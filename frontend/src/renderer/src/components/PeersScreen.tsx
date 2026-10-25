import { useSystemStatus } from './systemStatus'
import { short } from './utils'

type Tone = 'ok' | 'warn' | 'bad'
const cls = (t: Tone): string => (t === 'ok' ? 'status-ok' : t === 'warn' ? 'status-warn' : 'status-fail')

type Card = { name: string; state: string; tone: Tone; desc: string; details: [string, string][] }

export default function PeersScreen() {
  const s = useSystemStatus()
  const healthy = s.backend === true && s.chain?.valid !== false

  const qkdMode = s.qkd?.qkd_mode ?? 'unknown'
  const cards: Card[] = [
    {
      name: 'API Server',
      state: s.backend === null ? 'CHECKING' : s.backend ? 'ONLINE' : 'OFFLINE',
      tone: s.backend ? 'ok' : s.backend === null ? 'warn' : 'bad',
      desc: 'FastAPI backend · ML-KEM-768, ML-DSA-65',
      details: [
        ['Auth', 'JWT bearer'],
        ['Last checked', s.at]
      ]
    },
    {
      name: 'QKD Channel',
      state: s.qkd ? qkdMode.toUpperCase() : 'UNKNOWN',
      tone: s.qkd ? (s.qkd.qkd_available && qkdMode === 'hardware' ? 'ok' : 'warn') : 'bad',
      desc: s.qkd?.detail ?? 'Status unavailable',
      details: [
        ['TLS mode', s.qkd?.tls_mode_in_use ?? '—'],
        ['TLS-PSK supported', s.qkd ? (s.qkd.tls_psk_supported ? 'yes' : 'no') : '—']
      ]
    },
    {
      name: 'Hash-chain Ledger',
      state: s.chain ? (s.chain.valid ? 'VALID' : 'BROKEN') : 'UNKNOWN',
      tone: s.chain ? (s.chain.valid ? 'ok' : 'bad') : 'warn',
      desc: 'Local SHA-256 chain · tamper-evident',
      details: [
        ['Records', s.chain ? String(s.chain.records_checked) : '—'],
        ['Tip hash', short(s.chain?.ledger_tip_hash, 6)]
      ]
    },
    {
      name: 'Hyperledger Fabric',
      state: s.fabric === null ? 'UNKNOWN' : s.fabric ? 'ENABLED' : 'NOT CONNECTED',
      tone: s.fabric ? 'ok' : 'warn',
      desc: 'Distributed anchor (optional)',
      details: [
        ['Mode', s.fabric ? 'Anchoring records on chain' : 'Local signed ledger only'],
        ['Enable with', 'FABRIC_ENABLED=1']
      ]
    }
  ]

  return (
    <section className="content-card large-card">
      <div className="card-title">
        <div>
          <h2>Network Components</h2>
          <p>Live status of the services behind the ledger, read from the backend.</p>
        </div>

        <span className={'badge ' + (healthy ? 'badge-success' : 'badge-warning')}>
          {healthy ? 'NETWORK HEALTHY' : 'DEGRADED'}
        </span>
      </div>

      <div className="peer-grid">
        {cards.map((c) => (
          <div className="peer-card" key={c.name}>
            <div className="peer-header">
              <h3>{c.name}</h3>
              <span className={cls(c.tone)}>● {c.state}</span>
            </div>
            <p>{c.desc}</p>
            {c.details.map(([k, v]) => (
              <div className="peer-details" key={k}>
                <span>{k}</span>
                <strong>{v}</strong>
              </div>
            ))}
          </div>
        ))}
      </div>

      <div className="action-row">
        <button className="secondary-button" onClick={s.refresh} disabled={s.loading}>
          {s.loading ? 'Refreshing…' : '⟳ Refresh'}
        </button>
      </div>
    </section>
  )
}
