import { useEffect, useState } from 'react'
import { checkBackend, getAccessLog, getFabricStatus, getQKDStatus, verifyHashChain } from '../services/api'
import type { AccessLogRow } from '../services/api'

export type Chain = { valid: boolean; records_checked: number; ledger_tip_hash?: string; failed_sequence?: number }
export type Qkd = { qkd_mode: string; qkd_available: boolean; detail: string; tls_mode_in_use?: string; tls_psk_supported?: boolean }

type State = {
  loading: boolean
  backend: boolean | null
  qkd: Qkd | null
  fabric: boolean | null
  chain: Chain | null
  rows: AccessLogRow[]
  at: string
}

// One place that asks the real backend how everything is doing.
export function useSystemStatus() {
  const [tick, setTick] = useState(0)
  const [state, setState] = useState<State>({
    loading: true,
    backend: null,
    qkd: null,
    fabric: null,
    chain: null,
    rows: [],
    at: '—'
  })

  useEffect(() => {
    let alive = true
    void (async () => {
      const [h, q, f, c, l] = await Promise.allSettled([
        checkBackend(),
        getQKDStatus(),
        getFabricStatus(),
        verifyHashChain(),
        getAccessLog(200)
      ])
      if (!alive) return
      setState({
        loading: false,
        backend: h.status === 'fulfilled',
        qkd: q.status === 'fulfilled' ? (q.value as Qkd) : null,
        fabric: f.status === 'fulfilled' ? !!(f.value as { enabled: boolean }).enabled : null,
        chain: c.status === 'fulfilled' ? (c.value as Chain) : null,
        rows: l.status === 'fulfilled' ? l.value : [],
        at: new Date().toLocaleTimeString()
      })
    })()
    return () => {
      alive = false
    }
  }, [tick])

  const refresh = () => {
    setState((s) => ({ ...s, loading: true }))
    setTick((t) => t + 1)
  }

  return { ...state, refresh }
}
