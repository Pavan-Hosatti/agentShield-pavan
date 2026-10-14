import { useState } from 'react'
import { THREAT_MAP, type ThreatEntry } from '../engine/v3Engine'
import './ThreatMapTab.css'

type FilterPlane = 'ALL' | 'Control' | 'Execution' | 'Evaluation' | 'Network'
type FilterConfig = 'ALL' | 'A' | 'B' | 'C'

export default function ThreatMapTab() {
  const [plane, setPlane] = useState<FilterPlane>('ALL')
  const [config, setConfig] = useState<FilterConfig>('ALL')
  const [hoveredId, setHoveredId] = useState<string | null>(null)

  const filtered = THREAT_MAP.filter(t => {
    const planeMatch = plane === 'ALL' || t.plane === plane
    const configMatch = config === 'ALL' ||
      (config === 'A' && !t.blockedInA) ||   // show what A MISSES
      (config === 'B' && !t.blockedInB) ||
      (config === 'C' && !t.blockedInC)
    return planeMatch && configMatch
  })

  const critCount = THREAT_MAP.filter(t => t.severity === 'CRITICAL').length
  const missedByA = THREAT_MAP.filter(t => !t.blockedInA).length
  const missedByB = THREAT_MAP.filter(t => !t.blockedInB).length
  const missedByC = THREAT_MAP.filter(t => !t.blockedInC).length

  return (
    <div className="tm-tab">
      {/* Header stats */}
      <div className="tm-header">
        <div className="tm-title">▶ THREAT MAP — {THREAT_MAP.length} ATTACK VECTORS</div>
        <div className="tm-stats">
          <div className="tm-stat"><span className="ts-val ts-red">{critCount}</span><span className="ts-label">CRITICAL</span></div>
          <div className="tm-stat"><span className="ts-val ts-red">{missedByA}</span><span className="ts-label">OPEN IN A</span></div>
          <div className="tm-stat"><span className="ts-val ts-yellow">{missedByB}</span><span className="ts-label">OPEN IN B</span></div>
          <div className="tm-stat"><span className="ts-val ts-green">0</span><span className="ts-label">OPEN IN C</span></div>
        </div>
      </div>

      {/* Filters */}
      <div className="tm-filters">
        <span className="tf-label">PLANE:</span>
        {(['ALL','Control','Execution','Evaluation','Network'] as FilterPlane[]).map(p => (
          <button key={p} className={`tf-btn ${plane === p ? 'tf-active' : ''}`} onClick={() => setPlane(p)}>{p}</button>
        ))}
        <span className="tf-label" style={{ marginLeft: 12 }}>SHOW GAPS IN:</span>
        {(['ALL','A','B','C'] as FilterConfig[]).map(c => (
          <button key={c}
            className={`tf-btn ${config === c ? 'tf-active' : ''} ${c !== 'ALL' ? `tf-cfg-${c.toLowerCase()}` : ''}`}
            onClick={() => setConfig(c)}
          >
            {c === 'ALL' ? 'All' : `Config ${c} gaps`}
          </button>
        ))}
      </div>

      {/* Matrix table */}
      <div className="tm-table-wrap">
        <table className="tm-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>THREAT</th>
              <th>METHOD</th>
              <th>PLANE</th>
              <th>DEFENDED BY</th>
              <th>INVARIANT</th>
              <th>SEV</th>
              <th>CFG A</th>
              <th>CFG B</th>
              <th>CFG C</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(t => (
              <tr
                key={t.id}
                className={`tm-row ${hoveredId === t.id ? 'tm-row-hover' : ''}`}
                onMouseEnter={() => setHoveredId(t.id)}
                onMouseLeave={() => setHoveredId(null)}
              >
                <td className="td-id">{t.id}</td>
                <td className="td-name">{t.name}</td>
                <td className="td-method">{t.method}</td>
                <td><PlaneTag plane={t.plane} /></td>
                <td className="td-defense">{t.defendedBy}</td>
                <td className="td-inv">{t.invariant}</td>
                <td><SevTag sev={t.severity} /></td>
                <td><BlockTag blocked={t.blockedInA} /></td>
                <td><BlockTag blocked={t.blockedInB} /></td>
                <td><BlockTag blocked={t.blockedInC} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Coverage summary bars */}
      <div className="tm-coverage">
        <div className="tc-title">▶ BASELINE COVERAGE ({THREAT_MAP.length} threats)</div>
        {(['A','B','C'] as const).map(c => {
          const blocked = THREAT_MAP.filter(t =>
            c === 'A' ? t.blockedInA : c === 'B' ? t.blockedInB : t.blockedInC
          ).length
          const pct = blocked / THREAT_MAP.length
          const color = c === 'C' ? 'var(--green-bright)' : c === 'B' ? 'var(--yellow-bright)' : 'var(--red-bright)'
          return (
            <div key={c} className="tc-row">
              <span className="tc-label">Config {c}</span>
              <div className="tc-bar-wrap">
                <div className="tc-bar" style={{ width: `${pct * 100}%`, background: color }} />
              </div>
              <span className="tc-pct" style={{ color }}>{blocked}/{THREAT_MAP.length}</span>
              <span className="tc-detail" style={{ color }}>
                {blocked === THREAT_MAP.length ? '— ALL THREATS BLOCKED ✓' : `— ${THREAT_MAP.length - blocked} open`}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function PlaneTag({ plane }: { plane: ThreatEntry['plane'] }) {
  const colors: Record<ThreatEntry['plane'], string> = {
    Control:    'var(--cyan-mid)',
    Execution:  'var(--orange-bright)',
    Evaluation: 'var(--green-mid)',
    Network:    'var(--yellow-mid)',
  }
  return <span className="plane-tag" style={{ color: colors[plane], borderColor: colors[plane] }}>{plane}</span>
}

function SevTag({ sev }: { sev: ThreatEntry['severity'] }) {
  const cls = sev === 'CRITICAL' ? 'sev-critical' : sev === 'HIGH' ? 'sev-high' : 'sev-medium'
  return <span className={`sev-tag ${cls}`}>{sev}</span>
}

function BlockTag({ blocked }: { blocked: boolean }) {
  return blocked
    ? <span className="block-tag block-yes">BLOCKED</span>
    : <span className="block-tag block-no">OPEN</span>
}
