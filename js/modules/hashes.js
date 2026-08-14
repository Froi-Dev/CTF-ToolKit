import { hashesData, icons } from '../data.js';

export function renderHashes() {
  const main = document.getElementById('main');
  main.innerHTML = `<div class="main-content">
    <div class="page-header">
      <div><div class="page-title">Hashes / Passwords</div><div class="page-subtitle">Hash identification, cracking, and credential management</div></div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm">${icons.plus} Add Hash</button>
        <button class="btn btn-primary btn-sm">${icons.play} Crack All</button>
      </div>
    </div>
    ${renderHashInput()}
    ${renderHashResults()}
    ${renderCrackingTools()}
  </div>`;
}

function renderHashInput() {
  return `<div class="section">
    <div class="section-title mb-4">Hash Input</div>
    <div class="hash-input-group">
      <input class="input" type="text" placeholder="Paste hash value..." style="font-family:var(--font-mono);font-size:var(--text-xs)" />
      <select class="select" style="width:150px">
        <option>Auto-detect</option>
        <option>MD5</option>
        <option>SHA-1</option>
        <option>SHA-256</option>
        <option>SHA-512 crypt</option>
        <option>NTLM</option>
        <option>bcrypt</option>
      </select>
      <button class="btn btn-primary">${icons.search} Identify & Crack</button>
    </div>
  </div>`;
}

function renderHashResults() {
  const rows = hashesData.hashes.map(h => {
    const statusCls = h.status === 'cracked' ? 'badge-success' : h.status === 'cracking' ? 'badge-warning' : 'badge-info';
    return `<tr>
      <td class="mono text-muted" style="font-size:var(--text-xs);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${h.hash}</td>
      <td class="text-secondary">${h.type}</td>
      <td><span class="badge badge-dot ${statusCls}">${h.status}</span></td>
      <td class="mono font-medium" style="font-size:var(--text-xs);color:${h.plaintext?'var(--success)':'var(--text-muted)'}">${h.plaintext || '—'}</td>
      <td class="text-muted">${h.source}</td>
    </tr>`;
  }).join('');

  return `<div class="section">
    <div class="section-header">
      <div class="section-title">Hash Database</div>
      <span class="text-xs text-muted">${hashesData.hashes.filter(h=>h.status==='cracked').length} / ${hashesData.hashes.length} cracked</span>
    </div>
    <table class="data-table">
      <thead><tr><th>Hash</th><th>Type</th><th>Status</th><th>Plaintext</th><th>Source</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderCrackingTools() {
  return `<div class="section">
    <div class="section-title mb-4">Cracking Configuration</div>
    <div class="split-h split-h-1-1">
      <div class="panel"><div class="panel-body">
        <div class="kv-list">
          <div class="kv-key">Tool</div><div class="kv-value">hashcat</div>
          <div class="kv-key">Mode</div><div class="kv-value">Dictionary + Rules</div>
          <div class="kv-key">Wordlist</div><div class="kv-value mono" style="font-size:var(--text-xs)">rockyou.txt</div>
          <div class="kv-key">Rules</div><div class="kv-value mono" style="font-size:var(--text-xs)">best64.rule</div>
        </div>
      </div></div>
      <div class="panel"><div class="panel-body">
        <div class="kv-list">
          <div class="kv-key">GPU</div><div class="kv-value">NVIDIA RTX 4090</div>
          <div class="kv-key">Speed</div><div class="kv-value mono">8.2 GH/s (MD5)</div>
          <div class="kv-key">Progress</div><div class="kv-value">67%</div>
          <div class="kv-key">ETA</div><div class="kv-value mono">00:04:32</div>
        </div>
      </div></div>
    </div>
  </div>`;
}
