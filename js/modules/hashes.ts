import { icons } from '../data.ts';

export function renderHashes(view?: string) {
  const main = document.getElementById('main');
  if (!main) return;
  main.innerHTML = `<div class="main-content">
    <div class="page-header">
      <div><div class="page-title">Hashes / Passwords</div><div class="page-subtitle">Hash identification, cracking, and credential management</div></div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm">${icons.plus} Add Hash</button>
        <button class="btn btn-primary btn-sm">${icons.play} Crack All</button>
      </div>
    </div>
    ${view === 'database' ? renderHashResults() : view === 'cracking' ? renderCrackingTools() : renderHashInput()}
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
  return `<div class="section">
    <div class="section-header">
      <div class="section-title">Hash Database</div>
      <span class="text-xs text-muted">0 results</span>
    </div>
    <table class="data-table">
      <thead><tr><th>Hash</th><th>Type</th><th>Status</th><th>Plaintext</th><th>Source</th></tr></thead>
      <tbody><tr><td colspan="5" class="text-muted">No hashes have been added or returned by an analyzer.</td></tr></tbody>
    </table>
  </div>`;
}

function renderCrackingTools() {
  return `<div class="section">
    <div class="section-title mb-4">Cracking Configuration</div>
    <div class="panel"><div class="panel-body text-sm text-muted">No cracking job is configured. Runtime details will appear here only after a real cracking backend is connected.</div></div>
  </div>`;
}

