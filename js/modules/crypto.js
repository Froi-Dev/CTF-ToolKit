import { cryptoData, icons } from '../data.js';

export function renderCrypto() {
  const main = document.getElementById('main');
  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header">
      <div><div class="page-title">Cryptography Workbench</div><div class="page-subtitle">Build transformation chains to decode and decrypt data</div></div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm">${icons.copy} Copy Result</button>
        <button class="btn btn-primary btn-sm">${icons.play} Run Pipeline</button>
      </div>
    </div>
    <div class="crypto-layout">
      ${renderInput()}
      ${renderPipeline()}
      ${renderResults()}
    </div>
  </div>`;
}

function renderInput() {
  return `<div class="crypto-input">
    <div class="section-title">Input</div>
    <textarea class="textarea" rows="8" placeholder="Paste encoded/encrypted data here..." style="min-height:160px;font-size:var(--text-xs)">Q1RGe2NyMXB0MF9jaDQxbl9tNHN0M3J9</textarea>
    <div class="kv-list" style="font-size:var(--text-xs)">
      <div class="kv-key">Length</div><div class="kv-value mono">32 chars</div>
      <div class="kv-key">Encoding</div><div class="kv-value mono">Base64 (detected)</div>
      <div class="kv-key">Entropy</div><div class="kv-value mono">4.82 bits/char</div>
    </div>
    <div class="section-title mt-8">Available Transforms</div>
    <div class="flex gap-2" style="flex-wrap:wrap">
      ${cryptoData.transforms.map(t => `<button class="btn btn-sm btn-secondary" data-transform="${t}">${t}</button>`).join('')}
    </div>
  </div>`;
}

function renderPipeline() {
  const steps = cryptoData.pipeline.map((s, i) => {
    const params = Object.entries(s.params).map(([k,v]) => `${k}: ${v}`).join(', ');
    return `
      ${i > 0 ? '<div class="crypto-arrow">↓</div>' : ''}
      <div class="crypto-step active">
        <div class="crypto-step-num">${i + 1}</div>
        <div class="crypto-step-label">
          <div style="font-weight:500">${s.name}</div>
          ${params ? `<div class="text-xs text-muted">${params}</div>` : ''}
        </div>
        <div class="crypto-step-remove">${icons.x}</div>
      </div>
    `;
  }).join('');

  return `<div class="crypto-pipeline">
    <div class="section-title">Transformation Pipeline</div>
    ${steps}
    <div class="crypto-arrow">↓</div>
    <div class="crypto-add-step">
      ${icons.plus}
      <span>Add transformation step</span>
    </div>
    <div class="mt-8">
      <div class="section-title mb-4">Pipeline Summary</div>
      <div class="panel"><div class="panel-body">
        <div class="mono text-xs" style="color:var(--accent)">Base64 → Hex → XOR(0x17)</div>
      </div></div>
    </div>
  </div>`;
}

function renderResults() {
  const results = cryptoData.results.map(r => {
    const confClass = r.confidence > 80 ? 'confidence-high' : r.confidence > 50 ? 'confidence-medium' : 'confidence-low';
    const confColor = r.confidence > 80 ? 'var(--success)' : r.confidence > 50 ? 'var(--warning)' : 'var(--text-muted)';
    return `<div class="crypto-result-item">
      <div class="crypto-result-chain">${r.chain}</div>
      <div class="crypto-result-value">${r.value}</div>
      <div class="crypto-result-confidence">
        <div class="confidence-bar"><div class="confidence-fill ${confClass}" style="width:${r.confidence}%"></div></div>
        <span style="color:${confColor}">${r.confidence}%</span>
      </div>
    </div>`;
  }).join('');

  return `<div class="crypto-output">
    <div class="section-title">Candidate Results</div>
    <div class="crypto-results">${results}</div>
    <div class="mt-8">
      <div class="section-title mb-4">Flag Detection</div>
      <div class="panel">
        <div class="panel-header" style="background:var(--success-bg);color:var(--success)">
          ${icons.flag} Flag Pattern Matched
        </div>
        <div class="panel-body">
          <div class="mono" style="font-size:var(--text-sm);word-break:break-all">CTF{cr1pt0_ch41n_m4st3r}</div>
          <div class="text-xs text-muted mt-4">Pattern: CTF{...} — Confidence: 94%</div>
        </div>
      </div>
    </div>
  </div>`;
}
