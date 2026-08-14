import { stegoData, icons } from '../data.js';

export function renderStego() {
  const main = document.getElementById('main');
  main.innerHTML = `<div class="main-content">
    <div class="page-header">
      <div><div class="page-title">Steganography</div><div class="page-subtitle">${stegoData.image} — Image analysis and hidden data extraction</div></div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm">${icons.download} Export Findings</button>
      </div>
    </div>
    <div class="split-h split-h-1-1">
      <div>
        ${renderMetadata()}
        ${renderAnalyses()}
      </div>
      <div>
        ${renderImagePreview()}
        ${renderExtracted()}
      </div>
    </div>
  </div>`;
}

function renderMetadata() {
  const kvs = stegoData.metadata.map(m => {
    const isAnomaly = m.key.includes('Anomaly') || m.key.includes('GPS');
    return `<div class="kv-key">${m.key}</div><div class="kv-value mono" ${isAnomaly?'style="color:var(--warning);font-weight:500"':''}>${m.value}</div>`;
  }).join('');

  return `<div class="section">
    <div class="section-title mb-4">Image Metadata</div>
    <div class="panel"><div class="panel-body"><div class="kv-list">${kvs}</div></div></div>
  </div>`;
}

function renderAnalyses() {
  const rows = stegoData.analyses.map(a => `<tr>
    <td class="font-medium">${a.name}</td>
    <td><span class="badge badge-dot badge-success">${a.status}</span></td>
    <td class="text-secondary" style="font-size:var(--text-xs)">${a.result}</td>
  </tr>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">Analysis Results</div>
    <table class="data-table">
      <thead><tr><th>Analysis</th><th>Status</th><th>Result</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderImagePreview() {
  return `<div class="section">
    <div class="section-title mb-4">Image Preview</div>
    <div class="panel">
      <div class="panel-body" style="text-align:center;padding:var(--sp-12)">
        <div style="width:100%;height:180px;background:var(--bg-tertiary);border-radius:var(--radius-sm);display:flex;align-items:center;justify-content:center;color:var(--text-muted);font-size:var(--text-sm)">
          <div>
            <div style="font-size:var(--text-2xl);margin-bottom:var(--sp-2)">🖼</div>
            <div>suspicious.png</div>
            <div class="text-xs">1920 × 1080</div>
          </div>
        </div>
      </div>
    </div>
  </div>`;
}

function renderExtracted() {
  return `<div class="section">
    <div class="section-title mb-4">Extracted Data</div>
    <table class="data-table">
      <thead><tr><th>Type</th><th>Data</th><th>Method</th></tr></thead>
      <tbody>
        <tr><td>Archive</td><td class="mono" style="font-size:var(--text-xs)">embedded.zip (48 KB)</td><td class="text-muted">File Carving</td></tr>
        <tr><td>String</td><td class="mono" style="font-size:var(--text-xs)">admin_shadow</td><td class="text-muted">EXIF Metadata</td></tr>
        <tr><td>GPS</td><td class="mono" style="font-size:var(--text-xs)">48.8566°N, 2.3522°E (Paris)</td><td class="text-muted">EXIF Metadata</td></tr>
        <tr><td>Hidden Data</td><td class="mono" style="font-size:var(--text-xs)">68 bytes in LSB channel</td><td class="text-muted">LSB Analysis</td></tr>
      </tbody>
    </table>
  </div>`;
}
