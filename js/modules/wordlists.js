import { wordlistsData, icons } from '../data.js';

export function renderWordlists() {
  const main = document.getElementById('main');
  main.innerHTML = `<div class="main-content">
    <div class="page-header">
      <div><div class="page-title">Wordlists</div><div class="page-subtitle">Manage wordlists for password cracking and brute-force attacks</div></div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm">${icons.upload} Import</button>
        <button class="btn btn-primary btn-sm">${icons.plus} Create Custom</button>
      </div>
    </div>
    ${renderWordlistTable()}
    ${renderCustomGenerator()}
  </div>`;
}

function renderWordlistTable() {
  const rows = wordlistsData.map(w => `<tr class="clickable">
    <td class="mono font-medium" style="font-size:var(--text-xs)">${w.name}</td>
    <td class="mono text-muted" style="font-size:var(--text-xs)">${w.entries.toLocaleString()}</td>
    <td class="text-muted">${w.size}</td>
    <td class="text-secondary">${w.desc}</td>
    <td>
      <div class="flex gap-2">
        <button class="btn btn-sm btn-ghost">${icons.download}</button>
        <button class="btn btn-sm btn-ghost">${icons.copy}</button>
      </div>
    </td>
  </tr>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">Available Wordlists</div>
    <table class="data-table">
      <thead><tr><th>Name</th><th>Entries</th><th>Size</th><th>Description</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderCustomGenerator() {
  return `<div class="section">
    <div class="section-title mb-4">Custom Wordlist Generator</div>
    <div class="split-h split-h-1-1">
      <div class="panel"><div class="panel-body">
        <div class="settings-field">
          <div class="settings-field-label">Base words (one per line)</div>
          <textarea class="textarea" rows="5" placeholder="shadow\nprotocol\nadmin\nctf\n2026">shadow\nprotocol\nadmin\nctf\n2026</textarea>
        </div>
        <div class="settings-field">
          <div class="settings-field-label">Mutation rules</div>
          <div class="flex gap-3" style="flex-wrap:wrap">
            <label class="flex items-center gap-2 text-sm"><input type="checkbox" checked /> Leetspeak</label>
            <label class="flex items-center gap-2 text-sm"><input type="checkbox" checked /> Case variants</label>
            <label class="flex items-center gap-2 text-sm"><input type="checkbox" checked /> Append numbers</label>
            <label class="flex items-center gap-2 text-sm"><input type="checkbox" /> Append symbols</label>
            <label class="flex items-center gap-2 text-sm"><input type="checkbox" /> Combinations</label>
          </div>
        </div>
        <button class="btn btn-primary mt-4">${icons.play} Generate</button>
      </div></div>
      <div class="panel"><div class="panel-body">
        <div class="settings-field-label mb-4">Preview (first 10)</div>
        <div class="code-viewer"><pre>sh4d0w
Sh4d0w
shadow2026
pr0t0c0l
Protocol
admin_shadow
Adm1n
ctf2026
CTF2026
sh4d0w_pr0t0c0l</pre></div>
        <div class="text-xs text-muted mt-4">Estimated: ~2,847 entries · 24 KB</div>
      </div></div>
    </div>
  </div>`;
}
