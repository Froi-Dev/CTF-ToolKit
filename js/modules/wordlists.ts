import { icons } from '../data.ts';

export function renderWordlists(view?: string) {
  const main = document.getElementById('main');
  if (!main) return;
  main.innerHTML = `<div class="main-content">
    <div class="page-header">
      <div><div class="page-title">Wordlists</div><div class="page-subtitle">Manage wordlists for password cracking and brute-force attacks</div></div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm">${icons.upload} Import</button>
        <button class="btn btn-primary btn-sm">${icons.plus} Create Custom</button>
      </div>
    </div>
    ${view === 'generator' ? renderCustomGenerator() : renderWordlistTable()}
  </div>`;
}

function renderWordlistTable() {
  return `<div class="section">
    <div class="section-title mb-4">Available Wordlists</div>
    <table class="data-table">
      <thead><tr><th>Name</th><th>Entries</th><th>Size</th><th>Description</th><th></th></tr></thead>
      <tbody><tr><td colspan="5" class="text-muted">No wordlists have been imported.</td></tr></tbody>
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
          <textarea class="textarea" rows="5" placeholder="Enter one base word per line"></textarea>
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
        <div class="code-viewer"><pre>No preview generated.</pre></div>
        <div class="text-xs text-muted mt-4">Generate a wordlist to calculate its estimated size.</div>
      </div></div>
    </div>
  </div>`;
}

