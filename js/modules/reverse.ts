import { reverseData, icons } from '../data.ts';

let activeTab = 'overview';

export function renderReverse(view?: string) {
  if (view === 'overview' || view === 'sections' || view === 'strings' || view === 'disasm') activeTab = view;
  const main = document.getElementById('main');
  if (!main) return;
  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header">
      <div><div class="page-title">Reverse Engineering</div><div class="page-subtitle">${reverseData.binary.name} — ${reverseData.binary.type}</div></div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm">${icons.download} Decompile</button>
        <button class="btn btn-secondary btn-sm">${icons.terminal} Open in Debugger</button>
      </div>
    </div>
    <div class="tab-bar" id="re-tabs">
      <div class="tab-item ${activeTab==='overview'?'active':''}" data-tab="overview">Overview</div>
      <div class="tab-item ${activeTab==='sections'?'active':''}" data-tab="sections">Sections</div>
      <div class="tab-item ${activeTab==='imports'?'active':''}" data-tab="imports">Imports <span class="tab-count">${reverseData.imports.length}</span></div>
      <div class="tab-item ${activeTab==='exports'?'active':''}" data-tab="exports">Exports <span class="tab-count">${reverseData.exports.length}</span></div>
      <div class="tab-item ${activeTab==='strings'?'active':''}" data-tab="strings">Strings <span class="tab-count">${reverseData.strings.length}</span></div>
      <div class="tab-item ${activeTab==='disasm'?'active':''}" data-tab="disasm">Disassembly</div>
    </div>
    <div id="re-content">${renderRETab(activeTab)}</div>
  </div>`;
  bindREEvents();
}

function renderRETab(tab: string): string {
  switch(tab) {
    case 'overview': return renderOverview();
    case 'sections': return renderSections();
    case 'imports': return renderImports();
    case 'exports': return renderExports();
    case 'strings': return renderStringsTab();
    case 'disasm': return renderDisasm();
    default: return '';
  }
}

function renderOverview() {
  const b = reverseData.binary;
  return `<div class="re-info-grid">
    <div>
      <div class="section-title mb-4">Binary Information</div>
      <div class="panel"><div class="panel-body">
        <div class="kv-list">
          <div class="kv-key">File</div><div class="kv-value mono">${b.name}</div>
          <div class="kv-key">Type</div><div class="kv-value mono">${b.type}</div>
          <div class="kv-key">Architecture</div><div class="kv-value mono">${b.arch}</div>
          <div class="kv-key">Compiler</div><div class="kv-value mono">${b.compiler}</div>
          <div class="kv-key">Stripped</div><div class="kv-value">${b.stripped ? 'Yes' : 'No'}</div>
          <div class="kv-key">Size</div><div class="kv-value mono">${b.size}</div>
        </div>
      </div></div>
    </div>
    <div>
      <div class="section-title mb-4">Security Properties</div>
      <div class="panel"><div class="panel-body">
        <div class="re-protections">
          ${reverseData.protections.map(p => `
            <div class="re-protection-label">${p.name}</div>
            <div class="re-protection-value ${p.status}">${p.value}</div>
          `).join('')}
        </div>
      </div></div>
    </div>
  </div>
  ${renderDisasm()}`;
}

function renderSections() {
  const rows = reverseData.sections.map(s => `<tr>
    <td class="mono font-medium" style="font-size:var(--text-xs)">${s.name}</td>
    <td class="mono text-muted" style="font-size:var(--text-xs)">${s.vaddr}</td>
    <td class="mono text-muted" style="font-size:var(--text-xs)">${s.size}</td>
    <td class="mono" style="font-size:var(--text-xs)">${s.perms}</td>
  </tr>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">Sections</div>
    <table class="data-table">
      <thead><tr><th>Name</th><th>Virtual Address</th><th>Size</th><th>Permissions</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderImports() {
  const rows = reverseData.imports.map(i => `<tr>
    <td class="mono" style="font-size:var(--text-xs)">${i}</td>
    <td class="text-muted">libc</td>
  </tr>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">Imported Functions</div>
    <table class="data-table">
      <thead><tr><th>Function</th><th>Library</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderExports() {
  const rows = reverseData.exports.map(e => `<tr>
    <td class="mono font-medium" style="font-size:var(--text-xs)">${e}</td>
    <td class="text-muted">Function</td>
  </tr>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">Exported Symbols</div>
    <table class="data-table">
      <thead><tr><th>Symbol</th><th>Type</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderStringsTab() {
  const rows = reverseData.strings.map(s => `<tr class="clickable">
    <td class="mono text-muted" style="font-size:var(--text-xs)">${s.offset}</td>
    <td class="mono" style="font-size:var(--text-xs)">${s.value}</td>
  </tr>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">Interesting Strings</div>
    <table class="data-table">
      <thead><tr><th>Offset</th><th>Value</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderDisasm() {
  const lines = reverseData.disassembly.map(d => {
    let instr = d.instr;
    // Syntax highlighting
    instr = instr.replace(/^(\w+)/, '<span class="keyword">$1</span>');
    instr = instr.replace(/\b(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|eax|ebx|ecx|edx|esi|edi|r\d+)\b/g, '<span class="register">$1</span>');
    instr = instr.replace(/\b(0x[0-9a-fA-F]+)\b/g, '<span class="number">$1</span>');
    instr = instr.replace(/(;.*)$/, '<span class="comment">$1</span>');
    return `<div class="disasm-line">
      <span class="disasm-addr">${d.addr}</span>
      <span class="disasm-bytes">${d.bytes}</span>
      <span class="disasm-instr">${instr}</span>
    </div>`;
  }).join('');

  return `<div class="section">
    <div class="section-header">
      <div class="section-title">Disassembly — main()</div>
      <div class="flex gap-3">
        <button class="btn btn-sm btn-ghost">${icons.search} Search</button>
        <button class="btn btn-sm btn-ghost">${icons.copy} Copy</button>
      </div>
    </div>
    <div class="disasm-viewer">${lines}</div>
  </div>`;
}

function bindREEvents() {
  document.querySelectorAll<HTMLElement>('#re-tabs .tab-item').forEach(tab => {
    tab.addEventListener('click', () => {
      activeTab = tab.dataset.tab ?? 'overview';
      renderReverse();
    });
  });
}


