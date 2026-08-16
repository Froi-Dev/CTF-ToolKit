import { ApiError } from '../api/client.ts';
import { analyzeReverseArtifact, type ReverseAnalysisResponse, type ReverseSeverity } from '../api/reversing.ts';
import { icons, severityClass } from '../data.ts';

type ReverseTab = 'overview' | 'findings' | 'strings' | 'functions' | 'disassembly' | 'validation' | 'data' | 'flags' | 'dynamic';

let activeTab: ReverseTab = 'overview';
let selectedFile: File | null = null;
let latestResponse: ReverseAnalysisResponse | null = null;
let activeRequest: AbortController | null = null;
let customFlagPrefix = '';
let analyzing = false;
let statusMessage = 'Ready — static analysis only; the artifact will not be executed.';
let statusIsError = false;

function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>'"]/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character] || character);
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 ** 2).toFixed(1)} MiB`;
}

function hex(value: number | null): string {
  return value === null ? 'Unavailable' : `0x${value.toString(16)}`;
}

function displayBool(value: boolean | null): string {
  return value === null ? 'Unknown' : value ? 'Yes' : 'No';
}

function mapRouteView(view?: string): ReverseTab {
  if (view === 'sections') return 'data';
  if (view === 'disasm') return 'disassembly';
  if (view === 'strings') return 'strings';
  return 'overview';
}

export function renderReverse(view?: string): void {
  if (view) activeTab = mapRouteView(view);
  renderShell();
}

function renderShell(): void {
  const main = document.getElementById('main');
  if (!main) return;
  const result = latestResponse;
  const subtitle = result
    ? `${escapeHtml(result.file.name)} — ${escapeHtml(result.file.detected_type)} — ${formatBytes(result.file.size)}`
    : 'Evidence-backed static analysis for executables, bytecode, scripts, and challenge binaries';
  main.innerHTML = `<div class="main-content-wide" id="reverse-page">
    <div class="page-header">
      <div><div class="page-title">Reverse Engineering</div><div class="page-subtitle">${subtitle}</div></div>
      <div class="page-actions">
        <input id="reverse-file" type="file" hidden>
        <button class="btn btn-secondary btn-sm" id="reverse-select">${icons.folder} Choose Artifact</button>
        <button class="btn btn-primary btn-sm" id="reverse-run" ${selectedFile && !analyzing ? '' : 'disabled'}>${analyzing ? `${icons.loader} Analyzing...` : `${icons.play} Analyze`}</button>
        ${result ? `<button class="btn btn-secondary btn-sm" id="reverse-export">${icons.download} Export JSON</button>` : ''}
      </div>
    </div>
    ${renderSelectionPanel()}
    ${result ? renderTabs(result) : renderEmptyState()}
  </div>`;
  bindEvents();
}

function renderSelectionPanel(): string {
  return `<div class="panel mb-4 reverse-config"><div class="panel-body flex items-center gap-4" style="flex-wrap:wrap">
    <div style="flex:1;min-width:260px">
      <div class="text-sm">${selectedFile ? escapeHtml(selectedFile.name) : 'No artifact selected'}</div>
      <div class="text-xs text-muted">64 MiB limit / hostile content is stored temporarily and inspected without execution.</div>
    </div>
    <label class="text-xs reverse-prefix">Flag prefix
      <input id="reverse-prefix" class="input input-sm" maxlength="32" value="${escapeHtml(customFlagPrefix)}" placeholder="optional">
    </label>
    <div class="text-xs ${statusIsError ? 'reverse-status-error' : 'text-muted'}" id="reverse-status">${escapeHtml(statusMessage)}</div>
  </div></div>`;
}

function renderEmptyState(): string {
  return `<div class="panel"><div class="panel-body empty-state">
    ${icons.reverse}<div class="empty-state-text">Choose an artifact to identify its format, protections, notable strings, imports, validation leads, flag candidates, and shortest evidence-backed solving path.</div>
  </div></div>`;
}

function renderTabs(result: ReverseAnalysisResponse): string {
  const tabs: Array<[ReverseTab, string, number | null]> = [
    ['overview', 'Overview', null], ['findings', 'Notable Findings', result.findings.length],
    ['strings', 'Strings', result.strings.length], ['functions', 'Functions', result.functions.length],
    ['disassembly', 'Disassembly', result.disassembly.length], ['validation', 'Validation', result.validation_leads.length],
    ['data', 'Data / Constants', result.sections.length], ['flags', 'Flag Analysis', result.flags.length],
    ['dynamic', 'Dynamic Analysis', result.dynamic_recommendations.length],
  ];
  return `<div class="tab-bar reverse-tabs" id="reverse-tabs">${tabs.map(([id, label, count]) => `
    <button class="tab-item ${activeTab === id ? 'active' : ''}" data-reverse-tab="${id}">${label}${count === null ? '' : ` <span class="tab-count">${count}</span>`}</button>`).join('')}
  </div><div id="reverse-content">${renderTab(result)}</div>`;
}

function renderTab(result: ReverseAnalysisResponse): string {
  switch (activeTab) {
    case 'findings': return renderFindings(result);
    case 'strings': return renderStrings(result);
    case 'functions': return renderFunctions(result);
    case 'disassembly': return renderDisassembly(result);
    case 'validation': return renderValidation(result);
    case 'data': return renderData(result);
    case 'flags': return renderFlags(result);
    case 'dynamic': return renderDynamic(result);
    default: return renderOverview(result);
  }
}

function renderOverview(result: ReverseAnalysisResponse): string {
  const file = result.file;
  return `<div class="section">
    <div class="panel mb-4"><div class="panel-header">Reverse Engineering Assessment</div><div class="panel-body">
      <div class="text-sm">${escapeHtml(result.summary)}</div>
      ${result.warnings.map(warning => `<div class="reverse-warning text-xs mt-4">${escapeHtml(warning)}</div>`).join('')}
    </div></div>
    <div class="re-info-grid mb-4">
      <div class="panel"><div class="panel-header">File Information</div><div class="panel-body"><div class="kv-list">
        <div class="kv-key">File</div><div class="kv-value mono">${escapeHtml(file.name)}</div>
        <div class="kv-key">Type</div><div class="kv-value">${escapeHtml(file.detected_type)}</div>
        <div class="kv-key">Architecture</div><div class="kv-value mono">${escapeHtml(file.architecture || 'Unknown')} ${file.bits ? `/ ${file.bits}-bit` : ''}</div>
        <div class="kv-key">Endian / OS</div><div class="kv-value">${escapeHtml(file.endian || 'Unknown')} / ${escapeHtml(file.operating_system || 'Unknown')}</div>
        <div class="kv-key">Entry point</div><div class="kv-value mono">${hex(file.entry_point)}</div>
        <div class="kv-key">Stripped / Packed</div><div class="kv-value">${displayBool(file.stripped)} / ${displayBool(file.packed)}</div>
        <div class="kv-key">Extension</div><div class="kv-value"><span class="badge ${file.extension_matches ? 'badge-success' : 'badge-error'}">${file.extension_matches ? 'Consistent' : 'Mismatch'}</span></div>
        <div class="kv-key">SHA-256</div><div class="kv-value mono reverse-hash">${file.hashes.sha256}</div>
      </div></div></div>
      <div class="panel"><div class="panel-header">Security Protections</div><div class="panel-body">
        ${result.protections.length ? `<div class="re-protections">${result.protections.map(protection => `
          <div class="re-protection-label" title="${escapeHtml(protection.significance)}">${escapeHtml(protection.name)}</div>
          <div class="re-protection-value ${protection.status}">${escapeHtml(protection.value)}</div>`).join('')}</div>` : '<div class="text-sm text-muted">Protection parsing is unavailable for this format.</div>'}
      </div></div>
    </div>
    ${renderFlagCards(result)}
    <div class="section-title mb-4">Top Findings</div>
    ${result.findings.length ? result.findings.slice(0, 4).map(renderFinding).join('') : emptyPanel('No notable finding crossed the reporting threshold.')}
    <div class="section-title mt-4 mb-4">Shortest CTF Solving Path</div>
    <div class="panel"><div class="panel-body"><ol class="reverse-path">${result.solving_path.map(step => `<li>${escapeHtml(step)}</li>`).join('')}</ol></div></div>
  </div>`;
}

function renderFinding(finding: ReverseAnalysisResponse['findings'][number]): string {
  return `<details class="panel mb-4 reverse-finding reverse-severity-${finding.severity}" open>
    <summary class="panel-header"><span class="badge badge-dot ${severityClass(finding.severity)}">${finding.severity.toUpperCase()}</span><span>${escapeHtml(finding.title)}</span><span class="mono text-muted">${Math.round(finding.confidence * 100)}%</span></summary>
    <div class="panel-body"><div class="kv-list">
      <div class="kv-key">Evidence</div><div class="kv-value">${escapeHtml(finding.evidence)}</div>
      <div class="kv-key">Why it matters</div><div class="kv-value">${escapeHtml(finding.why_it_matters)}</div>
      <div class="kv-key">Next step</div><div class="kv-value">${escapeHtml(finding.recommendation)}</div>
      <div class="kv-key">Location</div><div class="kv-value mono">${escapeHtml(finding.location || 'Not localized')}</div>
    </div></div>
  </details>`;
}

function renderFindings(result: ReverseAnalysisResponse): string {
  return `<div class="section"><div class="section-title mb-4">Notable Findings</div>${result.findings.length ? result.findings.map(renderFinding).join('') : emptyPanel('No notable finding crossed the reporting threshold.')}</div>`;
}

function renderStrings(result: ReverseAnalysisResponse): string {
  const rows = result.strings.map(item => `<tr>
    <td><span class="badge badge-dot ${severityClass(item.importance)}">${item.importance.toUpperCase()}</span></td>
    <td class="mono text-muted">${hex(item.offset)}</td><td>${escapeHtml(item.category)}</td>
    <td class="mono reverse-wrap">${escapeHtml(item.value)}</td><td class="text-muted">${escapeHtml(item.reason)}</td>
  </tr>`).join('');
  return `<div class="section"><div class="section-header"><div class="section-title">Prioritized Strings</div><div class="text-xs text-muted">${result.strings_truncated ? 'Bounded result — additional strings were omitted.' : 'ASCII and Unicode'}</div></div>
    ${rows ? `<div class="reverse-table-wrap"><table class="data-table"><thead><tr><th>Priority</th><th>Offset</th><th>Category</th><th>Value</th><th>Reason</th></tr></thead><tbody>${rows}</tbody></table></div>` : emptyPanel('No printable strings met the minimum length.')}
  </div>`;
}

function renderFunctions(result: ReverseAnalysisResponse): string {
  const imports = result.imports.map(item => `<tr><td><span class="badge badge-dot ${severityClass(item.importance)}">${item.importance.toUpperCase()}</span></td><td class="mono">${escapeHtml(item.name)}</td><td>${escapeHtml(item.library || 'Unknown')}</td><td>${escapeHtml(item.category)}</td><td class="text-muted">${escapeHtml(item.reason)}</td></tr>`).join('');
  const functions = result.functions.map(item => `<div class="panel mb-4"><div class="panel-header"><span class="mono">${escapeHtml(item.name)}</span><span class="mono text-muted">${item.address === null ? 'address unavailable' : hex(item.address)} / ${Math.round(item.confidence * 100)}%</span></div><div class="panel-body"><div class="text-sm">${escapeHtml(item.likely_role)}</div><div class="text-xs text-muted mt-4">${item.evidence.map(escapeHtml).join(' ')}</div></div></div>`).join('');
  return `<div class="section"><div class="section-title mb-4">Important Functions</div>${functions || emptyPanel('No function symbols or disassembler labels were recovered.')}
    <div class="section-title mt-4 mb-4">Notable Imports</div>${imports ? `<div class="reverse-table-wrap"><table class="data-table"><thead><tr><th>Priority</th><th>Function</th><th>Library</th><th>Purpose</th><th>Importance</th></tr></thead><tbody>${imports}</tbody></table></div>` : emptyPanel('No imports were recovered from this format.')}
  </div>`;
}

function renderDisassembly(result: ReverseAnalysisResponse): string {
  if (!result.disassembly.length) return `<div class="section"><div class="section-title mb-4">Focused Disassembly</div>${emptyPanel(result.tools.objdump ? 'The disassembler could not produce instructions for this artifact.' : 'objdump is unavailable. Install it or set CTFKIT_OBJDUMP_PATH to enable bounded static disassembly.')}</div>`;
  const lines = result.disassembly.map(line => `<div class="disasm-line"><span class="disasm-addr">${hex(line.address)}</span><span class="disasm-bytes">${escapeHtml(line.bytes)}</span><span class="disasm-instr">${escapeHtml(line.instruction)}</span></div>`).join('');
  return `<div class="section"><div class="section-header"><div class="section-title">Focused Disassembly</div><div class="text-xs text-muted">Bounded to ${result.limits.max_disassembly_lines} lines</div></div><div class="disasm-viewer">${lines}</div></div>`;
}

function renderValidation(result: ReverseAnalysisResponse): string {
  const leads = result.validation_leads.map(lead => `<div class="panel mb-4"><div class="panel-header"><span>${escapeHtml(lead.kind)}</span><span class="mono text-muted">${Math.round(lead.confidence * 100)}%</span></div><div class="panel-body"><div class="kv-list"><div class="kv-key">Evidence</div><div class="kv-value">${escapeHtml(lead.evidence)}</div><div class="kv-key">Interpretation</div><div class="kv-value">${escapeHtml(lead.interpretation)}</div><div class="kv-key">Next step</div><div class="kv-value">${escapeHtml(lead.next_step)}</div></div></div></div>`).join('');
  return `<div class="section"><div class="section-title mb-4">Validation Logic</div>${leads || emptyPanel('Validation logic was not recovered. The report does not infer a password or transformation without evidence.')}
    <div class="section-title mt-4 mb-4">Observed Transformation Leads</div>${result.transformations.length ? `<div class="panel"><div class="panel-body">${result.transformations.map(item => `<span class="badge badge-info mr-2">${escapeHtml(item)}</span>`).join('')}</div></div>` : emptyPanel('No supported transformation was evidenced by imports or strings.')}
  </div>`;
}

function renderData(result: ReverseAnalysisResponse): string {
  const rows = result.sections.map(section => `<tr class="${section.suspicious ? 'reverse-suspicious-row' : ''}"><td class="mono">${escapeHtml(section.name)}</td><td class="mono">${hex(section.virtual_address)}</td><td class="mono">${hex(section.file_offset)}</td><td>${formatBytes(section.size)}</td><td class="mono">${escapeHtml(section.permissions)}</td><td class="mono">${section.entropy.toFixed(3)}</td><td>${escapeHtml(section.reason || '')}</td></tr>`).join('');
  return `<div class="section"><div class="section-title mb-4">Sections and Constants</div>${rows ? `<div class="reverse-table-wrap"><table class="data-table"><thead><tr><th>Section</th><th>Address</th><th>File offset</th><th>Size</th><th>Perms</th><th>Entropy</th><th>Assessment</th></tr></thead><tbody>${rows}</tbody></table></div>` : emptyPanel('Detailed section parsing is unavailable for this artifact format.')}</div>`;
}

function renderFlagCards(result: ReverseAnalysisResponse): string {
  if (!result.flags.length) return '';
  return `<div class="section-title mb-4">Flag Candidates</div>${result.flags.map(flag => `<div class="panel mb-4 reverse-flag"><div class="panel-header"><span class="badge badge-success">CANDIDATE — NOT CONFIRMED</span><span class="mono">${Math.round(flag.confidence * 100)}%</span></div><div class="panel-body"><div class="reverse-flag-value">${escapeHtml(flag.value)}</div><div class="text-xs text-muted mt-4">${escapeHtml(flag.source)} + ${hex(flag.offset)} / ${escapeHtml(flag.matched_pattern)}</div></div></div>`).join('')}`;
}

function renderFlags(result: ReverseAnalysisResponse): string {
  const locations = result.likely_flag_locations.map((location, index) => `<div class="panel mb-4"><div class="panel-header">${index + 1}. Likely location</div><div class="panel-body text-sm">${escapeHtml(location)}</div></div>`).join('');
  return `<div class="section">${renderFlagCards(result)}<div class="section-title ${result.flags.length ? 'mt-4 ' : ''}mb-4">Likely Flag Locations</div>${locations || emptyPanel('No evidence-backed flag location was ranked. Continue from validation and success-path leads.')}
    <div class="panel mt-4"><div class="panel-body text-xs text-muted">Regex matches remain candidates until reviewed or corroborated. The analyzer never marks a flag confirmed automatically.</div></div>
  </div>`;
}

function renderDynamic(result: ReverseAnalysisResponse): string {
  const cards = result.dynamic_recommendations.map(item => `<div class="panel mb-4"><div class="panel-header"><span class="mono">${escapeHtml(item.breakpoint)}</span></div><div class="panel-body"><div class="kv-list"><div class="kv-key">Why</div><div class="kv-value">${escapeHtml(item.why)}</div><div class="kv-key">Inspect</div><div class="kv-value">${escapeHtml(item.inspect)}</div><div class="kv-key">Command</div><div class="kv-value mono">${escapeHtml(item.command || 'Tool-specific')}</div></div></div></div>`).join('');
  return `<div class="section"><div class="section-title mb-4">Dynamic Analysis Recommendations</div>${cards || emptyPanel('No artifact-specific breakpoint was derived from the available evidence.')}<div class="panel mt-4"><div class="panel-body text-xs text-muted">Run dynamic analysis only inside an isolated, authorized CTF or training environment. This module does not execute uploads.</div></div></div>`;
}

function emptyPanel(message: string): string {
  return `<div class="panel"><div class="panel-body text-sm text-muted">${escapeHtml(message)}</div></div>`;
}

function bindEvents(): void {
  const picker = document.getElementById('reverse-file') as HTMLInputElement | null;
  document.getElementById('reverse-select')?.addEventListener('click', () => picker?.click());
  picker?.addEventListener('change', () => {
    selectedFile = picker.files?.[0] || null;
    statusMessage = selectedFile ? `${selectedFile.name} selected.` : 'No artifact selected.';
    statusIsError = false;
    renderShell();
  });
  document.getElementById('reverse-prefix')?.addEventListener('input', event => {
    customFlagPrefix = (event.target as HTMLInputElement).value;
  });
  document.getElementById('reverse-run')?.addEventListener('click', runAnalysis);
  document.getElementById('reverse-export')?.addEventListener('click', exportReport);
  document.querySelectorAll<HTMLElement>('[data-reverse-tab]').forEach(tab => tab.addEventListener('click', () => {
    activeTab = (tab.dataset.reverseTab || 'overview') as ReverseTab;
    renderShell();
  }));
}

async function runAnalysis(): Promise<void> {
  if (!selectedFile || analyzing) return;
  activeRequest?.abort();
  activeRequest = new AbortController();
  analyzing = true;
  statusIsError = false;
  statusMessage = 'Inspecting headers, sections, protections, strings, imports, and validation leads...';
  renderShell();
  try {
    latestResponse = await analyzeReverseArtifact(selectedFile, { customFlagPrefix, signal: activeRequest.signal });
    statusMessage = `Analysis complete — ${latestResponse.findings.length} finding(s), ${latestResponse.flags.length} flag candidate(s).`;
    activeTab = 'overview';
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    statusIsError = true;
    statusMessage = error instanceof ApiError ? `${error.code}: ${error.message}` : error instanceof Error ? error.message : 'Analysis failed.';
  } finally {
    analyzing = false;
    activeRequest = null;
    renderShell();
  }
}

function exportReport(): void {
  if (!latestResponse) return;
  const blob = new Blob([JSON.stringify(latestResponse, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${latestResponse.file.name.replace(/[^a-z0-9._-]/gi, '_')}.reverse-report.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}
