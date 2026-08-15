import { autoTriageFile, type AutoTriageResponse, type AutoTriageStatus } from '../api/autotriage.ts';
import { ApiError } from '../api/client.ts';
import { icons } from '../data.ts';

type AutoTriageView = 'new' | 'queue' | 'actions';

let currentView: AutoTriageView = 'new';
let selectedFile: File | null = null;
let latestResponse: AutoTriageResponse | null = null;
let history: AutoTriageResponse[] = [];
let activeRequest: AbortController | null = null;
let running = false;
let statusMessage = 'Ready';
let statusError = false;

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

function statusBadge(status: AutoTriageStatus): string {
  const badgeClass = status === 'completed'
    ? 'badge-success'
    : status === 'failed'
      ? 'badge-error'
      : status === 'unavailable'
        ? 'badge-warning'
        : 'badge-info';
  return `<span class="badge badge-dot ${badgeClass}">${escapeHtml(status)}</span>`;
}

export function renderAutoTriage(view?: string): void {
  currentView = view === 'queue' || view === 'actions' ? view : 'new';
  renderShell();
}

function renderShell(): void {
  const main = document.getElementById('main');
  if (!main) return;
  const subtitle = latestResponse
    ? `${escapeHtml(latestResponse.original_filename)} · ${escapeHtml(latestResponse.detected_type)} · ${formatBytes(latestResponse.size)}`
    : 'Automatic static classification and analyzer selection';
  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header">
      <div><div class="page-title">Auto Triage</div><div class="page-subtitle">${subtitle}</div></div>
      <div class="page-actions">
        <input id="autotriage-file" type="file" hidden>
        <button class="btn btn-secondary btn-sm" id="autotriage-select">${icons.folder} Choose File</button>
        <button class="btn btn-primary btn-sm" id="autotriage-run" ${selectedFile && !running ? '' : 'disabled'}>${running ? `${icons.loader} Analyzing…` : `${icons.play} Auto Analyze`}</button>
      </div>
    </div>
    <div class="panel mb-4"><div class="panel-body flex items-center gap-4">
      <div style="flex:1">
        <div class="text-sm">${selectedFile ? escapeHtml(selectedFile.name) : 'No file selected'}</div>
        <div class="text-xs text-muted">Maximum 32 MiB. Uploaded artifacts are inspected statically and never executed.</div>
      </div>
      <div class="text-xs ${statusError ? '' : 'text-muted'}" ${statusError ? 'style="color:var(--error)"' : ''}>${escapeHtml(statusMessage)}</div>
    </div></div>
    ${currentView === 'queue' ? renderQueue() : currentView === 'actions' ? renderActions() : renderNewAnalysis()}
  </div>`;
  bindEvents();
}

function routeIsAutoTriage(): boolean {
  const path = window.location.hash.replace(/^#\/?/, '');
  return path === 'autotriage' || path.startsWith('autotriage/');
}

function renderNewAnalysis(): string {
  if (running) return `${renderDropZone()}${renderRunning()}`;
  if (latestResponse) return `${renderDropZone()}${renderResult(latestResponse)}`;
  return `${renderDropZone()}${renderCapabilityPreview()}`;
}

function renderDropZone(): string {
  return `<div class="section"><div class="section-title mb-4">File Input</div>
    <div class="drop-zone" id="autotriage-drop-zone">
      <div class="drop-zone-icon">${icons.upload}</div>
      <div class="drop-zone-text">${selectedFile ? escapeHtml(selectedFile.name) : 'Drop one challenge file here'}</div>
      <div class="drop-zone-hint">Images, archives, PCAP, binaries, documents, text, and unknown blobs</div>
      <div class="drop-zone-hint mt-4" style="color:var(--accent)">or click to browse</div>
    </div>
  </div>`;
}

function renderCapabilityPreview(): string {
  const capabilities = [
    ['File identification', 'Magic bytes, MIME, extension consistency'],
    ['Hashes & entropy', 'MD5, SHA-1, SHA-256, and Shannon entropy'],
    ['Metadata & strings', 'Format metadata plus ASCII and UTF-16 strings'],
    ['Signatures & archives', 'Embedded files, bounded carving, and safe archive inspection'],
    ['Flag candidates', 'File, extracted content, LSB streams, and network streams'],
    ['LSB / bit planes', 'Automatically enabled for detected PNG and JPEG images'],
    ['Network protocols', 'Automatically enabled for PCAP/PCAPNG when TShark is available'],
  ];
  return `<div class="section"><div class="section-header"><div class="section-title">Automatic analyzer plan</div><span class="badge badge-outline">Type-aware</span></div>
    <div class="grid-2">${capabilities.map(([label, detail]) => `<div class="panel"><div class="panel-body"><div class="text-sm">${label}</div><div class="text-xs text-muted mt-4">${detail}</div></div></div>`).join('')}</div>
  </div>`;
}

function renderRunning(): string {
  return `<div class="section"><div class="section-header"><div class="section-title">Analysis Progress</div><span class="badge badge-dot badge-warning">running</span></div>
    <div class="panel"><div class="panel-body"><div class="progress-stages">
      <div class="progress-stage running"><div class="progress-stage-icon"><span class="spin" style="color:var(--accent)">${icons.loader}</span></div><div class="progress-stage-label">Static file triage and analyzer selection</div><div class="progress-stage-meta">working</div></div>
      <div class="progress-stage pending"><div class="progress-stage-icon"><span style="color:var(--text-muted)">${icons.circle}</span></div><div class="progress-stage-label">Applicable specialist analyzer</div><div class="progress-stage-meta">pending</div></div>
    </div></div></div>
  </div>`;
}

function renderResult(result: AutoTriageResponse): string {
  const forensics = result.forensics;
  const suspiciousLsb = result.steganography?.lsb.filter(item => item.suspicious) || [];
  const flags = [
    ...forensics.flags.map(item => ({ ...item, analyzer: 'file' })),
    ...(result.steganography?.flags || []).map(item => ({ ...item, analyzer: 'lsb' })),
    ...(result.network?.flags || []).map(item => ({ ...item, analyzer: 'network' })),
  ];
  return `<div class="section">
    <div class="section-header"><div class="section-title">Triage Result</div><span class="text-xs text-muted">${result.duration_ms} ms · ${escapeHtml(result.analysis_id)}</span></div>
    ${result.warnings.length ? `<div class="panel mb-4"><div class="panel-header" style="color:var(--warning)">Warnings / unavailable tools</div><div class="panel-body text-xs">${result.warnings.map(item => `<div>· ${escapeHtml(item)}</div>`).join('')}</div></div>` : ''}
    <div class="grid-2 mb-4">
      <div class="panel"><div class="panel-header">File</div><div class="panel-body"><div class="kv-list">
        <div class="kv-key">Detected type</div><div class="kv-value mono">${escapeHtml(result.detected_type)}</div>
        <div class="kv-key">MIME</div><div class="kv-value mono">${escapeHtml(result.mime_type)}</div>
        <div class="kv-key">Size</div><div class="kv-value">${formatBytes(result.size)}</div>
        <div class="kv-key">Entropy</div><div class="kv-value mono">${forensics.entropy.bits_per_byte.toFixed(4)} · ${escapeHtml(forensics.entropy.classification)}</div>
        <div class="kv-key">SHA-256</div><div class="kv-value mono" style="word-break:break-all">${forensics.hashes.sha256}</div>
      </div></div></div>
      <div class="panel"><div class="panel-header">Evidence summary</div><div class="panel-body"><div class="kv-list">
        <div class="kv-key">Metadata</div><div class="kv-value">${forensics.metadata.length}</div>
        <div class="kv-key">Strings</div><div class="kv-value">${forensics.strings.length}${forensics.strings_truncated ? ' (limited)' : ''}</div>
        <div class="kv-key">Embedded files</div><div class="kv-value">${forensics.embedded_files.length}</div>
        <div class="kv-key">Archives</div><div class="kv-value">${forensics.archives.length}</div>
        <div class="kv-key">Suspicious LSB streams</div><div class="kv-value">${suspiciousLsb.length}</div>
        <div class="kv-key">Flag candidates</div><div class="kv-value">${flags.length}</div>
      </div></div></div>
    </div>
    ${renderAnalyzerRuns(result)}
    ${renderCapabilities(result)}
    ${renderEvidenceTables(result, flags, suspiciousLsb)}
  </div>`;
}

function renderAnalyzerRuns(result: AutoTriageResponse): string {
  return `<div class="section"><div class="section-title mb-4">Selected analyzers</div><table class="data-table"><thead><tr><th>Analyzer</th><th>Category</th><th>Status</th><th>Duration</th><th>Result</th></tr></thead><tbody>
    ${result.analyzer_runs.map(run => `<tr><td class="mono">${escapeHtml(run.analyzer)}</td><td>${escapeHtml(run.category)}</td><td>${statusBadge(run.status)}</td><td>${run.duration_ms} ms</td><td class="text-muted">${escapeHtml(run.message)}</td></tr>`).join('')}
  </tbody></table></div>`;
}

function renderCapabilities(result: AutoTriageResponse): string {
  return `<div class="section"><div class="section-title mb-4">Triage skills</div><div class="grid-2">
    ${result.capabilities.map(item => `<div class="panel"><div class="panel-body"><div class="flex items-center gap-3"><div class="text-sm" style="flex:1">${escapeHtml(item.label)}</div>${statusBadge(item.status)}</div><div class="text-xs text-muted mt-4">${item.result_count} result${item.result_count === 1 ? '' : 's'} · ${escapeHtml(item.message)}</div></div></div>`).join('')}
  </div></div>`;
}

function renderEvidenceTables(
  result: AutoTriageResponse,
  flags: Array<{ value: string; source: string; offset: number; analyzer: string }>,
  suspiciousLsb: NonNullable<AutoTriageResponse['steganography']>['lsb'],
): string {
  const metadataRows = result.forensics.metadata.slice(0, 30).map(item => `<tr><td>${escapeHtml(item.key)}</td><td class="mono" style="word-break:break-all">${escapeHtml(item.value)}</td></tr>`).join('');
  const stringRows = result.forensics.strings.slice(0, 50).map(item => `<tr><td class="mono">0x${item.offset.toString(16)}</td><td>${escapeHtml(item.encoding)}</td><td class="mono" style="word-break:break-all">${escapeHtml(item.value)}</td></tr>`).join('');
  return `<div class="section"><div class="section-title mb-4">Metadata</div><table class="data-table"><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>${metadataRows || '<tr><td colspan="2" class="text-muted">No format metadata extracted.</td></tr>'}</tbody></table></div>
    <div class="section"><div class="section-title mb-4">Strings (first 50)</div><table class="data-table"><thead><tr><th>Offset</th><th>Encoding</th><th>Value</th></tr></thead><tbody>${stringRows || '<tr><td colspan="3" class="text-muted">No printable strings found.</td></tr>'}</tbody></table></div>
    ${suspiciousLsb.length ? `<div class="section"><div class="section-title mb-4">Suspicious LSB streams</div><table class="data-table"><thead><tr><th>Stream</th><th>Printable</th><th>Entropy</th><th>Preview</th></tr></thead><tbody>${suspiciousLsb.map(item => `<tr><td class="mono">${escapeHtml(item.stream)}</td><td>${(item.printable_ratio * 100).toFixed(1)}%</td><td>${item.entropy.bits_per_byte.toFixed(4)}</td><td class="mono">${escapeHtml(item.preview_ascii)}</td></tr>`).join('')}</tbody></table></div>` : ''}
    ${flags.length ? `<div class="section"><div class="section-title mb-4">Flag candidates</div><table class="data-table"><thead><tr><th>Candidate</th><th>Analyzer</th><th>Source</th><th>Offset</th></tr></thead><tbody>${flags.map(item => `<tr><td class="mono">${escapeHtml(item.value)}</td><td>${escapeHtml(item.analyzer)}</td><td>${escapeHtml(item.source)}</td><td class="mono">0x${item.offset.toString(16)}</td></tr>`).join('')}</tbody></table><div class="text-xs text-muted mt-4">Pattern matches are candidates and are not automatically confirmed.</div></div>` : ''}
    ${result.network ? `<div class="section"><div class="section-title mb-4">Network summary</div><div class="panel"><div class="panel-body"><div class="kv-list"><div class="kv-key">Packets</div><div class="kv-value">${result.network.capture.analyzed_packet_count}</div><div class="kv-key">Hosts</div><div class="kv-value">${result.network.capture.unique_hosts}</div><div class="kv-key">TCP streams</div><div class="kv-value">${result.network.tcp_streams.length}</div><div class="kv-key">Credentials</div><div class="kv-value">${result.network.plaintext_credentials.length}</div><div class="kv-key">Transferred files</div><div class="kv-value">${result.network.transferred_files.length}</div></div></div></div></div>` : ''}`;
}

function renderQueue(): string {
  const runningRow = running && selectedFile ? `<tr><td class="mono">${escapeHtml(selectedFile.name)}</td><td>pending detection</td><td>${formatBytes(selectedFile.size)}</td><td><span class="badge badge-dot badge-warning">running</span></td><td>—</td></tr>` : '';
  const rows = history.map(result => `<tr><td class="mono">${escapeHtml(result.original_filename)}</td><td>${escapeHtml(result.detected_type)}</td><td>${formatBytes(result.size)}</td><td><span class="badge badge-dot badge-success">complete</span></td><td>${result.capabilities.reduce((count, item) => count + item.result_count, 0)}</td></tr>`).join('');
  return `<div class="section"><div class="section-header"><div class="section-title">Session Queue & Progress</div><span class="text-xs text-muted">In-memory for this browser session</span></div><table class="data-table"><thead><tr><th>File</th><th>Type</th><th>Size</th><th>Status</th><th>Results</th></tr></thead><tbody>${runningRow}${rows || (!running ? '<tr><td colspan="5" class="text-muted">No analyses have run in this session.</td></tr>' : '')}</tbody></table></div>`;
}

function renderActions(): string {
  return `<div class="grid-2">
    <div class="section"><div class="section-title mb-4">Run triage</div><div class="panel"><div class="panel-body"><div class="text-sm mb-4">${selectedFile ? escapeHtml(selectedFile.name) : 'Choose a file first.'}</div><button class="btn btn-primary w-full" id="autotriage-action-run" ${selectedFile && !running ? '' : 'disabled'}>${icons.play} Auto Analyze</button></div></div></div>
    <div class="section"><div class="section-title mb-4">Analyzer policy</div><div class="panel"><div class="panel-body"><div class="text-sm">Baseline checks always run. Image and network analyzers are selected from detected magic bytes, never the filename extension.</div><button class="btn btn-secondary w-full mt-4" id="autotriage-settings">${icons.settings} Analyzer Settings</button></div></div></div>
  </div>${latestResponse ? renderAnalyzerRuns(latestResponse) : ''}`;
}

function bindEvents(): void {
  const input = document.getElementById('autotriage-file') as HTMLInputElement | null;
  const select = document.getElementById('autotriage-select');
  const run = document.getElementById('autotriage-run');
  const actionRun = document.getElementById('autotriage-action-run');
  const dropZone = document.getElementById('autotriage-drop-zone');
  const settings = document.getElementById('autotriage-settings');
  select?.addEventListener('click', () => input?.click());
  dropZone?.addEventListener('click', () => input?.click());
  input?.addEventListener('change', () => selectArtifact(input.files?.[0] || null));
  run?.addEventListener('click', () => void runAnalysis());
  actionRun?.addEventListener('click', () => void runAnalysis());
  settings?.addEventListener('click', () => { window.location.hash = 'settings/analyzers'; });
  dropZone?.addEventListener('dragover', event => { event.preventDefault(); dropZone.classList.add('dragover'); });
  dropZone?.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone?.addEventListener('drop', event => {
    event.preventDefault();
    dropZone.classList.remove('dragover');
    selectArtifact(event.dataTransfer?.files[0] || null);
  });
}

function selectArtifact(file: File | null): void {
  if (!file || running) return;
  selectedFile = file;
  latestResponse = null;
  statusMessage = `${file.name} selected`;
  statusError = false;
  renderShell();
}

async function runAnalysis(): Promise<void> {
  if (!selectedFile || running) return;
  const file = selectedFile;
  activeRequest?.abort();
  activeRequest = new AbortController();
  running = true;
  statusMessage = 'Running static triage and applicable specialist analyzers…';
  statusError = false;
  renderShell();
  try {
    const response = await autoTriageFile(file, activeRequest.signal);
    latestResponse = response;
    history = [response, ...history.filter(item => item.analysis_id !== response.analysis_id)].slice(0, 20);
    statusMessage = `Completed ${response.analyzer_runs.filter(item => item.status === 'completed').length} analyzer(s)`;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    statusMessage = error instanceof ApiError && error.code === 'NETWORK_ERROR'
      ? 'Backend unavailable. Start FastAPI on 127.0.0.1:8000.'
      : error instanceof Error ? error.message : 'Auto triage failed.';
    statusError = true;
  } finally {
    running = false;
    if (routeIsAutoTriage()) renderShell();
  }
}
