import { ApiError } from '../api/client.ts';
import {
  triageForensicsFile,
  type ForensicsTriageResponse,
} from '../api/forensics.ts';
import { icons } from '../data.ts';

type TriageTab = 'overview' | 'metadata' | 'strings' | 'archives' | 'extracted' | 'flags';

let activeTab: TriageTab = 'overview';
let selectedFile: File | null = null;
let latestResponse: ForensicsTriageResponse | null = null;
let activeRequest: AbortController | null = null;

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

function badge(ok: boolean, yes: string, no: string): string {
  return `<span class="badge ${ok ? 'badge-success' : 'badge-error'}">${ok ? yes : no}</span>`;
}

export function renderForensics(view?: string): void {
  activeRequest?.abort();
  activeRequest = null;
  selectedFile = null;
  latestResponse = null;
  activeTab = 'overview';
  if (view === 'disk-partition') {
    renderUnavailableWorkspace(
      'Disk / Partition Forensics',
      'Inspect partition tables, filesystems, deleted entries, and disk-image timelines.',
      ['Partition discovery', 'Filesystem browsing', 'Deleted-file recovery', 'Filesystem timeline'],
      'This workspace is not implemented yet. It will require an isolated Sleuth Kit integration before disk images can be analyzed safely.',
    );
    return;
  }
  renderShell();
}

function renderUnavailableWorkspace(title: string, subtitle: string, capabilities: string[], note: string): void {
  const main = document.getElementById('main');
  if (!main) return;
  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header">
      <div><div class="page-title">${title}</div><div class="page-subtitle">${subtitle}</div></div>
      <span class="badge badge-outline">Not implemented</span>
    </div>
    <div class="grid-2">
      ${capabilities.map(capability => `<div class="panel"><div class="panel-body">
        <div class="section-title mb-4">${capability}</div>
        <div class="text-sm text-muted">Analyzer unavailable</div>
      </div></div>`).join('')}
    </div>
    <div class="panel mt-8"><div class="panel-body text-sm text-muted">${note}</div></div>
  </div>`;
}

function renderShell(): void {
  const main = document.getElementById('main');
  if (!main) return;
  const result = latestResponse;
  const subtitle = result
    ? `${escapeHtml(result.original_filename)} · ${escapeHtml(result.magic.description)} · ${formatBytes(result.size)}`
    : 'Static file identification, archive inspection, extraction, and flag discovery';
  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header">
      <div><div class="page-title">File / Forensics Triage</div><div class="page-subtitle">${subtitle}</div></div>
      <div class="page-actions">
        <input id="forensics-file" type="file" hidden>
        <button class="btn btn-secondary btn-sm" id="forensics-select">${icons.folder} Choose File</button>
        <button class="btn btn-primary btn-sm" id="forensics-run" ${selectedFile ? '' : 'disabled'}>${icons.play} Analyze</button>
      </div>
    </div>
    <div class="panel mb-4">
      <div class="panel-body flex items-center gap-4">
        <div style="flex:1">
          <div class="text-sm" id="forensics-selection">${selectedFile ? escapeHtml(selectedFile.name) : 'No file selected'}</div>
          <div class="text-xs text-muted">Uploads are limited to 32 MiB. Files are inspected statically and never executed.</div>
        </div>
        <div class="text-xs text-muted" id="forensics-status">${result ? `Analysis ${escapeHtml(result.analysis_id)}` : 'Ready'}</div>
      </div>
    </div>
    ${result ? renderTabs(result) : renderEmptyState()}
  </div>`;
  bindEvents();
}

function renderEmptyState(): string {
  return `<div class="section"><div class="panel"><div class="panel-body">
    <div class="section-title mb-4">No triage result</div>
    <div class="text-sm text-muted">Choose a file to identify its content, calculate hashes and entropy, extract strings and flag candidates, discover archives, and safely inspect embedded artifacts.</div>
  </div></div></div>`;
}

function renderTabs(result: ForensicsTriageResponse): string {
  const tabs: Array<[TriageTab, string, number | null]> = [
    ['overview', 'Overview', null],
    ['metadata', 'Metadata', result.metadata.length],
    ['strings', 'Strings', result.strings.length],
    ['archives', 'Archives', result.archives.reduce((count, archive) => count + archive.member_count, 0)],
    ['extracted', 'Extracted', result.extracted_artifacts.length],
    ['flags', 'Flag Candidates', result.flags.length],
  ];
  return `<div class="tab-bar" id="forensics-tabs">${tabs.map(([id, label, count]) => `
    <div class="tab-item ${activeTab === id ? 'active' : ''}" data-tab="${id}">${label}${count === null ? '' : ` <span class="tab-count">${count}</span>`}</div>`).join('')}
  </div><div id="forensics-content">${renderTab(result)}</div>`;
}

function renderTab(result: ForensicsTriageResponse): string {
  switch (activeTab) {
    case 'metadata': return renderMetadata(result);
    case 'strings': return renderStrings(result);
    case 'archives': return renderArchives(result);
    case 'extracted': return renderExtracted(result);
    case 'flags': return renderFlags(result);
    default: return renderOverview(result);
  }
}

function renderOverview(result: ForensicsTriageResponse): string {
  const warningHtml = result.warnings.length
    ? `<div class="panel mb-4"><div class="panel-header" style="color:var(--warning)">Warnings</div><div class="panel-body text-xs">${result.warnings.map(item => `<div>· ${escapeHtml(item)}</div>`).join('')}</div></div>`
    : '';
  return `<div class="forensics-layout">
    <div>
      <div class="section">
        <div class="section-title mb-4">Identification</div>
        <div class="panel"><div class="panel-body"><div class="kv-list">
          <div class="kv-key">Magic type</div><div class="kv-value mono">${escapeHtml(result.magic.detected_type)}</div>
          <div class="kv-key">MIME</div><div class="kv-value mono">${escapeHtml(result.magic.mime_type)}</div>
          <div class="kv-key">Confidence</div><div class="kv-value mono">${Math.round(result.magic.confidence * 100)}%</div>
          <div class="kv-key">Extension</div><div class="kv-value">${badge(!result.extension.mismatch, 'Consistent', 'Mismatch')} ${escapeHtml(result.extension.reason)}</div>
          <div class="kv-key">Entropy</div><div class="kv-value mono">${result.entropy.bits_per_byte.toFixed(4)} bits/byte · ${escapeHtml(result.entropy.classification)}</div>
          <div class="kv-key">Signatures</div><div class="kv-value mono">${result.signatures.length} (${result.embedded_files.length} embedded)</div>
        </div></div></div>
      </div>
      ${warningHtml}
    </div>
    <div>
      <div class="section">
        <div class="section-title mb-4">Cryptographic Hashes</div>
        <div class="panel"><div class="panel-body"><div class="kv-list">
          <div class="kv-key">MD5</div><div class="kv-value mono" style="word-break:break-all">${result.hashes.md5}</div>
          <div class="kv-key">SHA-1</div><div class="kv-value mono" style="word-break:break-all">${result.hashes.sha1}</div>
          <div class="kv-key">SHA-256</div><div class="kv-value mono" style="word-break:break-all">${result.hashes.sha256}</div>
        </div></div></div>
      </div>
      <div class="section">
        <div class="section-title mb-4">Embedded Signatures</div>
        ${result.embedded_files.length ? `<div class="panel"><div class="panel-body">${result.embedded_files.map(item => `<div class="text-xs mb-4"><span class="mono">0x${item.offset.toString(16)}</span> · ${escapeHtml(item.detected_type)} · ${item.estimated_size === null ? 'size unknown' : formatBytes(item.estimated_size)} · ${item.extracted_artifact_id ? 'carved' : 'detected only'}</div>`).join('')}</div></div>` : '<div class="text-xs text-muted">No embedded file signature was found.</div>'}
      </div>
    </div>
  </div>`;
}

function renderMetadata(result: ForensicsTriageResponse): string {
  return `<div class="section"><div class="section-title mb-4">Content Metadata</div><div class="panel"><div class="panel-body"><div class="kv-list">${result.metadata.map(item => `
    <div class="kv-key">${escapeHtml(item.key)}</div><div class="kv-value mono">${escapeHtml(item.value)}</div>`).join('')}
  </div></div></div></div>`;
}

function renderStrings(result: ForensicsTriageResponse): string {
  if (!result.strings.length) return '<div class="section"><div class="text-sm text-muted">No printable strings met the four-character minimum.</div></div>';
  return `<div class="section"><div class="section-header"><div class="section-title">Printable Strings</div><span class="text-xs text-muted">${result.strings_truncated ? 'Result limit reached' : `${result.strings.length} results`}</span></div>
    <table class="data-table"><thead><tr><th>Offset</th><th>Encoding</th><th>Value</th></tr></thead><tbody>${result.strings.map(item => `<tr>
      <td class="mono text-muted">0x${item.offset.toString(16)}</td><td>${escapeHtml(item.encoding)}</td><td class="mono" style="word-break:break-all">${escapeHtml(item.value)}</td>
    </tr>`).join('')}</tbody></table></div>`;
}

function renderArchives(result: ForensicsTriageResponse): string {
  if (!result.archives.length) return '<div class="section"><div class="text-sm text-muted">The uploaded file is not a supported ZIP, TAR, or Gzip archive.</div></div>';
  return result.archives.map(archive => `<div class="section">
    <div class="section-header"><div class="section-title">${escapeHtml(archive.format.toUpperCase())} · ${archive.member_count} members</div><span class="text-xs text-muted">${formatBytes(archive.total_uncompressed_size)} expanded</span></div>
    <table class="data-table"><thead><tr><th>Member</th><th>Kind</th><th>Size</th><th>Extraction</th></tr></thead><tbody>${archive.members.map(member => `<tr>
      <td class="mono" style="word-break:break-all">${escapeHtml(member.path)}</td><td>${escapeHtml(member.kind)}</td><td>${formatBytes(member.size)}</td>
      <td>${member.extractable ? badge(true, member.kind === 'file' ? 'Extracted' : 'Safe', '') : `<span class="badge badge-error">Skipped</span> <span class="text-xs text-muted">${escapeHtml(member.skipped_reason || '')}</span>`}</td>
    </tr>`).join('')}</tbody></table></div>`).join('');
}

function renderExtracted(result: ForensicsTriageResponse): string {
  if (!result.extracted_artifacts.length) return '<div class="section"><div class="text-sm text-muted">No archive member or embedded file was safely extracted.</div></div>';
  return `<div class="section"><div class="section-header"><div class="section-title">Extracted Artifact Provenance</div><span class="text-xs text-muted">Temporary analysis copies are not retained</span></div>
    <table class="data-table"><thead><tr><th>Source</th><th>Method</th><th>Detected</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>${result.extracted_artifacts.map(item => `<tr>
      <td class="mono">${escapeHtml(item.source_path)}</td><td>${escapeHtml(item.extraction_method)}</td><td>${escapeHtml(item.detected_type)}</td><td>${formatBytes(item.size)}</td><td class="mono" style="font-size:var(--text-xs);word-break:break-all">${item.hashes.sha256}</td>
    </tr>`).join('')}</tbody></table></div>`;
}

function renderFlags(result: ForensicsTriageResponse): string {
  if (!result.flags.length) return '<div class="section"><div class="text-sm text-muted">No configured flag pattern matched the file or safely extracted members.</div></div>';
  return `<div class="section"><div class="section-title mb-4">Review Required</div>${result.flags.map(flag => `<div class="panel mb-4">
    <div class="panel-header" style="color:var(--success)">${icons.flag} Candidate · ${Math.round(flag.confidence * 100)}%</div>
    <div class="panel-body"><div class="mono" style="word-break:break-all">${escapeHtml(flag.value)}</div><div class="text-xs text-muted mt-4">${escapeHtml(flag.source)} · byte offset 0x${flag.offset.toString(16)} · not automatically confirmed</div><div class="text-xs mono mt-4">${escapeHtml(flag.context)}</div></div>
  </div>`).join('')}</div>`;
}

function bindEvents(): void {
  const input = document.getElementById('forensics-file') as HTMLInputElement | null;
  const select = document.getElementById('forensics-select') as HTMLButtonElement | null;
  const run = document.getElementById('forensics-run') as HTMLButtonElement | null;
  select?.addEventListener('click', () => input?.click());
  input?.addEventListener('change', () => {
    selectedFile = input.files?.[0] || null;
    latestResponse = null;
    activeTab = 'overview';
    renderShell();
  });
  run?.addEventListener('click', () => void runTriage());
  document.querySelectorAll<HTMLElement>('#forensics-tabs .tab-item').forEach(tab => {
    tab.addEventListener('click', () => {
      activeTab = (tab.dataset.tab as TriageTab | undefined) || 'overview';
      renderShell();
    });
  });
}

async function runTriage(): Promise<void> {
  if (!selectedFile) return;
  const run = document.getElementById('forensics-run') as HTMLButtonElement | null;
  const status = document.getElementById('forensics-status');
  activeRequest?.abort();
  activeRequest = new AbortController();
  if (run) {
    run.disabled = true;
    run.innerHTML = `${icons.loader} Analyzing…`;
  }
  if (status) status.textContent = 'Reading and inspecting hostile input…';
  try {
    latestResponse = await triageForensicsFile(selectedFile, activeRequest.signal);
    activeTab = 'overview';
    renderShell();
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    const message = error instanceof ApiError && error.code === 'NETWORK_ERROR'
      ? 'Backend unavailable. Start the FastAPI server on 127.0.0.1:8000.'
      : error instanceof Error ? error.message : 'Triage failed.';
    if (status) status.innerHTML = `<span style="color:var(--error)">${escapeHtml(message)}</span>`;
  } finally {
    if (run) {
      run.disabled = false;
      run.innerHTML = `${icons.play} Analyze`;
    }
  }
}
