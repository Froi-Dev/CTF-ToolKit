import { ApiError } from '../api/client.ts';
import {
  triageForensicsFile,
  type ForensicsTriageResponse,
} from '../api/forensics.ts';
import { icons } from '../data.ts';

type TriageTab = 'overview' | 'findings' | 'metadata' | 'qr' | 'strings' | 'archives' | 'extracted' | 'flags';

let activeTab: TriageTab = 'overview';
let selectedFile: File | null = null;
let latestResponse: ForensicsTriageResponse | null = null;
let activeRequest: AbortController | null = null;
let customFlagRegex = '';
let workspaceView = 'files';

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
  workspaceView = view || 'files';
  if (view === 'disk-partition') {
    // This is now handled by the separate disk module.
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
  const workspace = workspaceView === 'pdf-qr'
    ? { title: 'PDF / QR Analysis', subtitle: 'Inspect PDF evidence and recover QR codes or barcodes from documents, images, and media', accept: 'image/*,application/pdf,.pdf,.docx,.xlsx,.pptx,.odt,.gif,.mp4,.mov,.avi,.mkv,.webm' }
    : { title: 'File / Archive Analysis', subtitle: 'Static file identification, archive inspection, metadata, PDF, and QR/barcode recovery', accept: '' };
  const subtitle = result
    ? `${escapeHtml(result.original_filename)} · ${escapeHtml(result.magic.description)} · ${formatBytes(result.size)}`
    : workspace.subtitle;
  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header">
      <div><div class="page-title">${workspace.title}</div><div class="page-subtitle">${subtitle}</div></div>
      <div class="page-actions">
        <input id="forensics-file" type="file" ${workspace.accept ? `accept="${workspace.accept}"` : ''} hidden>
        <button class="btn btn-secondary btn-sm" id="forensics-select">${icons.folder} Choose File</button>
        <button class="btn btn-primary btn-sm" id="forensics-run" ${selectedFile ? '' : 'disabled'}>${icons.play} Analyze</button>
      </div>
    </div>
    <div class="panel mb-4">
      <div class="panel-body flex items-center gap-4" style="flex-wrap:wrap">
        <div style="flex:1">
          <div class="text-sm" id="forensics-selection">${selectedFile ? escapeHtml(selectedFile.name) : 'No file selected'}</div>
          <div class="text-xs text-muted">Uploads are limited to 32 MiB. Files are inspected statically and never executed.</div>
        </div>
        <label class="text-xs text-muted" style="min-width:240px">Custom flag regex (optional)
          <input class="input mono mt-4" id="forensics-flag-regex" maxlength="256" value="${escapeHtml(customFlagRegex)}" placeholder="ACME\\{[^}]+\\}">
        </label>
        <div class="text-xs text-muted" id="forensics-status">${result ? `Analysis ${escapeHtml(result.analysis_id)}` : 'Ready'}</div>
      </div>
    </div>
    ${result ? renderTabs(result) : renderEmptyState()}
  </div>`;
  bindEvents();
}

function renderEmptyState(): string {
  const lead = workspaceView === 'pdf-qr'
    ? 'Choose a PDF, image, Office document, GIF, or video to inspect metadata and embedded evidence while running multi-decoder QR/barcode recovery.'
    : 'Choose evidence to run file identification, ExifTool metadata intelligence, recursive decoding, QR/barcode recovery, strings, archive discovery, and safe embedded-artifact inspection.';
  return `<div class="section"><div class="panel"><div class="panel-body">
    <div class="section-title mb-4">No triage result</div>
    <div class="text-sm text-muted">${lead}</div>
  </div></div></div>`;
}

function renderTabs(result: ForensicsTriageResponse): string {
  const tabs: Array<[TriageTab, string, number | null]> = [
    ['overview', 'Overview', null],
    ['findings', 'Notable Findings', result.notable_findings.length],
    ['metadata', 'Metadata', result.metadata_analysis.all_metadata.length],
    ['qr', 'QR / Barcode Recovery', result.qr_barcode.findings.length],
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
    case 'findings': return renderFindings(result);
    case 'metadata': return renderMetadata(result);
    case 'qr': return renderQR(result);
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
  const leads = result.notable_findings.filter(item => item.severity !== 'info').slice(0, 5);
  return `${leads.length ? `<div class="section"><div class="section-header"><div class="section-title">Strongest Leads</div><button class="btn btn-secondary btn-sm" data-forensics-tab="findings">Review all</button></div>${leads.map(item => findingCard(item)).join('')}</div>` : ''}<div class="forensics-layout">
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

function severityBadge(severity: string): string {
  const style = severity === 'critical' ? 'badge-error' : severity === 'high' ? 'badge-warning' : severity === 'medium' ? 'badge-info' : 'badge-outline';
  return `<span class="badge ${style}">${escapeHtml(severity.toUpperCase())}</span>`;
}

function findingCard(item: ForensicsTriageResponse['notable_findings'][number]): string {
  const destination: TriageTab = item.analyzer === 'metadata' ? 'metadata' : item.analyzer === 'qr_barcode' ? 'qr' : item.section === 'flags' ? 'flags' : 'overview';
  return `<div class="panel mb-4" id="finding-${escapeHtml(item.finding_id)}"><div class="panel-header flex items-center gap-4">${severityBadge(item.severity)} <span>${escapeHtml(item.title)}</span></div><div class="panel-body"><div class="text-sm">${escapeHtml(item.reason)}</div>${item.field ? `<div class="text-xs text-muted mt-4">Field: <span class="mono">${escapeHtml(item.field)}</span></div>` : ''}${item.value ? `<div class="mono text-xs mt-4" style="word-break:break-all">${escapeHtml(item.value)}</div>` : ''}<button class="btn btn-secondary btn-sm mt-4" data-forensics-tab="${destination}">Open analyzer</button></div></div>`;
}

function renderFindings(result: ForensicsTriageResponse): string {
  if (!result.notable_findings.length) return '<div class="section"><div class="text-sm text-muted">No evidence-backed notable findings were produced.</div></div>';
  return `<div class="section"><div class="section-title mb-4">Notable Findings</div><div class="text-sm text-muted mb-4">Ranked analyst leads. A critical item is backed by a configured flag-pattern match; no result is inferred or fabricated.</div>${result.notable_findings.map(item => findingCard(item)).join('')}</div>`;
}

function renderMetadata(result: ForensicsTriageResponse): string {
  const analysis = result.metadata_analysis;
  const gps = analysis.gps ? `<div class="panel mb-4"><div class="panel-header">GPS Coordinates · notable</div><div class="panel-body"><div class="mono">${analysis.gps.latitude}, ${analysis.gps.longitude}</div><div class="text-xs text-muted mt-4">${analysis.gps.altitude === null ? '' : `Altitude ${analysis.gps.altitude} · `}${escapeHtml(analysis.gps.location || analysis.gps.timestamp || '')}</div></div></div>` : '';
  const decoded = analysis.decoded.map(item => `<div class="panel mb-4"><div class="panel-header">${severityBadge(item.flags.length ? 'critical' : 'high')} ${escapeHtml(item.field)} · ${escapeHtml(item.detected_encoding)} (${Math.round(item.confidence * 100)}%)</div><div class="panel-body"><div class="text-xs text-muted">Original</div><div class="mono text-xs" style="word-break:break-all">${escapeHtml(item.original)}</div><div class="text-xs text-muted mt-4">Transformation chain</div><div class="mono text-xs">${item.chain.map(step => escapeHtml(step.transform)).join(' → ')}</div><div class="text-xs text-muted mt-4">Decoded</div><div class="mono" style="word-break:break-all">${escapeHtml(item.decoded)}</div></div></div>`).join('');
  const timeline = analysis.timeline.length ? `<div class="panel mb-4"><div class="panel-header">Metadata Timeline</div><div class="panel-body">${analysis.timeline.map(item => `<div class="mb-4"><div class="mono text-xs">${escapeHtml(item.normalized_timestamp || item.timestamp)}</div><div class="text-sm">${escapeHtml(item.description)}</div><div class="text-xs text-muted">${escapeHtml(item.field)}</div></div>`).join('')}${analysis.timestamp_anomalies.map(item => `<div class="text-xs" style="color:var(--warning)">TIMESTAMP ANOMALY · ${escapeHtml(item)}</div>`).join('')}</div></div>` : '';
  const embedded = analysis.embedded_objects.map(item => `<div class="panel mb-4"><div class="panel-header">${escapeHtml(item.kind)} · ${escapeHtml(item.tag)}</div><div class="panel-body text-xs"><div>${escapeHtml(item.description)}</div>${item.byte_size === null ? '' : `<div class="text-muted mt-4">${formatBytes(item.byte_size)}</div>`}${item.data_base64 ? `<a class="btn btn-secondary btn-sm mt-4" download="${escapeHtml(item.kind.replace(/\s+/g, '-'))}.bin" href="data:${escapeHtml(item.mime_type || 'application/octet-stream')};base64,${item.data_base64}">Extract object</a>` : ''}</div></div>`).join('');
  const categories = Object.entries(analysis.categories).map(([category, entries]) => `<details class="panel mb-4"><summary class="panel-header" style="cursor:pointer">${escapeHtml(category)} · ${entries.length}</summary><div class="panel-body"><div class="kv-list">${entries.map(item => `<div class="kv-key">${severityBadge(item.importance)} ${escapeHtml(item.key)}</div><div class="kv-value mono" style="word-break:break-all">${escapeHtml(item.display_value)}</div>`).join('')}</div></div></details>`).join('');
  return `<div class="section"><div class="section-header"><div><div class="section-title">Deep Media Metadata</div><div class="text-sm text-muted mt-4">${escapeHtml(analysis.summary)}</div></div><span class="badge ${analysis.tool_available ? 'badge-success' : 'badge-error'}">${analysis.tool_available ? `ExifTool ${escapeHtml(analysis.tool_version || '')}` : 'ExifTool unavailable'}</span></div>${gps}${decoded ? `<div class="section-title mb-4">Encoded Metadata</div>${decoded}` : ''}${timeline}${embedded ? `<div class="section-title mb-4">Embedded Objects</div>${embedded}` : ''}<div class="section-title mb-4">All Metadata by Category</div>${categories || '<div class="text-sm text-muted">No deep metadata was returned.</div>'}<details class="panel mt-8"><summary class="panel-header" style="cursor:pointer">Raw ExifTool Output</summary><div class="panel-body"><pre class="mono text-xs" style="white-space:pre-wrap;word-break:break-all;max-height:520px;overflow:auto">${escapeHtml(analysis.raw_exiftool)}</pre></div></details></div>`;
}

function renderQR(result: ForensicsTriageResponse): string {
  const qr = result.qr_barcode;
  const decoders = `<div class="panel mb-4"><div class="panel-header">Decoder Coverage</div><div class="panel-body text-xs"><div>Available: ${escapeHtml(qr.decoders_available.join(', ') || 'none')}</div><div class="text-muted mt-4">Unavailable: ${escapeHtml(qr.decoders_unavailable.join(', ') || 'none')}</div><div class="text-muted mt-4">Scanned ${qr.scanned_sources.length} image/page/frame source(s); ${qr.attempts.length} recorded decoder attempts.</div>${qr.warnings.map(item => `<div style="color:var(--warning)" class="mt-4">${escapeHtml(item)}</div>`).join('')}</div></div>`;
  const findings = qr.findings.map(item => `<div class="panel mb-4"><div class="panel-header">${severityBadge(item.secondary_analysis?.flags.length ? 'critical' : 'high')} ${escapeHtml(item.symbology)} · ${escapeHtml(item.confidence)} confidence</div><div class="panel-body"><div class="kv-list"><div class="kv-key">Source</div><div class="kv-value">${escapeHtml(item.source)}</div><div class="kv-key">Location</div><div class="kv-value mono">${item.bounding_box ? `x=${item.bounding_box.x}, y=${item.bounding_box.y}, width=${item.bounding_box.width}, height=${item.bounding_box.height}` : 'decoder did not expose coordinates'}</div><div class="kv-key">Recovery method</div><div class="kv-value">${escapeHtml(item.recovery_method)}</div><div class="kv-key">Decoder</div><div class="kv-value">${escapeHtml(item.decoder)}</div><div class="kv-key">Decoded content</div><div class="kv-value mono" style="word-break:break-all">${escapeHtml(item.decoded_value)}</div></div>${item.secondary_analysis ? `<div class="mt-4 text-xs text-muted">Recursive decode: ${escapeHtml(item.secondary_analysis.detected_encodings.join(', '))}</div>${item.secondary_analysis.decoded ? `<div class="mono mt-4" style="word-break:break-all">${escapeHtml(item.secondary_analysis.chain.map(step => step.transform).join(' → '))} → ${escapeHtml(item.secondary_analysis.decoded)}</div>` : ''}` : ''}<details class="mt-4"><summary class="text-xs" style="cursor:pointer">Evidence provenance</summary><div class="mono text-xs mt-4">${item.provenance.map(step => `${escapeHtml(step.operation)} [${escapeHtml(step.tool)}]`).join(' → ')}</div></details></div></div>`).join('');
  const structures = qr.structures.map(item => `<div class="panel mb-4"><div class="panel-header">QR STRUCTURE DETECTED · decode failed</div><div class="panel-body"><div class="kv-list"><div class="kv-key">Source</div><div class="kv-value">${escapeHtml(item.source)}</div><div class="kv-key">Finder patterns</div><div class="kv-value">${item.finder_patterns ?? 'unknown'}</div><div class="kv-key">Estimated version</div><div class="kv-value">${item.estimated_version ?? 'unknown'}</div><div class="kv-key">Modules</div><div class="kv-value">${escapeHtml(item.estimated_modules || 'unknown')}</div><div class="kv-key">Orientation</div><div class="kv-value">${item.orientation_degrees ?? 'unknown'}°</div></div></div></div>`).join('');
  const variants = qr.variants.map(item => `<div class="panel"><div class="panel-header">${item.best_candidate ? 'Best Recovery Candidate · ' : ''}${escapeHtml(item.label)}</div><div class="panel-body"><img src="data:image/png;base64,${item.image_base64}" alt="${escapeHtml(item.label)}" style="display:block;max-width:100%;max-height:360px;image-rendering:pixelated;margin:auto"><div class="text-xs text-muted mt-4">${escapeHtml(item.source)} · ${item.width}×${item.height}</div><a class="btn btn-secondary btn-sm mt-4" download="recovery-${escapeHtml(item.variant_id)}.png" href="data:image/png;base64,${item.image_base64}">Download Recovery Image</a></div></div>`).join('');
  return `<div class="section"><div class="section-title mb-4">QR / Barcode Recovery</div>${decoders}${findings || '<div class="text-sm text-muted mb-4">No decoder returned a validated payload.</div>'}${structures}${variants ? `<div class="section-title mb-4">Enhanced Variants</div><div class="grid-2">${variants}</div>` : ''}<details class="panel mt-8"><summary class="panel-header" style="cursor:pointer">Recovery Attempts · ${qr.attempts.length}</summary><div class="panel-body"><table class="data-table"><thead><tr><th>Source</th><th>Variant</th><th>Decoder</th><th>Result</th></tr></thead><tbody>${qr.attempts.map(item => `<tr><td>${escapeHtml(item.source)}</td><td>${escapeHtml(item.variant)}</td><td>${escapeHtml(item.decoder)}</td><td>${item.success ? '✓ decoded' : '✗ no payload'}</td></tr>`).join('')}</tbody></table></div></details></div>`;
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
    <div class="panel-header flag-evidence-header" style="color:var(--success)">${icons.flag} Candidate · ${Math.round(flag.confidence * 100)}%</div>
    <div class="panel-body"><div class="mono" style="word-break:break-all">${escapeHtml(flag.value)}</div><div class="text-xs text-muted mt-4">${escapeHtml(flag.source)} · byte offset 0x${flag.offset.toString(16)} · not automatically confirmed</div><div class="text-xs mono mt-4">${escapeHtml(flag.context)}</div></div>
  </div>`).join('')}</div>`;
}

function bindEvents(): void {
  const input = document.getElementById('forensics-file') as HTMLInputElement | null;
  const select = document.getElementById('forensics-select') as HTMLButtonElement | null;
  const run = document.getElementById('forensics-run') as HTMLButtonElement | null;
  const regex = document.getElementById('forensics-flag-regex') as HTMLInputElement | null;
  select?.addEventListener('click', () => input?.click());
  input?.addEventListener('change', () => {
    selectedFile = input.files?.[0] || null;
    latestResponse = null;
    activeTab = 'overview';
    renderShell();
  });
  run?.addEventListener('click', () => void runTriage());
  regex?.addEventListener('input', () => { customFlagRegex = regex.value; });
  document.querySelectorAll<HTMLElement>('#forensics-tabs .tab-item').forEach(tab => {
    tab.addEventListener('click', () => {
      activeTab = (tab.dataset.tab as TriageTab | undefined) || 'overview';
      renderShell();
    });
  });
  document.querySelectorAll<HTMLElement>('[data-forensics-tab]').forEach(element => {
    element.addEventListener('click', () => {
      activeTab = (element.dataset.forensicsTab as TriageTab | undefined) || 'overview';
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
    latestResponse = await triageForensicsFile(selectedFile, activeRequest.signal, customFlagRegex.trim() || undefined);
    activeTab = workspaceView === 'pdf-qr' && selectedFile.type === 'application/pdf' ? 'metadata'
      : workspaceView === 'pdf-qr' ? 'qr' : 'overview';
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
