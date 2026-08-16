import { ApiError, apiRequest } from '../api/client.ts';
import {
  analyzeStegoImage,
  type StegoAnalysisResponse,
  type StegoFinding,
} from '../api/stego.ts';
import { icons } from '../data.ts';

type StegoTab = 'zsteg' | 'strings' | 'lsb' | 'metadata';
type InspectorView = 'text' | 'hex' | 'binary' | 'raw';

let activeTab: StegoTab = 'zsteg';
let selectedFile: File | null = null;
let latestResponse: StegoAnalysisResponse | null = null;
let activeRequest: AbortController | null = null;
let showAll = false;
let deepScan = false;
let inspectedFindingId: string | null = null;
let inspectorView: InspectorView = 'text';

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

function percent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function severityColor(severity: StegoFinding['severity']): string {
  return ({
    critical: 'var(--error)', high: 'var(--warning)', medium: 'var(--accent)',
    low: 'var(--text-muted)', noise: 'var(--text-muted)',
  })[severity];
}

function badge(ok: boolean, yes: string, no: string): string {
  return `<span class="badge ${ok ? 'badge-success' : 'badge-error'}">${ok ? yes : no}</span>`;
}

export function renderStego(): void {
  activeRequest?.abort();
  activeRequest = null;
  selectedFile = null;
  latestResponse = null;
  activeTab = 'zsteg';
  inspectedFindingId = null;
  renderShell();
}

function renderShell(): void {
  const main = document.getElementById('main');
  if (!main) return;
  const result = latestResponse;
  const subtitle = result
    ? `${escapeHtml(result.original_filename)} · ${escapeHtml(result.image.format)} · ${result.image.width}x${result.image.height} · ${formatBytes(result.size)}`
    : 'Native bit-plane extraction, ranked steganography findings, structure, metadata, QR, and carving';
  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header">
      <div><div class="page-title">ZSteg</div><div class="page-subtitle">${subtitle}</div></div>
      <div class="page-actions">
        <input id="stego-file" type="file" accept="image/png,image/bmp,image/gif,image/tiff,image/webp,image/jpeg,.png,.bmp,.gif,.tif,.tiff,.webp,.jpg,.jpeg" hidden>
        <button class="btn btn-secondary btn-sm" id="stego-select">${icons.folder} Choose Image</button>
        <button class="btn btn-primary btn-sm" id="stego-run" ${selectedFile ? '' : 'disabled'}>${icons.play} Analyze</button>
      </div>
    </div>
    <div class="panel mb-4"><div class="panel-body flex items-center gap-4" style="flex-wrap:wrap">
      <div style="flex:1;min-width:260px">
        <div class="text-sm">${selectedFile ? escapeHtml(selectedFile.name) : 'No image selected'}</div>
        <div class="text-xs text-muted">32 MiB limit · PNG, BMP, GIF, TIFF, lossless WebP; JPEG is accepted for lower-confidence triage.</div>
      </div>
      <label class="text-xs" style="display:flex;align-items:center;gap:8px"><input id="stego-show-all" type="checkbox" ${showAll ? 'checked' : ''}> Show bounded noise results</label>
      <label class="text-xs" style="display:flex;align-items:center;gap:8px"><input id="stego-deep-scan" type="checkbox" ${deepScan ? 'checked' : ''}> Deep scan (slower)</label>
      <div class="text-xs text-muted" id="stego-status">${result && result.pixel_scan
        ? `${result.pixel_scan.mode} · ${result.pixel_scan.candidates_evaluated} variants · ${result.pixel_scan.elapsed_ms} ms${result.pixel_scan.truncated ? ' · time limit reached' : ''}`
        : 'Ready'}</div>
    </div></div>
    ${result ? renderTabs(result) : renderEmptyState()}
    ${result ? renderInspector(result) : ''}
  </div>`;
  bindEvents();
}

function renderEmptyState(): string {
  return `<div class="section"><div class="panel"><div class="panel-body">
    <div class="section-title mb-4">No image analyzed</div>
    <div class="text-sm text-muted">Choose an image, then review ZSteg results, extracted strings, LSB streams, and metadata.</div>
  </div></div></div>`;
}

function renderTabs(result: StegoAnalysisResponse): string {
  const tabs: Array<[StegoTab, string, number | null]> = [
    ['zsteg', 'ZSteg', result.findings.length],
    ['strings', 'Strings', null],
    ['lsb', 'LSB', result.lsb.filter(item => item.suspicious).length],
    ['metadata', 'Meta Data', result.metadata.length],
  ];
  return `<div class="tab-bar" id="stego-tabs">${tabs.map(([id, label, count]) => `
    <div class="tab-item ${activeTab === id ? 'active' : ''}" data-tab="${id}">${label}${count === null ? '' : ` <span class="tab-count">${count}</span>`}</div>`).join('')}
  </div><div id="stego-content">${renderTab(result)}</div>`;
}

function renderTab(result: StegoAnalysisResponse): string {
  switch (activeTab) {
    case 'strings': return renderStrings(result);
    case 'lsb': return renderLsb(result);
    case 'metadata': return renderMetadata(result);
    default: return renderZsteg(result);
  }
}

function compactFinding(finding: StegoFinding): string {
  const value = finding.flags[0]?.value || finding.preview_text.slice(0, 120) || finding.detected_type;
  return `<tr>
    <td style="color:${severityColor(finding.severity)}">${finding.severity.toUpperCase()}</td>
    <td class="mono">${escapeHtml(finding.method?.notation || finding.source)}</td>
    <td class="mono" style="word-break:break-all">${escapeHtml(value)}</td>
    <td>${Math.round(finding.confidence * 100)}%</td>
    <td><button class="btn btn-secondary btn-sm" data-inspect="${finding.finding_id}">Inspect</button></td>
  </tr>`;
}

function renderZsteg(result: StegoAnalysisResponse): string {
  const extracted = result.findings.filter(item => item.method || item.source === 'external_tool');
  return `<div class="section">
    <div class="section-header"><div class="section-title">ZSteg</div><span class="text-xs text-muted">${result.pixel_scan?.mode || 'quick'} · ${result.pixel_scan?.candidates_evaluated || 0} variants</span></div>
    ${result.findings.length ? `<div class="panel mb-4"><div class="panel-body" style="padding:10px 12px">
      <div class="text-xs mb-4"><strong>Suspicious Findings</strong> · ${result.findings.length}</div>
      <table class="data-table"><thead><tr><th>Level</th><th>Method</th><th>Value</th><th>Confidence</th><th></th></tr></thead><tbody>${result.findings.slice(0, 4).map(compactFinding).join('')}</tbody></table>
    </div></div>` : ''}
    <table class="data-table"><thead><tr><th>Method</th><th>Detected</th><th>Offset</th><th>Entropy</th><th>Preview</th><th></th></tr></thead><tbody>${extracted.map(item => `<tr>
      <td class="mono">${escapeHtml(item.method?.notation || 'external:zsteg')}</td><td>${escapeHtml(item.detected_type)}</td><td class="mono">0x${item.offset.toString(16)}</td><td>${item.entropy.toFixed(4)}</td><td class="mono" style="word-break:break-all">${escapeHtml(item.preview_text.slice(0, 120))}</td><td><button class="btn btn-secondary btn-sm" data-inspect="${item.finding_id}">Inspect</button></td>
    </tr>`).join('')}</tbody></table>
  </div>`;
}

function renderStrings(result: StegoAnalysisResponse): string {
  const rows = new Map<string, { source: string; printable: number; value: string }>();
  result.findings.forEach(item => {
    const value = item.flags[0]?.value || item.preview_text;
    if (value && item.printable_ratio >= 0.5) rows.set(`${item.method?.notation || item.source}:${value}`, {
      source: item.method?.notation || item.source, printable: item.printable_ratio, value,
    });
  });
  result.lsb.forEach(item => {
    if (item.preview_ascii && item.printable_ratio >= 0.5) rows.set(`lsb:${item.stream}:${item.preview_ascii}`, {
      source: `lsb:${item.stream}`, printable: item.printable_ratio, value: item.preview_ascii,
    });
  });
  return `<div class="section"><div class="section-title mb-4">Strings</div>${rows.size
    ? `<table class="data-table"><thead><tr><th>Source</th><th>Printable</th><th>String</th></tr></thead><tbody>${[...rows.values()].map(item => `<tr><td class="mono">${escapeHtml(item.source)}</td><td>${percent(item.printable)}</td><td class="mono" style="word-break:break-all">${escapeHtml(item.value.slice(0, 500))}</td></tr>`).join('')}</tbody></table>`
    : '<div class="text-sm text-muted">No ranked printable strings were extracted.</div>'}</div>`;
}

function renderLsb(result: StegoAnalysisResponse): string {
  const methods = result.findings.filter(item => item.method?.bit_order === 'lsb');
  return `<div class="section"><div class="section-title mb-4">LSB</div>
    <div class="text-xs text-muted mb-4"><span class="mono">b1,b,lsb,xy</span> = 1 bit · blue channel · least-significant bit · XY order.</div>
    <table class="data-table mb-4"><thead><tr><th>Stream</th><th>Bytes</th><th>Printable</th><th>Entropy</th><th>Preview</th></tr></thead><tbody>${result.lsb.map(item => `<tr><td class="mono">${escapeHtml(item.stream)}</td><td>${formatBytes(item.extracted_bytes)}</td><td>${percent(item.printable_ratio)}</td><td>${item.entropy.bits_per_byte.toFixed(4)}</td><td class="mono" style="word-break:break-all">${escapeHtml(item.preview_ascii)}</td></tr>`).join('')}</tbody></table>
    ${methods.length ? `<table class="data-table"><thead><tr><th>Method</th><th>Order</th><th>Detected</th><th></th></tr></thead><tbody>${methods.map(item => `<tr><td class="mono">${escapeHtml(item.method?.notation)}</td><td>${escapeHtml(item.method?.byte_bit_order)}</td><td>${escapeHtml(item.detected_type)}</td><td><button class="btn btn-secondary btn-sm" data-inspect="${item.finding_id}">Inspect</button></td></tr>`).join('')}</tbody></table>` : ''}
  </div>`;
}

function renderOverview(result: StegoAnalysisResponse): string {
  const counts = (['critical', 'high', 'medium', 'low'] as const).map(
    severity => [severity, result.findings.filter(item => item.severity === severity).length] as const,
  );
  const external = result.external_validation.map(item => `${item.tool}: ${item.executed ? 'validated' : item.available ? 'available' : 'unavailable'}`).join(' · ');
  return `<div class="section">
    <div class="section-title mb-4">Forensic Analysis Complete</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px" class="mb-4">
      ${counts.map(([severity, count]) => `<div class="panel"><div class="panel-body"><div class="text-xs" style="color:${severityColor(severity)};text-transform:uppercase">${severity}</div><div style="font-size:26px">${count}</div></div></div>`).join('')}
    </div>
    ${result.findings.length ? `<div class="section-title mb-4">Suspicious Findings</div>${result.findings.slice(0, 5).map(renderFindingCard).join('')}` : '<div class="panel"><div class="panel-body text-sm text-muted">No meaningful hidden-data candidate survived ranking.</div></div>'}
    <div class="forensics-layout mt-4"><div class="panel"><div class="panel-body"><div class="kv-list">
      <div class="kv-key">Image</div><div class="kv-value mono">${escapeHtml(result.image.format)} · ${result.image.width}×${result.image.height} · ${escapeHtml(result.image.mode)}</div>
      <div class="kv-key">Pixel variants</div><div class="kv-value mono">${result.pixel_scan?.candidates_evaluated ?? 0}</div>
      <div class="kv-key">Unique streams</div><div class="kv-value mono">${result.pixel_scan?.unique_streams ?? 0}</div>
      <div class="kv-key">Hidden noise</div><div class="kv-value mono">${result.pixel_scan?.noise_hidden ?? 0}</div>
      <div class="kv-key">QR / barcodes</div><div class="kv-value mono">${result.barcodes.length}</div>
    </div></div></div><div class="panel"><div class="panel-body"><div class="kv-list">
      <div class="kv-key">Trailing data</div><div class="kv-value">${badge(result.trailing_bytes.present, formatBytes(result.trailing_bytes.size), 'None')}</div>
      <div class="kv-key">Embedded signatures</div><div class="kv-value mono">${result.signatures.length}</div>
      <div class="kv-key">Native engine</div><div class="kv-value">Active</div>
      <div class="kv-key">External validation</div><div class="kv-value text-xs">${escapeHtml(external || 'None')}</div>
      <div class="kv-key">SHA-256</div><div class="kv-value mono" style="word-break:break-all">${result.hashes.sha256}</div>
    </div></div></div></div>
  </div>`;
}

function renderFindingCard(finding: StegoFinding): string {
  const flag = finding.flags[0]?.value;
  return `<div class="panel mb-4" style="border-left:3px solid ${severityColor(finding.severity)}">
    <div class="panel-header" style="display:flex;justify-content:space-between;gap:12px">
      <span><span style="color:${severityColor(finding.severity)}">[${finding.severity.toUpperCase()}]</span> ${escapeHtml(finding.title)}</span>
      <span class="mono">${Math.round(finding.confidence * 100)}%</span>
    </div>
    <div class="panel-body">
      ${flag ? `<div class="mono mb-4" style="font-size:16px;color:var(--success);word-break:break-all">${escapeHtml(flag)}</div>` : `<div class="mono mb-4" style="word-break:break-all">${escapeHtml(finding.preview_text.slice(0, 240))}</div>`}
      <div class="text-xs text-muted mb-4">${escapeHtml(finding.explanation)}</div>
      <div class="kv-list">
        <div class="kv-key">Method</div><div class="kv-value mono">${escapeHtml(finding.method?.notation || finding.source)}</div>
        <div class="kv-key">Type</div><div class="kv-value">${escapeHtml(finding.detected_type)}</div>
        <div class="kv-key">Offset</div><div class="kv-value mono">0x${finding.offset.toString(16)}</div>
      </div>
      <button class="btn btn-secondary btn-sm mt-4" data-inspect="${finding.finding_id}">Inspect Extraction</button>
      <button class="btn btn-secondary btn-sm mt-4" data-export="${finding.finding_id}">Export Data</button>
    </div>
  </div>`;
}

function renderFindings(result: StegoAnalysisResponse): string {
  const note = result.pixel_scan?.noise_hidden
    ? `<div class="text-xs text-muted mb-4">${result.pixel_scan.noise_hidden} deduplicated noise streams are hidden. Enable “Show bounded noise results” and re-run to inspect a small sample.</div>` : '';
  return `<div class="section"><div class="section-title mb-4">Suspicious Findings</div>${note}${result.findings.length
    ? result.findings.map(renderFindingCard).join('')
    : '<div class="text-sm text-muted">No ranked findings.</div>'}</div>`;
}

function renderStructure(result: StegoAnalysisResponse): string {
  const trailing = result.trailing_bytes.present ? `<div class="panel mb-4"><div class="panel-header">Trailing data detected</div><div class="panel-body"><div class="kv-list">
    <div class="kv-key">Offset</div><div class="kv-value mono">0x${result.trailing_bytes.offset.toString(16)}</div>
    <div class="kv-key">Size</div><div class="kv-value mono">${formatBytes(result.trailing_bytes.size)}</div>
    <div class="kv-key">Detected</div><div class="kv-value mono">${escapeHtml(result.trailing_bytes.detected_type || 'unknown')}</div>
  </div></div></div>` : '';
  if (result.image.format === 'PNG') return `<div class="section"><div class="section-title mb-4">PNG Structure</div>${trailing}
    <table class="data-table"><thead><tr><th>#</th><th>Chunk</th><th>Offset</th><th>Length</th><th>CRC</th><th>Assessment</th></tr></thead><tbody>${result.png_chunks.map(chunk => `<tr>
      <td>${chunk.index}</td><td class="mono">${escapeHtml(chunk.chunk_type)}</td><td class="mono">0x${chunk.offset.toString(16)}</td><td>${formatBytes(chunk.data_length)}</td><td>${badge(chunk.crc_valid, 'Valid', 'Invalid')}</td><td>${chunk.suspicious ? `<span style="color:var(--warning)">${escapeHtml(chunk.explanation)}</span>` : 'Expected'}</td>
    </tr>`).join('')}</tbody></table></div>`;
  if (result.image.format === 'JPEG') return `<div class="section"><div class="section-title mb-4">JPEG Structure</div>${trailing}<table class="data-table"><thead><tr><th>#</th><th>Marker</th><th>Name</th><th>Offset</th><th>Length</th></tr></thead><tbody>${result.jpeg_segments.map(segment => `<tr><td>${segment.index}</td><td class="mono">${segment.marker}</td><td>${escapeHtml(segment.name)}</td><td class="mono">0x${segment.offset.toString(16)}</td><td>${formatBytes(segment.segment_length)}</td></tr>`).join('')}</tbody></table></div>`;
  return `<div class="section"><div class="section-title mb-4">${escapeHtml(result.image.format)} Container</div>${trailing}<div class="panel"><div class="panel-body text-sm text-muted">Pixel, metadata, entropy, and signature analysis completed. Dedicated chunk parsing is currently provided for PNG and JPEG.</div></div></div>`;
}

function renderPlanes(result: StegoAnalysisResponse): string {
  const channels = [...new Set(result.bit_plane_visuals.map(item => item.channel))];
  return `<div class="section"><div class="section-title mb-4">Visual Bit Planes</div><div class="text-xs text-muted mb-4">White pixels have a 1 in the selected channel bit; black pixels have a 0. Open the image in a new tab for closer inspection.</div>
    ${channels.map(channel => `<div class="panel mb-4"><div class="panel-header">${escapeHtml(channel)} channel</div><div class="panel-body" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px">${result.bit_plane_visuals.filter(item => item.channel === channel).map(item => `<a href="data:image/png;base64,${item.png_base64}" target="_blank" rel="noopener" style="text-decoration:none"><div class="text-xs mono mb-4">${item.label} · ones ${percent(item.one_ratio)}</div><img src="data:image/png;base64,${item.png_base64}" alt="${item.label}" style="width:100%;image-rendering:pixelated;border:1px solid var(--border)">${item.qr_payloads.length ? `<div class="text-xs mt-4" style="color:var(--success)">QR: ${escapeHtml(item.qr_payloads.join(', '))}</div>` : ''}</a>`).join('')}</div></div>`).join('')}
  </div>`;
}

function renderExtractions(result: StegoAnalysisResponse): string {
  const candidates = result.findings.filter(item => item.method);
  return `<div class="section"><div class="panel mb-4"><div class="panel-header">Equivalent zsteg-style notation</div><div class="panel-body text-sm"><span class="mono">b1,b,lsb,xy</span> means <strong>1 bit</strong> from the <strong>blue channel</strong>, selecting the <strong>least-significant bit</strong>, with <strong>XY row-major traversal</strong>. CTFKit separately records whether extracted bits form bytes MSB-first or LSB-first.</div></div>
    <table class="data-table"><thead><tr><th>Severity</th><th>Method</th><th>Byte order</th><th>Offset</th><th>Entropy</th><th>Printable</th><th>Detected</th><th></th></tr></thead><tbody>${candidates.map(item => `<tr>
      <td style="color:${severityColor(item.severity)}">${item.severity.toUpperCase()}</td><td class="mono">${escapeHtml(item.method?.notation)}</td><td>${escapeHtml(item.method?.byte_bit_order)}</td><td class="mono">0x${item.offset.toString(16)}</td><td>${item.entropy.toFixed(4)}</td><td>${percent(item.printable_ratio)}</td><td>${escapeHtml(item.detected_type)}</td><td><button class="btn btn-secondary btn-sm" data-inspect="${item.finding_id}">Inspect</button></td>
    </tr>`).join('')}</tbody></table></div>`;
}

function renderCarving(result: StegoAnalysisResponse): string {
  return `<div class="section"><div class="section-title mb-4">Embedded / Appended Files</div>${result.signatures.length ? `<table class="data-table mb-4"><thead><tr><th>Offset</th><th>Type</th><th>Source</th><th>Size</th><th>Carved</th></tr></thead><tbody>${result.signatures.map(item => `<tr><td class="mono">0x${item.offset.toString(16)}</td><td>${escapeHtml(item.detected_type)}</td><td>${escapeHtml(item.source)}</td><td>${item.estimated_size === null ? 'unknown' : formatBytes(item.estimated_size)}</td><td>${item.carved_artifact_id ? 'Yes' : 'No'}</td></tr>`).join('')}</tbody></table>` : '<div class="text-sm text-muted mb-4">No embedded signatures found.</div>'}
    <div class="text-xs text-muted">Carved artifacts are analyzed as untrusted data and linked to their parent artifact. This stateless endpoint removes temporary server-side copies after the response; use Export Data on a retained finding to save its bounded payload.</div>
  </div>`;
}

function renderMetadata(result: StegoAnalysisResponse): string {
  return `<div class="section"><div class="section-title mb-4">Metadata Analysis</div><div class="panel"><div class="panel-body"><div class="kv-list">${result.metadata.map(item => `<div class="kv-key">${escapeHtml(item.source)} · ${escapeHtml(item.key)}</div><div class="kv-value mono" style="word-break:break-all">${escapeHtml(item.value)}</div>`).join('')}</div></div></div>
    ${result.warnings.length ? `<div class="panel mt-4"><div class="panel-header" style="color:var(--warning)">Warnings</div><div class="panel-body text-xs">${result.warnings.map(item => `<div>• ${escapeHtml(item)}</div>`).join('')}</div></div>` : ''}</div>`;
}

function findingBytes(finding: StegoFinding): Uint8Array {
  const binary = atob(finding.data_base64);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function inspectorContent(finding: StegoFinding): string {
  const bytes = findingBytes(finding);
  if (inspectorView === 'hex') return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(' ');
  if (inspectorView === 'binary') return Array.from(bytes.slice(0, 4096), byte => byte.toString(2).padStart(8, '0')).join(' ');
  if (inspectorView === 'raw') return Array.from(bytes.slice(0, 4096), byte => String.fromCharCode(byte)).join('');
  return finding.preview_text;
}

function renderInspector(result: StegoAnalysisResponse): string {
  if (!inspectedFindingId) return '';
  const finding = result.findings.find(item => item.finding_id === inspectedFindingId);
  if (!finding) return '';
  return `<div class="panel mt-4" id="stego-inspector"><div class="panel-header" style="display:flex;justify-content:space-between"><span>Extraction Inspector</span><button class="btn btn-secondary btn-sm" id="stego-close-inspector">Close</button></div><div class="panel-body">
    <div class="kv-list mb-4">
      <div class="kv-key">Finding</div><div class="kv-value">${escapeHtml(finding.title)}</div>
      <div class="kv-key">Extraction method</div><div class="kv-value mono">${escapeHtml(finding.method?.notation || finding.source)}</div>
      <div class="kv-key">Channel / bits</div><div class="kv-value mono">${escapeHtml(finding.method ? `${finding.method.channels} · ${finding.method.bits_per_channel}-bit · ${finding.method.bit_order}` : 'n/a')}</div>
      <div class="kv-key">Traversal / byte order</div><div class="kv-value mono">${escapeHtml(finding.method ? `${finding.method.traversal} · ${finding.method.byte_bit_order}` : 'n/a')}</div>
      <div class="kv-key">Offset / length</div><div class="kv-value mono">0x${finding.offset.toString(16)} · ${formatBytes(finding.length)}</div>
      <div class="kv-key">Entropy / printable</div><div class="kv-value mono">${finding.entropy.toFixed(4)} · ${percent(finding.printable_ratio)}</div>
      <div class="kv-key">Detected / confidence</div><div class="kv-value">${escapeHtml(finding.detected_type)} · ${percent(finding.confidence)}</div>
      <div class="kv-key">Analysis chain</div><div class="kv-value">${finding.analysis_chain.map(step => `${escapeHtml(step.operation)}: ${escapeHtml(step.detail)}`).join(' → ')}</div>
    </div>
    <div class="tab-bar" id="stego-inspector-tabs">${(['text', 'hex', 'binary', 'raw'] as InspectorView[]).map(view => `<div class="tab-item ${inspectorView === view ? 'active' : ''}" data-view="${view}">${view.toUpperCase()}</div>`).join('')}</div>
    <pre class="mono" style="white-space:pre-wrap;word-break:break-all;max-height:360px;overflow:auto;background:var(--bg-primary);padding:12px">${escapeHtml(inspectorContent(finding))}</pre>
    <button class="btn btn-primary btn-sm" data-export="${finding.finding_id}">Export Data${finding.data_truncated ? ' (bounded preview)' : ''}</button>
  </div></div>`;
}

function exportFinding(findingId: string): void {
  const finding = latestResponse?.findings.find(item => item.finding_id === findingId);
  if (!finding) return;
  const bytes = findingBytes(finding);
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  const url = URL.createObjectURL(new Blob([copy.buffer]));
  const link = document.createElement('a');
  link.href = url;
  link.download = `ctfkit-${finding.detected_type}-${finding.finding_id.slice(0, 8)}.bin`;
  link.click();
  URL.revokeObjectURL(url);
}

function bindEvents(): void {
  const input = document.getElementById('stego-file') as HTMLInputElement | null;
  document.getElementById('stego-select')?.addEventListener('click', () => input?.click());
  input?.addEventListener('change', () => {
    selectedFile = input.files?.[0] || null;
    latestResponse = null;
    inspectedFindingId = null;
    activeTab = 'zsteg';
    renderShell();
  });
  document.getElementById('stego-run')?.addEventListener('click', () => void runAnalysis());
  document.getElementById('stego-show-all')?.addEventListener('change', event => {
    showAll = (event.currentTarget as HTMLInputElement).checked;
  });
  document.getElementById('stego-deep-scan')?.addEventListener('change', event => {
    deepScan = (event.currentTarget as HTMLInputElement).checked;
  });
  document.querySelectorAll<HTMLElement>('#stego-tabs .tab-item').forEach(tab => tab.addEventListener('click', () => {
    activeTab = (tab.dataset.tab as StegoTab | undefined) || 'zsteg';
    inspectedFindingId = null;
    renderShell();
  }));
  document.querySelectorAll<HTMLElement>('[data-inspect]').forEach(button => button.addEventListener('click', () => {
    inspectedFindingId = button.dataset.inspect || null;
    inspectorView = 'text';
    renderShell();
    document.getElementById('stego-inspector')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }));
  document.querySelectorAll<HTMLElement>('[data-export]').forEach(button => button.addEventListener('click', () => exportFinding(button.dataset.export || '')));
  document.getElementById('stego-close-inspector')?.addEventListener('click', () => { inspectedFindingId = null; renderShell(); });
  document.querySelectorAll<HTMLElement>('#stego-inspector-tabs .tab-item').forEach(tab => tab.addEventListener('click', () => {
    inspectorView = (tab.dataset.view as InspectorView | undefined) || 'text';
    renderShell();
  }));
}

async function runAnalysis(): Promise<void> {
  if (!selectedFile) return;
  const run = document.getElementById('stego-run') as HTMLButtonElement | null;
  const status = document.getElementById('stego-status');
  activeRequest?.abort();
  activeRequest = new AbortController();
  if (run) { run.disabled = true; run.innerHTML = `${icons.loader} Analyzing...`; }
  if (status) status.textContent = 'Running bounded image analysis in the worker pool…';
  try {
    latestResponse = await analyzeStegoImage(selectedFile, showAll, deepScan, activeRequest.signal);
    activeTab = 'zsteg';
    inspectedFindingId = null;
    renderShell();
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    let message = error instanceof Error ? error.message : 'Steganography analysis failed.';
    if (error instanceof ApiError && error.code === 'NETWORK_ERROR') {
      try {
        await apiRequest<{ status: string }>('/health');
        message = 'The backend is online, but the steganography request was interrupted. Check the backend terminal for the recorded analyzer error, then retry the image.';
      } catch {
        message = 'Backend unavailable. Start the FastAPI server on 127.0.0.1:8000.';
      }
    }
    if (status) status.innerHTML = `<span style="color:var(--error)">${escapeHtml(message)}</span>`;
  } finally {
    if (run) { run.disabled = false; run.innerHTML = `${icons.play} Analyze`; }
  }
}
