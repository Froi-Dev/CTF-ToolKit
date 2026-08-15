import { ApiError } from '../api/client.ts';
import { analyzeStegoImage, type StegoAnalysisResponse } from '../api/stego.ts';
import { icons } from '../data.ts';

type StegoTab = 'overview' | 'structure' | 'channels' | 'lsb' | 'carving' | 'metadata' | 'flags';

let activeTab: StegoTab = 'overview';
let selectedFile: File | null = null;
let latestResponse: StegoAnalysisResponse | null = null;
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

function percent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function badge(ok: boolean, yes: string, no: string): string {
  return `<span class="badge ${ok ? 'badge-success' : 'badge-error'}">${ok ? yes : no}</span>`;
}

export function renderStego(): void {
  activeRequest?.abort();
  activeRequest = null;
  selectedFile = null;
  latestResponse = null;
  activeTab = 'overview';
  renderShell();
}

function renderShell(): void {
  const main = document.getElementById('main');
  if (!main) return;
  const result = latestResponse;
  const subtitle = result
    ? `${escapeHtml(result.original_filename)} · ${result.image.format} · ${result.image.width}x${result.image.height} · ${formatBytes(result.size)}`
    : 'PNG/JPEG metadata, structure, trailing data, LSB, bit-plane, entropy, and carving analysis';
  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header">
      <div><div class="page-title">Steganography</div><div class="page-subtitle">${subtitle}</div></div>
      <div class="page-actions">
        <input id="stego-file" type="file" accept="image/png,image/jpeg,.png,.jpg,.jpeg" hidden>
        <button class="btn btn-secondary btn-sm" id="stego-select">${icons.folder} Choose Image</button>
        <button class="btn btn-primary btn-sm" id="stego-run" ${selectedFile ? '' : 'disabled'}>${icons.play} Analyze</button>
      </div>
    </div>
    <div class="panel mb-4">
      <div class="panel-body flex items-center gap-4">
        <div style="flex:1">
          <div class="text-sm" id="stego-selection">${selectedFile ? escapeHtml(selectedFile.name) : 'No image selected'}</div>
          <div class="text-xs text-muted">Uploads are limited to 32 MiB. Supported formats: PNG and JPEG.</div>
        </div>
        <div class="text-xs text-muted" id="stego-status">${result ? `Analysis ${escapeHtml(result.analysis_id)}` : 'Ready'}</div>
      </div>
    </div>
    ${result ? renderTabs(result) : renderEmptyState()}
  </div>`;
  bindEvents();
}

function renderEmptyState(): string {
  return `<div class="section"><div class="panel"><div class="panel-body">
    <div class="section-title mb-4">No steganography result</div>
    <div class="text-sm text-muted">Choose a PNG or JPEG image to inspect real metadata, PNG/JPEG structure, trailing bytes, embedded signatures, channel statistics, bit planes, LSB streams, entropy, carved artifacts, and flag candidates.</div>
  </div></div></div>`;
}

function renderTabs(result: StegoAnalysisResponse): string {
  const tabs: Array<[StegoTab, string, number | null]> = [
    ['overview', 'Overview', null],
    ['structure', 'Structure', result.png_chunks.length + result.jpeg_segments.length],
    ['channels', 'Channels', result.channels.length],
    ['lsb', 'LSB', result.lsb.filter(item => item.suspicious).length],
    ['carving', 'Carving', result.carved_artifacts.length],
    ['metadata', 'Metadata', result.metadata.length],
    ['flags', 'Flag Candidates', result.flags.length],
  ];
  return `<div class="tab-bar" id="stego-tabs">${tabs.map(([id, label, count]) => `
    <div class="tab-item ${activeTab === id ? 'active' : ''}" data-tab="${id}">${label}${count === null ? '' : ` <span class="tab-count">${count}</span>`}</div>`).join('')}
  </div><div id="stego-content">${renderTab(result)}</div>`;
}

function renderTab(result: StegoAnalysisResponse): string {
  switch (activeTab) {
    case 'structure': return renderStructure(result);
    case 'channels': return renderChannels(result);
    case 'lsb': return renderLsb(result);
    case 'carving': return renderCarving(result);
    case 'metadata': return renderMetadata(result);
    case 'flags': return renderFlags(result);
    default: return renderOverview(result);
  }
}

function renderOverview(result: StegoAnalysisResponse): string {
  const suspiciousLsb = result.lsb.filter(item => item.suspicious).length;
  const warningHtml = result.warnings.length
    ? `<div class="panel mb-4"><div class="panel-header" style="color:var(--warning)">Warnings</div><div class="panel-body text-xs">${result.warnings.map(item => `<div>· ${escapeHtml(item)}</div>`).join('')}</div></div>`
    : '';
  return `<div class="forensics-layout">
    <div>
      <div class="section">
        <div class="section-title mb-4">Image Summary</div>
        <div class="panel"><div class="panel-body"><div class="kv-list">
          <div class="kv-key">Format</div><div class="kv-value mono">${result.image.format}</div>
          <div class="kv-key">Dimensions</div><div class="kv-value mono">${result.image.width} x ${result.image.height}</div>
          <div class="kv-key">Mode</div><div class="kv-value mono">${escapeHtml(result.image.mode)}${result.image.has_alpha ? ' · alpha present' : ''}</div>
          <div class="kv-key">File entropy</div><div class="kv-value mono">${result.entropy.file.bits_per_byte.toFixed(4)} bits/byte · ${escapeHtml(result.entropy.file.classification)}</div>
          <div class="kv-key">Pixel entropy</div><div class="kv-value mono">${result.entropy.pixel_data.bits_per_byte.toFixed(4)} bits/byte · ${escapeHtml(result.entropy.pixel_data.classification)}</div>
          <div class="kv-key">Trailing bytes</div><div class="kv-value">${badge(result.trailing_bytes.present, `${formatBytes(result.trailing_bytes.size)} present`, 'None detected')}</div>
        </div></div></div>
      </div>
      ${warningHtml}
    </div>
    <div>
      <div class="section">
        <div class="section-title mb-4">Stego Indicators</div>
        <div class="panel"><div class="panel-body"><div class="kv-list">
          <div class="kv-key">Embedded signatures</div><div class="kv-value mono">${result.signatures.length}</div>
          <div class="kv-key">Carved artifacts</div><div class="kv-value mono">${result.carved_artifacts.length}</div>
          <div class="kv-key">Suspicious LSB streams</div><div class="kv-value mono">${suspiciousLsb}</div>
          <div class="kv-key">Flag candidates</div><div class="kv-value mono">${result.flags.length}</div>
          <div class="kv-key">SHA-256</div><div class="kv-value mono" style="word-break:break-all">${result.hashes.sha256}</div>
        </div></div></div>
      </div>
    </div>
  </div>`;
}

function renderStructure(result: StegoAnalysisResponse): string {
  const trailing = result.trailing_bytes.present
    ? `<div class="panel mb-4"><div class="panel-header">Trailing Bytes</div><div class="panel-body"><div class="kv-list">
      <div class="kv-key">Offset</div><div class="kv-value mono">0x${result.trailing_bytes.offset.toString(16)}</div>
      <div class="kv-key">Size</div><div class="kv-value mono">${formatBytes(result.trailing_bytes.size)}</div>
      <div class="kv-key">Detected</div><div class="kv-value mono">${escapeHtml(result.trailing_bytes.detected_type || 'unknown')}</div>
      <div class="kv-key">Preview</div><div class="kv-value mono" style="word-break:break-all">${escapeHtml(result.trailing_bytes.preview_hex)}</div>
    </div></div></div>`
    : '';
  if (result.image.format === 'PNG') {
    return `<div class="section"><div class="section-header"><div class="section-title">PNG Chunks</div><span class="text-xs text-muted">${result.png_chunks_truncated ? 'Result limit reached' : `${result.png_chunks.length} chunks`}</span></div>
      ${trailing}
      <table class="data-table"><thead><tr><th>#</th><th>Type</th><th>Offset</th><th>Length</th><th>CRC</th></tr></thead><tbody>${result.png_chunks.map(chunk => `<tr>
        <td>${chunk.index}</td><td class="mono">${escapeHtml(chunk.chunk_type)}</td><td class="mono">0x${chunk.offset.toString(16)}</td><td>${formatBytes(chunk.data_length)}</td><td>${badge(chunk.crc_valid, 'Valid', 'Invalid')}</td>
      </tr>`).join('')}</tbody></table></div>`;
  }
  return `<div class="section"><div class="section-header"><div class="section-title">JPEG Segments</div><span class="text-xs text-muted">${result.jpeg_segments_truncated ? 'Result limit reached' : `${result.jpeg_segments.length} segments`}</span></div>
    ${trailing}
    <table class="data-table"><thead><tr><th>#</th><th>Marker</th><th>Name</th><th>Offset</th><th>Length</th></tr></thead><tbody>${result.jpeg_segments.map(segment => `<tr>
      <td>${segment.index}</td><td class="mono">${segment.marker}</td><td>${escapeHtml(segment.name)}</td><td class="mono">0x${segment.offset.toString(16)}</td><td>${formatBytes(segment.segment_length)}</td>
    </tr>`).join('')}</tbody></table></div>`;
}

function renderChannels(result: StegoAnalysisResponse): string {
  return `<div class="section"><div class="section-title mb-4">Color Channel Inspection</div>
    <table class="data-table mb-4"><thead><tr><th>Channel</th><th>Range</th><th>Mean</th><th>Std Dev</th><th>Entropy</th><th>LSB Ones</th></tr></thead><tbody>${result.channels.map(channel => `<tr>
      <td class="mono">${escapeHtml(channel.channel)}</td><td>${channel.minimum}-${channel.maximum}</td><td>${channel.mean.toFixed(2)}</td><td>${channel.standard_deviation.toFixed(2)}</td><td>${channel.entropy.toFixed(4)}</td><td>${percent(channel.lsb_one_ratio)}</td>
    </tr>`).join('')}</tbody></table>
    <div class="section-title mb-4">Bit Planes</div>
    <table class="data-table"><thead><tr><th>Channel</th><th>Bit</th><th>One Ratio</th><th>Binary Entropy</th><th>Bias</th></tr></thead><tbody>${result.bit_planes.map(plane => `<tr>
      <td class="mono">${escapeHtml(plane.channel)}</td><td>${plane.bit}</td><td>${percent(plane.one_ratio)}</td><td>${plane.entropy.toFixed(4)}</td><td>${plane.biased ? '<span class="badge badge-error">Biased</span>' : '<span class="badge badge-success">Balanced</span>'}</td>
    </tr>`).join('')}</tbody></table></div>`;
}

function renderLsb(result: StegoAnalysisResponse): string {
  return `<div class="section"><div class="section-title mb-4">Least Significant Bit Streams</div>
    <table class="data-table"><thead><tr><th>Stream</th><th>Extracted</th><th>Printable</th><th>Entropy</th><th>Signals</th><th>Preview</th></tr></thead><tbody>${result.lsb.map(item => `<tr>
      <td class="mono">${escapeHtml(item.stream)}</td><td>${formatBytes(item.extracted_bytes)}${item.truncated ? ' · truncated' : ''}</td><td>${percent(item.printable_ratio)}</td><td>${item.entropy.bits_per_byte.toFixed(4)}</td><td>${item.suspicious ? '<span class="badge badge-error">Review</span>' : '<span class="badge badge-success">Quiet</span>'} ${item.signatures.length ? `${item.signatures.length} sig` : ''} ${item.flags.length ? `${item.flags.length} flag` : ''}</td><td class="mono" style="word-break:break-all">${escapeHtml(item.preview_ascii)}</td>
    </tr>`).join('')}</tbody></table></div>`;
}

function renderCarving(result: StegoAnalysisResponse): string {
  const signatures = result.signatures.length
    ? `<table class="data-table mb-4"><thead><tr><th>Offset</th><th>Type</th><th>Source</th><th>Size</th><th>Carved</th></tr></thead><tbody>${result.signatures.map(item => `<tr>
      <td class="mono">0x${item.offset.toString(16)}</td><td>${escapeHtml(item.detected_type)}</td><td>${escapeHtml(item.source)}</td><td>${item.estimated_size === null ? 'unknown' : formatBytes(item.estimated_size)}</td><td>${item.carved_artifact_id ? '<span class="badge badge-success">Yes</span>' : '<span class="badge badge-error">No</span>'}</td>
    </tr>`).join('')}</tbody></table>`
    : '<div class="text-sm text-muted mb-4">No embedded or trailing file signatures were found.</div>';
  const carved = result.carved_artifacts.length
    ? `<table class="data-table"><thead><tr><th>Offset</th><th>Detected</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>${result.carved_artifacts.map(item => `<tr>
      <td class="mono">0x${item.source_offset.toString(16)}</td><td>${escapeHtml(item.detected_type)}</td><td>${formatBytes(item.size)}</td><td class="mono" style="word-break:break-all">${item.hashes.sha256}</td>
    </tr>`).join('')}</tbody></table>`
    : '<div class="text-sm text-muted">No artifact could be safely carved within current limits.</div>';
  return `<div class="section"><div class="section-title mb-4">Signature Carving</div>${signatures}<div class="section-title mb-4">Carved Artifacts</div>${carved}</div>`;
}

function renderMetadata(result: StegoAnalysisResponse): string {
  return `<div class="section"><div class="section-title mb-4">Image Metadata</div><div class="panel"><div class="panel-body"><div class="kv-list">${result.metadata.map(item => `
    <div class="kv-key">${escapeHtml(item.source)} · ${escapeHtml(item.key)}</div><div class="kv-value mono">${escapeHtml(item.value)}</div>`).join('')}
  </div></div></div></div>`;
}

function renderFlags(result: StegoAnalysisResponse): string {
  if (!result.flags.length) return '<div class="section"><div class="text-sm text-muted">No configured flag pattern matched the image, metadata, trailing bytes, carved data, or extracted LSB streams.</div></div>';
  return `<div class="section"><div class="section-title mb-4">Review Required</div>${result.flags.map(flag => `<div class="panel mb-4">
    <div class="panel-header" style="color:var(--success)">${icons.flag} Candidate · ${Math.round(flag.confidence * 100)}%</div>
    <div class="panel-body"><div class="mono" style="word-break:break-all">${escapeHtml(flag.value)}</div><div class="text-xs text-muted mt-4">${escapeHtml(flag.source)} · byte offset 0x${flag.offset.toString(16)} · not automatically confirmed</div><div class="text-xs mono mt-4">${escapeHtml(flag.context)}</div></div>
  </div>`).join('')}</div>`;
}

function bindEvents(): void {
  const input = document.getElementById('stego-file') as HTMLInputElement | null;
  const select = document.getElementById('stego-select') as HTMLButtonElement | null;
  const run = document.getElementById('stego-run') as HTMLButtonElement | null;
  select?.addEventListener('click', () => input?.click());
  input?.addEventListener('change', () => {
    selectedFile = input.files?.[0] || null;
    latestResponse = null;
    activeTab = 'overview';
    renderShell();
  });
  run?.addEventListener('click', () => void runAnalysis());
  document.querySelectorAll<HTMLElement>('#stego-tabs .tab-item').forEach(tab => {
    tab.addEventListener('click', () => {
      activeTab = (tab.dataset.tab as StegoTab | undefined) || 'overview';
      renderShell();
    });
  });
}

async function runAnalysis(): Promise<void> {
  if (!selectedFile) return;
  const run = document.getElementById('stego-run') as HTMLButtonElement | null;
  const status = document.getElementById('stego-status');
  activeRequest?.abort();
  activeRequest = new AbortController();
  if (run) {
    run.disabled = true;
    run.innerHTML = `${icons.loader} Analyzing...`;
  }
  if (status) status.textContent = 'Inspecting image structure, channels, and hidden-data candidates...';
  try {
    latestResponse = await analyzeStegoImage(selectedFile, activeRequest.signal);
    activeTab = 'overview';
    renderShell();
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    const message = error instanceof ApiError && error.code === 'NETWORK_ERROR'
      ? 'Backend unavailable. Start the FastAPI server on 127.0.0.1:8000.'
      : error instanceof Error ? error.message : 'Steganography analysis failed.';
    if (status) status.innerHTML = `<span style="color:var(--error)">${escapeHtml(message)}</span>`;
  } finally {
    if (run) {
      run.disabled = false;
      run.innerHTML = `${icons.play} Analyze`;
    }
  }
}
