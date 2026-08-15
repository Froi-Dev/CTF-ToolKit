import { ApiError } from '../api/client.ts';
import {
  analyzePcapFile,
  type NetworkAnalysisResponse,
  type ProtocolHierarchyNode,
  type TcpStream,
} from '../api/network.ts';
import { icons } from '../data.ts';

type NetworkTab = 'overview' | 'packets' | 'protocols' | 'conversations' | 'application' | 'streams' | 'evidence' | 'timeline';
type StreamView = 'ascii' | 'hex';

const MAX_UPLOAD_BYTES = 128 * 1024 * 1024;
const MAX_TABLE_ROWS = 500;
const MAX_STREAM_RENDER_BYTES = 128 * 1024;

let activeTab: NetworkTab = 'overview';
let activeStreamView: StreamView = 'ascii';
let selectedFile: File | null = null;
let latestResponse: NetworkAnalysisResponse | null = null;
let selectedStreamId: number | null = null;
let activeRequest: AbortController | null = null;
let analyzing = false;
let statusMessage = 'Ready for an offline capture artifact';
let statusIsError = false;

function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>'"]/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character] || character);
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MiB`;
  return `${(value / 1024 ** 3).toFixed(1)} GiB`;
}

function formatDuration(seconds: number): string {
  const whole = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(whole / 3600);
  const minutes = Math.floor((whole % 3600) / 60);
  const remaining = whole % 60;
  return [hours, minutes, remaining].map(value => String(value).padStart(2, '0')).join(':');
}

function formatTimestamp(value: string | null): string {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function emptyTableRow(columns: number, message: string): string {
  return `<tr><td colspan="${columns}" class="text-muted">${escapeHtml(message)}</td></tr>`;
}

export function renderNetwork(): void {
  activeRequest?.abort();
  activeRequest = null;
  activeTab = 'overview';
  activeStreamView = 'ascii';
  selectedFile = null;
  latestResponse = null;
  selectedStreamId = null;
  analyzing = false;
  statusMessage = 'Ready for an offline capture artifact';
  statusIsError = false;
  renderShell();
}

function renderShell(): void {
  const main = document.getElementById('main');
  if (!main) return;
  const result = latestResponse;
  const subtitle = result
    ? `${escapeHtml(result.capture.original_filename)} · ${result.capture.packet_count.toLocaleString()} decoded packets · offline analysis`
    : 'Upload a provided CTF PCAP or PCAPNG file for offline investigation';
  main.innerHTML = `<div class="main-content-wide" id="network-page">
    <div class="page-header">
      <div><div class="page-title">Network / PCAP Analysis</div><div class="page-subtitle">${subtitle}</div></div>
      <div class="page-actions">
        <input id="network-file" type="file" accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap,application/x-pcapng" hidden>
        ${result ? `<button class="btn btn-secondary btn-sm" id="network-export">${icons.download} Export JSON</button>` : ''}
        <button class="btn btn-secondary btn-sm" id="network-select">${icons.folder} Choose PCAP</button>
        <button class="btn btn-primary btn-sm" id="network-run" ${selectedFile && !analyzing ? '' : 'disabled'}>${analyzing ? `${icons.loader} Analyzing…` : `${icons.play} Analyze`}</button>
      </div>
    </div>
    <div class="panel mb-4">
      <div class="panel-body flex items-center gap-4">
        <div style="flex:1;min-width:0">
          <div class="text-sm truncate" id="network-selection">${selectedFile ? escapeHtml(selectedFile.name) : 'No capture selected'}</div>
          <div class="text-xs text-muted">PCAP/PCAPNG only, up to 128 MiB. The saved capture is analyzed offline; no network interface is accessed.</div>
        </div>
        <div class="text-xs ${statusIsError ? '' : 'text-muted'}" id="network-status" ${statusIsError ? 'style="color:var(--error)"' : ''}>${escapeHtml(statusMessage)}</div>
      </div>
    </div>
    ${result ? renderResults(result) : renderUploadState()}
  </div>`;
  bindEvents();
}

function renderUploadState(): string {
  return `<div class="section">
    <div class="drop-zone" id="network-drop-zone" role="button" tabindex="0">
      <div class="drop-zone-icon">${icons.upload}</div>
      <div class="drop-zone-text">Drop a challenge capture here or choose a PCAP</div>
      <div class="drop-zone-hint">No sample packets, findings, credentials, or conversations are displayed before analysis.</div>
    </div>
  </div>`;
}

function renderResults(result: NetworkAnalysisResponse): string {
  const tabs: Array<[NetworkTab, string, number | null]> = [
    ['overview', 'Overview', null],
    ['packets', 'Packets', result.packets.length],
    ['protocols', 'Protocols', null],
    ['conversations', 'Conversations', result.conversations.length],
    ['application', 'DNS / HTTP / FTP', result.dns.length + result.http.length + result.ftp.length],
    ['streams', 'TCP Streams', result.tcp_streams.length],
    ['evidence', 'Evidence', result.plaintext_credentials.length + result.transferred_files.length + result.flags.length],
    ['timeline', 'Timeline', result.timeline.length],
  ];
  return `${renderStats(result)}
    <div class="tab-bar network-tabs" id="network-tabs">${tabs.map(([id, label, count]) => `
      <div class="tab-item ${activeTab === id ? 'active' : ''}" data-tab="${id}">${label}${count === null ? '' : ` <span class="tab-count">${count}</span>`}</div>`).join('')}
    </div>
    <div id="network-content">${renderTab(result)}</div>`;
}

function renderStats(result: NetworkAnalysisResponse): string {
  const dnsQueries = result.dns.filter(record => record.kind === 'query').length;
  const httpRequests = result.http.filter(message => message.kind === 'request').length;
  return `<div class="pcap-stats"><div class="stat-row">
    <div class="stat-item"><div class="stat-label">Decoded Packets</div><div class="stat-value">${result.capture.packet_count.toLocaleString()}</div></div>
    <div class="stat-item"><div class="stat-label">Duration</div><div class="stat-value">${formatDuration(result.capture.duration_seconds)}</div></div>
    <div class="stat-item"><div class="stat-label">Unique Hosts</div><div class="stat-value">${result.capture.unique_hosts.toLocaleString()}</div></div>
    <div class="stat-item"><div class="stat-label">TCP Streams</div><div class="stat-value">${result.tcp_streams.length.toLocaleString()}</div></div>
    <div class="stat-item"><div class="stat-label">DNS Queries</div><div class="stat-value">${dnsQueries.toLocaleString()}</div></div>
    <div class="stat-item"><div class="stat-label">HTTP Requests</div><div class="stat-value">${httpRequests.toLocaleString()}</div></div>
  </div></div>`;
}

function renderTab(result: NetworkAnalysisResponse): string {
  switch (activeTab) {
    case 'packets': return renderPackets(result);
    case 'protocols': return renderProtocols(result);
    case 'conversations': return renderConversations(result);
    case 'application': return renderApplication(result);
    case 'streams': return renderStreams(result);
    case 'evidence': return renderEvidence(result);
    case 'timeline': return renderTimeline(result);
    default: return renderOverview(result);
  }
}

function renderOverview(result: NetworkAnalysisResponse): string {
  const warnings = result.warnings.length
    ? `<div class="panel mb-4"><div class="panel-header" style="color:var(--warning)">Analysis warnings</div><div class="panel-body text-xs">${result.warnings.map(warning => `<div>· ${escapeHtml(warning)}</div>`).join('')}</div></div>`
    : '';
  return `${warnings}<div class="network-evidence-grid mb-8">
    <div class="panel"><div class="panel-header">Capture artifact</div><div class="panel-body"><div class="kv-list">
      <div class="kv-key">Format</div><div class="kv-value mono">${escapeHtml(result.capture.format)}</div>
      <div class="kv-key">File size</div><div class="kv-value">${formatBytes(result.capture.size)}</div>
      <div class="kv-key">Captured bytes</div><div class="kv-value">${formatBytes(result.capture.captured_bytes)}</div>
      <div class="kv-key">First packet</div><div class="kv-value">${escapeHtml(formatTimestamp(result.capture.first_seen))}</div>
      <div class="kv-key">Last packet</div><div class="kv-value">${escapeHtml(formatTimestamp(result.capture.last_seen))}</div>
      <div class="kv-key">SHA-256</div><div class="kv-value mono" style="word-break:break-all">${result.capture.sha256}</div>
    </div></div></div>
    <div class="panel"><div class="panel-header">Discovered evidence</div><div class="panel-body"><div class="kv-list">
      <div class="kv-key">Credentials</div><div class="kv-value">${result.plaintext_credentials.length}</div>
      <div class="kv-key">Transferred files</div><div class="kv-value">${result.transferred_files.length}</div>
      <div class="kv-key">Flag candidates</div><div class="kv-value">${result.flags.length}</div>
      <div class="kv-key">Interesting ports</div><div class="kv-value">${result.interesting_ports.length}</div>
      <div class="kv-key">Timeline events</div><div class="kv-value">${result.timeline.length}</div>
      <div class="kv-key">Analyzer</div><div class="kv-value mono">${escapeHtml(result.analyzer)}</div>
    </div></div></div>
  </div>
  <div class="split-h split-h-1-1"><div>${renderProtocols(result, 12)}</div><div>${renderConversations(result, 12)}</div></div>`;
}

function flattenProtocols(nodes: ProtocolHierarchyNode[], depth = 0): Array<{ node: ProtocolHierarchyNode; depth: number }> {
  return nodes.flatMap(node => [{ node, depth }, ...flattenProtocols(node.children, depth + 1)]);
}

function renderProtocols(result: NetworkAnalysisResponse, limit?: number): string {
  const all = flattenProtocols(result.protocol_hierarchy);
  const rows = all.slice(0, limit ?? all.length);
  return `<div class="section"><div class="section-header"><div class="section-title">Protocol hierarchy</div><span class="text-xs text-muted">${all.length} decoded layers</span></div>
    <table class="data-table"><thead><tr><th>Protocol</th><th>Packets</th><th>Capture %</th></tr></thead><tbody>
      ${rows.length ? rows.map(({ node, depth }) => `<tr><td class="font-medium" style="padding-left:calc(var(--sp-4) + ${depth} * var(--sp-6))">${escapeHtml(node.protocol)}</td><td class="mono">${node.packets.toLocaleString()}</td><td><div class="flex items-center gap-3"><div class="network-protocol-bar"><div style="width:${Math.min(100, node.percentage)}%"></div></div><span class="text-xs text-muted">${node.percentage.toFixed(2)}%</span></div></td></tr>`).join('') : emptyTableRow(3, 'No protocol hierarchy was decoded.')}
    </tbody></table></div>`;
}

function renderConversations(result: NetworkAnalysisResponse, limit?: number): string {
  const conversations = result.conversations.slice(0, limit ?? MAX_TABLE_ROWS);
  return `<div class="section"><div class="section-header"><div class="section-title">Conversations</div><span class="text-xs text-muted">${result.conversations.length > conversations.length ? `Showing ${conversations.length} of ${result.conversations.length}` : `${conversations.length} results`}</span></div>
    <table class="data-table"><thead><tr><th>Endpoint A</th><th>Endpoint B</th><th>Transport</th><th>Packets</th><th>Bytes</th><th>Applications</th></tr></thead><tbody>
      ${conversations.length ? conversations.map(item => `<tr><td class="mono">${escapeHtml(item.endpoint_a)}</td><td class="mono">${escapeHtml(item.endpoint_b)}</td><td>${escapeHtml(item.transport.toUpperCase())}</td><td>${(item.packets_a_to_b + item.packets_b_to_a).toLocaleString()}</td><td>${formatBytes(item.bytes_a_to_b + item.bytes_b_to_a)}</td><td>${escapeHtml(item.application_protocols.join(', ') || '—')}</td></tr>`).join('') : emptyTableRow(6, 'No TCP or UDP conversations were found.')}
    </tbody></table></div>`;
}

function renderPackets(result: NetworkAnalysisResponse): string {
  const packets = result.packets.slice(0, MAX_TABLE_ROWS);
  const limitNote = result.packet_records_truncated || result.packets.length > packets.length
    ? `Showing ${packets.length} bounded packet records; the backend reported additional packets.`
    : `${packets.length} packet records`;
  return `<div class="section"><div class="section-header"><div class="section-title">Packet metadata</div><span class="text-xs text-muted">${limitNote}</span></div>
    <table class="data-table"><thead><tr><th>No.</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr></thead><tbody>
      ${packets.length ? packets.map(packet => `<tr><td class="mono">${packet.number}</td><td class="mono">${escapeHtml(formatTimestamp(packet.timestamp))}</td><td class="mono">${escapeHtml(packet.source || '—')}${packet.source_port === null ? '' : `:${packet.source_port}`}</td><td class="mono">${escapeHtml(packet.destination || '—')}${packet.destination_port === null ? '' : `:${packet.destination_port}`}</td><td>${escapeHtml(packet.displayed_protocol)}</td><td>${formatBytes(packet.wire_length)}</td><td class="text-muted">${escapeHtml(packet.info)}</td></tr>`).join('') : emptyTableRow(7, 'No packets were decoded from the capture.')}
    </tbody></table></div>`;
}

function renderApplication(result: NetworkAnalysisResponse): string {
  const dns = result.dns.slice(0, MAX_TABLE_ROWS);
  const http = result.http.slice(0, MAX_TABLE_ROWS);
  const ftp = result.ftp.slice(0, MAX_TABLE_ROWS);
  return `<div class="section"><div class="section-header"><div class="section-title">DNS</div><span class="text-xs text-muted">${result.dns.length} records</span></div>
    <table class="data-table"><thead><tr><th>Frame</th><th>Kind</th><th>Name</th><th>Type</th><th>Answers</th></tr></thead><tbody>${dns.length ? dns.map(item => `<tr><td class="mono">${item.frame_number}</td><td>${escapeHtml(item.kind)}</td><td class="mono">${escapeHtml(item.name || '—')}</td><td>${escapeHtml(item.query_type || '—')}</td><td class="mono">${escapeHtml(item.answers.join(', ') || '—')}</td></tr>`).join('') : emptyTableRow(5, 'No DNS traffic was found.')}</tbody></table></div>
    <div class="section"><div class="section-header"><div class="section-title">HTTP</div><span class="text-xs text-muted">${result.http.length} messages</span></div>
    <table class="data-table"><thead><tr><th>Frame</th><th>Kind</th><th>Method / Status</th><th>Host</th><th>URI</th><th>Content</th></tr></thead><tbody>${http.length ? http.map(item => `<tr><td class="mono">${item.frame_number}</td><td>${escapeHtml(item.kind)}</td><td>${escapeHtml(item.method || item.status_code || '—')}</td><td class="mono">${escapeHtml(item.host || '—')}</td><td class="mono">${escapeHtml(item.uri || '—')}</td><td>${escapeHtml(item.content_type || '—')}</td></tr>`).join('') : emptyTableRow(6, 'No HTTP traffic was found.')}</tbody></table></div>
    <div class="section"><div class="section-header"><div class="section-title">FTP</div><span class="text-xs text-muted">${result.ftp.length} messages</span></div>
    <table class="data-table"><thead><tr><th>Frame</th><th>Kind</th><th>Command / Code</th><th>Argument / Response</th><th>Stream</th></tr></thead><tbody>${ftp.length ? ftp.map(item => `<tr><td class="mono">${item.frame_number}</td><td>${escapeHtml(item.kind)}</td><td class="mono">${escapeHtml(item.command || item.response_code || '—')}</td><td class="mono">${escapeHtml(item.argument || item.response_text || '—')}</td><td>${item.stream_id === null ? '—' : `#${item.stream_id}`}</td></tr>`).join('') : emptyTableRow(5, 'No FTP control traffic was found.')}</tbody></table></div>
    <div class="section"><div class="section-header"><div class="section-title">Interesting ports</div><span class="text-xs text-muted">Evidence-based service hints</span></div>
    <table class="data-table"><thead><tr><th>Port</th><th>Transport</th><th>Service</th><th>Packets</th><th>Reason</th></tr></thead><tbody>${result.interesting_ports.length ? result.interesting_ports.map(item => `<tr><td class="mono">${item.port}</td><td>${item.transport.toUpperCase()}</td><td>${escapeHtml(item.service)}</td><td>${item.packet_count.toLocaleString()}</td><td class="text-muted">${escapeHtml(item.reason)}</td></tr>`).join('') : emptyTableRow(5, 'No configured interesting ports were observed.')}</tbody></table></div>`;
}

function renderStreams(result: NetworkAnalysisResponse): string {
  const streams = result.tcp_streams.slice(0, MAX_TABLE_ROWS);
  const selected = result.tcp_streams.find(stream => stream.stream_id === selectedStreamId) || null;
  return `<div class="section"><div class="section-header"><div class="section-title">TCP stream discovery</div><span class="text-xs text-muted">Select a stream to inspect TShark reconstruction</span></div>
    <table class="data-table"><thead><tr><th>Stream</th><th>Endpoint A</th><th>Endpoint B</th><th>Protocols</th><th>Packets</th><th>Wire bytes</th><th>Reconstructed</th><th>State</th></tr></thead><tbody>
      ${streams.length ? streams.map(stream => `<tr class="clickable ${selected?.stream_id === stream.stream_id ? 'network-row-selected' : ''}" data-stream="${stream.stream_id}"><td class="mono">#${stream.stream_id}</td><td class="mono">${escapeHtml(stream.endpoint_a)}</td><td class="mono">${escapeHtml(stream.endpoint_b)}</td><td>${escapeHtml(stream.application_protocols.join(', ') || 'TCP')}</td><td>${stream.packet_count.toLocaleString()}</td><td>${formatBytes(stream.wire_bytes)}</td><td>${formatBytes(stream.reconstructed_bytes)}</td><td>${stream.reset_seen ? '<span class="badge badge-warning">RST</span>' : stream.fin_seen ? '<span class="badge badge-success">FIN</span>' : '<span class="badge badge-info">Observed</span>'}</td></tr>`).join('') : emptyTableRow(8, 'No TCP streams were discovered.')}
    </tbody></table></div>${selected ? renderStreamViewer(selected) : '<div class="panel"><div class="panel-body text-sm text-muted">Select a reconstructed stream above.</div></div>'}`;
}

function decodeStreamPrefix(stream: TcpStream): Uint8Array {
  try {
    const binary = atob(stream.reconstructed_base64);
    const length = Math.min(binary.length, MAX_STREAM_RENDER_BYTES);
    const bytes = new Uint8Array(length);
    for (let index = 0; index < length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes;
  } catch {
    return new Uint8Array();
  }
}

function renderStreamViewer(stream: TcpStream): string {
  const content = activeStreamView === 'hex' ? renderHexStream(stream) : renderAsciiStream(stream);
  return `<div class="section"><div class="section-header"><div class="section-title">Reconstructed stream #${stream.stream_id}</div><span class="text-xs text-muted">${escapeHtml(stream.endpoint_a)} ↔ ${escapeHtml(stream.endpoint_b)}${stream.reconstruction_truncated ? ' · backend limit reached' : ''}</span></div>
    <div class="raw-viewer"><div class="raw-viewer-toolbar"><div class="tab-bar" style="border:none;margin:0">
      <div class="tab-item ${activeStreamView === 'ascii' ? 'active' : ''}" data-stream-view="ascii" style="padding:var(--sp-2) var(--sp-4);font-size:var(--text-xs)">ASCII</div>
      <div class="tab-item ${activeStreamView === 'hex' ? 'active' : ''}" data-stream-view="hex" style="padding:var(--sp-2) var(--sp-4);font-size:var(--text-xs)">Hex</div>
    </div><div class="topbar-spacer"></div><span class="text-xs text-muted">Rendering up to ${formatBytes(MAX_STREAM_RENDER_BYTES)}</span></div>
    <div class="raw-viewer-content">${content}</div></div></div>`;
}

function renderAsciiStream(stream: TcpStream): string {
  const bytes = decodeStreamPrefix(stream);
  const text = Array.from(bytes, byte => byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.').join('');
  if (!text) return '<div class="empty-state-text">No reconstructed payload bytes are available.</div>';
  return text.split(/\r?\n/).map((line, index) => {
    let safe = escapeHtml(line);
    safe = safe.replace(/\b(USER|PASS|RETR|Authorization:)\b/gi, '<span class="code-highlight">$1</span>');
    return `<div class="code-line"><span class="code-line-num">${index + 1}</span><span class="code-line-content">${safe}</span></div>`;
  }).join('');
}

function renderHexStream(stream: TcpStream): string {
  const bytes = decodeStreamPrefix(stream);
  if (!bytes.length) return '<div class="empty-state-text">No reconstructed payload bytes are available.</div>';
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = bytes.slice(offset, offset + 16);
    const hex = Array.from(chunk, byte => byte.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
    const ascii = Array.from(chunk, byte => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.').join('');
    lines.push(`${offset.toString(16).padStart(8, '0')}  ${hex}  |${escapeHtml(ascii)}|`);
  }
  return `<pre>${lines.join('\n')}</pre>`;
}

function renderEvidence(result: NetworkAnalysisResponse): string {
  return `<div class="section"><div class="section-header"><div class="section-title">Plaintext credential candidates</div><span class="text-xs text-muted">Sensitive evidence from decoded traffic</span></div>
    <table class="data-table"><thead><tr><th>Protocol</th><th>Username</th><th>Secret</th><th>Stream</th><th>Confidence</th><th>Source</th></tr></thead><tbody>${result.plaintext_credentials.length ? result.plaintext_credentials.map(item => `<tr><td>${escapeHtml(item.protocol)}</td><td class="mono">${escapeHtml(item.username || '—')}</td><td class="mono" style="color:var(--warning)">${escapeHtml(item.secret)}</td><td>${item.stream_id === null ? '—' : `#${item.stream_id}`}</td><td>${Math.round(item.confidence * 100)}%</td><td class="text-muted">${escapeHtml(item.source)}</td></tr>`).join('') : emptyTableRow(6, 'No plaintext credential pattern was detected.')}</tbody></table></div>
    <div class="section"><div class="section-header"><div class="section-title">Transferred files</div><span class="text-xs text-muted">Temporary TShark exports are not retained by the backend</span></div>
    <table class="data-table"><thead><tr><th>Name</th><th>Protocol</th><th>Size</th><th>SHA-256</th><th>Content</th></tr></thead><tbody>${result.transferred_files.length ? result.transferred_files.map(item => `<tr><td class="mono">${escapeHtml(item.source_name)}</td><td>${escapeHtml(item.protocol)}</td><td>${formatBytes(item.size)}</td><td class="mono" style="word-break:break-all">${item.sha256}</td><td><button class="btn btn-secondary btn-sm" data-file-id="${escapeHtml(item.artifact_id)}">${icons.download} Download${item.content_truncated ? ' preview' : ''}</button></td></tr>`).join('') : emptyTableRow(5, 'No HTTP or FTP transferred object was exported.')}</tbody></table></div>
    <div class="section"><div class="section-header"><div class="section-title">Flag candidates</div><span class="text-xs text-muted">Regex candidates require analyst review</span></div>
      ${result.flags.length ? result.flags.map(flag => `<div class="panel mb-4"><div class="panel-header" style="color:var(--success)">${icons.flag} ${escapeHtml(flag.value)}</div><div class="panel-body"><div class="text-xs text-muted">${escapeHtml(flag.source)} · byte offset 0x${flag.offset.toString(16)} · ${Math.round(flag.confidence * 100)}% confidence · not automatically confirmed</div><div class="mono text-xs mt-4" style="word-break:break-all">${escapeHtml(flag.context)}</div></div></div>`).join('') : '<div class="text-sm text-muted">No configured flag pattern matched reconstructed streams or transferred files.</div>'}
    </div>`;
}

function renderTimeline(result: NetworkAnalysisResponse): string {
  const events = result.timeline.slice(0, MAX_TABLE_ROWS);
  return `<div class="section"><div class="section-header"><div class="section-title">Evidence timeline</div><span class="text-xs text-muted">Capture timestamps, not analysis time${events.length < result.timeline.length ? ` · showing ${events.length} of ${result.timeline.length}` : ''}</span></div>
    ${events.length ? `<div class="timeline">${events.map(event => `<div class="timeline-item"><div class="timeline-dot dot-info"></div><div class="timeline-content"><span class="font-medium">${escapeHtml(event.title)}</span> <span class="badge badge-info">${escapeHtml(event.event_type)}</span><div class="text-sm text-secondary">${escapeHtml(event.description)}</div><div class="timeline-time">${escapeHtml(formatTimestamp(event.timestamp))}${event.frame_number === null ? '' : ` · frame ${event.frame_number}`}${event.stream_id === null ? '' : ` · stream #${event.stream_id}`}</div></div></div>`).join('')}</div>` : '<div class="text-sm text-muted">No DNS, HTTP, or FTP timeline events were extracted.</div>'}
  </div>`;
}

function bindEvents(): void {
  const input = document.getElementById('network-file') as HTMLInputElement | null;
  const select = document.getElementById('network-select') as HTMLButtonElement | null;
  const run = document.getElementById('network-run') as HTMLButtonElement | null;
  const dropZone = document.getElementById('network-drop-zone');
  select?.addEventListener('click', () => input?.click());
  input?.addEventListener('change', () => selectCapture(input.files?.[0] || null));
  run?.addEventListener('click', () => void runAnalysis());
  dropZone?.addEventListener('click', () => input?.click());
  dropZone?.addEventListener('keydown', event => {
    if (event.key === 'Enter' || event.key === ' ') input?.click();
  });
  for (const eventName of ['dragenter', 'dragover']) {
    dropZone?.addEventListener(eventName, event => {
      event.preventDefault();
      dropZone.classList.add('dragover');
    });
  }
  for (const eventName of ['dragleave', 'drop']) {
    dropZone?.addEventListener(eventName, event => {
      event.preventDefault();
      dropZone.classList.remove('dragover');
    });
  }
  dropZone?.addEventListener('drop', event => selectCapture((event as DragEvent).dataTransfer?.files[0] || null));
  document.getElementById('network-export')?.addEventListener('click', exportResult);
  document.querySelectorAll<HTMLElement>('#network-tabs .tab-item').forEach(tab => {
    tab.addEventListener('click', () => {
      activeTab = (tab.dataset.tab as NetworkTab | undefined) || 'overview';
      renderShell();
    });
  });
  document.querySelectorAll<HTMLElement>('[data-stream]').forEach(row => {
    row.addEventListener('click', () => {
      selectedStreamId = Number(row.dataset.stream);
      activeStreamView = 'ascii';
      renderShell();
    });
  });
  document.querySelectorAll<HTMLElement>('[data-stream-view]').forEach(tab => {
    tab.addEventListener('click', () => {
      activeStreamView = (tab.dataset.streamView as StreamView | undefined) || 'ascii';
      renderShell();
    });
  });
  document.querySelectorAll<HTMLButtonElement>('[data-file-id]').forEach(button => {
    button.addEventListener('click', () => downloadTransferredFile(button.dataset.fileId || ''));
  });
}

function selectCapture(file: File | null): void {
  activeRequest?.abort();
  activeRequest = null;
  analyzing = false;
  selectedFile = file;
  latestResponse = null;
  selectedStreamId = null;
  activeTab = 'overview';
  statusIsError = false;
  if (!file) {
    statusMessage = 'Ready for an offline capture artifact';
  } else if (file.size > MAX_UPLOAD_BYTES) {
    statusMessage = `The selected file exceeds the ${formatBytes(MAX_UPLOAD_BYTES)} upload limit.`;
    statusIsError = true;
    selectedFile = null;
  } else {
    statusMessage = `${formatBytes(file.size)} selected · ready to analyze`;
  }
  renderShell();
}

async function runAnalysis(): Promise<void> {
  if (!selectedFile || analyzing) return;
  const controller = new AbortController();
  activeRequest?.abort();
  activeRequest = controller;
  analyzing = true;
  statusIsError = false;
  statusMessage = 'Uploading the saved capture and waiting for TShark analysis…';
  renderShell();
  try {
    latestResponse = await analyzePcapFile(selectedFile, controller.signal);
    selectedStreamId = latestResponse.tcp_streams[0]?.stream_id ?? null;
    activeTab = 'overview';
    statusMessage = `Analysis ${latestResponse.analysis_id}`;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    statusIsError = true;
    statusMessage = error instanceof ApiError && error.code === 'NETWORK_ERROR'
      ? 'Backend unavailable. Start FastAPI on 127.0.0.1:8000.'
      : error instanceof ApiError && error.code === 'TOOL_NOT_AVAILABLE'
        ? 'TShark is unavailable on the backend. Install TShark and add it to PATH.'
        : error instanceof Error ? error.message : 'PCAP analysis failed.';
  } finally {
    if (activeRequest === controller) {
      activeRequest = null;
      analyzing = false;
      if (document.getElementById('network-page')) renderShell();
    }
  }
}

function exportResult(): void {
  if (!latestResponse) return;
  const blob = new Blob([JSON.stringify(latestResponse, null, 2)], { type: 'application/json' });
  downloadBlob(blob, `${latestResponse.capture.original_filename}.analysis.json`);
}

function downloadTransferredFile(artifactId: string): void {
  const file = latestResponse?.transferred_files.find(item => item.artifact_id === artifactId);
  if (!file) return;
  try {
    const binary = atob(file.content_base64);
    const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
    downloadBlob(new Blob([bytes]), file.content_truncated ? `${file.source_name}.preview` : file.source_name);
  } catch {
    statusIsError = true;
    statusMessage = `Could not decode the exported content for ${file.source_name}.`;
    renderShell();
  }
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename.replace(/[\\/:*?"<>|]/g, '_');
  anchor.click();
  URL.revokeObjectURL(url);
}
