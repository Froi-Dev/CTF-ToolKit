import { ApiError } from '../api/client.ts';
import {
  analyzePcapFile,
  getPcapAnalysisProgress,
  type InvestigationCategory,
  type InvestigationTarget,
  type NetworkAnalysisResponse,
  type NetworkFlagCandidate,
  type ProtocolHierarchyNode,
  type TcpStream,
  type UdpStream,
} from '../api/network.ts';
import { icons } from '../data.ts';
import { sendRawArtifactToDecryptor } from './crypto.ts';

type NetworkTab = 'overview' | 'investigate' | 'packets' | 'protocols' | 'conversations' | 'application' | 'streams' | 'evidence' | 'timeline';
type StreamView = 'ascii' | 'hex';
type InvestigationFilter = 'all' | InvestigationCategory;
type InvestigationSort = 'suspicion' | 'newest' | 'oldest' | 'protocol';

const MAX_UPLOAD_BYTES = 128 * 1024 * 1024;
const MAX_TABLE_ROWS = 500;
const MAX_STREAM_RENDER_BYTES = 128 * 1024;

let activeTab: NetworkTab = 'overview';
let activeStreamView: StreamView = 'ascii';
let selectedFile: File | null = null;
let latestResponse: NetworkAnalysisResponse | null = null;
let selectedStreamId: number | null = null;
let selectedStreamProtocol: 'tcp' | 'udp' = 'tcp';
let selectedTargetId: string | null = null;
let selectedPacketNumber: number | null = null;
let investigationFilter: InvestigationFilter = 'all';
let investigationSort: InvestigationSort = 'suspicion';
let activeRequest: AbortController | null = null;
let progressPollTimer: number | null = null;
let analyzing = false;
let statusMessage = '';
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
  // Module state is the current browser-session workspace. Navigating to another
  // tool must not discard an analyzed capture or interrupt an analysis in flight.
  // Selecting another capture remains the explicit replacement boundary.
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
    ['investigate', 'Investigate', result.investigation_targets.length],
    ['packets', 'Packets', result.packets.length],
    ['protocols', 'Protocols', null],
    ['conversations', 'Conversations', result.conversations.length],
    ['application', 'DNS / HTTP / FTP', result.dns.length + result.http.length + result.ftp.length],
    ['streams', 'Streams', result.tcp_streams.length + result.udp_streams.length],
    ['evidence', 'Evidence', result.plaintext_credentials.length + result.transferred_files.length + result.insights.length + result.flags.length],
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
    <div class="stat-item"><div class="stat-label">UDP Streams</div><div class="stat-value">${result.udp_streams.length.toLocaleString()}</div></div>
    <div class="stat-item"><div class="stat-label">DNS Queries</div><div class="stat-value">${dnsQueries.toLocaleString()}</div></div>
    <div class="stat-item"><div class="stat-label">HTTP Requests</div><div class="stat-value">${httpRequests.toLocaleString()}</div></div>
    <div class="stat-item"><div class="stat-label">Suspicious Targets</div><div class="stat-value">${result.investigation_summary.suspicious_targets.toLocaleString()}</div></div>
  </div></div>`;
}

function renderTab(result: NetworkAnalysisResponse): string {
  switch (activeTab) {
    case 'investigate': return renderInvestigation(result);
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
      <div class="kv-key">Encapsulation</div><div class="kv-value">${escapeHtml(result.capture.encapsulations.join(', ') || 'Unknown')}</div>
      <div class="kv-key">Interfaces</div><div class="kv-value">${result.capture.interfaces.length}</div>
      <div class="kv-key">Snap length</div><div class="kv-value">${result.capture.snap_length === null ? 'Unknown' : formatBytes(result.capture.snap_length)}</div>
      <div class="kv-key">First packet</div><div class="kv-value">${escapeHtml(formatTimestamp(result.capture.first_seen))}</div>
      <div class="kv-key">Last packet</div><div class="kv-value">${escapeHtml(formatTimestamp(result.capture.last_seen))}</div>
      <div class="kv-key">SHA-256</div><div class="kv-value mono" style="word-break:break-all">${result.capture.sha256}</div>
    </div></div></div>
    <div class="panel"><div class="panel-header">Discovered evidence</div><div class="panel-body"><div class="kv-list">
      <div class="kv-key">Credentials</div><div class="kv-value">${result.plaintext_credentials.length}</div>
      <div class="kv-key">Transferred files</div><div class="kv-value">${result.transferred_files.length}</div>
      <div class="kv-key">Flag candidates</div><div class="kv-value">${result.flags.length}</div>
      <div class="kv-key">Decoded insights</div><div class="kv-value">${result.insights.length}</div>
      <div class="kv-key">Interesting ports</div><div class="kv-value">${result.interesting_ports.length}</div>
      <div class="kv-key">Timeline events</div><div class="kv-value">${result.timeline.length}</div>
      <div class="kv-key">IPv4 / IPv6 hosts</div><div class="kv-value">${result.endpoints.ipv4_hosts.length} / ${result.endpoints.ipv6_hosts.length}</div>
      <div class="kv-key">MAC addresses</div><div class="kv-value">${result.endpoints.mac_addresses.length}</div>
      <div class="kv-key">Analyzer</div><div class="kv-value mono">${escapeHtml(result.analyzer)}</div>
    </div></div></div>
  </div>
  ${renderAnalysisTimings(result)}
  <div class="split-h split-h-1-1"><div>${renderProtocols(result, 12)}</div><div>${renderConversations(result, 12)}</div></div>`;
}

function renderAnalysisTimings(result: NetworkAnalysisResponse): string {
  const stages = result.stage_timings.filter(item => item.stage !== 'total');
  const total = result.stage_timings.find(item => item.stage === 'total');
  return `<div class="section"><div class="section-header"><div class="section-title">Analysis performance</div><span class="text-xs text-muted">${total ? `${(total.duration_ms / 1000).toFixed(2)} seconds backend total` : 'Measured backend stages'}</span></div>
    <table class="data-table"><thead><tr><th>Stage</th><th>Duration</th><th>Detail</th></tr></thead><tbody>
      ${stages.length ? stages.map(item => `<tr><td class="font-medium">${escapeHtml(item.label)}</td><td class="mono">${(item.duration_ms / 1000).toFixed(3)}s</td><td class="text-muted">${escapeHtml(item.detail || '—')}</td></tr>`).join('') : emptyTableRow(3, 'No stage timings were returned.')}
    </tbody></table>
    ${result.tool_executions.length ? `<details class="mt-4"><summary class="text-sm">External TShark executions (${result.tool_executions.length})</summary><table class="data-table mt-4"><thead><tr><th>Operation</th><th>Duration</th><th>Exit</th></tr></thead><tbody>${result.tool_executions.map(item => `<tr><td class="mono">${escapeHtml(item.operation)}</td><td class="mono">${(item.duration_ms / 1000).toFixed(3)}s</td><td>${item.returncode}</td></tr>`).join('')}</tbody></table></details>` : ''}
  </div>`;
}

function targetTypeLabel(target: InvestigationTarget): string {
  return target.target_type.replaceAll('_', ' ').replace(/\b\w/g, character => character.toUpperCase());
}

function investigationTargets(result: NetworkAnalysisResponse): InvestigationTarget[] {
  const filtered = result.investigation_targets.filter(target => investigationFilter === 'all' || target.categories.includes(investigationFilter));
  return filtered.sort((left, right) => {
    if (investigationSort === 'newest') return Date.parse(right.last_seen || '') - Date.parse(left.last_seen || '');
    if (investigationSort === 'oldest') return Date.parse(left.first_seen || '') - Date.parse(right.first_seen || '');
    if (investigationSort === 'protocol') return (left.protocol || '').localeCompare(right.protocol || '') || right.suspicion.total - left.suspicion.total;
    return right.suspicion.total - left.suspicion.total;
  });
}

function renderInvestigation(result: NetworkAnalysisResponse): string {
  const targets = investigationTargets(result);
  const selected = targets.find(target => target.id === selectedTargetId) || targets[0] || null;
  const filters: Array<[InvestigationFilter, string]> = [
    ['all', 'All'], ['streams', 'Streams'], ['packets', 'Packets'], ['dns', 'DNS'], ['http', 'HTTP'],
    ['files', 'Files'], ['credentials', 'Credentials'], ['covert', 'Covert'], ['encoded', 'Encoded'],
    ['wireless', 'Wireless'], ['tls', 'TLS'], ['rare-traffic', 'Rare Traffic'],
  ];
  const outcome = result.investigation_summary.outcome === 'solved' ? 'Flag evidence recovered'
    : result.investigation_summary.outcome === 'partially-solved' ? 'Suspicious evidence partially decoded'
      : 'Manual investigation recommended';
  return `<div class="panel mb-4 investigation-summary">
    <div class="panel-body"><div class="flex items-center justify-between gap-4">
      <div><div class="text-xs text-muted">AUTO ANALYSIS COMPLETE</div><div class="font-medium mt-2">${escapeHtml(outcome)}</div><div class="text-sm text-secondary mt-2">${escapeHtml(result.investigation_summary.message)}</div></div>
      <div class="investigation-summary-count"><span>${result.investigation_summary.suspicious_targets}</span><small>ranked targets</small></div>
    </div></div>
  </div>
  <div class="investigation-toolbar mb-4">
    <div class="investigation-filters">${filters.map(([id, label]) => `<button class="btn btn-sm ${investigationFilter === id ? 'btn-primary' : 'btn-secondary'}" data-investigation-filter="${id}">${label}</button>`).join('')}</div>
    <label class="text-xs text-muted">Sort
      <select class="form-input" id="investigation-sort">
        <option value="suspicion" ${investigationSort === 'suspicion' ? 'selected' : ''}>Highest Suspicion</option>
        <option value="newest" ${investigationSort === 'newest' ? 'selected' : ''}>Newest</option>
        <option value="oldest" ${investigationSort === 'oldest' ? 'selected' : ''}>Oldest</option>
        <option value="protocol" ${investigationSort === 'protocol' ? 'selected' : ''}>Protocol</option>
      </select>
    </label>
  </div>
  <div class="investigation-workspace">
    <div class="investigation-target-list panel">
      <div class="panel-header">Ranked Targets <span class="tab-count">${targets.length}</span></div>
      <div class="investigation-target-scroll">${targets.length ? targets.map((target, index) => `
        <button class="investigation-target ${selected?.id === target.id ? 'active' : ''}" data-investigation-target="${escapeHtml(target.id)}">
          <span class="investigation-rank">#${index + 1}</span><span class="investigation-target-copy"><strong>${escapeHtml(target.title)}</strong><small>${escapeHtml(targetTypeLabel(target))}${target.protocol ? ` - ${escapeHtml(target.protocol.toUpperCase())}` : ''}</small></span><span class="investigation-mini-score">${Math.round(target.suspicion.total)}</span>
        </button>`).join('') : '<div class="panel-body text-sm text-muted">No target matches this category. The analyzer does not fabricate results for empty categories.</div>'}</div>
    </div>
    <div>${selected ? renderInvestigationTarget(selected) : '<div class="panel"><div class="panel-body text-sm text-muted">No measurable suspicious target was identified for this view.</div></div>'}</div>
  </div>`;
}

function renderInvestigationTarget(target: InvestigationTarget): string {
  const evidenceValue = (value: unknown): string => Array.isArray(value) ? value.join(', ') : typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value);
  return `<div class="panel investigation-detail">
    <div class="panel-header flex items-center justify-between gap-4"><span>${escapeHtml(target.title)}</span><span class="badge badge-warning">${escapeHtml(targetTypeLabel(target))}</span></div>
    <div class="panel-body">
      <div class="investigation-score-row">
        <div class="investigation-score"><span>${Math.round(target.suspicion.total)}</span><small>/ 100 suspicion</small></div>
        <div class="investigation-interpretation"><div class="text-xs text-muted">INTERPRETATION</div><div class="font-medium">${escapeHtml(target.interpretation || 'Unknown pattern')}</div><div class="text-xs text-muted mt-2">${target.interpretation_confidence === null ? 'No interpretation confidence assigned' : `${Math.round(target.interpretation_confidence * 100)}% interpretation confidence`}</div></div>
      </div>
      ${target.endpoints.length ? `<div class="text-xs text-muted mt-4">Endpoints</div><div class="mono text-sm mt-2">${target.endpoints.map(escapeHtml).join(' &harr; ')}</div>` : ''}
      <details class="investigation-why mt-4" open><summary>Why is this suspicious?</summary>
        <div class="investigation-reasons">${target.suspicion.reasons.map(reason => `<div class="investigation-reason"><span class="investigation-reason-score">+${reason.score.toFixed(reason.score % 1 ? 1 : 0)}</span><div><div>${escapeHtml(reason.description)}</div>${Object.keys(reason.evidence).length ? `<div class="text-xs text-muted mt-2">${Object.entries(reason.evidence).map(([key, value]) => `${escapeHtml(key)}: ${escapeHtml(evidenceValue(value))}`).join(' - ')}</div>` : ''}</div></div>`).join('')}</div>
      </details>
      ${target.hypotheses.length ? `<div class="mt-4"><div class="text-xs text-muted">HYPOTHESES, NOT CONCLUSIONS</div>${target.hypotheses.map(item => `<div class="text-sm mt-2">${escapeHtml(item)}</div>`).join('')}</div>` : ''}
      ${target.related_flags.length ? `<div class="panel mt-4"><div class="panel-header flag-evidence-header" style="color:var(--success)">${icons.flag} Recovered flag evidence</div><div class="panel-body mono">${target.related_flags.map(escapeHtml).join('<br>')}</div></div>` : ''}
      ${target.wireshark_filter ? `<div class="mt-4"><div class="text-xs text-muted">WIRESHARK DISPLAY FILTER</div><div class="investigation-filter-box mt-2"><code>${escapeHtml(target.wireshark_filter)}</code><button class="btn btn-secondary btn-sm" data-copy-filter="${escapeHtml(target.id)}">${icons.copy} Copy Filter</button></div></div>` : '<div class="text-xs text-muted mt-4">No safe object-specific Wireshark filter could be generated.</div>'}
      ${target.interesting_frames.length ? `<div class="mt-4"><div class="text-xs text-muted">INTERESTING FRAMES</div><div class="interesting-frames mt-2">${target.interesting_frames.map(frame => `<button class="interesting-frame" data-investigation-frame="${frame.frame_number}"><span>${frame.frame_number}</span><small>${escapeHtml(frame.description)}</small></button>`).join('')}</div></div>` : ''}
      <div class="mt-4"><div class="text-xs text-muted">RECOMMENDED MANUAL INVESTIGATION</div><ol class="investigation-actions">${target.recommended_actions.map(action => `<li>${escapeHtml(action)}</li>`).join('')}</ol></div>
    </div>
  </div>`;
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
  const selected = packets.find(packet => packet.number === selectedPacketNumber) || null;
  const limitNote = result.packet_records_truncated || result.packets.length > packets.length
    ? `Showing ${packets.length} bounded packet records; the backend reported additional packets.`
    : `${packets.length} packet records`;
  return `<div class="section"><div class="section-header"><div class="section-title">Packet metadata</div><span class="text-xs text-muted">${limitNote}</span></div>
    <table class="data-table"><thead><tr><th>No.</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr></thead><tbody>
      ${packets.length ? packets.map(packet => `<tr class="clickable ${selected?.number === packet.number ? 'network-row-selected' : ''}" data-packet-frame="${packet.number}"><td class="mono">${packet.number}</td><td class="mono">${escapeHtml(formatTimestamp(packet.timestamp))}</td><td class="mono">${escapeHtml(packet.source || '—')}${packet.source_port === null ? '' : `:${packet.source_port}`}</td><td class="mono">${escapeHtml(packet.destination || '—')}${packet.destination_port === null ? '' : `:${packet.destination_port}`}</td><td>${escapeHtml(packet.displayed_protocol)}</td><td>${formatBytes(packet.wire_length)}</td><td class="text-muted">${escapeHtml(packet.info)}</td></tr>`).join('') : emptyTableRow(7, 'No packets were decoded from the capture.')}
    </tbody></table></div>${selected ? renderPacketViewer(selected) : ''}`;
}

function renderPacketViewer(packet: NetworkAnalysisResponse['packets'][number]): string {
  return `<dialog class="detail-dialog" id="network-packet-dialog" aria-labelledby="network-packet-dialog-title">
    <div class="detail-dialog-header"><div><div class="section-title" id="network-packet-dialog-title">Frame ${packet.number} details</div><div class="text-xs text-muted mt-2">Packet metadata and Wireshark reference</div></div><button class="detail-dialog-close" data-close-network-dialog aria-label="Close packet details">&times;</button></div>
    <div class="detail-dialog-body"><div class="kv-list"><div class="kv-key">Timestamp</div><div class="kv-value mono">${escapeHtml(formatTimestamp(packet.timestamp))}</div><div class="kv-key">Endpoints</div><div class="kv-value mono">${escapeHtml(packet.source || 'unknown')}${packet.source_port === null ? '' : `:${packet.source_port}`} &rarr; ${escapeHtml(packet.destination || 'unknown')}${packet.destination_port === null ? '' : `:${packet.destination_port}`}</div><div class="kv-key">Protocol stack</div><div class="kv-value mono">${escapeHtml(packet.protocol_stack.join(' -> '))}</div><div class="kv-key">Payload</div><div class="kv-value">${formatBytes(packet.payload_length)}</div><div class="kv-key">Wireshark</div><div class="kv-value mono">frame.number == ${packet.number}</div></div></div>
  </dialog>`;
}

function renderApplication(result: NetworkAnalysisResponse): string {
  const dns = result.dns.slice(0, MAX_TABLE_ROWS);
  const http = result.http.slice(0, MAX_TABLE_ROWS);
  const ftp = result.ftp.slice(0, MAX_TABLE_ROWS);
  return `<div class="section"><div class="section-header"><div class="section-title">DNS</div><span class="text-xs text-muted">${result.dns.length} records</span></div>
    <table class="data-table"><thead><tr><th>Frame</th><th>Kind</th><th>Name</th><th>Type</th><th>Answers</th></tr></thead><tbody>${dns.length ? dns.map(item => `<tr><td class="mono">${item.frame_number}</td><td>${escapeHtml(item.kind)}</td><td class="mono">${escapeHtml(item.name || '—')}</td><td>${escapeHtml(item.query_type || '—')}</td><td class="mono">${escapeHtml(item.answers.join(', ') || '—')}</td></tr>`).join('') : emptyTableRow(5, 'No DNS traffic was found.')}</tbody></table></div>
    <div class="section"><div class="section-header"><div class="section-title">HTTP</div><span class="text-xs text-muted">${result.http.length} messages</span></div>
    <table class="data-table"><thead><tr><th>Frame</th><th>Kind</th><th>Method / Status</th><th>Host / URI</th><th>User-Agent</th><th>POST / response body</th></tr></thead><tbody>${http.length ? http.map(item => `<tr><td class="mono">${item.frame_number}</td><td>${escapeHtml(item.kind)}</td><td>${escapeHtml(item.method || item.status_code || '—')}</td><td class="mono">${escapeHtml(`${item.host || ''}${item.uri || ''}` || '—')}</td><td class="mono text-xs">${escapeHtml(item.user_agent || '—')}</td><td class="mono text-xs" style="white-space:pre-wrap;word-break:break-all">${escapeHtml(item.body_ascii_preview || item.content_type || '—')}${item.body_truncated ? '…' : ''}</td></tr>`).join('') : emptyTableRow(6, 'No HTTP traffic was found.')}</tbody></table></div>
    <div class="section"><div class="section-header"><div class="section-title">FTP</div><span class="text-xs text-muted">${result.ftp.length} messages</span></div>
    <table class="data-table"><thead><tr><th>Frame</th><th>Kind</th><th>Command / Code</th><th>Argument / Response</th><th>Stream</th></tr></thead><tbody>${ftp.length ? ftp.map(item => `<tr><td class="mono">${item.frame_number}</td><td>${escapeHtml(item.kind)}</td><td class="mono">${escapeHtml(item.command || item.response_code || '—')}</td><td class="mono">${escapeHtml(item.argument || item.response_text || '—')}</td><td>${item.stream_id === null ? '—' : `#${item.stream_id}`}</td></tr>`).join('') : emptyTableRow(5, 'No FTP control traffic was found.')}</tbody></table></div>
    <div class="section"><div class="section-header"><div class="section-title">Interesting ports</div><span class="text-xs text-muted">Evidence-based service hints</span></div>
    <table class="data-table"><thead><tr><th>Port</th><th>Transport</th><th>Service</th><th>Packets</th><th>Reason</th></tr></thead><tbody>${result.interesting_ports.length ? result.interesting_ports.map(item => `<tr><td class="mono">${item.port}</td><td>${item.transport.toUpperCase()}</td><td>${escapeHtml(item.service)}</td><td>${item.packet_count.toLocaleString()}</td><td class="text-muted">${escapeHtml(item.reason)}</td></tr>`).join('') : emptyTableRow(5, 'No configured interesting ports were observed.')}</tbody></table></div>`;
}

function renderStreams(result: NetworkAnalysisResponse): string {
  const streams: Array<{ protocol: 'tcp' | 'udp'; stream: TcpStream | UdpStream }> = [
    ...result.tcp_streams.map(stream => ({ protocol: 'tcp' as const, stream })),
    ...result.udp_streams.map(stream => ({ protocol: 'udp' as const, stream })),
  ].slice(0, MAX_TABLE_ROWS);
  const selected = streams.find(item => item.protocol === selectedStreamProtocol && item.stream.stream_id === selectedStreamId) || null;
  return `<div class="section"><div class="section-header"><div class="section-title">TCP / UDP stream discovery</div><span class="text-xs text-muted">Select a stream to inspect chronological raw reconstruction</span></div>
    <table class="data-table"><thead><tr><th>Stream</th><th>Endpoint A</th><th>Endpoint B</th><th>Protocols</th><th>Packets</th><th>Wire bytes</th><th>Reconstructed</th><th>State</th></tr></thead><tbody>
      ${streams.length ? streams.map(({ protocol, stream }) => `<tr class="clickable ${selected?.protocol === protocol && selected.stream.stream_id === stream.stream_id ? 'network-row-selected' : ''}" data-stream="${stream.stream_id}" data-stream-protocol="${protocol}"><td class="mono">${protocol.toUpperCase()} #${stream.stream_id}</td><td class="mono">${escapeHtml(stream.endpoint_a)}</td><td class="mono">${escapeHtml(stream.endpoint_b)}</td><td>${escapeHtml(stream.application_protocols.join(', ') || protocol.toUpperCase())}</td><td>${stream.packet_count.toLocaleString()}</td><td>${formatBytes(stream.wire_bytes)}</td><td>${formatBytes(stream.reconstructed_bytes)}</td><td>${protocol === 'tcp' && (stream as TcpStream).reset_seen ? '<span class="badge badge-warning">RST</span>' : protocol === 'tcp' && (stream as TcpStream).fin_seen ? '<span class="badge badge-success">FIN</span>' : '<span class="badge badge-info">Observed</span>'}</td></tr>`).join('') : emptyTableRow(8, 'No TCP or UDP streams were discovered.')}
    </tbody></table></div>${selected ? renderStreamViewer(selected.stream, selected.protocol) : ''}`;
}

function decodeStreamPrefix(stream: TcpStream | UdpStream): Uint8Array {
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

function renderStreamViewer(stream: TcpStream | UdpStream, protocol: 'tcp' | 'udp'): string {
  const content = activeStreamView === 'hex' ? renderHexStream(stream) : renderAsciiStream(stream);
  return `<dialog class="detail-dialog detail-dialog-wide" id="network-stream-dialog" aria-labelledby="network-stream-dialog-title">
    <div class="detail-dialog-header"><div><div class="section-title" id="network-stream-dialog-title">Reconstructed ${protocol.toUpperCase()} stream #${stream.stream_id}</div><div class="text-xs text-muted mt-2">${escapeHtml(stream.endpoint_a)} ↔ ${escapeHtml(stream.endpoint_b)}${stream.reconstruction_truncated ? ' · backend limit reached' : ''}</div></div><button class="detail-dialog-close" data-close-network-dialog aria-label="Close stream content">&times;</button></div>
    <div class="detail-dialog-body">
    <div class="raw-viewer"><div class="raw-viewer-toolbar"><div class="tab-bar" style="border:none;margin:0">
      <div class="tab-item ${activeStreamView === 'ascii' ? 'active' : ''}" data-stream-view="ascii" style="padding:var(--sp-2) var(--sp-4);font-size:var(--text-xs)">ASCII</div>
      <div class="tab-item ${activeStreamView === 'hex' ? 'active' : ''}" data-stream-view="hex" style="padding:var(--sp-2) var(--sp-4);font-size:var(--text-xs)">Hex</div>
    </div><div class="topbar-spacer"></div><button class="btn btn-primary btn-sm" data-send-stream="${stream.stream_id}" data-send-stream-protocol="${protocol}">Send Raw to Decryptor</button><span class="text-xs text-muted">Rendering up to ${formatBytes(MAX_STREAM_RENDER_BYTES)}</span></div>
    <div class="raw-viewer-content">${content}</div></div></div>
  </dialog>`;
}

function openNetworkDialog(): void {
  const dialog = document.querySelector<HTMLDialogElement>('#network-page .detail-dialog');
  if (!dialog) return;
  dialog.addEventListener('close', () => {
    if (dialog.id === 'network-stream-dialog') selectedStreamId = null;
    if (dialog.id === 'network-packet-dialog') selectedPacketNumber = null;
  });
  dialog.addEventListener('click', event => {
    if (event.target === dialog) dialog.close();
  });
  dialog.showModal();
}

function renderAsciiStream(stream: TcpStream | UdpStream): string {
  const bytes = decodeStreamPrefix(stream);
  const text = Array.from(bytes, byte => byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.').join('');
  if (!text) return '<div class="empty-state-text">No reconstructed payload bytes are available.</div>';
  return text.split(/\r?\n/).map((line, index) => {
    let safe = escapeHtml(line);
    safe = safe.replace(/\b(USER|PASS|RETR|Authorization:)\b/gi, '<span class="code-highlight">$1</span>');
    return `<div class="code-line"><span class="code-line-num">${index + 1}</span><span class="code-line-content">${safe}</span></div>`;
  }).join('');
}

function renderHexStream(stream: TcpStream | UdpStream): string {
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

function renderFlagCandidate(flag: NetworkFlagCandidate, result: NetworkAnalysisResponse): string {
  const target = result.investigation_targets.find(item => item.related_flags.includes(flag.value));
  return `<div class="panel mb-4"><div class="panel-header flag-evidence-header" style="color:var(--success)">${icons.flag} ${escapeHtml(flag.value)}</div><div class="panel-body"><div class="text-xs text-muted">${escapeHtml(flag.source)} · byte offset 0x${flag.offset.toString(16)} · ${Math.round(flag.confidence * 100)}% confidence${flag.frame_numbers.length ? ` · frames ${flag.frame_numbers.join(', ')}` : ''} · not automatically confirmed</div>${flag.decoding_steps.length ? `<div class="text-xs mt-4">Transforms: ${escapeHtml(flag.decoding_steps.join(' → '))}</div>` : ''}<div class="mono text-xs mt-4" style="word-break:break-all">${escapeHtml(flag.context)}</div>${target?.wireshark_filter ? `<div class="investigation-filter-box mt-4"><code>${escapeHtml(target.wireshark_filter)}</code><button class="btn btn-secondary btn-sm" data-copy-filter="${escapeHtml(target.id)}">${icons.copy} Copy Wireshark Filter</button></div>` : ''}</div></div>`;
}

function renderEvidence(result: NetworkAnalysisResponse): string {
  return `<div class="section"><div class="section-header"><div class="section-title">Decoded payload and correlation insights</div><span class="text-xs text-muted">Bounded passive transforms with packet provenance</span></div>
    ${result.insights.length ? result.insights.map(item => `<div class="panel mb-4"><div class="panel-header"><span class="badge badge-info">${escapeHtml(item.category)}</span> ${escapeHtml(item.title)}</div><div class="panel-body"><div class="text-xs text-muted">${escapeHtml(item.source)} · ${Math.round(item.confidence * 100)}% confidence${item.frame_numbers.length ? ` · frames ${item.frame_numbers.join(', ')}` : ''}${item.stream_id === null ? '' : ` · stream #${item.stream_id}`}</div>${item.decoding_steps.length ? `<div class="text-xs mt-4">Transforms: ${escapeHtml(item.decoding_steps.join(' → '))}</div>` : ''}<pre class="mono text-xs mt-4" style="white-space:pre-wrap;word-break:break-all">${escapeHtml(item.value)}</pre></div></div>`).join('') : '<div class="text-sm text-muted">No encoded payload, covert-channel, broadcast, or cross-protocol correlation insight was detected.</div>'}
    </div>
    <div class="section"><div class="section-header"><div class="section-title">Plaintext credential candidates</div><span class="text-xs text-muted">Sensitive evidence from decoded traffic</span></div>
    <table class="data-table"><thead><tr><th>Protocol</th><th>Username</th><th>Secret</th><th>Stream</th><th>Confidence</th><th>Source</th></tr></thead><tbody>${result.plaintext_credentials.length ? result.plaintext_credentials.map(item => `<tr><td>${escapeHtml(item.protocol)}</td><td class="mono">${escapeHtml(item.username || '—')}</td><td class="mono" style="color:var(--warning)">${escapeHtml(item.secret)}</td><td>${item.stream_id === null ? '—' : `#${item.stream_id}`}</td><td>${Math.round(item.confidence * 100)}%</td><td class="text-muted">${escapeHtml(item.source)}</td></tr>`).join('') : emptyTableRow(6, 'No plaintext credential pattern was detected.')}</tbody></table></div>
    <div class="section"><div class="section-header"><div class="section-title">Transferred files</div><span class="text-xs text-muted">Temporary TShark exports are not retained by the backend</span></div>
    <table class="data-table"><thead><tr><th>Name</th><th>Protocol</th><th>Size</th><th>SHA-256</th><th>Content</th></tr></thead><tbody>${result.transferred_files.length ? result.transferred_files.map(item => `<tr><td class="mono">${escapeHtml(item.source_name)}</td><td>${escapeHtml(item.protocol)}</td><td>${formatBytes(item.size)}</td><td class="mono" style="word-break:break-all">${item.sha256}</td><td><button class="btn btn-secondary btn-sm" data-file-id="${escapeHtml(item.artifact_id)}">${icons.download} Download${item.content_truncated ? ' preview' : ''}</button></td></tr>`).join('') : emptyTableRow(5, 'No HTTP or FTP object was exported.')}</tbody></table></div>
    <div class="section"><div class="section-header"><div class="section-title">Flag candidates</div><span class="text-xs text-muted">Regex candidates require analyst review</span></div>
      ${result.flags.length ? result.flags.map(flag => renderFlagCandidate(flag, result)).join('') : '<div class="text-sm text-muted">No configured flag pattern matched packet payloads, reconstructed streams, decoded evidence, or transferred files.</div>'}
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
  document.querySelectorAll<HTMLButtonElement>('[data-investigation-filter]').forEach(button => {
    button.addEventListener('click', () => {
      investigationFilter = (button.dataset.investigationFilter as InvestigationFilter | undefined) || 'all';
      selectedTargetId = null;
      renderShell();
    });
  });
  document.getElementById('investigation-sort')?.addEventListener('change', event => {
    investigationSort = (event.target as HTMLSelectElement).value as InvestigationSort;
    renderShell();
  });
  document.querySelectorAll<HTMLButtonElement>('[data-investigation-target]').forEach(button => {
    button.addEventListener('click', () => {
      selectedTargetId = button.dataset.investigationTarget || null;
      renderShell();
    });
  });
  document.querySelectorAll<HTMLButtonElement>('[data-copy-filter]').forEach(button => {
    button.addEventListener('click', () => void copyInvestigationFilter(button.dataset.copyFilter || ''));
  });
  document.querySelectorAll<HTMLButtonElement>('[data-investigation-frame]').forEach(button => {
    button.addEventListener('click', () => {
      selectedPacketNumber = Number(button.dataset.investigationFrame);
      activeTab = 'packets';
      renderShell();
    });
  });
  document.querySelectorAll<HTMLElement>('[data-packet-frame]').forEach(row => {
    row.addEventListener('click', () => {
      selectedPacketNumber = Number(row.dataset.packetFrame);
      renderShell();
    });
  });
  document.querySelectorAll<HTMLButtonElement>('[data-close-network-dialog]').forEach(button => {
    button.addEventListener('click', () => button.closest<HTMLDialogElement>('dialog')?.close());
  });
  document.querySelectorAll<HTMLElement>('[data-stream]').forEach(row => {
    row.addEventListener('click', () => {
      selectedStreamId = Number(row.dataset.stream);
      selectedStreamProtocol = row.dataset.streamProtocol === 'udp' ? 'udp' : 'tcp';
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
  document.querySelectorAll<HTMLButtonElement>('[data-send-stream]').forEach(button => {
    button.addEventListener('click', () => {
      if (!latestResponse) return;
      const protocol = button.dataset.sendStreamProtocol === 'udp' ? 'udp' : 'tcp';
      const streamId = Number(button.dataset.sendStream);
      const stream = protocol === 'tcp'
        ? latestResponse.tcp_streams.find(item => item.stream_id === streamId)
        : latestResponse.udp_streams.find(item => item.stream_id === streamId);
      if (!stream?.reconstructed_base64) return;
      sendRawArtifactToDecryptor(
        `${protocol}-stream-${streamId}.bin`,
        stream.reconstructed_base64,
        `${protocol.toUpperCase()} reconstructed stream`,
        `Network Analyzer · ${protocol.toUpperCase()} Stream ${streamId}`,
      );
    });
  });
  document.querySelectorAll<HTMLButtonElement>('[data-file-id]').forEach(button => {
    button.addEventListener('click', () => downloadTransferredFile(button.dataset.fileId || ''));
  });
  openNetworkDialog();
}

function selectCapture(file: File | null): void {
  stopProgressPolling();
  activeRequest?.abort();
  activeRequest = null;
  analyzing = false;
  selectedFile = file;
  latestResponse = null;
  selectedStreamId = null;
  selectedStreamProtocol = 'tcp';
  selectedTargetId = null;
  selectedPacketNumber = null;
  investigationFilter = 'all';
  investigationSort = 'suspicion';
  activeTab = 'overview';
  statusIsError = false;
  if (!file) {
    statusMessage = '';
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
  const progressId = crypto.randomUUID();
  startProgressPolling(progressId, controller.signal);
  try {
    latestResponse = await analyzePcapFile(
      selectedFile,
      controller.signal,
      undefined,
      progressId,
    );
    selectedStreamProtocol = latestResponse.tcp_streams.length ? 'tcp' : 'udp';
    selectedStreamId = null;
    selectedTargetId = latestResponse.investigation_targets[0]?.id ?? null;
    activeTab = latestResponse.investigation_summary.outcome === 'solved' ? 'overview' : 'investigate';
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
    stopProgressPolling();
    if (activeRequest === controller) {
      activeRequest = null;
      analyzing = false;
      if (document.getElementById('network-page')) renderShell();
    }
  }
}

function startProgressPolling(progressId: string, signal: AbortSignal): void {
  stopProgressPolling();
  const poll = async (): Promise<void> => {
    if (signal.aborted) return;
    try {
      const progress = await getPcapAnalysisProgress(progressId, signal);
      statusIsError = progress.status === 'failed';
      statusMessage = `${progress.detail} · ${(progress.elapsed_ms / 1000).toFixed(1)}s elapsed`;
      const status = document.getElementById('network-status');
      if (status) {
        status.textContent = statusMessage;
        status.style.color = statusIsError ? 'var(--error)' : '';
      }
      if (progress.status === 'complete' || progress.status === 'failed') stopProgressPolling();
    } catch (error) {
      // The POST and first poll can race before the progress record is registered.
      if (!(error instanceof ApiError && error.status === 404) && !signal.aborted) {
        statusMessage = 'Analysis is running; live progress is temporarily unavailable.';
      }
    }
  };
  void poll();
  progressPollTimer = window.setInterval(() => void poll(), 600);
}

function stopProgressPolling(): void {
  if (progressPollTimer !== null) {
    window.clearInterval(progressPollTimer);
    progressPollTimer = null;
  }
}

async function copyInvestigationFilter(targetId: string): Promise<void> {
  const target = latestResponse?.investigation_targets.find(item => item.id === targetId);
  if (!target?.wireshark_filter) return;
  try {
    await navigator.clipboard.writeText(target.wireshark_filter);
    statusIsError = false;
    statusMessage = 'Wireshark display filter copied to the clipboard.';
  } catch {
    statusIsError = true;
    statusMessage = 'Clipboard access was denied. Select and copy the displayed filter manually.';
  }
  renderShell();
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
