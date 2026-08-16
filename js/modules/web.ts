import { ApiError } from '../api/client.ts';
import {
  analyzeWebTarget,
  type FindingSeverity,
  type TargetScope,
  type WebAnalysisInput,
  type WebAnalysisResponse,
} from '../api/web.ts';
import { icons } from '../data.ts';

type ResultTab = 'findings' | 'endpoints' | 'surface' | 'tree' | 'evidence';

interface ScannerFormState {
  url: string;
  scope: TargetScope;
  depth: number;
  timeoutSeconds: number;
  maxPages: number;
  followRedirects: boolean;
  crawl: boolean;
  directoryDiscovery: boolean;
  apiDiscovery: boolean;
  javascript: boolean;
  sourceMaps: boolean;
  sensitiveFiles: boolean;
  cookies: string;
  headers: string;
  authenticatedUrl: string;
  authorized: boolean;
}

let result: WebAnalysisResponse | null = null;
let activeRequest: AbortController | null = null;
let analyzing = false;
let activeTab: ResultTab = 'findings';
let statusMessage = '';
let statusIsError = false;
let formState: ScannerFormState = {
  url: '', scope: 'ctf', depth: 2, timeoutSeconds: 8, maxPages: 25,
  followRedirects: true, crawl: true, directoryDiscovery: true, apiDiscovery: true,
  javascript: true, sourceMaps: true, sensitiveFiles: true,
  cookies: '', headers: '', authenticatedUrl: '', authorized: false,
};

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

function severityBadge(severity: FindingSeverity): string {
  return `<span class="badge badge-${severity}">${severity.toUpperCase()}</span>`;
}

function emptyState(title: string, description: string): string {
  return `<div class="empty-state"><div class="empty-state-icon">${icons.search}</div><div class="empty-state-title">${escapeHtml(title)}</div><div class="empty-state-desc">${escapeHtml(description)}</div></div>`;
}

export function renderWeb(): void {
  renderShell();
}

function renderShell(): void {
  const main = document.getElementById('main');
  if (!main) return;
  main.innerHTML = `<div class="main-content-wide" id="web-page">
    <div class="page-header">
      <div><div class="page-title">Web Recon Scanner</div></div>
      <div class="page-actions">
        ${result ? `<button class="btn btn-secondary btn-sm" id="web-export">${icons.download} Export JSON</button>` : ''}
        <button class="btn btn-primary btn-sm" id="web-run" ${analyzing ? 'disabled' : ''}>${analyzing ? `${icons.loader} Analyzing…` : `${icons.play} Start Analysis`}</button>
      </div>
    </div>
    ${renderConfiguration()}
    ${statusMessage ? `<div class="web-scan-status ${statusIsError ? 'error' : ''}">${escapeHtml(statusMessage)}</div>` : ''}
    ${result ? renderResults(result) : emptyState('No Web evidence collected', 'Run an authorized analysis to see ranked findings, endpoints, inputs, and raw evidence.')}
  </div>`;
  bindEvents();
}

function renderConfiguration(): string {
  const checked = (value: boolean): string => value ? 'checked' : '';
  return `<div class="panel mb-4 web-config-panel"><div class="panel-header"><span>Scan configuration</span><span class="badge badge-info">Bounded · same origin</span></div><div class="panel-body">
    <label class="web-target-field"><span>Target URL</span><input class="input mono" id="web-url" type="url" placeholder="http://challenge.local" value="${escapeHtml(formState.url)}"></label>
    <div class="web-config-primary">
      <label><span>Scope</span><select class="select" id="web-scope"><option value="ctf" ${formState.scope === 'ctf' ? 'selected' : ''}>CTF challenge</option><option value="lab" ${formState.scope === 'lab' ? 'selected' : ''}>Lab</option><option value="owned" ${formState.scope === 'owned' ? 'selected' : ''}>User-owned</option></select></label>
      <label><span>Depth</span><input class="input" id="web-depth" type="number" min="0" max="4" value="${formState.depth}"></label>
      <label><span>Max pages</span><input class="input" id="web-max-pages" type="number" min="1" max="50" value="${formState.maxPages}"></label>
      <label><span>Timeout (s)</span><input class="input" id="web-timeout" type="number" min="1" max="15" value="${formState.timeoutSeconds}"></label>
    </div>
    <div class="web-config-section"><div class="web-config-label">Scan coverage</div><div class="web-option-grid">
      <label><input id="web-follow" type="checkbox" ${checked(formState.followRedirects)}><span>Follow redirects</span></label>
      <label><input id="web-crawl" type="checkbox" ${checked(formState.crawl)}><span>Crawl same-origin pages</span></label>
      <label><input id="web-directory" type="checkbox" ${checked(formState.directoryDiscovery)}><span>Directory discovery</span></label>
      <label><input id="web-api" type="checkbox" ${checked(formState.apiDiscovery)}><span>API discovery</span></label>
      <label><input id="web-js" type="checkbox" ${checked(formState.javascript)}><span>JavaScript analysis</span></label>
      <label><input id="web-maps" type="checkbox" ${checked(formState.sourceMaps)}><span>Source-map discovery</span></label>
      <label><input id="web-sensitive" type="checkbox" ${checked(formState.sensitiveFiles)}><span>Sensitive-file checks</span></label>
    </div>
    </div>
    <details class="web-advanced-settings"><summary>Cookies and custom headers</summary><div class="web-config-secondary">
      <label><span>Cookies</span><input class="input mono" id="web-cookies" autocomplete="off" placeholder="session=value; role=user" value="${escapeHtml(formState.cookies)}"></label>
      <label><span>Headers (one Name: value per line)</span><textarea class="input mono" id="web-headers" rows="3" placeholder="Authorization: Bearer …">${escapeHtml(formState.headers)}</textarea></label>
      <label><span>Known authenticated URL (optional session check)</span><input class="input mono" id="web-authenticated-url" type="url" placeholder="http://challenge.local/dashboard" value="${escapeHtml(formState.authenticatedUrl)}"></label>
    </div></details>
    <div class="web-config-footer"><label class="web-authorization"><input id="web-authorized" type="checkbox" ${checked(formState.authorized)}><span>I confirm this target is an authorized CTF, lab, or system I own.</span></label>
      <div class="text-xs text-muted">Read-only requests · no form submission · no exploit payloads</div></div>
  </div></div>`;
}

function renderResults(data: WebAnalysisResponse): string {
  const summary = data.target_summary;
  const candidateLabel = data.flags.length
    ? `${data.flags.length} flag candidate${data.flags.length === 1 ? '' : 's'}`
    : data.flag_status === 'possible_lead' ? 'Possible lead' : 'No flag candidate';
  const tabs: Array<[ResultTab, string, number]> = [
    ['findings', 'Notable Findings', data.notable_findings.length],
    ['endpoints', 'Interesting Endpoints', data.endpoints.length],
    ['surface', 'Input / Attack Surface', data.attack_surface.length],
    ['tree', 'Recon Tree', data.recon_tree.length],
    ['evidence', 'Raw Evidence', data.raw_evidence.length],
  ];
  return `<div class="panel mb-4 web-target-summary"><div class="panel-header"><span>Target Summary</span><span class="badge ${data.flags.length || data.flag_status === 'possible_lead' ? 'badge-warning' : 'badge-outline'}">${escapeHtml(candidateLabel)}</span></div><div class="panel-body"><div class="kv-list">
      <div class="kv-key">URL</div><div class="kv-value mono">${escapeHtml(summary.url)}</div>
      <div class="kv-key">Final URL</div><div class="kv-value mono">${escapeHtml(summary.final_url)}</div>
      <div class="kv-key">Server</div><div class="kv-value">${escapeHtml(summary.server || 'Not disclosed')}</div>
      <div class="kv-key">Technologies</div><div class="kv-value">${escapeHtml(summary.technologies.join(', ') || 'No confident fingerprint')}</div>
      <div class="kv-key">Coverage</div><div class="kv-value">${summary.pages_analyzed} pages · ${summary.endpoints_discovered} endpoints · ${summary.javascript_files_analyzed} JS files</div>
    </div></div></div>
  ${data.warnings.length ? `<div class="panel mb-4"><div class="panel-header" style="color:var(--warning)">Warnings</div><div class="panel-body text-xs">${data.warnings.map(item => `<div>· ${escapeHtml(item)}</div>`).join('')}</div></div>` : ''}
  <div class="tab-bar web-result-tabs">${tabs.map(([id, label, count]) => `<button class="tab-item ${activeTab === id ? 'active' : ''}" data-web-tab="${id}">${label} <span class="tab-count">${count}</span></button>`).join('')}</div>
  <div class="web-result-content">${renderTab(data)}</div>`;
}

function renderTab(data: WebAnalysisResponse): string {
  if (activeTab === 'endpoints') return renderEndpoints(data);
  if (activeTab === 'surface') return renderSurface(data);
  if (activeTab === 'tree') return renderTree(data);
  if (activeTab === 'evidence') return renderEvidence(data);
  return renderFindings(data);
}

function renderFindings(data: WebAnalysisResponse): string {
  const findings = data.notable_findings.filter(finding => !finding.id.startsWith('flag-'));
  if (!data.flags.length && !findings.length) return emptyState('No notable findings', `Analyzed ${data.target_summary.pages_analyzed} pages and ${data.target_summary.endpoints_discovered} endpoints without a strong CTF lead.`);
  return `${renderFlagCandidates(data)}${findings.length ? `<div class="section web-notable-section"><div class="section-header"><div class="section-title">Notable findings</div><span class="text-xs text-muted">${findings.length} ranked lead${findings.length === 1 ? '' : 's'} · select a row for evidence</span></div>
  <div class="web-findings-list">${findings.map(finding => `<details class="web-finding-card severity-${finding.severity}">
    <summary>${severityBadge(finding.severity)}<span class="web-finding-title">${escapeHtml(finding.title)}</span><span class="web-finding-score">${finding.score}</span><span class="web-finding-confidence">${Math.round(finding.confidence * 100)}%</span></summary>
    <div class="web-finding-body"><div class="kv-list">
      <div class="kv-key">Location</div><div class="kv-value mono">${escapeHtml(finding.location)}</div>
      <div class="kv-key">Why it matters</div><div class="kv-value">${escapeHtml(finding.why_it_matters)}</div>
      <div class="kv-key">Suggested investigation</div><div class="kv-value">${escapeHtml(finding.suggested_investigation)}</div>
      <div class="kv-key">Sources</div><div class="kv-value">${escapeHtml(finding.sources.join(', ') || 'direct evidence')}</div>
      <div class="kv-key">Source type</div><div class="kv-value mono">${escapeHtml(finding.source_type)}</div>
      <div class="kv-key">Access</div><div class="kv-value">${finding.authenticated ? 'Authenticated session' : 'Anonymous'}</div>
    </div><div class="web-evidence-block"><div class="text-xs text-muted">Evidence</div>${finding.evidence.map(item => `<pre>${escapeHtml(item)}</pre>`).join('')}</div></div>
  </details>`).join('')}</div></div>` : ''}`;
}

function renderFlagCandidates(data: WebAnalysisResponse): string {
  if (!data.flags.length) return '';
  return `<div class="section web-flag-candidates"><div class="section-header"><div class="section-title">Flag candidates</div><span class="text-xs text-muted">Regex matches require analyst review</span></div>
    <div class="table-wrap"><table class="data-table"><thead><tr><th>Candidate</th><th>Found at</th><th>Source</th><th>Confidence</th><th>Status</th></tr></thead><tbody>${data.flags.map(flag => `<tr>
      <td><code class="web-flag-candidate-value">${escapeHtml(flag.value)}</code></td>
      <td class="mono web-flag-location">${escapeHtml(flag.location)}</td>
      <td>${escapeHtml(flag.source)}${flag.authenticated ? ' (authenticated)' : ''}</td>
      <td>${Math.round(flag.confidence * 100)}%</td>
      <td><span class="badge badge-warning">Candidate</span></td>
    </tr><tr class="web-flag-context-row"><td colspan="5"><span class="text-xs text-muted">Context:</span> <span class="mono text-xs">${escapeHtml(flag.context)}</span></td></tr>`).join('')}</tbody></table></div>
  </div>`;
}

function renderEndpoints(data: WebAnalysisResponse): string {
  return `<div class="table-wrap"><table class="data-table"><thead><tr><th>Priority</th><th>Route</th><th>Method</th><th>Source</th><th>Reason</th></tr></thead><tbody>${data.endpoints.length ? data.endpoints.map(endpoint => `<tr><td><span class="web-priority">${endpoint.priority}</span></td><td class="mono">${escapeHtml(endpoint.path)}</td><td><span class="badge badge-outline">${escapeHtml(endpoint.method)}</span></td><td>${escapeHtml(endpoint.sources.join(', '))}</td><td class="text-muted">${escapeHtml(endpoint.reason)}</td></tr>`).join('') : `<tr><td colspan="5">No endpoints were discovered.</td></tr>`}</tbody></table></div>`;
}

function renderSurface(data: WebAnalysisResponse): string {
  return `<div class="table-wrap"><table class="data-table"><thead><tr><th>Parameter</th><th>Endpoint</th><th>Method</th><th>Type</th><th>Potential Category</th></tr></thead><tbody>${data.attack_surface.length ? data.attack_surface.map(item => `<tr><td class="mono">${escapeHtml(item.parameter)}</td><td class="mono">${escapeHtml(item.endpoint)}</td><td>${escapeHtml(item.method)}</td><td>${escapeHtml(item.input_type || item.location)}</td><td>${escapeHtml(item.potential_category)}</td></tr>`).join('') : `<tr><td colspan="5">No named inputs were discovered.</td></tr>`}</tbody></table></div>`;
}

function renderTree(data: WebAnalysisResponse): string {
  if (!data.recon_tree.length) return emptyState('No recon tree', 'No same-origin evidence nodes were collected.');
  return `<div class="web-recon-tree">${data.recon_tree.map(node => `<div class="web-tree-node" style="--tree-depth:${Math.min(node.depth, 5)}"><span>${node.depth ? '└─' : '●'}</span><code>${escapeHtml(node.url)}</code><span class="badge badge-outline">${escapeHtml(node.source)}</span></div>`).join('')}</div>`;
}

function renderEvidence(data: WebAnalysisResponse): string {
  return `<div class="web-raw-list">${data.raw_evidence.map(item => `<details class="web-raw-item"><summary><span class="badge ${item.status_code !== null && item.status_code < 400 ? 'badge-success' : 'badge-warning'}">${item.status_code ?? 'ERR'}</span><span>${escapeHtml(item.kind)}</span>${item.authenticated ? '<span class="badge badge-info">AUTH</span>' : ''}<code>${escapeHtml(item.url)}</code><span>${formatBytes(item.body_preview.length)}</span></summary><div class="web-raw-body"><div class="text-xs text-muted">Headers</div><pre>${escapeHtml(item.headers.map(header => `${header.name}: ${header.value}`).join('\n') || 'No headers captured')}</pre><div class="text-xs text-muted">Body preview${item.truncated ? ' (truncated)' : ''}</div><pre>${escapeHtml(item.body_preview || 'No response body')}</pre></div></details>`).join('')}</div>`;
}

function bindEvents(): void {
  document.getElementById('web-run')?.addEventListener('click', () => void runAnalysis());
  document.getElementById('web-export')?.addEventListener('click', exportResult);
  document.querySelectorAll<HTMLElement>('[data-web-tab]').forEach(button => button.addEventListener('click', () => {
    activeTab = (button.dataset.webTab as ResultTab | undefined) || 'findings';
    captureFormState();
    renderShell();
  }));
}

function parseCookies(value: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  value.split(';').map(item => item.trim()).filter(Boolean).forEach(item => {
    const separator = item.indexOf('=');
    if (separator > 0) cookies[item.slice(0, separator).trim()] = item.slice(separator + 1).trim();
  });
  return cookies;
}

function parseHeaders(value: string): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of value.split('\n').map(item => item.trim()).filter(Boolean)) {
    const separator = line.indexOf(':');
    if (separator <= 0) throw new Error(`Invalid header line: ${line}`);
    headers[line.slice(0, separator).trim()] = line.slice(separator + 1).trim();
  }
  return headers;
}

function captureFormState(): void {
  const value = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null)?.value || '';
  const checked = (id: string): boolean => (document.getElementById(id) as HTMLInputElement | null)?.checked || false;
  formState = {
    url: value('web-url').trim(), scope: (value('web-scope') || 'ctf') as TargetScope,
    depth: Number(value('web-depth') || 2), timeoutSeconds: Number(value('web-timeout') || 8),
    maxPages: Number(value('web-max-pages') || 25), followRedirects: checked('web-follow'),
    crawl: checked('web-crawl'), directoryDiscovery: checked('web-directory'), apiDiscovery: checked('web-api'),
    javascript: checked('web-js'), sourceMaps: checked('web-maps'), sensitiveFiles: checked('web-sensitive'),
    cookies: value('web-cookies'), headers: value('web-headers'), authenticatedUrl: value('web-authenticated-url').trim(), authorized: checked('web-authorized'),
  };
}

async function runAnalysis(): Promise<void> {
  if (analyzing) return;
  captureFormState();
  if (!formState.url || !formState.authorized) {
    statusIsError = true;
    statusMessage = !formState.url ? 'Enter an HTTP or HTTPS target URL.' : 'Confirm that the target is explicitly authorized.';
    renderShell();
    return;
  }
  let headers: Record<string, string>;
  try { headers = parseHeaders(formState.headers); }
  catch (error) { statusIsError = true; statusMessage = error instanceof Error ? error.message : 'Invalid custom headers.'; renderShell(); return; }

  const input: WebAnalysisInput = {
    url: formState.url, target_scope: formState.scope, authorization_confirmed: true, method: 'GET',
    headers, cookies: parseCookies(formState.cookies), fetch_robots: true, fetch_sitemap: true,
    fetch_javascript: formState.javascript, source_map_discovery: formState.sourceMaps,
    crawl_same_origin: formState.crawl, directory_discovery: formState.directoryDiscovery,
    api_discovery: formState.apiDiscovery, sensitive_file_checks: formState.sensitiveFiles,
    follow_redirects: formState.followRedirects, scan_depth: formState.depth,
    max_pages: formState.maxPages, authenticated_url: formState.authenticatedUrl || null,
    timeout_ms: formState.timeoutSeconds * 1000,
    compare_without_auth: false,
  };
  const controller = new AbortController();
  activeRequest?.abort(); activeRequest = controller; analyzing = true; statusIsError = false;
  statusMessage = 'Collecting bounded evidence and ranking notable findings…'; renderShell();
  let requestTimedOut = false;
  const timeoutHandle = window.setTimeout(() => {
    requestTimedOut = true;
    controller.abort();
  }, 50_000);
  try {
    result = await analyzeWebTarget(input, controller.signal);
    activeTab = 'findings';
    statusMessage = `Analysis ${result.analysis_id.slice(0, 8)} completed: ${result.notable_findings.length} notable findings from ${result.target_summary.pages_analyzed} pages.`;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError' && !requestTimedOut) return;
    statusIsError = true;
    statusMessage = requestTimedOut
      ? 'The scan exceeded the 50-second client limit. Check the backend terminal for an unreachable target or restart the backend.'
      : error instanceof ApiError && error.code === 'NETWORK_ERROR'
      ? 'Backend unavailable. Start FastAPI on 127.0.0.1:8000.'
      : error instanceof Error ? error.message : 'Web recon analysis failed.';
  } finally {
    window.clearTimeout(timeoutHandle);
    if (activeRequest === controller) { activeRequest = null; analyzing = false; if (document.getElementById('web-page')) renderShell(); }
  }
}

function exportResult(): void {
  if (!result) return;
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = `web-recon-${result.analysis_id}.json`; anchor.click();
  URL.revokeObjectURL(url);
}
