import { decodeCrypto, type DecodeResponse, type TransformationStep } from '../api/crypto.ts';
import { ApiError } from '../api/client.ts';
import { icons } from '../data.ts';

const TRANSFORMS = ['Base64', 'Base32', 'Base85', 'Hex', 'Binary', 'URL', 'ROT13', 'Caesar', 'XOR'];
let latestResponse: DecodeResponse | null = null;
let activeRequest: AbortController | null = null;

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character] || character);
}

function formatStep(step: TransformationStep): string {
  return step.parameter ? `${step.transform} (${step.parameter})` : step.transform;
}

function formatChain(chain: TransformationStep[]): string {
  return chain.length ? chain.map(formatStep).join(' → ') : 'Input (no transformation)';
}

export function renderCrypto(): void {
  activeRequest?.abort();
  latestResponse = null;
  const main = document.getElementById('main');
  if (!main) return;

  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header">
      <div><div class="page-title">Cryptography Workbench</div><div class="page-subtitle">Discover, score, and rank recursive decoding chains</div></div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm" id="crypto-copy" disabled>${icons.copy} Copy Best Result</button>
        <button class="btn btn-primary btn-sm" id="crypto-run">${icons.play} Analyze</button>
      </div>
    </div>
    <div class="crypto-layout">
      <div class="crypto-input">
        <div class="section-title">Input</div>
        <textarea class="textarea" id="crypto-input" rows="8" maxlength="32768" placeholder="Paste encoded or encrypted text here..." style="min-height:160px;font-size:var(--text-xs)"></textarea>
        <div class="kv-list" style="font-size:var(--text-xs)">
          <div class="kv-key">Length</div><div class="kv-value mono" id="crypto-length">0 chars</div>
          <div class="kv-key">Detected</div><div class="kv-value mono" id="crypto-detected">Waiting for analysis</div>
          <div class="kv-key">Search</div><div class="kv-value mono" id="crypto-search">Depth ≤ 4</div>
        </div>
        <div class="section-title mt-8">Candidate Transformations</div>
        <div class="flex gap-2" style="flex-wrap:wrap">
          ${TRANSFORMS.map(transform => `<span class="btn btn-sm btn-secondary" title="Included in automatic search">${transform}</span>`).join('')}
        </div>
      </div>
      <div class="crypto-pipeline" id="crypto-pipeline">
        <div class="section-title">Best Decoding Chain</div>
        <div class="text-xs text-muted">Run analysis to build a ranked transformation chain.</div>
      </div>
      <div class="crypto-output">
        <div class="section-title">Ranked Results</div>
        <div class="crypto-results" id="crypto-results">
          <div class="text-xs text-muted">No analysis has run.</div>
        </div>
        <div class="mt-8" id="crypto-flags"></div>
      </div>
    </div>
  </div>`;

  const input = document.getElementById('crypto-input') as HTMLTextAreaElement | null;
  const run = document.getElementById('crypto-run') as HTMLButtonElement | null;
  const copy = document.getElementById('crypto-copy') as HTMLButtonElement | null;
  input?.addEventListener('input', () => {
    const length = document.getElementById('crypto-length');
    if (length) length.textContent = `${input.value.length.toLocaleString()} chars`;
  });
  run?.addEventListener('click', () => void runAnalysis());
  copy?.addEventListener('click', () => void copyBestResult(copy));
}

async function runAnalysis(): Promise<void> {
  const input = document.getElementById('crypto-input') as HTMLTextAreaElement | null;
  const run = document.getElementById('crypto-run') as HTMLButtonElement | null;
  const results = document.getElementById('crypto-results');
  if (!input || !run || !results) return;
  if (!input.value) {
    input.focus();
    results.innerHTML = '<div class="text-xs" style="color:var(--warning)">Enter data to analyze.</div>';
    return;
  }

  activeRequest?.abort();
  activeRequest = new AbortController();
  run.disabled = true;
  run.innerHTML = `${icons.loader} Searching…`;
  results.innerHTML = '<div class="text-xs text-muted">Exploring candidate transformations…</div>';

  try {
    latestResponse = await decodeCrypto(input.value, activeRequest.signal);
    renderResponse(latestResponse);
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    const message = error instanceof ApiError && error.code === 'NETWORK_ERROR'
      ? 'Backend unavailable. Start the FastAPI server on 127.0.0.1:8000.'
      : error instanceof Error ? error.message : 'Analysis failed.';
    results.innerHTML = `<div class="text-xs" style="color:var(--error)">${escapeHtml(message)}</div>`;
  } finally {
    run.disabled = false;
    run.innerHTML = `${icons.play} Analyze`;
  }
}

function renderResponse(response: DecodeResponse): void {
  const detected = document.getElementById('crypto-detected');
  const search = document.getElementById('crypto-search');
  const results = document.getElementById('crypto-results');
  const copy = document.getElementById('crypto-copy') as HTMLButtonElement | null;
  if (detected) {
    detected.textContent = response.detected_encodings.length
      ? response.detected_encodings.map(item => `${item.name} ${Math.round(item.confidence * 100)}%`).join(', ')
      : 'No syntax match';
  }
  if (search) {
    search.textContent = `${response.search.explored_states} states · ${response.search.elapsed_ms} ms${response.search.truncated ? ' · bounded' : ''}`;
  }
  if (copy) copy.disabled = response.results.length === 0;

  renderPipeline(response.results[0]?.chain || []);
  if (results) {
    results.innerHTML = response.results.length
      ? response.results.map(result => {
          const confidence = Math.round(result.score * 100);
          const confClass = confidence > 80 ? 'confidence-high' : confidence > 50 ? 'confidence-medium' : 'confidence-low';
          const suffix = result.output_truncated ? '… (preview)' : '';
          return `<div class="crypto-result-item">
            <div class="crypto-result-chain">${escapeHtml(formatChain(result.chain))}</div>
            <div class="crypto-result-value">${escapeHtml(result.output)}${suffix}</div>
            <div class="crypto-result-confidence">
              <div class="confidence-bar"><div class="confidence-fill ${confClass}" style="width:${confidence}%"></div></div>
              <span>${confidence}% · ${result.output_format} · H ${result.score_breakdown.entropy.toFixed(2)}</span>
            </div>
          </div>`;
        }).join('')
      : '<div class="text-xs text-muted">No viable transformations were found.</div>';
  }
  renderFlags(response);
}

function renderPipeline(chain: TransformationStep[]): void {
  const pipeline = document.getElementById('crypto-pipeline');
  if (!pipeline) return;
  const steps = chain.length
    ? chain.map((step, index) => `${index ? '<div class="crypto-arrow">↓</div>' : ''}
      <div class="crypto-step active">
        <div class="crypto-step-num">${index + 1}</div>
        <div class="crypto-step-label"><div style="font-weight:500">${escapeHtml(step.transform)}</div>
          ${step.parameter ? `<div class="text-xs text-muted">${escapeHtml(step.parameter)}</div>` : ''}
        </div>
      </div>`).join('')
    : '<div class="text-xs text-muted">The highest-ranked result is the original input.</div>';
  pipeline.innerHTML = `<div class="section-title">Best Decoding Chain</div>${steps}
    <div class="mt-8"><div class="section-title mb-4">Chain</div>
      <div class="panel"><div class="panel-body"><div class="mono text-xs" style="color:var(--accent)">${escapeHtml(formatChain(chain))}</div></div></div>
    </div>`;
}

function renderFlags(response: DecodeResponse): void {
  const flags = document.getElementById('crypto-flags');
  if (!flags) return;
  if (!response.flags.length) {
    flags.innerHTML = '<div class="section-title mb-4">Flag Detection</div><div class="text-xs text-muted">No configured flag pattern matched.</div>';
    return;
  }
  flags.innerHTML = `<div class="section-title mb-4">Flag Candidates</div>${response.flags.slice(0, 5).map(flag => `
    <div class="panel mb-4">
      <div class="panel-header" style="background:var(--success-bg);color:var(--success)">${icons.flag} Candidate · review required</div>
      <div class="panel-body">
        <div class="mono" style="font-size:var(--text-sm);word-break:break-all">${escapeHtml(flag.value)}</div>
        <div class="text-xs text-muted mt-4">${escapeHtml(flag.matched_pattern)} · ${Math.round(flag.confidence * 100)}% · offset ${flag.offset}</div>
      </div>
    </div>`).join('')}`;
}

async function copyBestResult(button: HTMLButtonElement): Promise<void> {
  const output = latestResponse?.results[0]?.output;
  if (!output) return;
  await navigator.clipboard.writeText(output);
  button.innerHTML = `${icons.check} Copied`;
  window.setTimeout(() => { button.innerHTML = `${icons.copy} Copy Best Result`; }, 1_200);
}

