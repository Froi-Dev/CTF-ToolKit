import {
  analyzeOpenSsl,
  analyzeCrypto,
  decodeCrypto,
  decryptOpenSsl,
  decryptRsa,
  runRecipe,
  type ArtifactDetection,
  type CryptoAnalyzeResponse,
  type DecodeResponse,
  type OpenSslAnalyzeResponse,
  type OpenSslCipher,
  type OpenSslDecryptCandidate,
  type OpenSslDecryptResponse,
  type OpenSslDigest,
  type OpenSslKdf,
  type PasswordEncoding,
  type RecipeOperation,
  type RecipeOperationName,
  type RecipeResponse,
  type RsaDecryptResponse,
  type RsaPadding,
  type TransformationStep,
  type ValueEncoding,
} from '../api/crypto.ts';
import { ApiError } from '../api/client.ts';
import { renderAdvancedCrypto } from './crypto_advanced_ui.ts';
import { icons } from '../data.ts';

const OPERATIONS: { id: RecipeOperationName; label: string }[] = [
  { id: 'base64', label: 'From Base64' }, { id: 'base32', label: 'From Base32' },
  { id: 'hex', label: 'From Hex / Base16' }, { id: 'base58', label: 'From Base58' },
  { id: 'base85', label: 'From Base85' }, { id: 'ascii85', label: 'From ASCII85' },
  { id: 'binary', label: 'From Binary' }, { id: 'octal', label: 'From Octal' },
  { id: 'decimal-ascii', label: 'Decimal ASCII' }, { id: 'url', label: 'URL Decode' },
  { id: 'html-entities', label: 'HTML Entities' }, { id: 'unicode-escapes', label: 'Unicode Escapes' },
  { id: 'escaped-bytes', label: 'Escaped Bytes' }, { id: 'morse', label: 'Morse' },
  { id: 'rot13', label: 'ROT13' }, { id: 'rot47', label: 'ROT47' },
  { id: 'caesar', label: 'Caesar Shift' },
  { id: 'utf-16', label: 'UTF-16 to UTF-8' }, { id: 'gunzip', label: 'Gunzip' },
  { id: 'xor', label: 'XOR Known Key' }, { id: 'ascii', label: 'ASCII' }, { id: 'utf-8', label: 'UTF-8' },
];

interface WorkspaceArtifact {
  id: string; name: string; value: string; encoding: ValueEncoding; kind: string; source: string;
}

let latestDecode: DecodeResponse | null = null;
let latestRecipe: RecipeResponse | null = null;
let recipe: RecipeOperation[] = [];
let artifacts: WorkspaceArtifact[] = [];
let activeRequest: AbortController | null = null;
let decryptorMode: 'openssl' | 'rsa' = 'openssl';
let pendingOpenSslArtifactId: string | null = null;
let latestOpenSslResult: OpenSslDecryptResponse | null = null;
let pendingDecoderInput: string | null = null;
let pendingDecoderAuto = false;

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

function errorMessage(error: unknown): string {
  if (error instanceof ApiError && error.code === 'NETWORK_ERROR') {
    return 'Backend unavailable. Start the FastAPI server on 127.0.0.1:8000.';
  }
  return error instanceof Error ? error.message : 'Cryptography operation failed.';
}

function artifactTray(): string {
  if (!artifacts.length) return '';
  return `<div class="crypto-tray panel">
    <div class="panel-header"><span>Shared Artifact Tray</span><span class="text-xs text-muted">${artifacts.length} artifact${artifacts.length === 1 ? '' : 's'}</span></div>
    <div class="panel-body crypto-artifact-list">
      ${artifacts.map(item => `<div class="crypto-artifact" data-artifact="${escapeHtml(item.id)}">
        <div><div class="mono text-xs">${escapeHtml(item.name)}</div><div class="text-xs text-muted">${escapeHtml(item.kind)} · ${escapeHtml(item.source)}</div></div>
        <div class="flex gap-2"><button class="btn btn-secondary btn-sm artifact-key" data-id="${escapeHtml(item.id)}">Use as key</button><button class="btn btn-secondary btn-sm artifact-cipher" data-id="${escapeHtml(item.id)}">Use as ciphertext</button></div>
      </div>`).join('')}
    </div>
  </div>`;
}

export function renderCrypto(view = 'decoder'): void {
  activeRequest?.abort();
  const main = document.getElementById('main');
  if (!main) return;
  if (view === 'decryptor') renderDecryptor(main);
  else if (view === 'advanced') renderAdvancedCrypto(main);
  else renderDecoder(main);
}

function renderDecoder(main: HTMLElement): void {
  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header">
      <div><div class="page-title">Cryptography / Decoder</div><div class="page-subtitle">Identify representations, inspect every layer, and preserve extracted artifacts</div></div>
      <div class="page-actions"><button class="btn btn-secondary btn-sm" id="auto-recipe" ${latestDecode?.results.length ? '' : 'disabled'}>Build Best Recipe</button><button class="btn btn-secondary btn-sm" id="crypto-copy" ${latestDecode?.results.length ? '' : 'disabled'}>${icons.copy} Copy Best</button><button class="btn btn-primary btn-sm" id="crypto-run">${icons.play} Auto Decode</button></div>
    </div>
    ${artifactTray()}
    <div class="crypto-layout crypto-decoder-layout mt-8">
      <section class="crypto-operations panel"><div class="panel-header">Operations</div><div class="panel-body">
        <div class="crypto-operation-grid">${OPERATIONS.map(item => `<button class="btn btn-secondary btn-sm crypto-operation" data-operation="${item.id}">${escapeHtml(item.label)}</button>`).join('')}</div>
      </div></section>
      <section class="crypto-pipeline panel"><div class="panel-header"><span>Recipe</span><button class="btn btn-secondary btn-sm" id="recipe-clear">Clear</button></div><div class="panel-body"><div id="recipe-steps"></div><button class="btn btn-primary btn-sm mt-8" id="recipe-run" ${recipe.length ? '' : 'disabled'}>${icons.play} Run Recipe</button></div></section>
      <section class="crypto-input panel"><div class="panel-header">Input</div><div class="panel-body"><textarea class="textarea" id="crypto-input" maxlength="32768" rows="10" placeholder="Paste encoded data, escaped bytes, or a key…"></textarea>
        <div class="crypto-input-meta text-xs"><span><span class="text-muted">Length</span> <span class="mono" id="crypto-length">0 chars</span></span><span><span class="text-muted">Detected</span> <span class="mono" id="crypto-detected">Waiting for analysis</span></span></div>
      </div></section>
      <section class="crypto-output panel"><div class="panel-header">Output</div><div class="panel-body"><div id="crypto-results"><div class="text-xs text-muted">Run Auto Decode or build a deterministic recipe.</div></div><div class="mt-8" id="crypto-flags"></div></div></section>
    </div>
  </div>`;
  bindTray();
  renderRecipeSteps();
  const input = document.getElementById('crypto-input') as HTMLTextAreaElement | null;
  if (input && pendingDecoderInput !== null) {
    input.value = pendingDecoderInput;
    const length = document.getElementById('crypto-length');
    if (length) length.textContent = `${input.value.length.toLocaleString()} chars`;
    pendingDecoderInput = null;
    if (pendingDecoderAuto) { pendingDecoderAuto = false; window.setTimeout(() => void runAutoDecode(), 0); }
  }
  input?.addEventListener('input', () => {
    const length = document.getElementById('crypto-length');
    if (length) length.textContent = `${input.value.length.toLocaleString()} chars`;
  });
  document.getElementById('crypto-run')?.addEventListener('click', () => void runAutoDecode());
  document.getElementById('recipe-run')?.addEventListener('click', () => void executeRecipe());
  document.getElementById('recipe-clear')?.addEventListener('click', () => { recipe = []; renderRecipeSteps(); });
  document.getElementById('crypto-copy')?.addEventListener('click', () => void copyBest());
  document.getElementById('auto-recipe')?.addEventListener('click', buildBestRecipe);
  document.querySelectorAll<HTMLButtonElement>('.crypto-operation').forEach(button => button.addEventListener('click', () => {
    const operation = button.dataset.operation as RecipeOperationName;
    const parameter = operation === 'xor'
      ? window.prompt('XOR key: text:key, hex:0011, 0x17, or buffer-hex:…')
      : operation === 'caesar' ? window.prompt('Caesar decode shift (1-25)') : null;
    if ((operation === 'xor' || operation === 'caesar') && !parameter) return;
    recipe.push({ operation, parameter, enabled: true });
    renderRecipeSteps();
  }));
}

function renderRecipeSteps(): void {
  const container = document.getElementById('recipe-steps');
  const run = document.getElementById('recipe-run') as HTMLButtonElement | null;
  if (run) run.disabled = !recipe.some(item => item.enabled);
  if (!container) return;
  container.innerHTML = recipe.length ? recipe.map((item, index) => `<div class="crypto-recipe-row ${item.enabled ? '' : 'disabled'}">
    <span class="crypto-step-num">${index + 1}</span><div class="crypto-step-label"><strong>${escapeHtml(item.operation)}</strong>${item.parameter ? `<div class="text-xs text-muted">${escapeHtml(item.parameter)}</div>` : ''}</div>
    <div class="crypto-recipe-actions"><button title="Move up" data-action="up" data-index="${index}">↑</button><button title="Move down" data-action="down" data-index="${index}">↓</button><button title="Enable or disable" data-action="toggle" data-index="${index}">${item.enabled ? 'On' : 'Off'}</button><button title="Duplicate" data-action="duplicate" data-index="${index}">⧉</button><button title="Remove" data-action="remove" data-index="${index}">×</button></div>
  </div>`).join('<div class="crypto-arrow">↓</div>') : '<div class="text-xs text-muted">Choose operations to build a recipe. Every enabled step returns its own analysis and artifact detections.</div>';
  container.querySelectorAll<HTMLButtonElement>('[data-action]').forEach(button => button.addEventListener('click', () => {
    const index = Number(button.dataset.index); const action = button.dataset.action;
    if (action === 'remove') recipe.splice(index, 1);
    if (action === 'toggle') recipe[index].enabled = !recipe[index].enabled;
    if (action === 'duplicate') recipe.splice(index + 1, 0, { ...recipe[index] });
    if (action === 'up' && index > 0) [recipe[index - 1], recipe[index]] = [recipe[index], recipe[index - 1]];
    if (action === 'down' && index < recipe.length - 1) [recipe[index + 1], recipe[index]] = [recipe[index], recipe[index + 1]];
    renderRecipeSteps();
  }));
}

async function runAutoDecode(): Promise<void> {
  const input = document.getElementById('crypto-input') as HTMLTextAreaElement | null;
  const results = document.getElementById('crypto-results');
  if (!input || !results || !input.value) { input?.focus(); return; }
  activeRequest?.abort(); activeRequest = new AbortController();
  results.innerHTML = '<div class="text-xs text-muted">Recursively investigating likely layers…</div>';
  try {
    latestDecode = await decodeCrypto(input.value, activeRequest.signal);
    const autoRecipe = document.getElementById('auto-recipe') as HTMLButtonElement | null;
    const copy = document.getElementById('crypto-copy') as HTMLButtonElement | null;
    if (autoRecipe) autoRecipe.disabled = !latestDecode.results.length;
    if (copy) copy.disabled = !latestDecode.results.length;
    const detected = document.getElementById('crypto-detected');
    if (detected) detected.textContent = latestDecode.detected_encodings.length ? latestDecode.detected_encodings.map(item => `${item.name} ${Math.round(item.confidence * 100)}%`).join(', ') : 'No syntax match';
    results.innerHTML = latestDecode.results.map((result, index) => resultCard(result.output, result.output_format, result.output_bytes, result.analysis.entropy, formatChain(result.chain), result.artifacts, index)).join('') || '<div class="text-xs text-muted">No viable transformation was found.</div>';
    bindSendButtons('decode'); renderFlags(latestDecode.flags);
  } catch (error) { results.innerHTML = `<div class="text-xs" style="color:var(--error)">${escapeHtml(errorMessage(error))}</div>`; }
}

function buildBestRecipe(): void {
  const chain = latestDecode?.results[0]?.chain; if (!chain?.length) return;
  const operationMap: Record<string, RecipeOperationName> = {
    Base64: 'base64', Base32: 'base32', Base58: 'base58', Hex: 'hex', Binary: 'binary',
    URL: 'url', ROT13: 'rot13', ROT47: 'rot47', Caesar: 'caesar', XOR: 'xor',
    Octal: 'octal', 'Decimal ASCII': 'decimal-ascii', 'HTML Entities': 'html-entities',
    'Unicode Escapes': 'unicode-escapes', 'Escaped Bytes': 'escaped-bytes', Morse: 'morse',
    'UTF-16': 'utf-16', Gunzip: 'gunzip',
  };
  recipe = chain.flatMap(step => {
    let operation = operationMap[step.transform];
    if (step.transform === 'Base85') operation = step.parameter === 'Ascii85' ? 'ascii85' : 'base85';
    return operation ? [{ operation, parameter: step.parameter, enabled: true }] : [];
  });
  renderRecipeSteps();
}

async function executeRecipe(): Promise<void> {
  const input = document.getElementById('crypto-input') as HTMLTextAreaElement | null;
  const results = document.getElementById('crypto-results');
  if (!input || !results || !input.value) { input?.focus(); return; }
  activeRequest?.abort(); activeRequest = new AbortController();
  results.innerHTML = '<div class="text-xs text-muted">Applying recipe…</div>';
  try {
    latestRecipe = await runRecipe(input.value, recipe, activeRequest.signal);
    results.innerHTML = latestRecipe.steps.map((step, index) => resultCard(step.output, step.output_format, step.output_bytes, step.analysis.entropy, `${index + 1}. ${step.operation}${step.parameter ? ` (${step.parameter})` : ''}`, step.artifacts, index)).join('');
    bindSendButtons('recipe'); renderFlags(latestRecipe.steps.flatMap(step => step.flags));
  } catch (error) { results.innerHTML = `<div class="text-xs" style="color:var(--error)">${escapeHtml(errorMessage(error))}</div>`; }
}

function resultCard(output: string, format: string, bytes: number, entropy: number, chain: string, detected: ArtifactDetection[], index: number): string {
  return `<div class="crypto-result-item"><div class="crypto-result-chain">${escapeHtml(chain)}</div><div class="crypto-result-value">${escapeHtml(output)}</div>
    <div class="crypto-result-confidence"><span>${bytes} bytes · ${format} · entropy ${entropy.toFixed(2)}</span></div>
    ${detected.map(item => `<div class="crypto-detection"><strong>${escapeHtml(item.label)}</strong><span>${Math.round(item.confidence * 100)}% · ${escapeHtml(item.mime)}</span>${item.send_to_decryptor ? `<button class="btn btn-primary btn-sm crypto-send" data-index="${index}">Send to Decryptor</button>` : ''}</div>`).join('')}
  </div>`;
}

function bindSendButtons(source: 'decode' | 'recipe'): void {
  document.querySelectorAll<HTMLButtonElement>('.crypto-send').forEach(button => button.addEventListener('click', () => {
    const index = Number(button.dataset.index);
    const result = source === 'decode' ? latestDecode?.results[index] : latestRecipe?.steps[index];
    if (!result) return;
    const detected = result.artifacts.find(item => item.send_to_decryptor);
    addArtifact(`decoded-${artifacts.length + 1}.${detected?.details.format === 'PEM' ? 'pem' : 'bin'}`, result.output_base64, 'base64', detected?.label || 'decoded bytes', 'Decoder');
    window.location.hash = '#crypto/decryptor';
  }));
}

function addArtifact(name: string, value: string, encoding: ValueEncoding, kind: string, source: string): WorkspaceArtifact {
  const artifact = { id: `crypto-${Date.now()}-${artifacts.length}`, name, value, encoding, kind, source };
  artifacts.push(artifact);
  return artifact;
}

export function sendRawArtifactToDecryptor(name: string, base64Value: string, kind: string, source: string): void {
  const artifact = addArtifact(name, base64Value, 'base64', kind, source);
  decryptorMode = 'openssl';
  pendingOpenSslArtifactId = artifact.id;
  if (window.location.hash.includes('crypto/decryptor')) renderCrypto('decryptor');
  else window.location.hash = '#crypto/decryptor';
}

function renderFlags(flags: DecodeResponse['flags']): void {
  const container = document.getElementById('crypto-flags'); if (!container) return;
  container.innerHTML = `<div class="section-title mb-4">Flag Candidates</div>${flags.length ? flags.slice(0, 8).map(flag => `<div class="crypto-flag"><span class="mono">${escapeHtml(flag.value)}</span><span>candidate · ${Math.round(flag.confidence * 100)}%</span></div>`).join('') : '<div class="text-xs text-muted">No configured flag pattern matched.</div>'}`;
}

async function copyBest(): Promise<void> {
  const output = latestDecode?.results[0]?.output; if (output) await navigator.clipboard.writeText(output);
}

function renderDecryptor(main: HTMLElement): void {
  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header"><div><div class="page-title">Cryptography / Decryptor</div><div class="page-subtitle">Recognize encrypted containers, validate candidates, and preserve binary artifacts</div></div><div class="page-actions"><button class="btn btn-secondary btn-sm" id="decrypt-analyze">Analyze</button><button class="btn btn-primary btn-sm" id="decrypt-run">${icons.play} Decrypt</button></div></div>
    ${artifactTray()}
    <div class="crypto-type-strip mt-8"><button class="${decryptorMode === 'openssl' ? 'active' : ''}" data-decryptor-mode="openssl">OpenSSL Enc</button><button class="${decryptorMode === 'rsa' ? 'active' : ''}" data-decryptor-mode="rsa">RSA</button><span title="Not implemented in this slice">Classical · unavailable</span><span title="Not implemented in this slice">XOR analysis · unavailable</span><span title="Not implemented in this slice">ECC · unavailable</span></div>
    ${decryptorMode === 'openssl' ? openSslWorkspace() : rsaWorkspace()}
    <div class="panel mt-8"><div class="panel-header">Challenge Mode</div><div class="panel-body"><span class="status-badge status-badge-muted">Not implemented</span><p class="text-xs text-muted mt-4">Multi-file source analysis, attack ranking, and automatic solver execution require the case/artifact/job foundation and are intentionally not simulated.</p></div></div>
  </div>`;
  bindTray();
  document.querySelectorAll<HTMLButtonElement>('[data-decryptor-mode]').forEach(button => button.addEventListener('click', () => {
    decryptorMode = button.dataset.decryptorMode === 'rsa' ? 'rsa' : 'openssl';
    renderDecryptor(main);
  }));
  if (decryptorMode === 'openssl') bindOpenSslWorkspace();
  document.getElementById('decrypt-analyze')?.addEventListener('click', () => void (decryptorMode === 'openssl' ? runOpenSslAnalysis() : runCryptoAnalysis()));
  document.getElementById('decrypt-run')?.addEventListener('click', () => void (decryptorMode === 'openssl' ? runOpenSslDecrypt() : runRsaDecrypt()));
  if (pendingOpenSslArtifactId && decryptorMode === 'openssl') {
    const pending = artifacts.find(item => item.id === pendingOpenSslArtifactId);
    if (pending) fillOpenSslArtifact(pending);
    pendingOpenSslArtifactId = null;
  }
}

function rsaWorkspace(): string {
  return `<div class="crypto-decrypt-layout mt-8">
    <section class="panel"><div class="panel-header">RSA Workspace</div><div class="panel-body">
      <label class="form-label" for="rsa-key">Key / certificate</label><textarea class="textarea" id="rsa-key" rows="10" placeholder="PEM, DER as Base64/Hex, or a recursively encoded RSA key"></textarea>
      <select class="select mt-4" id="rsa-key-encoding">${encodingOptions()}</select>
      <label class="form-label mt-8" for="rsa-ciphertext">Ciphertext</label><textarea class="textarea" id="rsa-ciphertext" rows="7" placeholder="Ciphertext as Hex, Base64, or text"></textarea>
      <div class="flex gap-4 mt-4"><select class="select" id="rsa-cipher-encoding">${encodingOptions()}</select><select class="select" id="rsa-padding"><option value="pkcs1v15">PKCS#1 v1.5</option><option value="oaep-sha1">OAEP / SHA-1</option><option value="oaep-sha256">OAEP / SHA-256</option><option value="raw">Raw / textbook RSA</option></select></div>
    </div></section>
    <section class="panel"><div class="panel-header">Findings & Plaintext</div><div class="panel-body" id="decrypt-results"><div class="text-xs text-muted">Analyze the supplied artifacts before choosing an operation.</div></div></section>
  </div>`;
}

function openSslWorkspace(): string {
  const options = artifacts.map(item => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name)} · ${escapeHtml(item.source)}</option>`).join('');
  return `<div class="crypto-decrypt-layout mt-8">
    <section class="panel"><div class="panel-header">OpenSSL Enc</div><div class="panel-body">
      <label class="form-label" for="openssl-cipher">Cipher</label><select class="select" id="openssl-cipher"><option value="auto">Auto Detect</option><option value="des-cbc">DES-CBC</option><option value="des-ede3-cbc">3DES / DES-EDE3-CBC</option><option value="aes-128-cbc">AES-128-CBC</option><option value="aes-192-cbc">AES-192-CBC</option><option value="aes-256-cbc">AES-256-CBC</option></select>
      <label class="form-label mt-8" for="openssl-input">Encrypted Input</label>
      <div class="flex gap-2 crypto-input-actions"><input type="file" id="openssl-file" hidden><button class="btn btn-secondary btn-sm" id="openssl-upload">Upload File</button><button class="btn btn-secondary btn-sm" id="openssl-paste-hex">Paste Hex</button><select class="select" id="openssl-artifact" aria-label="Artifact">${options || '<option value="">No artifacts available</option>'}</select><button class="btn btn-secondary btn-sm" id="openssl-use-artifact" ${options ? '' : 'disabled'}>Use Artifact</button></div>
      <textarea class="textarea mt-4 mono" id="openssl-input" rows="8" placeholder="Paste raw text, hexadecimal bytes, or Base64. Uploaded files and TCP streams remain binary-safe."></textarea>
      <div class="flex gap-4 mt-4"><select class="select" id="openssl-input-encoding">${encodingOptions()}</select><span class="text-xs text-muted" id="openssl-input-summary">No encrypted bytes loaded</span></div>
      <label class="form-label mt-8" for="openssl-password">Password (Optional)</label><input class="input" id="openssl-password" type="password" autocomplete="off" maxlength="4096" placeholder="Enter when known">
      <label class="form-label mt-4" for="openssl-password-encoding">Password Encoding</label><select class="select" id="openssl-password-encoding"><option value="utf-8">UTF-8</option><option value="ascii">ASCII</option><option value="hex">Hex</option><option value="base64">Base64</option></select>
      <div class="crypto-parameter-grid mt-8"><div><label class="form-label" for="openssl-kdf">KDF / Derivation</label><select class="select" id="openssl-kdf"><option value="auto">Auto Detect</option><option value="evp-bytes-to-key">EVP_BytesToKey</option><option value="pbkdf2">PBKDF2</option></select></div><div><label class="form-label" for="openssl-digest">Digest</label><select class="select" id="openssl-digest"><option value="auto">Auto Detect</option><option value="sha256">SHA-256</option><option value="md5">MD5</option></select></div></div>
      <div id="openssl-iterations-wrap" class="mt-4" hidden><label class="form-label" for="openssl-iterations">Iterations</label><input class="input" id="openssl-iterations" type="number" min="1" max="10000000" value="10000"></div>
      <div class="flex gap-4 mt-8"><button class="btn btn-secondary" id="openssl-analyze-inline">Analyze</button><button class="btn btn-primary" id="openssl-decrypt-inline">${icons.play} Decrypt</button></div>
    </div></section>
    <section class="panel"><div class="panel-header">OpenSSL Analysis & Plaintext</div><div class="panel-body" id="decrypt-results"><div class="text-xs text-muted">Analysis recognizes Salted__ and extracts its salt without requiring a password.</div></div></section>
  </div>`;
}

function bindOpenSslWorkspace(): void {
  const fileInput = document.getElementById('openssl-file') as HTMLInputElement | null;
  document.getElementById('openssl-upload')?.addEventListener('click', () => fileInput?.click());
  fileInput?.addEventListener('change', () => {
    const file = fileInput.files?.[0]; if (!file) return;
    const output = document.getElementById('decrypt-results');
    if (file.size > 2 * 1024 * 1024) {
      if (output) output.innerHTML = '<div class="text-xs" style="color:var(--error)">Encrypted files are limited to 2 MiB.</div>';
      return;
    }
    const reader = new FileReader();
    reader.addEventListener('load', () => {
      const field = document.getElementById('openssl-input') as HTMLTextAreaElement | null;
      const encoding = document.getElementById('openssl-input-encoding') as HTMLSelectElement | null;
      if (field && typeof reader.result === 'string') field.value = reader.result.split(',', 2)[1] || '';
      if (encoding) encoding.value = 'base64';
      setOpenSslInputSummary(`${file.name} · ${formatByteCount(file.size)} · raw file bytes`);
    });
    reader.readAsDataURL(file);
  });
  document.getElementById('openssl-paste-hex')?.addEventListener('click', () => {
    const field = document.getElementById('openssl-input') as HTMLTextAreaElement | null;
    const encoding = document.getElementById('openssl-input-encoding') as HTMLSelectElement | null;
    if (encoding) encoding.value = 'hex'; field?.focus();
  });
  document.getElementById('openssl-use-artifact')?.addEventListener('click', () => {
    const id = (document.getElementById('openssl-artifact') as HTMLSelectElement | null)?.value;
    const artifact = artifacts.find(item => item.id === id); if (artifact) fillOpenSslArtifact(artifact);
  });
  const kdf = document.getElementById('openssl-kdf') as HTMLSelectElement | null;
  const syncKdf = (): void => {
    const pbkdf2 = kdf?.value === 'pbkdf2';
    const wrap = document.getElementById('openssl-iterations-wrap'); if (wrap) wrap.hidden = !pbkdf2;
    const digest = document.getElementById('openssl-digest') as HTMLSelectElement | null;
    if (pbkdf2 && digest?.value === 'auto') digest.value = 'sha256';
  };
  kdf?.addEventListener('change', syncKdf); syncKdf();
  document.getElementById('openssl-analyze-inline')?.addEventListener('click', () => void runOpenSslAnalysis());
  document.getElementById('openssl-decrypt-inline')?.addEventListener('click', () => void runOpenSslDecrypt());
}

function setOpenSslInputSummary(value: string): void {
  const summary = document.getElementById('openssl-input-summary'); if (summary) summary.textContent = value;
}

function formatByteCount(value: number): string {
  return value < 1024 ? `${value} B` : value < 1024 ** 2 ? `${(value / 1024).toFixed(1)} KiB` : `${(value / 1024 ** 2).toFixed(1)} MiB`;
}

function openSslMaterial(): { value: string; encoding: ValueEncoding } | null {
  const field = document.getElementById('openssl-input') as HTMLTextAreaElement | null;
  const encoding = document.getElementById('openssl-input-encoding') as HTMLSelectElement | null;
  return field?.value ? { value: field.value, encoding: (encoding?.value || 'auto') as ValueEncoding } : null;
}

function openSslPassword(): string {
  return (document.getElementById('openssl-password') as HTMLInputElement | null)?.value || '';
}

async function runOpenSslAnalysis(): Promise<void> {
  const encrypted = openSslMaterial(); const output = document.getElementById('decrypt-results');
  if (!encrypted || !output) { (document.getElementById('openssl-input') as HTMLTextAreaElement | null)?.focus(); return; }
  activeRequest?.abort(); activeRequest = new AbortController();
  output.innerHTML = '<div class="text-xs text-muted">Inspecting raw bytes for an OpenSSL enc header…</div>';
  try { renderOpenSslAnalysis(await analyzeOpenSsl(encrypted, openSslPassword() || null, activeRequest.signal)); }
  catch (error) { output.innerHTML = `<div class="text-xs" style="color:var(--error)">${escapeHtml(errorMessage(error))}</div>`; }
}

function renderOpenSslAnalysis(response: OpenSslAnalyzeResponse): void {
  const output = document.getElementById('decrypt-results'); if (!output) return;
  const heading = response.detected ? 'OPENSSL ENCRYPTED PAYLOAD DETECTED' : 'RAW ENCRYPTED PAYLOAD LOADED';
  output.innerHTML = `<div class="crypto-analysis-heading">${heading}</div>
    <div class="kv-list text-xs"><div class="kv-key">Format</div><div class="kv-value mono">${response.detected ? 'OpenSSL enc' : 'Raw bytes / no header'}</div><div class="kv-key">Header</div><div class="kv-value mono">${response.header || 'Not present'}</div><div class="kv-key">Salt</div><div class="kv-value mono">${response.salt_hex || 'Not available'}</div><div class="kv-key">Encrypted Payload</div><div class="kv-value mono">${response.encrypted_payload_bytes.toLocaleString()} bytes</div><div class="kv-key">Cipher</div><div class="kv-value mono">Unknown</div><div class="kv-key">Password</div><div class="kv-value mono">${response.password_supplied ? 'Provided' : 'Required for decryption'}</div></div>
    <div class="crypto-ready mt-8"><strong>${response.status === 'invalid-payload' ? 'Invalid Payload' : 'Ready for Decryption'}</strong><p>${escapeHtml(response.message)}</p></div>`;
}

async function runOpenSslDecrypt(): Promise<void> {
  const encrypted = openSslMaterial(); const output = document.getElementById('decrypt-results'); const password = openSslPassword();
  if (!encrypted || !output) { (document.getElementById('openssl-input') as HTMLTextAreaElement | null)?.focus(); return; }
  if (!password) {
    activeRequest?.abort(); activeRequest = new AbortController();
    try { renderOpenSslAnalysis(await analyzeOpenSsl(encrypted, null, activeRequest.signal)); }
    catch (error) { output.innerHTML = `<div class="text-xs" style="color:var(--error)">${escapeHtml(errorMessage(error))}</div>`; }
    (document.getElementById('openssl-password') as HTMLInputElement | null)?.focus();
    return;
  }
  const iterations = Number((document.getElementById('openssl-iterations') as HTMLInputElement | null)?.value || 10000);
  const request = {
    encrypted,
    password,
    password_encoding: ((document.getElementById('openssl-password-encoding') as HTMLSelectElement | null)?.value || 'utf-8') as PasswordEncoding,
    cipher: ((document.getElementById('openssl-cipher') as HTMLSelectElement | null)?.value || 'auto') as OpenSslCipher,
    kdf: ((document.getElementById('openssl-kdf') as HTMLSelectElement | null)?.value || 'auto') as OpenSslKdf,
    digest: ((document.getElementById('openssl-digest') as HTMLSelectElement | null)?.value || 'auto') as OpenSslDigest,
    iterations: Number.isFinite(iterations) ? iterations : 10000,
  };
  activeRequest?.abort(); activeRequest = new AbortController();
  output.innerHTML = '<div class="text-xs text-muted">Trying the bounded OpenSSL compatibility matrix and validating padding…</div>';
  try { renderOpenSslDecrypt(await decryptOpenSsl(request, activeRequest.signal)); }
  catch (error) { output.innerHTML = `<div class="text-xs" style="color:var(--error)">${escapeHtml(errorMessage(error))}</div>`; }
}

function renderOpenSslDecrypt(response: OpenSslDecryptResponse): void {
  const output = document.getElementById('decrypt-results'); if (!output) return;
  latestOpenSslResult = response;
  if (response.status === 'rejected' || !response.candidates.length) {
    output.innerHTML = `<div class="crypto-rejected">DECRYPTION CANDIDATE REJECTED</div><p class="text-sm">${escapeHtml(response.rejection_reason || 'No candidate passed validation.')}</p><div class="section-title mt-8">Possible causes</div><ul class="crypto-recommendations">${response.possible_causes.map(cause => `<li>${escapeHtml(cause)}</li>`).join('')}</ul><div class="text-xs text-muted mt-8">${response.attempted_variants} bounded parameter variant${response.attempted_variants === 1 ? '' : 's'} evaluated. SUCCESS was not reported.</div>`;
    return;
  }
  renderOpenSslCandidate(response.candidates[0], response);
}

function renderOpenSslCandidate(candidate: OpenSslDecryptCandidate, response: OpenSslDecryptResponse): void {
  const output = document.getElementById('decrypt-results'); if (!output) return;
  const alternatives = response.candidates.length > 1 ? `<div class="section-title mt-8">Other padding-valid candidates</div>${response.candidates.slice(1).map(item => `<button class="crypto-candidate-row" data-openssl-candidate="${item.rank - 1}"><span>#${item.rank} · ${escapeHtml(item.cipher_label)} · ${escapeHtml(item.digest.toUpperCase())}</span><strong>${item.confidence}</strong></button>`).join('')}` : '';
  output.innerHTML = `<div class="crypto-success">OPENSSL DECRYPTION · SUCCESS</div>
    <div class="kv-list text-xs"><div class="kv-key">Format</div><div class="kv-value mono">${response.payload.detected ? 'OpenSSL Salted' : 'Raw encrypted bytes'}</div><div class="kv-key">Cipher</div><div class="kv-value mono">${escapeHtml(candidate.cipher_label)}</div><div class="kv-key">Password</div><div class="kv-value mono">Provided</div><div class="kv-key">Salt</div><div class="kv-value mono">${response.payload.salt_hex || 'None'}</div><div class="kv-key">KDF</div><div class="kv-value mono">${escapeHtml(candidate.kdf)}${candidate.iterations ? ` · ${candidate.iterations.toLocaleString()} iterations` : ''}</div><div class="kv-key">Digest</div><div class="kv-value mono">${escapeHtml(candidate.digest.toUpperCase())}</div><div class="kv-key">Padding</div><div class="kv-value mono" style="color:var(--success)">VALID</div><div class="kv-key">Printable</div><div class="kv-value mono">${candidate.printable_percentage.toFixed(1)}%</div><div class="kv-key">UTF-8</div><div class="kv-value mono">${candidate.utf8_valid ? 'Valid' : 'Invalid'}</div><div class="kv-key">File Magic</div><div class="kv-value mono">${escapeHtml(candidate.file_magic || 'None')}</div><div class="kv-key">Flag Pattern</div><div class="kv-value mono">${candidate.flags.length ? 'FOUND · candidate only' : 'Not found'}</div><div class="kv-key">Confidence</div><div class="kv-value mono">${candidate.confidence}</div></div>
    <details class="crypto-secret-details mt-8"><summary>Show derived key and IV</summary><div class="kv-list text-xs mt-4"><div class="kv-key">Key</div><div class="kv-value mono crypto-break">${candidate.key_hex}</div><div class="kv-key">IV</div><div class="kv-value mono crypto-break">${candidate.iv_hex}</div></div></details>
    <div class="section-title mt-8">Plaintext</div><pre class="crypto-plaintext">${escapeHtml(candidate.plaintext)}</pre>
    ${candidate.flags.map(flag => `<div class="crypto-flag mt-4"><span class="mono">${escapeHtml(flag.value)}</span><span>flag candidate · review required</span></div>`).join('')}
    <div class="flex gap-4 mt-8"><button class="btn btn-secondary btn-sm" id="openssl-save">Save Plaintext</button><button class="btn btn-secondary btn-sm" id="openssl-send-decoder">Send to Decoder</button><button class="btn btn-secondary btn-sm" id="openssl-analyze-result">Analyze Result</button></div>
    ${candidate.equivalent_command ? `<div class="section-title mt-8">Equivalent Command</div><pre class="crypto-command">${escapeHtml(candidate.equivalent_command)}</pre><div class="text-xs text-muted mt-4">Informational only. CTFKit performed the decryption natively.</div>` : ''}${alternatives}`;
  document.getElementById('openssl-save')?.addEventListener('click', () => savePlaintext(candidate));
  document.getElementById('openssl-send-decoder')?.addEventListener('click', () => sendPlaintextToDecoder(candidate, false));
  document.getElementById('openssl-analyze-result')?.addEventListener('click', () => sendPlaintextToDecoder(candidate, true));
  output.querySelectorAll<HTMLButtonElement>('[data-openssl-candidate]').forEach(button => button.addEventListener('click', () => {
    const selected = latestOpenSslResult?.candidates[Number(button.dataset.opensslCandidate)];
    if (selected && latestOpenSslResult) renderOpenSslCandidate(selected, latestOpenSslResult);
  }));
}

function savePlaintext(candidate: OpenSslDecryptCandidate): void {
  const binary = atob(candidate.plaintext_base64); const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
  const link = document.createElement('a'); link.href = url; link.download = 'openssl-plaintext.bin'; link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function sendPlaintextToDecoder(candidate: OpenSslDecryptCandidate, analyze: boolean): void {
  addArtifact(`openssl-plaintext-${artifacts.length + 1}.bin`, candidate.plaintext_base64, 'base64', 'OpenSSL plaintext', 'Decryptor');
  pendingDecoderInput = candidate.plaintext_format === 'utf-8' ? candidate.plaintext : candidate.plaintext_base64;
  pendingDecoderAuto = analyze;
  window.location.hash = '#crypto/decoder';
}

function fillOpenSslArtifact(item: WorkspaceArtifact): void {
  const field = document.getElementById('openssl-input') as HTMLTextAreaElement | null;
  const encoding = document.getElementById('openssl-input-encoding') as HTMLSelectElement | null;
  if (field) field.value = item.value; if (encoding) encoding.value = item.encoding;
  setOpenSslInputSummary(`${item.name} · ${item.kind} · raw artifact bytes`);
}

function encodingOptions(): string { return '<option value="auto">Auto detect</option><option value="text">Text / PEM</option><option value="hex">Hex</option><option value="base64">Base64</option>'; }

function material(prefix: 'rsa-key' | 'rsa-cipher'): { value: string; encoding: ValueEncoding } | null {
  const field = document.getElementById(prefix === 'rsa-key' ? 'rsa-key' : 'rsa-ciphertext') as HTMLTextAreaElement | null;
  const selector = document.getElementById(`${prefix}-encoding`) as HTMLSelectElement | null;
  return field?.value ? { value: field.value, encoding: (selector?.value || 'auto') as ValueEncoding } : null;
}

async function runCryptoAnalysis(): Promise<void> {
  const key = material('rsa-key'); const ciphertext = material('rsa-cipher'); const output = document.getElementById('decrypt-results');
  if (!key || !output) return;
  activeRequest?.abort(); activeRequest = new AbortController(); output.innerHTML = '<div class="text-xs text-muted">Parsing key and matching artifacts…</div>';
  try { renderCryptoAnalysis(await analyzeCrypto(key, ciphertext, activeRequest.signal)); }
  catch (error) { output.innerHTML = `<div class="text-xs" style="color:var(--error)">${escapeHtml(errorMessage(error))}</div>`; }
}

function renderCryptoAnalysis(response: CryptoAnalyzeResponse): void {
  const output = document.getElementById('decrypt-results'); if (!output) return;
  output.innerHTML = `<div class="kv-list text-xs"><div class="kv-key">Key</div><div class="kv-value mono">RSA ${response.key.key_type}</div><div class="kv-key">Modulus</div><div class="kv-value mono">${response.key.modulus_bits} bits</div><div class="kv-key">Exponent</div><div class="kv-value mono">${response.key.public_exponent}</div><div class="kv-key">Cipher match</div><div class="kv-value mono">${response.compatible === null ? 'No ciphertext' : response.compatible ? 'One compatible RSA block' : 'Length mismatch'}</div></div>
    <div class="section-title mt-8">Findings</div>${response.findings.map(item => `<div class="crypto-finding severity-${item.severity}"><div><strong>${escapeHtml(item.title)}</strong><span>${item.severity.toUpperCase()} · ${Math.round(item.confidence * 100)}%</span></div><p>${escapeHtml(item.description)}</p></div>`).join('')}
    ${response.recommended_actions.length ? `<div class="section-title mt-8">Recommended</div><ol class="crypto-recommendations">${response.recommended_actions.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ol>` : ''}`;
}

async function runRsaDecrypt(): Promise<void> {
  const key = material('rsa-key'); const ciphertext = material('rsa-cipher'); const output = document.getElementById('decrypt-results');
  const padding = (document.getElementById('rsa-padding') as HTMLSelectElement | null)?.value as RsaPadding;
  if (!key || !ciphertext || !output) return;
  activeRequest?.abort(); activeRequest = new AbortController(); output.innerHTML = '<div class="text-xs text-muted">Decrypting one RSA block locally…</div>';
  try { renderRsaResult(await decryptRsa(key, ciphertext, padding, activeRequest.signal)); }
  catch (error) { output.innerHTML = `<div class="text-xs" style="color:var(--error)">${escapeHtml(errorMessage(error))}</div>`; }
}

function renderRsaResult(response: RsaDecryptResponse): void {
  const output = document.getElementById('decrypt-results'); if (!output) return;
  output.innerHTML = `<div class="crypto-success">SUCCESS</div><div class="kv-list text-xs"><div class="kv-key">Key</div><div class="kv-value mono">RSA ${response.key.modulus_bits} bits</div><div class="kv-key">Padding</div><div class="kv-value mono">${response.padding}</div><div class="kv-key">Ciphertext</div><div class="kv-value mono">${response.ciphertext_bytes} bytes</div></div><div class="section-title mt-8">Plaintext</div><pre class="crypto-plaintext">${escapeHtml(response.plaintext)}</pre>${response.flags.length ? `<div class="crypto-flag mt-8"><span class="mono">${escapeHtml(response.flags[0].value)}</span><span>flag candidate · review required</span></div>` : ''}<button class="btn btn-secondary btn-sm mt-8" id="plaintext-decoder">Send to Decoder</button>`;
  document.getElementById('plaintext-decoder')?.addEventListener('click', () => {
    addArtifact(`rsa-plaintext-${artifacts.length + 1}.bin`, response.plaintext_base64, 'base64', 'RSA plaintext', 'Decryptor');
    window.location.hash = '#crypto/decoder';
  });
}

function bindTray(): void {
  document.querySelectorAll<HTMLButtonElement>('.artifact-key, .artifact-cipher').forEach(button => button.addEventListener('click', () => {
    const selected = artifacts.find(item => item.id === button.dataset.id); if (!selected) return;
    const asKey = button.classList.contains('artifact-key');
    if (asKey) decryptorMode = 'rsa';
    else if (selected.kind.toLowerCase().includes('openssl') || selected.source.startsWith('Network Analyzer')) {
      decryptorMode = 'openssl'; pendingOpenSslArtifactId = selected.id;
    }
    if (!window.location.hash.includes('crypto/decryptor')) { window.location.hash = '#crypto/decryptor'; window.setTimeout(() => fillArtifact(selected, asKey), 0); }
    else if (asKey) { renderCrypto('decryptor'); window.setTimeout(() => fillArtifact(selected, true), 0); }
    else if (decryptorMode === 'openssl') renderCrypto('decryptor');
    else fillArtifact(selected, false);
  }));
}

function fillArtifact(item: WorkspaceArtifact, asKey: boolean): void {
  if (!asKey && decryptorMode === 'openssl') { fillOpenSslArtifact(item); pendingOpenSslArtifactId = null; return; }
  const field = document.getElementById(asKey ? 'rsa-key' : 'rsa-ciphertext') as HTMLTextAreaElement | null;
  const encoding = document.getElementById(asKey ? 'rsa-key-encoding' : 'rsa-cipher-encoding') as HTMLSelectElement | null;
  if (field) field.value = item.value; if (encoding) encoding.value = item.encoding;
}
