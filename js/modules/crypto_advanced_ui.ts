import { analyzeSymmetric, analyzeStream, analyzeHash, analyzeCustom } from '../api/crypto_advanced.ts';

export function renderAdvancedCrypto(main: HTMLElement): void {
  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header">
      <div><div class="page-title">Cryptography / Advanced Analyzers</div><div class="page-subtitle">Symmetric, Stream, Hash, and Custom encryption analysis</div></div>
    </div>
    
    <div class="panel mt-4">
      <div class="panel-header">Analyze Raw Ciphertext (Symmetric / Stream)</div>
      <div class="panel-body">
        <textarea id="adv-ciphertext" class="form-control mb-4" rows="4" placeholder="Enter hex, base64, or raw bytes"></textarea>
        <div class="flex gap-2">
            <button class="btn btn-primary btn-sm" id="btn-sym">Analyze Symmetric</button>
            <button class="btn btn-secondary btn-sm" id="btn-stream">Analyze Stream</button>
        </div>
      </div>
    </div>

    <div class="panel mt-4">
      <div class="panel-header">Hash Cracking</div>
      <div class="panel-body">
        <input type="text" id="adv-hash" class="form-control mb-4" placeholder="Enter hash to identify and crack" />
        <button class="btn btn-primary btn-sm" id="btn-hash">Analyze Hash</button>
      </div>
    </div>

    <div class="panel mt-4">
      <div class="panel-header">Custom Python Encryption Analyzer</div>
      <div class="panel-body">
        <textarea id="adv-custom" class="form-control mb-4" rows="6" placeholder="Paste python encryption script..."></textarea>
        <button class="btn btn-primary btn-sm" id="btn-custom">Extract Variables & Generate Solver</button>
      </div>
    </div>

    <div class="panel mt-4">
      <div class="panel-header">Findings</div>
      <div class="panel-body" id="adv-findings">
        <div class="text-xs text-muted">Run an analyzer to view findings.</div>
      </div>
    </div>
  </div>`;

  document.getElementById('btn-sym')?.addEventListener('click', async () => {
    const val = (document.getElementById('adv-ciphertext') as HTMLTextAreaElement).value;
    const res = await analyzeSymmetric(val);
    document.getElementById('adv-findings')!.innerHTML = '<pre>' + JSON.stringify(res.findings, null, 2) + '</pre>';
  });

  document.getElementById('btn-stream')?.addEventListener('click', async () => {
    const val = (document.getElementById('adv-ciphertext') as HTMLTextAreaElement).value;
    const res = await analyzeStream([val]);
    document.getElementById('adv-findings')!.innerHTML = '<pre>' + JSON.stringify(res, null, 2) + '</pre>';
  });

  document.getElementById('btn-hash')?.addEventListener('click', async () => {
    const val = (document.getElementById('adv-hash') as HTMLInputElement).value;
    const res = await analyzeHash(val);
    document.getElementById('adv-findings')!.innerHTML = '<pre>' + JSON.stringify(res, null, 2) + '</pre>';
  });

  document.getElementById('btn-custom')?.addEventListener('click', async () => {
    const val = (document.getElementById('adv-custom') as HTMLTextAreaElement).value;
    const res = await analyzeCustom(val);
    document.getElementById('adv-findings')!.innerHTML = '<pre>' + JSON.stringify(res, null, 2) + '</pre>';
  });
}
