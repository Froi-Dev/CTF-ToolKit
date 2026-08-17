import { ApiError } from '../api/client.ts';
import { analyzeAudio, type AudioAnalysisResponse, type AudioArtifact } from '../api/audio.ts';
import { icons, severityClass } from '../data.ts';

type AudioTab = 'overview' | 'spectrogram' | 'playback' | 'signals' | 'evidence' | 'raw';

let activeTab: AudioTab = 'overview';
let selectedFile: File | null = null;
let latestResponse: AudioAnalysisResponse | null = null;
let activeRequest: AbortController | null = null;
let sourceUrl: string | null = null;
let customFlagPrefix = '';
let analyzing = false;
let statusMessage = 'Ready';
let statusIsError = false;

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

function formatDuration(value: number | null): string {
  if (value === null) return 'Unavailable';
  const minutes = Math.floor(value / 60);
  return `${String(minutes).padStart(2, '0')}:${(value % 60).toFixed(2).padStart(5, '0')}`;
}

function artifactUrl(artifact: AudioArtifact): string | null {
  return artifact.content_base64 ? `data:${artifact.mime_type};base64,${artifact.content_base64}` : null;
}

export function renderAudio(): void {
  renderShell();
}

function renderShell(): void {
  const main = document.getElementById('main');
  if (!main) return;
  const result = latestResponse;
  const subtitle = result
    ? `${escapeHtml(result.file.name)} / ${escapeHtml(result.file.container)} / ${formatDuration(result.file.duration_seconds)} / ${formatBytes(result.file.size)}`
    : 'Audio forensics, spectrogram, channel, tone, embedded-data, and PCM steganography analysis';
  main.innerHTML = `<div class="main-content-wide" id="audio-page">
    <div class="page-header">
      <div><div class="page-title">Audio Analyzer</div><div class="page-subtitle">${subtitle}</div></div>
      <div class="page-actions">
        <input id="audio-file" type="file" accept=".wav,.wave,.mp3,.flac,.ogg,.opus,.m4a,.aac,.aiff,.aif,.au,.raw,.pcm,audio/*" hidden>
        <button class="btn btn-secondary btn-sm" id="audio-select">${icons.folder} Choose Audio</button>
        <button class="btn btn-primary btn-sm" id="audio-run" ${selectedFile && !analyzing ? '' : 'disabled'}>${analyzing ? `${icons.loader} Analyzing...` : `${icons.play} Analyze`}</button>
      </div>
    </div>
    ${renderSelectionPanel()}
    ${result ? renderTabs(result) : renderEmptyState()}
  </div>`;
  bindEvents();
}

function renderSelectionPanel(): string {
  const raw = selectedFile ? /\.(raw|pcm)$/i.test(selectedFile.name) : false;
  return `<div class="panel mb-4"><div class="panel-body flex items-center gap-4" style="flex-wrap:wrap">
    <div style="flex:1;min-width:260px">
      <div class="text-sm">${selectedFile ? escapeHtml(selectedFile.name) : 'No audio selected'}</div>
      <div class="text-xs text-muted">64 MiB limit / WAV, MP3, FLAC, OGG, OPUS, M4A, AAC, AIFF, AU, RAW, and PCM.</div>
    </div>
    <label class="text-xs" style="display:flex;align-items:center;gap:8px">Flag prefix
      <input id="audio-prefix" class="input input-sm" style="width:120px" maxlength="32" value="${escapeHtml(customFlagPrefix)}" placeholder="optional">
    </label>
    <div class="text-xs ${statusIsError ? '' : 'text-muted'}" id="audio-status" ${statusIsError ? 'style="color:var(--error)"' : ''}>${escapeHtml(statusMessage)}</div>
    ${raw ? `<div class="grid-4" style="width:100%;gap:12px;padding-top:12px;border-top:1px solid var(--border-light)">
      <label class="text-xs">Sample rate<input class="input input-sm" id="raw-rate" type="number" value="44100" min="1" max="768000"></label>
      <label class="text-xs">Bit depth<select class="input input-sm" id="raw-depth"><option>8</option><option selected>16</option><option>24</option><option>32</option></select></label>
      <label class="text-xs">Channels<input class="input input-sm" id="raw-channels" type="number" value="1" min="1" max="32"></label>
      <label class="text-xs">Encoding<select class="input input-sm" id="raw-format"><option value="little:true">Signed little-endian</option><option value="big:true">Signed big-endian</option><option value="little:false">Unsigned little-endian</option><option value="big:false">Unsigned big-endian</option></select></label>
    </div>` : ''}
  </div></div>`;
}

function renderEmptyState(): string {
  return `<div class="section"><div class="panel"><div class="panel-body">
    <div class="section-title mb-4">No audio analyzed</div>
    <div class="text-sm text-muted">Choose an audio file, click Analyze, then review findings, the spectrogram, decoded signals, extracted evidence, and raw container details.</div>
  </div></div></div>`;
}

function renderTabs(result: AudioAnalysisResponse): string {
  const playableCount = result.artifacts.filter(a => ['reversed', 'slowed', 'sped-up', 'channel', 'difference-channel'].includes(a.kind)).length;
  const tabs: Array<[AudioTab, string, number | null]> = [
    ['overview', 'Overview', result.findings.length],
    ['spectrogram', 'Spectrogram', result.spectrogram ? 1 : 0],
    ['playback', 'Playback', playableCount + 1],
    ['signals', 'Signals', result.tones.dtmf_events.length + result.channels.length + (result.sstv?.detected ? 1 : 0)],
    ['evidence', 'Evidence', result.flags.length + result.artifacts.length],
    ['raw', 'Raw Details', result.riff_chunks.length],
  ];
  return `<div class="tab-bar" id="audio-tabs">${tabs.map(([id, label, count]) => `
    <div class="tab-item ${activeTab === id ? 'active' : ''}" data-audio-tab="${id}">${label}${count === null ? '' : ` <span class="tab-count">${count}</span>`}</div>`).join('')}
  </div><div id="audio-content">${renderTab(result)}</div>`;
}

function renderTab(result: AudioAnalysisResponse): string {
  switch (activeTab) {
    case 'spectrogram': return renderSpectrogram(result);
    case 'playback': return renderPlayback(result);
    case 'signals': return renderSignals(result);
    case 'evidence': return renderEvidence(result);
    case 'raw': return renderRaw(result);
    default: return renderOverview(result);
  }
}

function renderOverview(result: AudioAnalysisResponse): string {
  return `<div class="section">
    <div class="section-title mb-4">Analysis Summary</div>
    <div class="panel mb-4"><div class="panel-body">
      <div class="text-sm">${escapeHtml(result.summary)}</div>
      <div class="text-xs text-muted mt-4">${escapeHtml(result.evidence_integrity)}</div>
    </div></div>
    <div class="grid-2 mb-4">
      <div class="panel"><div class="panel-header">File Summary</div><div class="panel-body"><div class="kv-list">
        <div class="kv-key">File</div><div class="kv-value mono">${escapeHtml(result.file.name)}</div>
        <div class="kv-key">Format</div><div class="kv-value">${escapeHtml(result.file.detected_type)} / ${escapeHtml(result.file.codec)}</div>
        <div class="kv-key">Signal</div><div class="kv-value">${result.file.sample_rate?.toLocaleString() || '?'} Hz / ${result.file.bit_depth || '?'}-bit / ${escapeHtml(result.file.channel_layout || `${result.file.channels || '?'} channels`)}</div>
        <div class="kv-key">Duration</div><div class="kv-value mono">${formatDuration(result.file.duration_seconds)}</div>
        <div class="kv-key">Extension</div><div class="kv-value"><span class="badge ${result.file.extension_matches ? 'badge-success' : 'badge-error'}">${result.file.extension_matches ? 'Consistent' : 'Mismatch'}</span></div>
        <div class="kv-key">SHA-256</div><div class="kv-value mono" style="word-break:break-all">${result.file.hashes.sha256}</div>
      </div></div></div>
      <div class="panel"><div class="panel-header">Quick Stats</div><div class="panel-body"><div class="kv-list">
        <div class="kv-key">DTMF</div><div class="kv-value mono">${escapeHtml(result.tones.dtmf_sequence || 'Not detected')}</div>
        <div class="kv-key">Morse</div><div class="kv-value mono">${escapeHtml(result.tones.morse_text || 'Not detected')}</div>
        <div class="kv-key">SSTV</div><div class="kv-value">${result.sstv?.detected ? `<span class="badge badge-warning">${escapeHtml(result.sstv.mode || 'Detected')}</span>` : 'Not detected'}</div>
        <div class="kv-key">LSB leads</div><div class="kv-value">${result.lsb_candidates.length}</div>
        <div class="kv-key">Embedded files</div><div class="kv-value">${result.embedded_files.length}</div>
        <div class="kv-key">Ultrasonic</div><div class="kv-value">${result.tones.ultrasonic_peak_hz ? `${result.tones.ultrasonic_peak_hz.toFixed(1)} Hz` : 'No strong lead'}</div>
      </div></div></div>
    </div>
    ${renderFlags(result)}
    <div class="section-title mb-4">Notable Findings</div>
    ${result.findings.length ? result.findings.map(renderFinding).join('') : '<div class="panel"><div class="panel-body text-sm text-muted">No notable anomaly crossed the reporting threshold.</div></div>'}
    ${result.recommendations.length ? `<div class="panel mt-4"><div class="panel-header">Recommended Next Steps</div><div class="panel-body text-sm">${result.recommendations.map(item => `<div class="mb-4">${escapeHtml(item)}</div>`).join('')}</div></div>` : ''}
  </div>`;
}

function renderFlags(result: AudioAnalysisResponse): string {
  if (!result.flags.length) return '';
  return `<div class="section-title mb-4">Flag Candidates</div>${result.flags.map(flag => `<div class="panel mb-4" style="border-left:3px solid var(--success)">
    <div class="panel-header"><span style="color:var(--success)">[CANDIDATE]</span><span class="mono">${Math.round(flag.confidence * 100)}%</span></div>
    <div class="panel-body"><div class="mono" style="font-size:16px;color:var(--success);word-break:break-all">${escapeHtml(flag.value)}</div>
      <div class="text-xs text-muted mt-4">${escapeHtml(flag.extraction_method)} / review required</div></div>
  </div>`).join('')}`;
}

function renderFinding(item: AudioAnalysisResponse['findings'][number]): string {
  return `<div class="panel mb-4" style="border-left:3px solid ${severityColor(item.severity)}">
    <div class="panel-header"><span><span class="badge ${severityClass(item.severity)}">${item.severity}</span> ${escapeHtml(item.title)}</span><span class="mono">${Math.round(item.confidence * 100)}%</span></div>
    <div class="panel-body"><div class="text-sm">${escapeHtml(item.description)}</div>
      <div class="text-xs text-muted mt-4">${escapeHtml(item.method)}${item.location ? ` / ${escapeHtml(item.location)}` : ''}</div>
      ${item.recommendation ? `<div class="text-xs mt-4"><strong>Next:</strong> ${escapeHtml(item.recommendation)}</div>` : ''}
    </div></div>`;
}

function severityColor(severity: AudioAnalysisResponse['findings'][number]['severity']): string {
  return ({ critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', info: 'var(--info)' })[severity];
}

function renderSpectrogram(result: AudioAnalysisResponse): string {
  const specArtifact = result.artifacts.find(item => item.artifact_id === result.spectrogram?.artifact_id);
  const specUrl = specArtifact ? artifactUrl(specArtifact) : null;
  const wfArtifact = result.artifacts.find(item => item.kind === 'waveform-image');
  const wfUrl = wfArtifact ? artifactUrl(wfArtifact) : null;
  return `<div class="section"><div class="section-header"><div class="section-title">Spectrogram</div>${result.spectrogram ? `<span class="text-xs text-muted">FFT ${result.spectrogram.fft_size} / hop ${result.spectrogram.hop_size} / ${result.spectrogram.dynamic_range_db} dB</span>` : ''}</div>
    <div class="panel"><div class="panel-body">
      ${specUrl ? `<div style="overflow:auto;background:#050505"><img id="audio-spectrogram" src="${specUrl}" alt="Forensic STFT spectrogram" style="display:block;width:100%;min-width:720px"></div>
      <label class="text-xs mt-4" style="display:flex;align-items:center;gap:8px">Contrast <input id="spectrogram-contrast" type="range" min="75" max="200" value="100"></label>` : '<div class="text-sm text-muted">No spectrogram was generated for this input.</div>'}
    </div></div>
    ${wfUrl ? `<div class="panel mt-4"><div class="panel-header">Waveform</div><div class="panel-body"><div style="overflow:auto;background:#0c0c0c"><img src="${wfUrl}" alt="Time-domain waveform" style="display:block;width:100%;min-width:720px"></div></div></div>` : ''}
    ${result.spectrogram ? `<div class="grid-4 mt-4">${Object.entries(result.spectrogram.frequency_band_energy).map(([band, energy]) => `<div class="panel"><div class="panel-body"><div class="text-xs text-muted">${escapeHtml(band)}</div><div class="mono mt-4">${(energy * 100).toFixed(2)}%</div></div></div>`).join('')}</div>` : ''}
  </div>`;
}

function renderPlayback(result: AudioAnalysisResponse): string {
  const playerCards: Array<{ label: string; description: string; url: string | null }> = [];
  // Original
  playerCards.push({ label: 'Original', description: 'Original uploaded audio at normal speed.', url: sourceUrl });
  // Reversed
  const reversedArtifact = result.artifacts.find(a => a.kind === 'reversed');
  playerCards.push({ label: 'Reversed', description: 'Audio played in reverse for hidden messages.', url: reversedArtifact ? artifactUrl(reversedArtifact) : null });
  // Slowed
  const slowedArtifact = result.artifacts.find(a => a.kind === 'slowed');
  playerCards.push({ label: 'Slowed (0.5x)', description: 'Audio at half speed to reveal fast patterns.', url: slowedArtifact ? artifactUrl(slowedArtifact) : null });
  // Sped-up
  const spedUpArtifact = result.artifacts.find(a => a.kind === 'sped-up');
  playerCards.push({ label: 'Sped Up (2x)', description: 'Audio at double speed to reveal slow patterns.', url: spedUpArtifact ? artifactUrl(spedUpArtifact) : null });
  // Left channel
  const leftArtifact = result.artifacts.find(a => a.kind === 'channel' && a.filename.startsWith('left'));
  if (leftArtifact) playerCards.push({ label: 'Left Channel', description: 'Isolated left channel audio.', url: artifactUrl(leftArtifact) });
  // Right channel
  const rightArtifact = result.artifacts.find(a => a.kind === 'channel' && a.filename.startsWith('right'));
  if (rightArtifact) playerCards.push({ label: 'Right Channel', description: 'Isolated right channel audio.', url: artifactUrl(rightArtifact) });
  // Difference channel
  const diffArtifact = result.artifacts.find(a => a.kind === 'difference-channel');
  if (diffArtifact) playerCards.push({ label: 'L\u2212R Difference', description: 'Phase-cancellation difference between left and right channels.', url: artifactUrl(diffArtifact) });

  return `<div class="section">
    <div class="section-title mb-4">Audio Playback Variants</div>
    <div class="text-xs text-muted mb-4">Listen to all generated audio variants directly. Each card plays an excerpt of up to 10 seconds.</div>
    <div class="audio-playback-grid">
      ${playerCards.map(card => `<div class="panel audio-player-card">
        <div class="panel-header">${escapeHtml(card.label)}</div>
        <div class="panel-body">
          <div class="text-xs text-muted mb-4">${escapeHtml(card.description)}</div>
          ${card.url ? `<audio controls style="width:100%" src="${card.url}" preload="none"></audio>` : '<div class="text-xs text-muted" style="opacity:0.5">Not available</div>'}
        </div>
      </div>`).join('')}
    </div>
  </div>`;
}

function renderSignals(result: AudioAnalysisResponse): string {
  return `<div class="section"><div class="grid-2 mb-4">
    <div class="panel"><div class="panel-header">Waveform</div><div class="panel-body">${result.waveform ? `<div class="kv-list">
      <div class="kv-key">Peak</div><div class="kv-value mono">${result.waveform.peak.toFixed(5)}</div>
      <div class="kv-key">RMS</div><div class="kv-value mono">${result.waveform.rms.toFixed(5)}</div>
      <div class="kv-key">DC offset</div><div class="kv-value mono">${result.waveform.dc_offset.toFixed(5)}</div>
      <div class="kv-key">Clipping</div><div class="kv-value mono">${(result.waveform.clipping_ratio * 100).toFixed(2)}%</div>
      <div class="kv-key">Silence</div><div class="kv-value mono">${(result.waveform.silence_ratio * 100).toFixed(2)}%</div>
    </div>` : '<div class="text-sm text-muted">Waveform analysis unavailable.</div>'}</div></div>
    <div class="panel"><div class="panel-header">Detected Signals</div><div class="panel-body"><div class="kv-list">
      <div class="kv-key">DTMF</div><div class="kv-value mono">${escapeHtml(result.tones.dtmf_sequence || 'Not detected')}</div>
      <div class="kv-key">Morse</div><div class="kv-value mono">${escapeHtml(result.tones.morse_text || 'Not detected')}</div>
      <div class="kv-key">SSTV</div><div class="kv-value">${result.sstv?.detected ? `<span class="badge badge-warning">${escapeHtml(result.sstv.mode || 'Detected')}</span>${result.sstv.header_offset_seconds !== null ? ` <span class="text-xs text-muted">at ${result.sstv.header_offset_seconds.toFixed(3)}s</span>` : ''}` : 'Not detected'}</div>
      <div class="kv-key">Carrier</div><div class="kv-value">${result.tones.carrier_hz ? `${result.tones.carrier_hz.toFixed(1)} Hz` : 'None'}</div>
      <div class="kv-key">Ultrasonic</div><div class="kv-value">${result.tones.ultrasonic_peak_hz ? `${result.tones.ultrasonic_peak_hz.toFixed(1)} Hz` : 'No strong lead'}</div>
      <div class="kv-key">LSB leads</div><div class="kv-value">${result.lsb_candidates.length}</div>
    </div></div></div>
  </div>
  ${result.sstv?.detected ? `<div class="panel mb-4" style="border-left:3px solid var(--warning)"><div class="panel-header"><span style="color:var(--warning)">SSTV Transmission</span><span class="mono">${Math.round((result.sstv.confidence) * 100)}%</span></div><div class="panel-body"><div class="kv-list">
    <div class="kv-key">Mode</div><div class="kv-value">${escapeHtml(result.sstv.mode || 'Unknown')}</div>
    <div class="kv-key">Header offset</div><div class="kv-value mono">${result.sstv.header_offset_seconds !== null ? result.sstv.header_offset_seconds.toFixed(4) + 's' : 'Unknown'}</div>
    <div class="kv-key">Confidence</div><div class="kv-value mono">${(result.sstv.confidence * 100).toFixed(1)}%</div>
  </div><div class="text-xs text-muted mt-4">Use an SSTV decoder (QSSTV, MMSSTV, or an online tool) to extract the hidden image.</div></div></div>` : ''}
  <div class="section-title mb-4">Channel Analysis</div>
  ${result.channels.length ? `<table class="data-table"><thead><tr><th>Channel</th><th>RMS</th><th>Peak</th><th>DC offset</th><th>Entropy</th><th>&gt;16 kHz</th></tr></thead><tbody>${result.channels.map(channel => `<tr><td>${escapeHtml(channel.channel)}</td><td class="mono">${channel.rms.toFixed(5)}</td><td class="mono">${channel.peak.toFixed(5)}</td><td class="mono">${channel.dc_offset.toFixed(5)}</td><td class="mono">${channel.entropy.toFixed(3)}</td><td class="mono">${(channel.high_frequency_ratio * 100).toFixed(2)}%</td></tr>`).join('')}</tbody></table>` : '<div class="text-sm text-muted">No decoded channels available.</div>'}
  </div>`;
}

function renderEvidence(result: AudioAnalysisResponse): string {
  return `<div class="section">${renderFlags(result)}
    <div class="section-title mb-4">Extracted Evidence</div>
    <div class="panel mb-4"><div class="panel-body">${result.artifacts.length ? result.artifacts.map(item => `<div class="flex items-center gap-4 mb-4" style="padding-bottom:12px;border-bottom:1px solid var(--border-light)">
      <div style="flex:1;min-width:0"><div class="text-sm mono" style="word-break:break-all">${escapeHtml(item.filename)}</div><div class="text-xs text-muted">${escapeHtml(item.description)} / ${formatBytes(item.size)}</div></div>
      ${item.content_base64 ? `<button class="btn btn-secondary btn-sm" data-audio-artifact="${item.artifact_id}">${icons.download} Download</button>` : '<span class="badge badge-warning">Report limit</span>'}
    </div>`).join('') : '<div class="text-sm text-muted">No generated evidence artifacts.</div>'}</div></div>
    <div class="section-title mb-4">PCM Bit-Plane Leads</div>
    ${result.lsb_candidates.length ? `<table class="data-table"><thead><tr><th>Channel</th><th>Bit</th><th>Order</th><th>Printable</th><th>Entropy</th><th>Detected</th><th>Preview</th></tr></thead><tbody>${result.lsb_candidates.map(item => `<tr><td>${escapeHtml(item.channel)}</td><td class="mono">${item.bit_plane}</td><td>${escapeHtml(item.bit_order)}</td><td>${(item.printable_ratio * 100).toFixed(1)}%</td><td>${item.entropy.toFixed(3)}</td><td>${escapeHtml(item.recognized_type || 'Text lead')}</td><td class="mono" style="word-break:break-all">${escapeHtml(item.preview || '')}</td></tr>`).join('')}</tbody></table>` : '<div class="text-sm text-muted">No ranked PCM bit-plane lead.</div>'}
  </div>`;
}

function renderRaw(result: AudioAnalysisResponse): string {
  return `<div class="section"><div class="grid-2 mb-4">
    <div class="panel"><div class="panel-header">Tools and Warnings</div><div class="panel-body text-xs">
      ${Object.entries(result.tools).map(([name, available]) => `<div class="mb-4"><span class="badge ${available ? 'badge-success' : 'badge-error'}">${available ? 'Available' : 'Unavailable'}</span> <span class="mono">${escapeHtml(name)}</span></div>`).join('')}
      ${result.errors.map(item => `<div class="mb-4" style="color:var(--warning)">${escapeHtml(item)}</div>`).join('')}
    </div></div>
    <div class="panel"><div class="panel-header">Metadata</div><div class="panel-body"><div class="kv-list">${Object.entries(result.metadata).map(([key, value]) => `<div class="kv-key">${escapeHtml(key)}</div><div class="kv-value mono">${escapeHtml(value)}</div>`).join('') || '<div class="text-sm text-muted">No metadata recovered.</div>'}</div></div></div>
  </div>
  <div class="section-title mb-4">RIFF Chunks</div>
  ${result.riff_chunks.length ? `<table class="data-table mb-4"><thead><tr><th>Offset</th><th>Chunk</th><th>Size</th><th>Status</th><th>Preview</th></tr></thead><tbody>${result.riff_chunks.map(chunk => `<tr><td class="mono">0x${chunk.offset.toString(16)}</td><td class="mono">${escapeHtml(chunk.chunk_id)}</td><td>${formatBytes(chunk.size)}</td><td>${chunk.malformed ? 'Malformed' : chunk.known ? 'Known' : 'Unknown'}</td><td class="mono">${escapeHtml(chunk.preview || '')}</td></tr>`).join('')}</tbody></table>` : '<div class="text-sm text-muted mb-4">Not a parsed RIFF/WAVE container.</div>'}
  <div class="section-title mb-4">Strings</div>
  ${result.strings.length ? `<table class="data-table"><thead><tr><th>Value</th></tr></thead><tbody>${result.strings.slice(0, 100).map(item => `<tr><td class="mono" style="word-break:break-all">${escapeHtml(item)}</td></tr>`).join('')}</tbody></table>` : '<div class="text-sm text-muted">No printable strings recovered.</div>'}
  </div>`;
}

function bindEvents(): void {
  const input = document.getElementById('audio-file') as HTMLInputElement | null;
  document.getElementById('audio-select')?.addEventListener('click', () => input?.click());
  input?.addEventListener('change', () => selectFile(input.files?.[0] || null));
  document.getElementById('audio-run')?.addEventListener('click', () => void runAnalysis());
  document.querySelectorAll<HTMLElement>('[data-audio-tab]').forEach(tab => tab.addEventListener('click', () => {
    activeTab = (tab.dataset.audioTab as AudioTab | undefined) || 'overview';
    renderShell();
  }));
  const player = document.getElementById('audio-player') as HTMLAudioElement | null;
  (document.getElementById('audio-speed') as HTMLSelectElement | null)?.addEventListener('change', event => { if (player) player.playbackRate = Number((event.target as HTMLSelectElement).value); });
  (document.getElementById('audio-loop') as HTMLInputElement | null)?.addEventListener('change', event => { if (player) player.loop = (event.target as HTMLInputElement).checked; });
  (document.getElementById('spectrogram-contrast') as HTMLInputElement | null)?.addEventListener('input', event => {
    const image = document.getElementById('audio-spectrogram') as HTMLImageElement | null;
    if (image) image.style.filter = `contrast(${(event.target as HTMLInputElement).value}%)`;
  });
  document.querySelectorAll<HTMLButtonElement>('[data-audio-artifact]').forEach(button => button.addEventListener('click', () => downloadArtifact(button.dataset.audioArtifact || '')));
}

function selectFile(file: File | null): void {
  activeRequest?.abort();
  activeRequest = null;
  analyzing = false;
  latestResponse = null;
  activeTab = 'overview';
  statusIsError = false;
  if (sourceUrl) URL.revokeObjectURL(sourceUrl);
  sourceUrl = null;
  if (!file) {
    selectedFile = null;
    statusMessage = 'Ready';
  } else if (file.size > 64 * 1024 * 1024) {
    selectedFile = null;
    statusIsError = true;
    statusMessage = 'The selected file exceeds the 64 MiB limit.';
  } else {
    selectedFile = file;
    sourceUrl = URL.createObjectURL(file);
    statusMessage = `${formatBytes(file.size)} selected`;
  }
  renderShell();
}

async function runAnalysis(): Promise<void> {
  if (!selectedFile || analyzing) return;
  customFlagPrefix = (document.getElementById('audio-prefix') as HTMLInputElement | null)?.value.trim() || customFlagPrefix;
  const rawFormat = (document.getElementById('raw-format') as HTMLSelectElement | null)?.value.split(':');
  const raw = /\.(raw|pcm)$/i.test(selectedFile.name) ? {
    sampleRate: Number((document.getElementById('raw-rate') as HTMLInputElement).value),
    bitDepth: Number((document.getElementById('raw-depth') as HTMLSelectElement).value),
    channels: Number((document.getElementById('raw-channels') as HTMLInputElement).value),
    endianness: (rawFormat?.[0] || 'little') as 'little' | 'big',
    signed: rawFormat?.[1] !== 'false',
  } : undefined;
  const controller = new AbortController();
  activeRequest?.abort();
  activeRequest = controller;
  analyzing = true;
  statusIsError = false;
  statusMessage = 'Analyzing audio...';
  renderShell();
  try {
    latestResponse = await analyzeAudio(selectedFile, { raw, customFlagPrefix, signal: controller.signal });
    statusMessage = `Analysis ${latestResponse.analysis_id}`;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    statusIsError = true;
    statusMessage = error instanceof ApiError && error.code === 'NETWORK_ERROR'
      ? 'Backend unavailable. Start FastAPI on 127.0.0.1:8000.'
      : error instanceof Error ? error.message : 'Audio analysis failed.';
  } finally {
    if (activeRequest === controller) {
      activeRequest = null;
      analyzing = false;
      renderShell();
    }
  }
}

function downloadArtifact(artifactId: string): void {
  const artifact = latestResponse?.artifacts.find(item => item.artifact_id === artifactId);
  const url = artifact ? artifactUrl(artifact) : null;
  if (!artifact || !url) return;
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = artifact.filename.replace(/[\\/:*?"<>|]/g, '_');
  anchor.click();
}
