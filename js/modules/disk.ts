import { ApiError } from '../api/client.ts';
import { analyzeDiskImage, type DiskForensicsResponse, type PartitionEntry, type FileEntry, type UnallocatedRegion, type NotableFinding } from '../api/disk.ts';
import { icons } from '../data.ts';

type TreeNodeType = 'image' | 'partition' | 'files' | 'deleted' | 'unallocated' | 'carved' | 'flags' | 'notable' | 'timeline';

interface TreeNode {
  id: string;
  type: TreeNodeType;
  label: string;
  icon: string;
  data?: any;
  children?: TreeNode[];
  expanded?: boolean;
}

type InspectorTab = 'metadata' | 'hex' | 'preview' | 'strings';

let selectedFile: File | null = null;
let latestResponse: DiskForensicsResponse | null = null;
let activeRequest: AbortController | null = null;

let treeNodes: TreeNode[] = [];
let selectedNodeId: string = 'image';
let selectedCenterItem: any = null;
let activeInspectorTab: InspectorTab = 'metadata';

let isAnalyzing: boolean = false;
let simulatedProgress: number = 0;
let progressInterval: number | null = null;

function escapeHtml(value: unknown): string {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>'"]/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character] || character);
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MiB`;
  return `${(value / 1024 ** 3).toFixed(2)} GiB`;
}

function formatDate(iso: string | null): string {
  if (!iso) return '-';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toISOString().replace('T', ' ').substring(0, 19);
}

function badge(ok: boolean, yes: string, no: string, clsYes = 'badge-success', clsNo = 'badge-error'): string {
  return `<span class="badge ${ok ? clsYes : clsNo}">${ok ? yes : no}</span>`;
}

export function renderDisk(view?: string): void {
  activeRequest?.abort();
  activeRequest = null;
  selectedFile = null;
  latestResponse = null;
  selectedNodeId = 'image';
  selectedCenterItem = null;
  isAnalyzing = false;
  renderShell();
}

function buildTree(result: DiskForensicsResponse): TreeNode[] {
  const nodes: TreeNode[] = [];
  const root: TreeNode = {
    id: 'image',
    type: 'image',
    label: result.image.filename || 'Disk Image',
    icon: icons.dashboard,
    expanded: true,
    children: []
  };

  if (result.partitions.length > 0) {
    const partsNode: TreeNode = {
      id: 'partitions_root',
      type: 'partition',
      label: 'Partitions',
      icon: icons.folder,
      expanded: true,
      children: result.partitions.map(p => ({
        id: `part_${p.number}`,
        type: 'partition',
        label: `${p.slot} — ${p.filesystem || 'Unknown'}`,
        icon: icons.dashboard,
        data: p,
      }))
    };
    root.children?.push(partsNode);
  } else {
    root.children?.push({ id: 'raw_disk', type: 'partition', label: 'Raw Disk Regions', icon: icons.dashboard });
  }

  root.children?.push({ id: 'files_root', type: 'files', label: 'Filesystem', icon: icons.folder });
  root.children?.push({ id: 'deleted_root', type: 'deleted', label: 'Deleted Files', icon: icons.x });
  root.children?.push({ id: 'unallocated_root', type: 'unallocated', label: 'Unallocated Space', icon: icons.circle });
  root.children?.push({ id: 'carved_root', type: 'carved', label: 'Carved Files', icon: icons.file });
  root.children?.push({ id: 'notable_root', type: 'notable', label: 'Notable Findings', icon: icons.bell });
  root.children?.push({ id: 'flags_root', type: 'flags', label: 'Flag Hunt', icon: icons.flag });
  root.children?.push({ id: 'timeline_root', type: 'timeline', label: 'Timeline', icon: icons.dashboard });
  root.children?.push({ id: 'solution_root', type: 'solution', label: 'Likely Solution', icon: icons.check });

  nodes.push(root);
  return nodes;
}

function renderShell(): void {
  const main = document.getElementById('main');
  if (!main) return;
  
  if (latestResponse && treeNodes.length === 0) {
    treeNodes = buildTree(latestResponse);
  }

  main.innerHTML = `<div class="main-content-wide">
    <div class="page-header" style="margin-bottom: var(--sp-4);">
      <div class="topbar-breadcrumb">
        <span>Pr0y1 ToolKit</span><span class="topbar-breadcrumb-sep">/</span>
        <span>Forensics</span><span class="topbar-breadcrumb-sep">/</span>
        <span style="color:var(--text-primary)">Disk & Partitions</span>
      </div>
    </div>
    ${renderToolbar()}
    ${renderWorkspace()}
  </div>`;
  
  bindEvents();
}

function renderToolbar(): string {
  const imgInfo = latestResponse 
    ? `<div class="forensic-toolbar-info">
         <div class="forensic-toolbar-title">${escapeHtml(latestResponse.image.filename)}</div>
         <div class="forensic-toolbar-meta">
           <span>${formatBytes(latestResponse.image.size)}</span>
           <span>${escapeHtml(latestResponse.image.detected_image_type).toUpperCase()}</span>
           <span>${latestResponse.image.hashes?.sha256 ? 'SHA256 Verified' : ''}</span>
         </div>
       </div>`
    : `<div class="forensic-toolbar-info">
         <div class="forensic-toolbar-title">${selectedFile ? escapeHtml(selectedFile.name) : 'No Image Loaded'}</div>
       </div>`;

  return `
    <div class="forensic-toolbar mb-4">
      ${imgInfo}
      <div class="forensic-toolbar-actions">
        <input id="disk-file" type="file" hidden>
        <button class="btn btn-secondary btn-sm" id="disk-select">${icons.folder} Open Image</button>
        <button class="btn btn-primary btn-sm" id="disk-run" ${selectedFile && !isAnalyzing ? '' : 'disabled'}>
          ${isAnalyzing ? icons.loader : icons.play} ${isAnalyzing ? 'Analyzing...' : 'Analyze'}
        </button>
      </div>
    </div>
  `;
}

function renderWorkspace(): string {
  if (isAnalyzing) {
    return `
      <div class="forensic-pane" style="height: 60vh;">
        <div class="forensic-progress">
          <div class="forensic-progress-item done"><div class="forensic-progress-icon">${icons.check}</div> Image loaded</div>
          <div class="forensic-progress-item done"><div class="forensic-progress-icon">${icons.check}</div> Hashes calculated</div>
          <div class="forensic-progress-item ${simulatedProgress > 1 ? 'done' : 'active'}"><div class="forensic-progress-icon">${simulatedProgress > 1 ? icons.check : icons.loader}</div> Scanning partition tables</div>
          <div class="forensic-progress-item ${simulatedProgress > 2 ? 'done' : (simulatedProgress === 2 ? 'active' : '')}"><div class="forensic-progress-icon">${simulatedProgress > 2 ? icons.check : (simulatedProgress === 2 ? icons.loader : '')}</div> Finding deleted entries</div>
          <div class="forensic-progress-item ${simulatedProgress > 3 ? 'done' : (simulatedProgress === 3 ? 'active' : '')}"><div class="forensic-progress-icon">${simulatedProgress > 3 ? icons.check : (simulatedProgress === 3 ? icons.loader : '')}</div> Carving files</div>
          <div class="forensic-progress-item ${simulatedProgress > 4 ? 'done' : (simulatedProgress === 4 ? 'active' : '')}"><div class="forensic-progress-icon">${simulatedProgress > 4 ? icons.check : (simulatedProgress === 4 ? icons.loader : '')}</div> Flag hunt analysis</div>
        </div>
      </div>
    `;
  }

  if (!latestResponse) {
    return `<div class="forensic-pane" style="height: 60vh; display: grid; place-items: center; color: var(--text-muted); font-size: var(--text-sm);">Select a disk image to begin forensic analysis.</div>`;
  }

  return `
    <div class="forensic-panes">
      <div class="forensic-pane forensic-tree-pane">
        <div class="forensic-pane-header">Evidence Tree</div>
        <div class="forensic-pane-content forensic-tree-container">
          ${renderTreeNodes(treeNodes)}
        </div>
      </div>
      
      <div class="forensic-pane forensic-table-pane">
        <div class="forensic-pane-header">
          <span>${getCenterTitle()}</span>
          <div class="forensic-toolbar-actions">
            <input type="text" placeholder="Filter..." class="input input-sm" style="width: 150px;">
          </div>
        </div>
        <div class="forensic-pane-content forensic-table-container">
          ${renderCenterPane()}
        </div>
      </div>
      
      <div class="forensic-pane forensic-inspector-pane">
        <div class="forensic-pane-header">Inspector</div>
        <div class="inspector-tabs">
          ${['metadata', 'hex', 'preview', 'strings'].map(t => 
            `<div class="inspector-tab ${activeInspectorTab === t ? 'active' : ''}" data-tab="${t}">${t.charAt(0).toUpperCase() + t.slice(1)}</div>`
          ).join('')}
        </div>
        <div class="forensic-pane-content inspector-content">
          ${renderInspector()}
        </div>
      </div>
    </div>
  `;
}

function getCenterTitle(): string {
  if (selectedNodeId === 'image') return 'Disk Overview';
  if (selectedNodeId.startsWith('part_')) return 'Partition Explorer';
  if (selectedNodeId === 'deleted_root') return 'Deleted Files';
  if (selectedNodeId === 'unallocated_root') return 'Unallocated Regions';
  if (selectedNodeId === 'carved_root') return 'Carved Artifacts';
  if (selectedNodeId === 'notable_root') return 'Notable Findings';
  if (selectedNodeId === 'flags_root') return 'Flag Hunt Candidates';
  if (selectedNodeId === 'files_root') return 'Filesystem Contents';
  return 'Evidence Browser';
}

function renderTreeNodes(nodes: TreeNode[], depth = 0): string {
  return nodes.map(n => {
    const isExpanded = n.expanded !== false;
    const hasChildren = n.children && n.children.length > 0;
    const paddingLeft = depth * 16 + 8;
    
    let html = `
      <div class="forensic-tree-node ${selectedNodeId === n.id ? 'active' : ''}" data-id="${n.id}" style="padding-left: ${paddingLeft}px;">
        <div class="forensic-tree-icon">${hasChildren ? (isExpanded ? icons.chevronDown : icons.chevronRight) : n.icon}</div>
        <span>${escapeHtml(n.label)}</span>
      </div>
    `;
    
    if (hasChildren && isExpanded) {
      html += `<div>${renderTreeNodes(n.children!, depth + 1)}</div>`;
    }
    return html;
  }).join('');
}

function renderCenterPane(): string {
  const result = latestResponse!;
  
  if (selectedNodeId === 'solution_root') {
    let likelyFlag = result.flag_candidates?.length > 0 ? result.flag_candidates.sort((a, b) => b.confidence - a.confidence)[0] : null;
    
    if (!likelyFlag) {
      return `<div class="p-4"><div class="section-title text-muted">No confirmed flag found.</div>
      <div class="mt-4">Please check Notable Findings for investigation leads.</div></div>`;
    }
    
    return `<div style="padding: var(--sp-4)">
      <div class="section-title mb-4" style="color: var(--color-success)">Likely Solution</div>
      <div class="inspector-kv"><div class="inspector-kv-key">Flag</div><div class="inspector-kv-val mono font-bold" style="font-size: 1.2rem">${escapeHtml(likelyFlag.value)}</div></div>
      <div class="inspector-kv"><div class="inspector-kv-key">Confidence</div><div class="inspector-kv-val">${(likelyFlag.confidence * 100).toFixed(0)}%</div></div>
      <div class="inspector-kv"><div class="inspector-kv-key">Recovered From</div><div class="inspector-kv-val">${escapeHtml(likelyFlag.source)}</div></div>
      
      <div class="section-title mb-4 mt-6">Evidence Graph</div>
      <div class="p-4" style="background: var(--bg-2); border-radius: 8px; border: 1px solid var(--border-color); font-family: var(--font-mono);">
        ${result.evidence_edges ? result.evidence_edges.map(e => `
           <div><span style="color: var(--color-primary)">${escapeHtml(result.evidence_nodes.find(n => n.id === e.source_id)?.label || e.source_id)}</span> 
           <span style="color: var(--text-muted)">--[${escapeHtml(e.relation)}]--></span> 
           <span style="color: var(--color-success)">${escapeHtml(result.evidence_nodes.find(n => n.id === e.target_id)?.label || e.target_id)}</span></div>
        `).join('') : 'No evidence graph available.'}
      </div>
      
      <div class="section-title mb-4 mt-6">Equivalent Manual Commands</div>
      <pre style="background: var(--bg-2); padding: 1rem; border-radius: 8px;">
mmls disk.img
fls -r -o offset disk.img
icat -o offset disk.img inode > recovered_file
      </pre>
    </div>`;
  }
  
  if (selectedNodeId === 'image') {
    return `<div style="padding: var(--sp-4)">
      <div class="section-title mb-4">Image Properties</div>
      <div class="inspector-kv"><div class="inspector-kv-key">File Name</div><div class="inspector-kv-val">${escapeHtml(result.image.filename)}</div></div>
      <div class="inspector-kv"><div class="inspector-kv-key">Size</div><div class="inspector-kv-val">${formatBytes(result.image.size)}</div></div>
      <div class="inspector-kv"><div class="inspector-kv-key">Sector Size</div><div class="inspector-kv-val">${result.image.sector_size}</div></div>
      <div class="inspector-kv"><div class="inspector-kv-key">MD5</div><div class="inspector-kv-val">${result.image.hashes?.md5 || 'N/A'}</div></div>
      <div class="inspector-kv"><div class="inspector-kv-key">SHA256</div><div class="inspector-kv-val">${result.image.hashes?.sha256 || 'N/A'}</div></div>
      <div class="section-title mb-4 mt-6">Partitions</div>
      <table class="forensic-table">
        <thead><tr><th>Slot</th><th>Type</th><th>Start</th><th>Size</th><th>Filesystem</th></tr></thead>
        <tbody>
          ${result.partitions.map(p => `
            <tr class="center-row" data-type="partition" data-index="${p.number}">
              <td>${escapeHtml(p.slot)}</td><td>${escapeHtml(p.partition_type_name)}</td><td class="mono">${p.start_sector}</td><td>${escapeHtml(p.size_display)}</td><td>${escapeHtml(p.filesystem || '')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>`;
  }
  
  if (selectedNodeId === 'deleted_root') {
    if (!result.deleted_files.length) return `<div class="p-4 text-muted">No deleted files recovered.</div>`;
    return `
      <table class="forensic-table">
        <thead><tr><th>Name</th><th>Original Path</th><th>Filesystem</th><th>Inode</th><th>Size</th><th>Status</th></tr></thead>
        <tbody>
          ${result.deleted_files.map((f, i) => `
            <tr class="center-row ${selectedCenterItem === f ? 'selected' : ''}" data-type="file" data-index="${i}">
              <td>${icons.file} ${escapeHtml(f.name)}</td>
              <td>${escapeHtml(f.path)}</td>
              <td>-</td>
              <td class="mono">${f.inode || '-'}</td>
              <td>${escapeHtml(f.size_display)}</td>
              <td>${badge(false, 'Deleted', 'Deleted')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  }

  if (selectedNodeId === 'unallocated_root') {
    if (!result.unallocated_regions.length) return `<div class="p-4 text-muted">No unallocated regions found.</div>`;
    return `
      <table class="forensic-table">
        <thead><tr><th>Region</th><th>Start Sector</th><th>End Sector</th><th>Size</th><th>Findings</th></tr></thead>
        <tbody>
          ${result.unallocated_regions.map((u, i) => `
            <tr class="center-row ${selectedCenterItem === u ? 'selected' : ''}" data-type="unallocated" data-index="${i}">
              <td>Region ${i+1}</td>
              <td class="mono">${u.start_sector}</td>
              <td class="mono">${u.end_sector}</td>
              <td>${escapeHtml(u.size_display)}</td>
              <td>${u.suspicious ? badge(false, 'Suspicious', 'Suspicious') : '-'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  }

  if (selectedNodeId === 'notable_root') {
    if (!result.notable_findings.length) return `<div class="p-4 text-muted">No notable findings.</div>`;
    return `
      <table class="forensic-table">
        <thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>Evidence</th></tr></thead>
        <tbody>
          ${result.notable_findings.map((f, i) => `
            <tr class="center-row ${selectedCenterItem === f ? 'selected' : ''}" data-type="notable" data-index="${i}">
              <td>${badge(f.severity === 'INFO' || f.severity === 'LOW', f.severity, f.severity, 'badge-info', f.severity==='CRITICAL' ? 'badge-critical' : 'badge-warning')}</td>
              <td>${escapeHtml(f.title)}</td>
              <td>${escapeHtml(f.category)}</td>
              <td class="mono">${escapeHtml(f.evidence.substring(0, 40))}...</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  }
  
  if (selectedNodeId === 'flags_root') {
    if (!result.flag_candidates.length) return `<div class="p-4 text-muted">No flag candidates found.</div>`;
    return `
      <table class="forensic-table">
        <thead><tr><th>Confidence</th><th>Candidate</th><th>Location</th></tr></thead>
        <tbody>
          ${result.flag_candidates.map((f, i) => `
            <tr class="center-row ${selectedCenterItem === f ? 'selected' : ''}" data-type="flag" data-index="${i}">
              <td>${Math.round(f.confidence * 100)}%</td>
              <td class="mono">${escapeHtml(f.value)}</td>
              <td>${escapeHtml(f.source)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  }

  return `<div class="p-4 text-muted">Select an item to view contents.</div>`;
}

function renderInspector(): string {
  if (!selectedCenterItem) return `<div class="text-muted">Select an artifact to inspect.</div>`;

  const item = selectedCenterItem;

  if (activeInspectorTab === 'metadata') {
    let kvs = '';
    
    if (item.filename !== undefined && item.detected_image_type !== undefined) {
       // Image
       return `<div class="text-muted">Image metadata shown in overview.</div>`;
    } else if (item.inode !== undefined || item.path !== undefined) {
      // FileEntry
      const f = item as FileEntry;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Name</div><div class="inspector-kv-val">${escapeHtml(f.name)}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Path</div><div class="inspector-kv-val">${escapeHtml(f.path)}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Status</div><div class="inspector-kv-val">${escapeHtml(f.status)}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Size</div><div class="inspector-kv-val">${escapeHtml(f.size_display)}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Inode/MFT</div><div class="inspector-kv-val">${f.inode || '-'}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Permissions</div><div class="inspector-kv-val">${f.permissions || '-'}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">UID/GID</div><div class="inspector-kv-val">${f.uid || '-'}/${f.gid || '-'}</div></div>`;
      kvs += `<hr style="margin: 16px 0; border: 0; border-top: 1px solid var(--border-light);">`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Created</div><div class="inspector-kv-val">${formatDate(f.creation_time)}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Modified</div><div class="inspector-kv-val">${formatDate(f.modification_time)}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Accessed</div><div class="inspector-kv-val">${formatDate(f.access_time)}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Changed</div><div class="inspector-kv-val">${formatDate(f.change_time)}</div></div>`;
    } else if (item.severity !== undefined) {
      // Notable Finding
      const f = item as NotableFinding;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Title</div><div class="inspector-kv-val">${escapeHtml(f.title)}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Severity</div><div class="inspector-kv-val">${escapeHtml(f.severity)}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Category</div><div class="inspector-kv-val">${escapeHtml(f.category)}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Description</div><div class="inspector-kv-val">${escapeHtml(f.description)}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Evidence</div><div class="inspector-kv-val">${escapeHtml(f.evidence)}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Offset</div><div class="inspector-kv-val">${f.absolute_offset_hex || '-'}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Action</div><div class="inspector-kv-val">${escapeHtml(f.recommended_action || '-')}</div></div>`;
    } else if (item.start_sector !== undefined) {
      // Unallocated / Partition
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Start Sector</div><div class="inspector-kv-val">${item.start_sector}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">End Sector</div><div class="inspector-kv-val">${item.end_sector}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Size</div><div class="inspector-kv-val">${escapeHtml(item.size_display)}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Byte Offset</div><div class="inspector-kv-val">0x${(item.byte_offset || 0).toString(16).toUpperCase()}</div></div>`;
      if (item.suspicious !== undefined) {
        kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Suspicious</div><div class="inspector-kv-val">${item.suspicious ? 'Yes' : 'No'}</div></div>`;
        kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Reason</div><div class="inspector-kv-val">${escapeHtml(item.reason || '-')}</div></div>`;
      }
    } else if (item.confidence !== undefined) {
      // Flag
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Candidate</div><div class="inspector-kv-val">${escapeHtml(item.value)}</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Confidence</div><div class="inspector-kv-val">${Math.round(item.confidence * 100)}%</div></div>`;
      kvs += `<div class="inspector-kv"><div class="inspector-kv-key">Source</div><div class="inspector-kv-val">${escapeHtml(item.source)}</div></div>`;
    }

    return kvs;
  }

  if (activeInspectorTab === 'hex') {
    let offset = '00000000';
    if (item.absolute_offset_hex) offset = item.absolute_offset_hex.replace('0x', '').padStart(8, '0');
    else if (item.byte_offset) offset = item.byte_offset.toString(16).padStart(8, '0');
    
    // Fake hex view
    return `
      <div class="inspector-hex">
OFFSET      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F   ASCII

${offset}    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
${(parseInt(offset, 16) + 16).toString(16).padStart(8, '0').toUpperCase()}    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
      </div>
    `;
  }

  return `<div class="text-muted">Content not available in ${activeInspectorTab} view.</div>`;
}

function bindEvents(): void {
  const input = document.getElementById('disk-file') as HTMLInputElement | null;
  const select = document.getElementById('disk-select') as HTMLButtonElement | null;
  const run = document.getElementById('disk-run') as HTMLButtonElement | null;
  
  select?.addEventListener('click', () => input?.click());
  input?.addEventListener('change', () => {
    selectedFile = input.files?.[0] || null;
    latestResponse = null;
    treeNodes = [];
    selectedNodeId = 'image';
    selectedCenterItem = null;
    renderShell();
  });
  
  run?.addEventListener('click', () => void runDiskAnalysis());

  // Tree clicks
  document.querySelectorAll<HTMLElement>('.forensic-tree-node').forEach(node => {
    node.addEventListener('click', (e) => {
      e.stopPropagation();
      selectedNodeId = node.dataset.id || 'image';
      selectedCenterItem = null; // Reset center item when changing tree node
      renderShell();
    });
  });

  // Table row clicks
  document.querySelectorAll<HTMLElement>('.center-row').forEach(row => {
    row.addEventListener('click', () => {
      const type = row.dataset.type;
      const indexStr = row.dataset.index;
      if (!type || !indexStr || !latestResponse) return;
      const index = parseInt(indexStr, 10);
      
      switch (type) {
        case 'file': selectedCenterItem = latestResponse.deleted_files[index]; break;
        case 'unallocated': selectedCenterItem = latestResponse.unallocated_regions[index]; break;
        case 'partition': selectedCenterItem = latestResponse.partitions.find(p => p.number === index); break;
        case 'notable': selectedCenterItem = latestResponse.notable_findings[index]; break;
        case 'flag': selectedCenterItem = latestResponse.flag_candidates[index]; break;
      }
      renderShell();
    });
  });

  // Inspector tabs
  document.querySelectorAll<HTMLElement>('.inspector-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      activeInspectorTab = (tab.dataset.tab as InspectorTab) || 'metadata';
      renderShell();
    });
  });
}

async function runDiskAnalysis(): Promise<void> {
  if (!selectedFile) return;
  
  activeRequest?.abort();
  activeRequest = new AbortController();
  
  isAnalyzing = true;
  simulatedProgress = 1;
  treeNodes = [];
  renderShell();

  if (progressInterval) clearInterval(progressInterval);
  progressInterval = window.setInterval(() => {
    if (simulatedProgress < 5) {
      simulatedProgress++;
      renderShell();
    }
  }, 800);
  
  try {
    latestResponse = await analyzeDiskImage(selectedFile, activeRequest.signal);
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    console.error(error);
  } finally {
    if (progressInterval) clearInterval(progressInterval);
    isAnalyzing = false;
    renderShell();
  }
}
