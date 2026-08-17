import { apiRequest } from './client.ts';

export interface Hashes {
  md5: string;
  sha1: string;
  sha256: string;
}

export interface DiskImageInfo {
  filename: string;
  size: number;
  detected_image_type: string;
  mime_type: string;
  sector_size: number;
  total_sectors: number;
  hashes: Hashes;
}

export interface PartitionTableInfo {
  type: string;
  description: string;
}

export interface PartitionEntry {
  number: number;
  slot: string;
  start_sector: number;
  end_sector: number;
  sector_count: number;
  byte_offset: number;
  size_bytes: number;
  size_display: string;
  partition_type_id: string;
  partition_type_name: string;
  filesystem: string | null;
  bootable: boolean;
  status: 'allocated' | 'deleted' | 'extended';
}

export interface UnallocatedRegion {
  start_sector: number;
  end_sector: number;
  sector_count: number;
  byte_offset: number;
  size_bytes: number;
  size_display: string;
  location: string;
  suspicious: boolean;
  reason: string | null;
}

export interface FilesystemInfo {
  partition_number: number;
  filesystem_type: string;
  volume_label: string | null;
  volume_uuid: string | null;
  block_size: number | null;
  cluster_size: number | null;
  total_blocks: number | null;
  free_blocks: number | null;
  root_inode: number | null;
  inode_count: number | null;
  last_mounted: string | null;
  last_mount_time: string | null;
  last_write_time: string | null;
  creation_time: string | null;
  journal: boolean | null;
  dirty: boolean | null;
  details: Record<string, string | number | boolean | null>;
}

export interface FileEntry {
  id: string;
  path: string;
  name: string;
  is_directory: boolean;
  inode: number | null;
  size: number;
  size_display: string;
  status: string;
  permissions: string | null;
  uid: number | null;
  gid: number | null;
  access_time: string | null;
  modification_time: string | null;
  change_time: string | null;
  creation_time: string | null;
  partition_number: number;
  data_offset: number | null;
  interesting: boolean;
  interest_reasons: string[];
  children: FileEntry[];
}

export interface NotableFinding {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: number;
  category: string;
  title: string;
  description: string;
  evidence: string;
  partition: string | null;
  filesystem: string | null;
  file_path: string | null;
  inode_or_record: number | null;
  sector: number | null;
  absolute_offset: number | null;
  absolute_offset_hex: string | null;
  recommended_action: string;
  equivalent_command: string | null;
}

export interface DiskForensicsResponse {
  analysis_id: string;
  analyzer: string;
  category: 'disk-forensics';
  image: DiskImageInfo;
  partition_table: PartitionTableInfo;
  partitions: PartitionEntry[];
  unallocated_regions: UnallocatedRegion[];
  filesystems: FilesystemInfo[];
  files: FileEntry[];
  deleted_files: FileEntry[];
  recovered_files: any[];
  carved_files: any[];
  type_mismatches: any[];
  embedded_objects: any[];
  strings: any[];
  encoded_strings: any[];
  flag_candidates: any[];
  notable_findings: NotableFinding[];
  timeline: any[];
  warnings: string[];
  errors: string[];
  limits: any;
}

export function analyzeDiskImage(
  file: File,
  signal?: AbortSignal,
): Promise<DiskForensicsResponse> {
  const body = new FormData();
  body.append('file', file, file.name);
  return apiRequest<DiskForensicsResponse>('/forensics/disk/analyze', {
    method: 'POST',
    body,
    signal,
  });
}
