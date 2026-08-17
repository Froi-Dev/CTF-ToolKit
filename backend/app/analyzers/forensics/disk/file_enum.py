"""File enumeration for EXT2/3/4, FAT, and NTFS."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import BinaryIO

from app.schemas.disk_forensics import FileEntry


import subprocess
import re
import uuid
import logging

logger = logging.getLogger(__name__)

def enumerate_files(
    path: Path, partition_offset: int, fs_type: str, cluster_size: int | None, sector_size: int = 512
) -> list[FileEntry]:
    """Enumerate files in the filesystem using Sleuth Kit's fls."""
    entries: list[FileEntry] = []
    sector_offset = partition_offset // sector_size

    # Command: fls -p -r -l -o <offset> <image>
    # -p: full path
    # -r: recursive
    # -l: long format (gives size, uid, gid, etc.)
    cmd = ["fls", "-p", "-r", "-l", "-o", str(sector_offset), str(path)]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        logger.warning("fls not found. Sleuth Kit is required for full file enumeration.")
        return []
    except subprocess.CalledProcessError as e:
        logger.error(f"fls failed: {e.stderr}")
        return []

    # Example output of fls -p -r -l
    # r/r * 1234:   /path/to/deleted.txt    2023-01-01 12:00:00 ...
    # Wait, -l output: type/type * inode:   name    uid gid size    mtime   atime   ctime   crtime
    # Actually, let's just parse it.
    
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
            
        # Basic parsing: 'r/r * 1234:\tfile.txt'
        try:
            parts = line.split("\t")
            if len(parts) < 2:
                continue
                
            meta_part = parts[0].strip()  # "r/r * 1234:"
            name_part = parts[1].strip()
            
            is_deleted = "*" in meta_part
            is_dir = meta_part.startswith("d/")
            
            # Extract inode
            inode_match = re.search(r"(\d+(?:-\d+-\d+)?)", meta_part)
            inode_str = inode_match.group(1) if inode_match else "0"
            
            # If name part is just a single dot or double dot, skip
            if name_part.endswith("/.") or name_part.endswith("/.."):
                continue

            entry = FileEntry(
                id=str(uuid.uuid4()),
                path="/" + name_part,
                name=name_part.split("/")[-1] if "/" in name_part else name_part,
                is_directory=is_dir,
                inode=int(inode_str.split("-")[0]) if "-" in inode_str else int(inode_str),
                size=0, # Size parsing would require robust regex for -l
                status="deleted" if is_deleted else "allocated",
                partition_number=0, # To be filled by caller
            )
            entries.append(entry)
        except Exception as e:
            logger.debug(f"Failed to parse fls line: {line} - {e}")
            
    return entries
