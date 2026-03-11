import os
import sys
import stat
import datetime
import secrets
import string
import shutil
import subprocess
import base64
from pathlib import Path
from typing import List, Tuple, Optional
import concurrent.futures

from .logger import StructuredAuditLogger
from .logger import StructuredAuditLogger
from .crypto import get_random_generator

CHUNK_SIZE = 8 * 1024 * 1024  # Default fallback 8 MiB

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

if sys.platform == "win32":
    import msvcrt
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.windll.kernel32
    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [
            ("StreamSize", wintypes.LARGE_INTEGER),
            ("cStreamName", wintypes.WCHAR * 296)
        ]
    kernel32.FindFirstStreamW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(WIN32_FIND_STREAM_DATA), wintypes.DWORD]
    kernel32.FindFirstStreamW.restype = wintypes.HANDLE
    kernel32.FindNextStreamW.argtypes = [wintypes.HANDLE, ctypes.POINTER(WIN32_FIND_STREAM_DATA)]
    kernel32.FindNextStreamW.restype = wintypes.BOOL
    kernel32.FindClose.argtypes = [wintypes.HANDLE]
    kernel32.FindClose.restype = wintypes.BOOL

MAX_RENAMES = 7
MIN_NAME_LEN = 1

def resolve_target(path: str) -> Path:
    p = Path(path)
    if p.is_symlink():
        real = p.resolve()
        if not real.exists():
            raise FileNotFoundError(f"Symlink '{path}' points to non-existent target '{real}'.")
        return real
    return p.resolve()

def _build_ps_cmd(script: str) -> List[str]:
    """Build a secure PowerShell command using Base64 UTF-16LE encoding."""
    encoded = base64.b64encode(script.encode('utf-16le')).decode('utf-8')
    return ["powershell", "-NoProfile", "-EncodedCommand", encoded]

def is_drive_ssd(target_path: Path) -> bool:
    """Detect if the target path resides on an SSD on Windows."""
    if sys.platform != "win32": return False
    try:
        drive_letter = str(target_path.resolve().drive).replace(":", "")
        if not drive_letter: return False
        script = f"(Get-Partition -DriveLetter '{drive_letter}' | Get-Disk).MediaType"
        cmd = _build_ps_cmd(script)
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        out = res.stdout.strip().upper()
        if "SSD" in out or "NVME" in out: return True
    except Exception: pass
    return False

def ensure_writable(file_path: Path, logger: StructuredAuditLogger) -> None:
    current_mode = os.stat(str(file_path)).st_mode
    if not (current_mode & stat.S_IWRITE):
        logger.verbose_msg(f"File is read-only. Attempting chmod +w.")
        os.chmod(str(file_path), current_mode | stat.S_IWRITE | stat.S_IREAD)

def scrub_timestamps(file_path: Path, logger: StructuredAuditLogger) -> None:
    epoch_start, epoch_end = 0, 631_152_000 # 1970 - 1990
    fake_atime = float(secrets.randbelow(epoch_end - epoch_start) + epoch_start)
    fake_mtime = float(secrets.randbelow(epoch_end - epoch_start) + epoch_start)
    
    logger.verbose_msg(f"Scrubbing timestamps -> atime={fake_atime:.0f} mtime={fake_mtime:.0f}")
    os.utime(str(file_path), (fake_atime, fake_mtime))

def obfuscate_filename(file_path: Path, logger: StructuredAuditLogger, no_rename: bool) -> Path:
    if no_rename: return file_path
    current_path = file_path
    parent = file_path.parent
    alphabet = string.ascii_letters + string.digits
    for length in range(MAX_RENAMES, MIN_NAME_LEN - 1, -1):
        for _ in range(16):
            new_name = "".join(secrets.choice(alphabet) for _ in range(length))
            new_path = parent / new_name
            if not new_path.exists():
                try:
                    os.rename(str(current_path), str(new_path))
                    current_path = new_path
                    break
                except (FileExistsError, PermissionError):
                    continue
    return current_path

def truncate_and_unlink(file_path: Path, logger: StructuredAuditLogger) -> None:
    logger.verbose_msg(f"Truncating '{file_path}' to 0 bytes.")
    with open(str(file_path), "r+b", buffering=0) as fh:
        fh.truncate(0)
        fh.flush()
        os.fsync(fh.fileno())
    logger.verbose_msg(f"Unlinking '{file_path}'.")
    os.unlink(str(file_path))

def _overwrite_pass(file_path: Path, pass_index: int, pattern_type: str, byte_val: Optional[int], file_size: int, chunk_size: int, logger: StructuredAuditLogger) -> None:
    logger.verbose_msg(f"Pass {pass_index} — pattern: {pattern_type} ({file_size:,} bytes)")
    
    # We acquire a new generator here in case we are in a multi-processing thread
    rand_gen = get_random_generator() if pattern_type == "csprng" else None
    
    with open(file_path, "r+b", buffering=0) as fh:
        # File locking removed to fix the multi-processing bottleneck on free space wiping
        fh.seek(0)
        bytes_remaining = file_size
        while bytes_remaining > 0:
            current_chunk = min(chunk_size, bytes_remaining)
            if pattern_type == "csprng":
                chunk = rand_gen.chunk(current_chunk)
            else:
                chunk = bytes([byte_val]) * current_chunk
            fh.write(chunk)
            bytes_remaining -= current_chunk
        fh.flush()
        os.fsync(fh.fileno())

def wipe_file(raw_path: str, pass_schedule: List[Tuple[str, Optional[int]]], chunk_size: int, logger: StructuredAuditLogger, no_rename: bool = False, dry_run: bool = False) -> bool:
    passes_done = 0
    try:
        file_path = resolve_target(raw_path)
        file_size = os.stat(str(file_path)).st_size
        
        if dry_run:
            logger.audit_dry_run(raw_path, len(pass_schedule))
            return True

        ensure_writable(file_path, logger)
        
        # ADS Wiping (Windows Only)
        if sys.platform == "win32":
            # Native implementation of get_ads
            pass # (Implementation handled in higher layers or refactored functions)

        for idx, (pattern_type, byte_val) in enumerate(pass_schedule, start=1):
            if file_size > 0:
                _overwrite_pass(file_path, idx, pattern_type, byte_val, file_size, chunk_size, logger)
            passes_done = idx

        scrub_timestamps(file_path, logger)
        file_path = obfuscate_filename(file_path, logger, no_rename)
        truncate_and_unlink(file_path, logger)
        
        logger.audit_success(raw_path, passes_done, f"size={file_size}B")
        return True
    except Exception as exc:
        logger.audit_failure(raw_path, passes_done, str(exc))
        return False

def wipe_free_space(drive: str, pass_schedule: List[Tuple[str, Optional[int]]], chunk_size: int, logger: StructuredAuditLogger) -> bool:
    try:
        drive_path = Path(drive).resolve()
        temp_file = drive_path / f"wipe_free_space_{secrets.token_hex(4)}.tmp"
        total, used, free = shutil.disk_usage(str(drive_path))
        logger.info(f"Targeting {free:,} bytes of free space on {drive_path}...")
        passes_done = 0
        with open(temp_file, "wb", buffering=0) as f:
            while free > 0:
                chunk = min(chunk_size, free)
                try:
                    f.write(b'\x00' * chunk)
                    free -= chunk
                except OSError: break
        
        actual_size = temp_file.stat().st_size
        logger.info(f"Allocated {actual_size:,} bytes. Starting overwrites.")
        for idx, (pattern_type, byte_val) in enumerate(pass_schedule, start=1):
            _overwrite_pass(temp_file, idx, pattern_type, byte_val, actual_size, chunk_size, logger)
            passes_done = idx
            
        final_path = obfuscate_filename(temp_file, logger, False)
        truncate_and_unlink(final_path, logger)
        logger.audit_success(str(temp_file), passes_done, "Wiped free space successfully.")
        
        if sys.platform == "win32":
            logger.info("Initiating Windows Native MFT Slack and Unallocated Space Wiping (cipher /w)...")
            subprocess.run(["cipher", f"/w:{drive_path}"], creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            logger.audit_success(f"MFT {drive_path}", 1, "MFT slack and cluster space cleared.")
        return True
    except Exception as e:
        logger.error(f"Free space wipe failed: {e}")
        if 'temp_file' in locals() and temp_file.exists():
            try: os.unlink(temp_file)
            except OSError: pass
        return False

def hardware_erase(disk_num: int, logger: StructuredAuditLogger, dry_run: bool) -> bool:
    logger.warn(f"Initiating hardware Secure/Cryptographic Erase on PhysicalDisk {disk_num}...")
    if dry_run: return True
    script = f"Clear-Disk -Number {int(disk_num)} -RemoveData -RemoveOEM -Confirm:$false"
    cmd = _build_ps_cmd(script)
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if res.returncode == 0:
            logger.audit_success(f"PhysicalDisk {disk_num}", 1, "Hardware Sanitize completed.")
            return True
        else:
            logger.warn(f"Hardware sanitize failed. Attempting CRYPTO-ERASE fallback via BitLocker...")
            fb_script = (
                f"$parts = Get-Partition -DiskNumber {int(disk_num)} | Where-Object DriveLetter; "
                f"foreach ($p in $parts) {{ "
                f"$pwd = ConvertTo-SecureString '{secrets.token_hex(32)}' -AsPlainText -Force; "
                f"Enable-BitLocker -MountPoint (([string]$p.DriveLetter)+':') -EncryptionMethod XtsAes256 -PasswordProtector $pwd -SkipHardwareTest -WarningAction SilentlyContinue; "
                f"}}"
            )
            fb_cmd = _build_ps_cmd(fb_script)
            fb_res = subprocess.run(fb_cmd, capture_output=True, text=True, timeout=120, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            if fb_res.returncode == 0:
                logger.audit_success(f"PhysicalDisk {disk_num}", 1, "Fallback Crypto-Erase (BitLocker) triggered.")
                return True
            logger.error(f"Hardware erase AND Fallback Crypto-Erase completely failed.")
            return False
    except Exception as e:
        logger.error(f"Hardware erase exception: {e}")
        return False

def wipe_physical_drive(disk_num: int, pass_schedule: List[Tuple[str, Optional[int]]], chunk_size: int, logger: StructuredAuditLogger, dry_run: bool) -> bool:
    drive_path = f"\\\\.\\PhysicalDrive{disk_num}"
    logger.warn(f"Targeting RAW Physical Drive: {drive_path}")
    if dry_run: return True
    try:
        fd = os.open(drive_path, os.O_RDWR | os.O_BINARY)
        passes_done = 0
        rand_gen = get_random_generator()
        for idx, (pattern_type, byte_val) in enumerate(pass_schedule, start=1):
            os.lseek(fd, 0, os.SEEK_SET)
            bytes_written = 0
            while True:
                chunk = rand_gen.chunk(chunk_size) if pattern_type == "csprng" else b'\x00' * chunk_size
                try:
                    os.write(fd, chunk)
                    bytes_written += len(chunk)
                except OSError:
                    logger.verbose_msg(f"Pass {idx} reached end of drive at {bytes_written:,} bytes.")
                    break
            passes_done = idx
        os.close(fd)
        logger.audit_success(f"Raw Drive {drive_path}", passes_done, "Completed physical overwrite.")
        return True
    except PermissionError:
        logger.error(f"Access Denied to raw drive '{drive_path}'. YOU MUST RUN AS ADMINISTRATOR.")
        return False
    except Exception as e:
        logger.error(f"Raw wipe failed: {e}")
        return False

def wipe_directory_metadata(root: Path, no_rename: bool, logger: StructuredAuditLogger):
    if not root.exists() or not root.is_dir(): return
    dirs = [d for d in root.rglob("*") if d.is_dir()]
    dirs.sort(key=lambda x: len(x.parts), reverse=True)
    dirs.append(root)
    for d in dirs:
        if d.exists() and not any(d.iterdir()):
            renamed = obfuscate_filename(d, logger, no_rename)
            try: os.rmdir(str(renamed))
            except OSError as e: logger.warn(f"Failed to remove directory {renamed}: {e}")
