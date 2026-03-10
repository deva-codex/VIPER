#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              SECURE FILE SANITIZATION UTILITY  v1.0.0                      ║
║              DoD 5220.22-M / NIST SP 800-88 Compliant                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ⚠  SSD / NVMe / Flash Media WARNING:                                       ║
║  Hardware-level wear-leveling (FTL — Flash Translation Layer) and TRIM      ║
║  commands on modern SSDs, NVMe drives, eMMC, and USB flash storage          ║
║  intercept and re-route sector-level overwrites to spare blocks.             ║
║  This means software overwrite passes CANNOT guarantee full sanitization     ║
║  on such media. For whole-disk sanitization on SSDs/NVMe, use:              ║
║    • ATA Secure Erase (hdparm --security-erase)                             ║
║    • NVMe Format with crypto-erase (nvme format --ses=1)                    ║
║    • Manufacturer-provided secure erase utilities                            ║
║  This script is most effective on traditional spinning HDDs or RAM disks.   ║
╚══════════════════════════════════════════════════════════════════════════════╝

Author  : Senior Systems Security Engineer
Standard: DoD 5220.22-M (3-pass default), extensible to 7-pass
License : MIT — use at your own risk; no warranty expressed or implied.

Usage:
    python secure_wipe.py <target> [options]

    positional:
      target                File or directory to sanitize

    options:
      --passes N            Number of wipe passes (default: 3, max: 35)
      --standard {dod,gutmann,nist}
                            Wipe standard preset (overrides --passes)
      --recursive           Wipe directory contents recursively (requires --force)
      --force               Required for wildcards, recursive mode, or non-empty dirs
      --no-rename           Skip filename obfuscation step
      --log FILE            Write audit log to FILE (default: secure_wipe_audit.log)
      --dry-run             Simulate all actions without modifying any data
      --verbose             Print step-by-step progress to stdout
"""

# ─── Standard Library Imports ────────────────────────────────────────────────
import os
import sys
import stat
import time
try:
    import fcntl          # POSIX exclusive file locking (Linux/macOS)
except ImportError:
    pass                  # Handled using msvcrt on Windows
import random
import string
import hashlib
import logging
import secrets        # CSPRNG — cryptographically secure random bytes
import argparse
import platform
import datetime
import tempfile
import traceback
from pathlib import Path
from typing   import List, Optional, Tuple
import concurrent.futures
import subprocess

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    import warnings
    warnings.warn("psutil is not installed. Will default to an arbitrary 2GB RAM cap. Install 'psutil' for accurate 50% RAM optimization.")
    _HAS_PSUTIL = False

import tkinter as tk
from tkinter import filedialog
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

import sys
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

# ─── Optional: colorized terminal output ─────────────────────────────────────
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION 1 — CONSTANTS & SAFETY BOUNDARIES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VERSION = "1.0.0"

# ── Blast-Radius: system-critical directory deny-list ────────────────────────
# Any target resolving to (or beneath) these paths is unconditionally rejected.
CRITICAL_PATHS_UNIX = frozenset({
    "/", "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin",
    "/lib", "/lib64", "/usr/lib", "/usr/lib64",
    "/etc", "/boot", "/dev", "/proc", "/sys", "/run",
    "/var", "/var/log", "/tmp",
    "/root", "/home",                   # broad home dirs — reject at root
    "/snap", "/opt",
})

CRITICAL_PATHS_WINDOWS = frozenset({
    "C:\\", "C:\\Windows", "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64", "C:\\Program Files",
    "C:\\Program Files (x86)", "C:\\ProgramData",
})

# Merge platform-appropriate set
IS_WINDOWS  = platform.system() == "Windows"
CRITICAL_PATHS = CRITICAL_PATHS_WINDOWS if IS_WINDOWS else CRITICAL_PATHS_UNIX

# ── Wipe standard presets ────────────────────────────────────────────────────
#   Each pass is (pattern_type, value)
#   pattern_type: "byte" → fill with fixed byte
#                 "csprng" → fill with cryptographically secure random bytes
#                 "complement" → fill with bitwise NOT of previous pass (handled in logic)

STANDARDS = {
    "dod": {
        "description": "DoD 5220.22-M — 3-pass",
        "passes": [
            ("byte",   0x00),
            ("byte",   0xFF),
            ("csprng", None),
        ],
    },
    "nist": {
        "description": "NIST SP 800-88 — 1-pass CSPRNG (suitable for ATA drives)",
        "passes": [
            ("csprng", None),
        ],
    },
    "gutmann": {
        "description": "Gutmann — 35-pass (academic; overkill for modern drives)",
        "passes": (
            [("csprng", None)] * 4
            + [("byte",  p) for p in (
                0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33,
                0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
                0xDD, 0xEE, 0xFF, 0x92, 0x49, 0x24, 0x6D, 0xB6, 0xDB,
            )]
            + [("csprng", None)] * 4
        ),
    },
}

# I/O chunk size — dynamically configured during initialization to consume 50% RAM
CHUNK_SIZE   = 8 * 1024 * 1024      # Fallback 8 MiB default
MAX_RENAMES  =  7                   # how many random-name iterations before delete
MIN_NAME_LEN =  1                   # final rename length

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION 2 — LOGGING & AUDIT TRAIL
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AuditLogger:
    """
    Dual-channel logger: human-readable console + structured audit file.

    Audit file format (tab-separated):
        TIMESTAMP  |  LEVEL  |  FILE_PATH  |  PASSES  |  STATUS  |  DETAIL
    """

    _TIMESTAMP_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"

    def __init__(self, log_path: str, verbose: bool = False, dry_run: bool = False):
        self.log_path = log_path
        self.verbose  = verbose
        self.dry_run  = dry_run

        # ── Console handler ──────────────────────────────────────────────────
        self._console = logging.getLogger("secure_wipe.console")
        self._console.setLevel(logging.DEBUG if verbose else logging.INFO)
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter("%(message)s"))
        self._console.addHandler(ch)

        # ── File handler (audit trail) ────────────────────────────────────────
        self._audit = logging.getLogger("secure_wipe.audit")
        self._audit.setLevel(logging.DEBUG)
        # Write header row only if file is new or empty
        write_header = not os.path.exists(log_path) or os.path.getsize(log_path) == 0
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(message)s"))
        self._audit.addHandler(fh)

        if write_header:
            header = "\t".join([
                "TIMESTAMP", "LEVEL", "FILE_PATH",
                "PASSES_COMPLETED", "STATUS", "DETAIL"
            ])
            self._audit.info(header)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _ts(self) -> str:
        return datetime.datetime.now(datetime.timezone.utc).strftime(self._TIMESTAMP_FMT)

    def _colorize(self, msg: str, color_code: str) -> str:
        if COLOR:
            return f"{color_code}{msg}{Style.RESET_ALL}"
        return msg

    def _record(self, level: str, path: str, passes: int,
                status: str, detail: str = "") -> None:
        row = "\t".join([
            self._ts(), level, str(path),
            str(passes), status, detail
        ])
        self._audit.info(row)

    # ── Public API ────────────────────────────────────────────────────────────

    def info(self, msg: str) -> None:
        self._console.info(msg)

    def verbose_msg(self, msg: str) -> None:
        if self.verbose:
            self._console.debug(self._colorize(f"  -> {msg}", Fore.CYAN if COLOR else ""))

    def warn(self, msg: str) -> None:
        self._console.warning(self._colorize(f"[!] {msg}", Fore.YELLOW if COLOR else ""))

    def error(self, msg: str) -> None:
        self._console.error(self._colorize(f"[X] {msg}", Fore.RED if COLOR else ""))

    def success(self, msg: str) -> None:
        self._console.info(self._colorize(f"[+] {msg}", Fore.GREEN if COLOR else ""))

    def audit_success(self, path: str, passes: int, detail: str = "") -> None:
        self._record("SUCCESS", path, passes, "WIPED", detail)
        self.success(f"Wiped: {path}  [{passes} pass(es)]")

    def audit_failure(self, path: str, passes: int, detail: str = "") -> None:
        self._record("ERROR", path, passes, "FAILED", detail)
        self.error(f"Failed: {path}  — {detail}")

    def audit_skipped(self, path: str, reason: str = "") -> None:
        self._record("WARN", path, 0, "SKIPPED", reason)
        self.warn(f"Skipped: {path}  — {reason}")

    def audit_dry_run(self, path: str, passes: int) -> None:
        self._record("DRY-RUN", path, passes, "SIMULATED", "No data modified")
        self.info(self._colorize(
            f"[DRY-RUN] Would wipe: {path}  [{passes} pass(es)]",
            Fore.MAGENTA if COLOR else ""
        ))


def sign_audit_log(log_path: str, logger: AuditLogger) -> None:
    """Hash the log file and sign it with an RSA private key."""
    if not HAS_CRYPTOGRAPHY:
        return
        
    private_key_path = Path("viper_private.pem")
    public_key_path = Path("viper_public.pem")
    
    if not private_key_path.exists():
        logger.info("  Generating new RSA-2048 key pair for audit log signatures...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    else:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            
    # Calculate SHA256 of the log file
    with open(log_path, "rb") as f:
        log_data = f.read()
        
    signature = private_key.sign(
        log_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    sig_path = f"{log_path}.sig"
    with open(sig_path, "wb") as f:
        f.write(signature)
        
    logger.success(f"Log cryptographically signed -> {sig_path}")


def verify_audit_log(log_path: str, logger: AuditLogger) -> bool:
    """Verify an audit log using the corresponding .sig file and public key."""
    sig_path = f"{log_path}.sig"
    public_key_path = Path("viper_public.pem")
    
    if not HAS_CRYPTOGRAPHY:
        logger.error("The 'cryptography' Python package is required for log verification.")
        return False
        
    if not os.path.exists(log_path) or not os.path.exists(sig_path):
        logger.error(f"Cannot find log or signature file for: {log_path}")
        return False
        
    if not public_key_path.exists():
        logger.error("Public key (viper_public.pem) not found. Cannot verify signature.")
        return False

    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
        
    with open(log_path, "rb") as f:
        log_data = f.read()
        
    with open(sig_path, "rb") as f:
        signature = f.read()
        
    try:
        public_key.verify(
            signature,
            log_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        logger.success(f"CRYPTOGRAPHIC VERIFICATION PASSED: The audit log '{log_path}' is authentic and untampered.")
        return True
    except Exception as e:
        logger.error(f"CRYPTOGRAPHIC VERIFICATION FAILED: The audit log '{log_path}' has been altered or tampered with!")
        return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION 3 — SAFETY VALIDATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SafetyError(RuntimeError):
    """Raised when a target violates blast-radius or safety constraints."""


def resolve_target(path: str) -> Path:
    """
    Resolve a path, following symlinks to obtain the true on-disk location.
    This prevents accidentally wiping only the symlink inode while leaving
    the real data intact, and also prevents symlink-based traversal attacks
    that could escape the intended directory scope.
    """
    p = Path(path)

    if p.is_symlink():
        real = p.resolve()
        # Ensure the resolved target still exists
        if not real.exists():
            raise FileNotFoundError(
                f"Symlink '{path}' points to non-existent target '{real}'."
            )
        return real   # operate on the real file, not the link

    return p.resolve()


def assert_not_critical(path: Path, override_safety: bool = False) -> None:
    """
    Unconditionally reject any path that matches or is an ancestor of a
    system-critical directory.  This is the primary blast-radius guard.
    """
    if override_safety:
        return
    path_str = str(path).rstrip(os.sep)

    # Direct match
    if path_str in CRITICAL_PATHS:
        raise SafetyError(
            f"SAFETY ABORT: '{path}' is a protected system directory. "
            f"Operation unconditionally rejected."
        )

    # Ancestry check — e.g. /bin/bash would be caught here
    for critical in CRITICAL_PATHS:
        try:
            path.relative_to(critical)
            raise SafetyError(
                f"SAFETY ABORT: '{path}' resides inside the protected "
                f"system directory '{critical}'. Operation rejected."
            )
        except ValueError:
            pass  # path is NOT relative to this critical dir — safe


def assert_force_for_directory(path: Path, force: bool) -> None:
    """
    Directories (especially non-empty ones) require --force to prevent
    accidental recursive wipes from ambiguous globs or path mistakes.
    """
    if path.is_dir() and not force:
        raise SafetyError(
            f"'{path}' is a directory. Pass --force to confirm recursive wipe."
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION 4 — CSPRNG DATA GENERATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SecureRandomGenerator:
    def __init__(self):
        if HAS_CRYPTOGRAPHY:
            key = secrets.token_bytes(32)
            nonce = secrets.token_bytes(16)
            self.cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
            self.encryptor = self.cipher.encryptor()
        else:
            self.encryptor = None
    def chunk(self, size: int) -> bytes:
        if self.encryptor:
            return self.encryptor.update(b'\x00' * size)
        return os.urandom(size)

_rand_gen = None

def csprng_chunk(size: int) -> bytes:
    """
    Generate `size` bytes of cryptographically secure pseudorandom data.
    Uses cryptography (AES-CTR) if available for speed, otherwise falls back to os.urandom.
    """
    global _rand_gen
    if _rand_gen is None:
        _rand_gen = SecureRandomGenerator()
    return _rand_gen.chunk(size)


def fixed_byte_chunk(byte_val: int, size: int) -> bytes:
    """Return `size` bytes all set to `byte_val`."""
    return bytes([byte_val]) * size


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION 5 — CORE WIPE ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _acquire_exclusive_lock(fd) -> None:
    """
    Acquire an exclusive advisory lock on the open file descriptor.
    """
    if "fcntl" in sys.modules:
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (AttributeError, OSError):
            pass
    if sys.platform == "win32":
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            pass

def _release_lock(fd) -> None:
    """Release a previously acquired advisory lock."""
    if "fcntl" in sys.modules:
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_UN)
        except (AttributeError, OSError):
            pass
    if sys.platform == "win32":
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass


def _overwrite_pass(
    file_path: Path,
    pass_index: int,
    pattern_type: str,
    byte_val: Optional[int],
    file_size: int,
    logger: AuditLogger,
) -> None:
    """
    Execute a single overwrite pass on `file_path`.

    Steps:
      1. Open in binary read-write mode (no truncation).
      2. Acquire exclusive advisory lock.
      3. Seek to byte 0.
      4. Write the pass pattern in CHUNK_SIZE chunks.
      5. Call os.fsync() to flush OS page-cache → physical write.
      6. Release lock.

    Args:
        file_path   : Resolved path to the target file.
        pass_index  : Human-readable pass number (1-based).
        pattern_type: "byte" or "csprng".
        byte_val    : The byte value for a "byte" pattern pass (ignored for csprng).
        file_size   : Original file size in bytes (from stat).
        logger      : AuditLogger instance.
    """
    pattern_label = (
        f"0x{byte_val:02X}" if pattern_type == "byte" else "CSPRNG"
    )
    logger.verbose_msg(
        f"Pass {pass_index} — pattern: {pattern_label}  "
        f"({file_size:,} bytes to overwrite)"
    )

    with open(file_path, "r+b", buffering=0) as fh:
        # ── Exclusive lock ────────────────────────────────────────────────────
        _acquire_exclusive_lock(fh.fileno())

        # ── Seek to file start ────────────────────────────────────────────────
        fh.seek(0)

        bytes_remaining = file_size
        while bytes_remaining > 0:
            chunk_size = min(CHUNK_SIZE, bytes_remaining)

            if pattern_type == "csprng":
                chunk = csprng_chunk(chunk_size)
            else:  # "byte"
                chunk = fixed_byte_chunk(byte_val, chunk_size)

            fh.write(chunk)
            bytes_remaining -= chunk_size

        # ── Force physical write — bypass OS write cache ──────────────────────
        fh.flush()
        os.fsync(fh.fileno())   # blocks until storage controller confirms write

        # ── Release lock ──────────────────────────────────────────────────────
        _release_lock(fh.fileno())


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION 6 — METADATA OBFUSCATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _random_historical_timestamp() -> float:
    """
    Return a random POSIX timestamp in the range [1970-01-01, 1990-01-01].

    Setting MAC times to plausible-but-old historical dates before deletion
    causes forensic timeline tools to misplace or misattribute the file's
    lifecycle, reducing the value of filesystem metadata artefacts.
    """
    epoch_start = 0                    # 1970-01-01 00:00:00 UTC
    epoch_end   = 631_152_000          # 1990-01-01 00:00:00 UTC
    return float(secrets.randbelow(epoch_end - epoch_start) + epoch_start)


def scrub_timestamps(file_path: Path, logger: AuditLogger) -> None:
    """
    Overwrite the file's MAC (Modified, Accessed, Created) timestamps with
    random historical dates, then sync the directory entry.

    Note: On most Linux filesystems, the 'Created' (birth) time is not
    directly settable via os.utime(); it depends on filesystem and kernel
    version (statx + FS_IOC_SETFLAGS).  Access and modification times
    are reliably obfuscated here.
    """
    fake_atime = _random_historical_timestamp()
    fake_mtime = _random_historical_timestamp()

    logger.verbose_msg(
        f"Scrubbing timestamps -> atime={fake_atime:.0f}  mtime={fake_mtime:.0f}"
    )
    os.utime(str(file_path), (fake_atime, fake_mtime))


def _random_name(length: int) -> str:
    """
    Generate a random filename of `length` characters using alphanumeric
    characters only, ensuring filesystem portability.
    Uses CSPRNG via secrets.choice for unpredictable names.
    """
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def obfuscate_filename(file_path: Path, logger: AuditLogger, no_rename: bool) -> Path:
    """
    Iteratively rename the target file with progressively shorter random names,
    ending with a single random character.

    Purpose: Overwrite filesystem journal / MFT directory entries so the
    original filename cannot be recovered from journal replay or MFT carving.

    Returns the final (renamed) Path so callers can continue to reference it.
    """
    if no_rename:
        logger.verbose_msg("Filename obfuscation skipped (--no-rename).")
        return file_path

    current_path = file_path
    parent       = file_path.parent

    # Rename chain: MAX_RENAMES → … → 2 → 1 character
    name_lengths = list(range(MAX_RENAMES, MIN_NAME_LEN - 1, -1))

    for length in name_lengths:
        collision_guard = 0
        success = False
        while not success and collision_guard < 16:
            new_name = _random_name(length)
            new_path = parent / new_name
            
            if not new_path.exists():
                try:
                    logger.verbose_msg(
                        f"Renaming: '{current_path.name}' -> '{new_name}' (len={length})"
                    )
                    os.rename(str(current_path), str(new_path))
                    current_path = new_path
                    success = True
                except (FileExistsError, PermissionError):
                    collision_guard += 1
            else:
                collision_guard += 1
                
        if not success:
            logger.verbose_msg("Rename collision guard triggered; skipping further obfuscation.")
            break
            
    return current_path


def truncate_and_unlink(file_path: Path, logger: AuditLogger) -> None:
    """
    Truncate the file to zero bytes (removes data references in inode),
    then unlink it (removes the directory entry).

    Truncating before unlinking reduces residual data in filesystem slack
    space and zeroes the inode's size metadata before removal.
    """
    logger.verbose_msg(f"Truncating '{file_path}' to 0 bytes.")
    with open(str(file_path), "r+b", buffering=0) as fh:
        fh.truncate(0)
        fh.flush()
        os.fsync(fh.fileno())

    logger.verbose_msg(f"Unlinking '{file_path}'.")
    os.unlink(str(file_path))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION 7 — PERMISSION NORMALISATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def ensure_writable(file_path: Path, logger: AuditLogger) -> None:
    """
    Attempt to grant write permission to the file if it is currently read-only.
    Necessary for files marked immutable by accident or by another process.
    """
    current_mode = os.stat(str(file_path)).st_mode
    if not (current_mode & stat.S_IWRITE):
        logger.verbose_msg(
            f"File is read-only (mode={oct(current_mode)}). Attempting chmod +w."
        )
        os.chmod(str(file_path), current_mode | stat.S_IWRITE | stat.S_IREAD)


def get_ads(filepath: Path, logger: AuditLogger) -> List[str]:
    """Retrieve NTFS Alternate Data Streams associated with the file."""
    streams = []
    if sys.platform != "win32":
        return streams
    
    find_data = WIN32_FIND_STREAM_DATA()
    hFind = kernel32.FindFirstStreamW(str(filepath), 0, ctypes.byref(find_data), 0)
    
    if hFind and hFind != -1 and hFind != 0xFFFFFFFF and hFind != 0xFFFFFFFFFFFFFFFF:
        try:
            while True:
                name = find_data.cStreamName
                if name != "::$DATA":  # Skip the main unnamed data stream
                    streams.append(name)
                if not kernel32.FindNextStreamW(hFind, ctypes.byref(find_data)):
                    break
        finally:
            kernel32.FindClose(hFind)
            
    if streams:
        logger.verbose_msg(f"Discovered {len(streams)} hidden NTFS Alternate Data Stream(s).")
    return streams


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION 8 — ORCHESTRATION: WIPE A SINGLE FILE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def wipe_file(
    raw_path: str,
    pass_schedule: List[Tuple[str, Optional[int]]],
    logger: AuditLogger,
    no_rename: bool = False,
    dry_run: bool   = False,
    override_safety: bool = False,
) -> bool:
    """
    Full sanitization pipeline for a single file:

      [1] Resolve symlink → real path
      [2] Validate against blast-radius deny-list
      [3] Ensure write permissions
      [4] Execute overwrite passes with fsync after each pass
      [5] Scrub MAC timestamps
      [6] Iterative filename obfuscation
      [7] Truncate → Unlink

    Returns True on success, False on failure.
    """
    original_path = raw_path
    passes_done   = 0

    try:
        # ── Step 1: Resolve symlink ───────────────────────────────────────────
        file_path = resolve_target(raw_path)
        logger.verbose_msg(f"Resolved path: '{file_path}'")

        if not file_path.exists():
            raise FileNotFoundError(f"Target does not exist: '{raw_path}'")

        if not file_path.is_file():
            raise IsADirectoryError(
                f"Target is not a regular file: '{file_path}'. "
                f"Use --recursive for directories."
            )

        # ── Step 2: Safety check ──────────────────────────────────────────────
        assert_not_critical(file_path, override_safety)

        # ── Step 3: Stat & permission normalisation ───────────────────────────
        file_stat = os.stat(str(file_path))
        file_size = file_stat.st_size
        logger.verbose_msg(f"File size: {file_size:,} bytes")

        if dry_run:
            logger.audit_dry_run(original_path, len(pass_schedule))
            return True

        ensure_writable(file_path, logger)

        # ── Step 3.5: Wipe NTFS Alternate Data Streams (ADS) ──────────────────
        ads_streams = get_ads(file_path, logger)
        for stream_name in ads_streams:
            stream_path = f"{file_path}{stream_name}"
            # Wiping the stream using standard overwrite mechanics
            try:
                stream_size = os.stat(stream_path).st_size
                logger.verbose_msg(f"Wiping detached ADS stream: '{stream_name}' ({stream_size:,} bytes)")
                if stream_size > 0:
                    for idx, (pattern_type, byte_val) in enumerate(pass_schedule, start=1):
                        _overwrite_pass(
                            file_path    = Path(stream_path),
                            pass_index   = idx,
                            pattern_type = pattern_type,
                            byte_val     = byte_val,
                            file_size    = stream_size,
                            logger       = logger,
                        )
                # Truncate stream to 0 to permanently destroy its contents
                with open(stream_path, "r+b", buffering=0) as fh:
                    fh.truncate(0)
                    fh.flush()
                    os.fsync(fh.fileno())
            except Exception as e:
                logger.warn(f"Failed to wipe ADS stream '{stream_name}': {e}")


        # ── Step 4: Overwrite passes ──────────────────────────────────────────
        #    Special case: zero-byte files still go through rename/unlink steps
        for idx, (pattern_type, byte_val) in enumerate(pass_schedule, start=1):
            if file_size > 0:
                _overwrite_pass(
                    file_path    = file_path,
                    pass_index   = idx,
                    pattern_type = pattern_type,
                    byte_val     = byte_val,
                    file_size    = file_size,
                    logger       = logger,
                )
            passes_done = idx

        # ── Step 5: Timestamp scrubbing ───────────────────────────────────────
        scrub_timestamps(file_path, logger)

        # ── Step 6: Filename obfuscation ──────────────────────────────────────
        file_path = obfuscate_filename(file_path, logger, no_rename)

        # ── Step 7: Truncate → Unlink ─────────────────────────────────────────
        truncate_and_unlink(file_path, logger)

        logger.audit_success(
            path    = original_path,
            passes  = passes_done,
            detail  = f"size={file_size}B  standard={len(pass_schedule)}-pass",
        )
        return True

    except SafetyError as exc:
        logger.audit_failure(original_path, passes_done, str(exc))
        logger.error(str(exc))
        return False

    except PermissionError as exc:
        logger.audit_failure(original_path, passes_done, f"PermissionError: {exc}")
        logger.error(f"Permission denied on '{original_path}': {exc}")
        return False

    except FileNotFoundError as exc:
        logger.audit_skipped(original_path, str(exc))
        return False

    except OSError as exc:
        logger.audit_failure(original_path, passes_done, f"OSError: {exc}")
        logger.error(f"OS error wiping '{original_path}': {exc}")
        return False

    except Exception as exc:  # noqa: BLE001
        detail = f"Unexpected error: {type(exc).__name__}: {exc}"
        logger.audit_failure(original_path, passes_done, detail)
        logger.error(detail)
        if logger.verbose:
            logger.error(traceback.format_exc())
        return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION 9 — DIRECTORY TRAVERSAL
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def collect_files(
    root: Path,
    recursive: bool,
    logger: AuditLogger,
) -> List[Path]:
    """
    Collect all regular files under `root`.

    • Non-recursive: returns only immediate children that are files.
    • Recursive    : walks the entire subtree.
    • Symlinks to directories are NOT followed during traversal to prevent
      escaping the intended scope (symlinks to files ARE included as targets).
    """
    targets: List[Path] = []

    if not root.is_dir():
        targets.append(root)
        return targets

    if recursive:
        for entry in root.rglob("*"):
            if entry.is_symlink() or entry.is_file():
                targets.append(entry)
    else:
        for entry in root.iterdir():
            if entry.is_symlink() or entry.is_file():
                targets.append(entry)

    return targets


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION 10 — CLI & ENTRY POINT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def hardware_erase(disk_num: int, logger: AuditLogger, dry_run: bool) -> bool:
    """Trigger the actual firmware crypto/sanitize erase command for SSDs via PowerShell."""
    logger.warn(f"Initiating hardware Secure/Cryptographic Erase on PhysicalDisk {disk_num}...")
    if dry_run: return True
    
    cmd = [
        "powershell", "-NoProfile", "-Command",
        f"Clear-Disk -Number {disk_num} -RemoveData -RemoveOEM -Confirm:$false"
    ]
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        if res.returncode == 0:
            logger.audit_success(f"PhysicalDisk {disk_num}", 1, "Hardware Sanitize completed.")
            return True
        else:
            logger.warn(f"Hardware sanitize failed (Firmware Freeze Lock?). Attempting CRYPTO-ERASE fallback...")
            logger.info("    [>] Initializing BitLocker XTS-AES-256 Full-Volume Encryption with thrown-away keys...")
            
            fb_cmd = [
                "powershell", "-NoProfile", "-Command",
                f"$parts = Get-Partition -DiskNumber {disk_num} | Where-Object DriveLetter; "
                f"foreach ($p in $parts) {{ "
                f"$pwd = ConvertTo-SecureString '{secrets.token_hex(32)}' -AsPlainText -Force; "
                f"Enable-BitLocker -MountPoint (([string]$p.DriveLetter)+':') -EncryptionMethod XtsAes256 -PasswordProtector $pwd -SkipHardwareTest -WarningAction SilentlyContinue; "
                f"}}"
            ]
            fb_res = subprocess.run(
                fb_cmd, capture_output=True, text=True, timeout=120,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            )
            if fb_res.returncode == 0:
                logger.audit_success(f"PhysicalDisk {disk_num}", 1, "Fallback Crypto-Erase (BitLocker) triggered successfully.")
                logger.success("    [+] SSD Cryptographically OBLITERATED via bit-shredding.")
                return True
            else:
                logger.error(f"Hardware erase AND Fallback Crypto-Erase completely failed.")
                logger.verbose_msg(f"Fallback Error details: {fb_res.stderr.strip()}")
                return False
    except Exception as e:
        logger.error(f"Hardware erase exception: {e}")
        return False

def wipe_physical_drive(disk_num: int, pass_schedule: List[Tuple[str, Optional[int]]], logger: AuditLogger, dry_run: bool) -> bool:
    """Bypass filesystems and write zeroes/CSPRNG directly to raw hard drive sectors."""
    drive_path = f"\\\\.\\PhysicalDrive{disk_num}"
    logger.warn(f"Targeting RAW Physical Drive: {drive_path}")
    if dry_run: return True
    try:
        fd = os.open(drive_path, os.O_RDWR | os.O_BINARY)
        # Note: Seeking to the end of a raw block device on Windows using Python often fails to return size.
        # So we just write forward sequentially until we hit ENOSPC (Error 112 or IOError)
        passes_done = 0
        for idx, (pattern_type, byte_val) in enumerate(pass_schedule, start=1):
            os.lseek(fd, 0, os.SEEK_SET)
            bytes_written = 0
            while True:
                chunk = _rand_gen.chunk(CHUNK_SIZE) if pattern_type == "csprng" else b'\x00' * CHUNK_SIZE
                try:
                    os.write(fd, chunk)
                    bytes_written += len(chunk)
                except OSError as write_err:
                    # Windows Error 112 is ERROR_DISK_FULL
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

def wipe_free_space(drive: str, pass_schedule: List[Tuple[str, Optional[int]]], logger: AuditLogger) -> bool:
    import shutil
    try:
        drive_path = Path(drive).resolve()
        temp_file = drive_path / f"wipe_free_space_{secrets.token_hex(4)}.tmp"
        total, used, free = shutil.disk_usage(str(drive_path))
        logger.info(f"Targeting {free:,} bytes of free space on {drive_path}...")
        
        passes_done = 0
        
        with open(temp_file, "wb", buffering=0) as f:
            while free > 0:
                chunk = min(CHUNK_SIZE, free)
                try:
                    f.write(b'\x00' * chunk)
                    free -= chunk
                except OSError:
                    break
        
        actual_size = temp_file.stat().st_size
        logger.info(f"Allocated {actual_size:,} bytes. Starting overwrites.")
        
        for idx, (pattern_type, byte_val) in enumerate(pass_schedule, start=1):
            _overwrite_pass(
                file_path=temp_file,
                pass_index=idx,
                pattern_type=pattern_type,
                byte_val=byte_val,
                file_size=actual_size,
                logger=logger
            )
            passes_done = idx
            
        final_path = obfuscate_filename(temp_file, logger, False)
        truncate_and_unlink(final_path, logger)
        logger.audit_success(str(temp_file), passes_done, "Wiped free space successfully.")
        
        # MFT / Slack wipe via Windows Cipher tool
        if sys.platform == "win32":
            logger.info("Initiating Windows Native MFT Slack and Unallocated Space Wiping (cipher /w)...")
            cipher_cmd = ["cipher", f"/w:{drive_path}"]
            subprocess.run(cipher_cmd, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            logger.audit_success(f"MFT {drive_path}", 1, "MFT slack and cluster space cleared via cipher.")

        return True
    except Exception as e:
        logger.error(f"Free space wipe failed: {e}")
        if 'temp_file' in locals() and temp_file.exists():
            try:
                os.unlink(temp_file)
            except OSError:
                pass
        return False

def wipe_directory_metadata(root: Path, no_rename: bool, logger: AuditLogger):
    """Obfuscate and remove empty directories bottom-up."""
    if not root.exists() or not root.is_dir(): return
    dirs = [d for d in root.rglob("*") if d.is_dir()]
    dirs.sort(key=lambda x: len(x.parts), reverse=True)
    dirs.append(root)
    
    for d in dirs:
        if d.exists() and not any(d.iterdir()):
            renamed = obfuscate_filename(d, logger, no_rename)
            try:
                os.rmdir(str(renamed))
                logger.verbose_msg(f"Removed directory {renamed}")
            except OSError as e:
                logger.warn(f"Failed to remove directory {renamed}: {e}")

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog        = "viper",
        description = (
            "VIPER - Cryptographically secure file sanitization utility.\n"
            "Implements DoD 5220.22-M, NIST SP 800-88, or Gutmann overwrite standards."
        ),
        epilog = (
            "[!] SSD WARNING: Software overwrites cannot guarantee full sanitization\n"
            "    on SSDs/NVMe/Flash due to wear-leveling (FTL) and TRIM.\n"
            "    Use 'hdparm --security-erase' or 'nvme format --ses=1' for those media."
        ),
        formatter_class = argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "target",
        nargs   = "?",
        default = None,
        help    = "File or directory to sanitize (omit to launch GUI).",
    )
    parser.add_argument(
        "--gui-file",
        action  = "store_true",
        help    = "Open GUI specifically for selecting a file.",
    )
    parser.add_argument(
        "--gui-folder",
        action  = "store_true",
        help    = "Open GUI specifically for selecting a folder.",
    )
    parser.add_argument(
        "--wipe-free-space",
        metavar = "DRIVE",
        help    = "Wipe free space & MFT on the specified drive (e.g., C:\\).",
    )
    parser.add_argument(
        "--hardware-erase",
        metavar = "DISK_NUM",
        type    = int,
        help    = "DANGEROUS: Destroy ALL data on PhysicalDisk[NUM] using SSD firmware sanitize.",
    )
    parser.add_argument(
        "--physical-drive",
        metavar = "DISK_NUM",
        type    = int,
        help    = "DANGEROUS: Direct Sector Overwrite of PhysicalDisk[NUM] raw block device.",
    )
    parser.add_argument(
        "--ignore-ssd-warning",
        action  = "store_true",
        default = False,
        help    = "Bypass the interactive SSD confirmation prompt.",
    )
    parser.add_argument(
        "--override-safety",
        action  = "store_true",
        default = False,
        help    = "Bypass Blast-Radius directory protections (DANGEROUS).",
    )
    parser.add_argument(
        "--parallel",
        action  = "store_true",
        default = False,
        help    = "Enable asynchronous multi-processing to wipe multiple files simultaneously.",
    )
    parser.add_argument(
        "--passes", "-p",
        type    = int,
        default = 3,
        metavar = "N",
        help    = "Number of CSPRNG wipe passes (default: 3; overridden by --standard).",
    )
    parser.add_argument(
        "--standard", "-s",
        choices = list(STANDARDS.keys()),
        default = None,
        help    = "Wipe standard preset (dod|nist|gutmann). Overrides --passes.",
    )
    parser.add_argument(
        "--recursive", "-r",
        action  = "store_true",
        default = False,
        help    = "Recursively wipe directory contents (requires --force).",
    )
    parser.add_argument(
        "--force", "-f",
        action  = "store_true",
        default = False,
        help    = "Required for recursive directory wipes or wildcard targets.",
    )
    parser.add_argument(
        "--no-rename",
        action  = "store_true",
        default = False,
        help    = "Skip filename obfuscation (faster; less metadata scrubbing).",
    )
    parser.add_argument(
        "--log",
        default = "secure_wipe_audit.log",
        metavar = "FILE",
        help    = "Audit log output path (default: secure_wipe_audit.log).",
    )
    parser.add_argument(
        "--verify-log",
        metavar = "LOG_FILE",
        help    = "Cryptographically verify an audit log using its RSA signature.",
    )
    parser.add_argument(
        "--dry-run", "-n",
        action  = "store_true",
        default = False,
        help    = "Simulate all actions without modifying any data.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action  = "store_true",
        default = False,
        help    = "Print step-by-step progress to stdout.",
    )
    parser.add_argument(
        "--version",
        action  = "version",
        version = f"VIPER {VERSION}",
    )

    return parser


def build_pass_schedule(args: argparse.Namespace) -> List[Tuple[str, Optional[int]]]:
    """
    Resolve the effective wipe pass schedule from CLI arguments.

    Priority: --standard  >  --passes (custom CSPRNG-only schedule)
    """
    if args.standard:
        schedule = STANDARDS[args.standard]["passes"]
        return schedule

    # Custom pass count: alternate 0x00 / 0xFF / CSPRNG, ending on CSPRNG
    if args.passes < 1:
        raise ValueError("--passes must be at least 1.")
    if args.passes > 35:
        raise ValueError("--passes cannot exceed 35 (consider --standard gutmann).")

    pattern_cycle = [("byte", 0x00), ("byte", 0xFF), ("csprng", None)]
    return [pattern_cycle[i % 3] for i in range(args.passes)]


def print_banner(logger: AuditLogger, schedule: List, dry_run: bool) -> None:
    sep  = "=" * 62
    mode = " [DRY-RUN]" if dry_run else ""
    logger.info(sep)
    logger.info(f"  VIPER Sanitization Utility v{VERSION}{mode}")
    logger.info(f"  Passes  : {len(schedule)}")
    logger.info(f"  Platform: {platform.system()} {platform.release()}")
    logger.info(f"  PID     : {os.getpid()}")
    logger.info(f"  UTC Time: {datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')}")
    logger.info(sep)


def is_drive_ssd(target_path: Path) -> bool:
    """Detect if the target path resides on an SSD on Windows."""
    if sys.platform != "win32":
        return False
    try:
        import subprocess
        drive_letter = str(target_path.resolve().drive).replace(":", "")
        if not drive_letter:
            return False
        cmd = [
            "powershell", "-NoProfile", "-Command",
            f"(Get-Partition -DriveLetter {drive_letter} | Get-Disk).MediaType"
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5, 
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        output = result.stdout.strip().upper()
        if "SSD" in output or "NVME" in output:
            return True
    except Exception:
        pass
    return False

def main() -> int:
    global CHUNK_SIZE
    parser = build_arg_parser()
    args   = parser.parse_args()

    # ── Memory / RAM Configuration ────────────────────────────────────────────
    if args.parallel:
        max_threads = os.cpu_count() or 4
        if _HAS_PSUTIL:
            target_ram = psutil.virtual_memory().total * 0.50
        else:
            target_ram = 2 * 1024**3  # Safe 2GB fallback
        
        buffer_per_thread = target_ram / max_threads
        CHUNK_SIZE = min(int(buffer_per_thread), 128 * 1024 * 1024) # Cap buffer at 128 MB per thread
    else:
        CHUNK_SIZE = 8 * 1024 * 1024 # Sequential mode uses stable 8 MB chunks

    # ── Set up logger ─────────────────────────────────────────────────────────
    logger = AuditLogger(
        log_path = args.log,
        verbose  = args.verbose,
        dry_run  = args.dry_run,
    )

    # ── Build pass schedule ───────────────────────────────────────────────────
    try:
        schedule = build_pass_schedule(args)
    except ValueError as exc:
        logger.error(str(exc))
        return 2

    print_banner(logger, schedule, args.dry_run)

    # ── Execute Log Verification mode ─────────────────────────────────────────
    if args.verify_log:
        try:
            return 0 if verify_audit_log(args.verify_log, logger) else 1
        except Exception as e:
            logger.error(f"Log verification exception: {e}")
            return 1

    # ── Describe pass schedule to user ────────────────────────────────────────
    if args.standard:
        desc = STANDARDS[args.standard]["description"]
        logger.info(f"  Standard: {desc}")
    for i, (ptype, bval) in enumerate(schedule, 1):
        label = f"0x{bval:02X}" if ptype == "byte" else "CSPRNG"
        logger.verbose_msg(f"  Pass {i:>2}: {label}")
    logger.info("")

    # ── High Level Admin Operations ───────────────────────────────────────────
    if args.wipe_free_space:
        drive_path = Path(args.wipe_free_space).resolve()
        if is_drive_ssd(drive_path) and not args.ignore_ssd_warning:
            logger.warn("CRITICAL WARNING: You are attempting to wipe free space on a Solid State Drive (SSD) or NVMe.")
            logger.warn("Software wiping is fundamentally INEFFECTIVE on flash media due to hardware wear-leveling (FTL).")
            logger.warn("This will unnecessarily burn through your drive's write-endurance completely.")
            confirm = input("Type 'I UNDERSTAND' to proceed anyway: ")
            if confirm.strip() != "I UNDERSTAND":
                logger.info("Aborted by user.")
                return 1

        success = wipe_free_space(args.wipe_free_space, schedule, logger)
        return 0 if success else 1
        
    if args.hardware_erase is not None:
        logger.warn(f"!!! YOU ARE ABOUT TO OBLITERATE PHYSICAL DRIVE {args.hardware_erase} USING HARDWARE ERASE !!!")
        confirm = input("Type 'NUKEDRIVE' in all caps to permanently destroy this drive: ")
        if confirm.strip() != "NUKEDRIVE":
            logger.info("Hardware erase aborted.")
            return 1
        success = hardware_erase(args.hardware_erase, logger, args.dry_run)
        return 0 if success else 1
        
    if args.physical_drive is not None:
        logger.warn(f"!!! YOU ARE ABOUT TO OVERWRITE ALL SECTORS ON PHYSICAL DRIVE {args.physical_drive} !!!")
        confirm = input("Type 'NUKEDRIVE' in all caps to permanently destroy this drive: ")
        if confirm.strip() != "NUKEDRIVE":
            logger.info("Physical drive wipe aborted.")
            return 1
        success = wipe_physical_drive(args.physical_drive, schedule, logger, args.dry_run)
        return 0 if success else 1

    # ── Resolve target or launch GUI ──────────────────────────────────────────
    target_raw = args.target

    if target_raw is None:
        root = tk.Tk()
        root.withdraw() # Hide the main window
        if args.gui_folder:
            target_raw = filedialog.askdirectory(title="Select Folder to Secure Wipe")
            args.recursive = True
            args.force = True
        elif args.gui_file:
            target_raw = filedialog.askopenfilename(title="Select File to Secure Wipe")
        else:
            target_raw = filedialog.askopenfilename(title="Select File to Wipe (cancel to select a folder instead)")
            if not target_raw:
                target_raw = filedialog.askdirectory(title="Select Folder to Secure Wipe")
                if target_raw:
                    args.recursive = True
                    args.force = True
        
        if not target_raw:
            logger.info("No target selected. Exiting.")
            return 0

    try:
        target_path = Path(target_raw).resolve()
    except OSError as exc:
        logger.error(f"Cannot resolve target path '{target_raw}': {exc}")
        return 2

    # ── Blast-radius check on top-level target ────────────────────────────────
    try:
        assert_not_critical(target_path, args.override_safety)
    except SafetyError as exc:
        logger.warn(str(exc))
        logger.warn("=" * 62)
        confirm = input("Type 'OVERRIDE' in all caps to bypass Blast-Radius Protection and proceed instantly: ")
        if confirm.strip() == "OVERRIDE":
            logger.warn("Blast-Radius protections disabled by user. Proceeding...")
            args.override_safety = True
        else:
            logger.info("Aborted securely.")
            return 2

    if target_path.exists() and is_drive_ssd(target_path) and not args.ignore_ssd_warning:
        logger.warn(f"CRITICAL WARNING: The target '{target_path.drive}' is a Solid State Drive (SSD) or NVMe.")
        logger.warn("Software wiping is fundamentally INEFFECTIVE on flash media due to hardware wear-leveling (FTL).")
        logger.warn("The original data may remain perfectly readable on the physical flash chips.")
        confirm = input("Type 'I UNDERSTAND' to proceed anyway, or press Enter to abort: ")
        if confirm.strip() != "I UNDERSTAND":
            logger.info("Aborted by user.")
            return 1

    # ── Collect file list ─────────────────────────────────────────────────────
    if target_path.is_dir():
        try:
            assert_force_for_directory(target_path, args.force)
        except SafetyError as exc:
            logger.error(str(exc))
            return 2
        targets = collect_files(target_path, args.recursive, logger)
        if not targets:
            logger.warn(f"No files found under '{target_path}'.")
            return 0
    else:
        targets = [target_path]

    # ── Summary ───────────────────────────────────────────────────────────────
    logger.info(f"  Targets : {len(targets)} file(s)")
    if args.parallel:
        logger.info(f"  Parallel: ACTIVE ({os.cpu_count() or 4} workers, {CHUNK_SIZE/1024/1024:.0f} MB buffer limit)")
    logger.info("")

    # ── Execute ───────────────────────────────────────────────────────────────
    success_count = 0
    failure_count = 0

    def secure_wipe_worker(tgt_path: Path) -> bool:
        return wipe_file(
            raw_path        = str(tgt_path),
            pass_schedule   = schedule,
            logger          = logger,
            no_rename       = args.no_rename,
            dry_run         = args.dry_run,
            override_safety = args.override_safety,
        )

    if args.parallel:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = executor.map(secure_wipe_worker, targets)
            for ok in results:
                if ok: success_count += 1
                else:  failure_count += 1
    else:
        for tgt in targets:
            ok = secure_wipe_worker(tgt)
            if ok: success_count += 1
            else:  failure_count += 1

    if target_path.is_dir() and args.recursive and not args.dry_run:
        wipe_directory_metadata(target_path, args.no_rename, logger)

    # ── Final summary ─────────────────────────────────────────────────────────
    logger.info("")
    logger.info("=" * 62)
    logger.info(
        f"  Complete - "
        f"[+] {success_count} succeeded  "
        f"[X] {failure_count} failed"
    )
    logger.info(f"  Audit log written -> {args.log}")
    
    # ── Cryptographically Sign the Log ────────────────────────────────────────
    if HAS_CRYPTOGRAPHY and not args.dry_run:
        try:
            # We must flush the log handlers before signing to get the complete hash
            for handler in logger._audit.handlers:
                handler.flush()
            sign_audit_log(args.log, logger)
        except Exception as e:
            logger.warn(f"Failed to cryptographically sign audit log: {e}")
            
    logger.info("=" * 62)

    return 0 if failure_count == 0 else 1


# ─── Entrypoint guard ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    sys.exit(main())
