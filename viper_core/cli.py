import sys
import argparse
import datetime
import os
import tkinter as tk
from tkinter import filedialog
from pathlib import Path
import platform
import concurrent.futures

from .logger import StructuredAuditLogger
from .crypto import verify_audit_log, sign_audit_log, HAS_CRYPTOGRAPHY
from .utils import (
    assert_not_critical, SafetyError, collect_files, assert_force_for_directory
)
from .engine import (
    CHUNK_SIZE, HAS_PSUTIL, is_drive_ssd, wipe_free_space, 
    hardware_erase, wipe_physical_drive, wipe_file,
    wipe_directory_metadata
)

VERSION = "1.1.0"

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
        "passes": [("csprng", None)],
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

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog        = "viper",
        description = (
            "VIPER - Cryptographically secure file sanitization utility.\n"
            "Implements DoD 5220.22-M, NIST SP 800-88, or Gutmann standards."
        ),
        formatter_class = argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("target", nargs="?", default=None, help="File or directory to sanitize.")
    parser.add_argument("--gui-file", action="store_true", help="Open GUI specifically for selecting a file.")
    parser.add_argument("--gui-folder", action="store_true", help="Open GUI specifically for selecting a folder.")
    parser.add_argument("--wipe-free-space", metavar="DRIVE", help="Wipe free space & MFT on the specified drive.")
    parser.add_argument("--hardware-erase", metavar="DISK_NUM", type=int, help="DANGEROUS: SSD firmware sanitize.")
    parser.add_argument("--physical-drive", metavar="DISK_NUM", type=int, help="DANGEROUS: Direct Sector Overwrite.")
    parser.add_argument("--ignore-ssd-warning", action="store_true", default=False, help="Bypass SSD confirmation.")
    parser.add_argument("--override-safety", action="store_true", default=False, help="Bypass Blast-Radius protections.")
    parser.add_argument("--parallel", action="store_true", default=False, help="Enable asynchronous multi-processing.")
    parser.add_argument("--passes", "-p", type=int, default=3, help="Number of CSPRNG wipe passes.")
    parser.add_argument("--standard", "-s", choices=list(STANDARDS.keys()), default=None, help="Wipe standard preset.")
    parser.add_argument("--recursive", "-r", action="store_true", default=False, help="Recursively wipe directory contents.")
    parser.add_argument("--force", "-f", action="store_true", default=False, help="Required for recursive directory wipes.")
    parser.add_argument("--no-rename", action="store_true", default=False, help="Skip filename obfuscation.")
    parser.add_argument("--log", default="secure_wipe_audit.log", metavar="FILE", help="Audit log output path.")
    parser.add_argument("--verify-log", metavar="LOG_FILE", help="Cryptographically verify an audit log.")
    parser.add_argument("--dry-run", "-n", action="store_true", default=False, help="Simulate actions without destruction.")
    parser.add_argument("--verbose", "-v", action="store_true", default=False, help="Print step-by-step progress.")
    parser.add_argument("--version", action="version", version=f"VIPER {VERSION}")

    return parser

def build_pass_schedule(args: argparse.Namespace) -> list:
    if args.standard:
        return STANDARDS[args.standard]["passes"]

    if args.passes < 1 or args.passes > 35:
        raise ValueError("--passes must be between 1 and 35.")

    pattern_cycle = [("byte", 0x00), ("byte", 0xFF), ("csprng", None)]
    return [pattern_cycle[i % 3] for i in range(args.passes)]

def print_banner(logger: StructuredAuditLogger, schedule: list, dry_run: bool) -> None:
    sep  = "=" * 62
    mode = " [DRY-RUN]" if dry_run else ""
    logger.info(sep)
    logger.info(f"  VIPER Sanitization Utility v{VERSION}{mode}")
    logger.info(f"  Passes  : {len(schedule)}")
    logger.info(f"  Platform: {platform.system()} {platform.release()}")
    logger.info(f"  UTC Time: {datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')}")
    logger.info(sep)

def execute_cli() -> int:
    parser = build_arg_parser()
    args   = parser.parse_args()

    # Memory cap logic from engine
    global CHUNK_SIZE
    if args.parallel:
        max_threads = os.cpu_count() or 4
        # We no longer hard-cap at 128MB. If running massive NVMe drives, we allow larger buffer limits.
        target_ram = psutil.virtual_memory().total * 0.50 if HAS_PSUTIL else 2 * 1024**3
        CHUNK_SIZE = int(target_ram / max_threads)
    else:
        CHUNK_SIZE = 8 * 1024 * 1024

    logger = StructuredAuditLogger(args.log, args.verbose, args.dry_run)

    try:
        schedule = build_pass_schedule(args)
    except ValueError as exc:
        logger.error(str(exc))
        return 2

    print_banner(logger, schedule, args.dry_run)

    if args.verify_log:
        try:
            return 0 if verify_audit_log(args.verify_log, logger) else 1
        except Exception as e:
            logger.error(f"Log verification exception: {e}")
            return 1

    # Describe pass schedule
    for i, (ptype, bval) in enumerate(schedule, 1):
        label = f"0x{bval:02X}" if ptype == "byte" else "CSPRNG"
        logger.verbose_msg(f"  Pass {i:>2}: {label}")
    logger.info("")

    # High Level Admin Operations
    if args.wipe_free_space:
        drive_path = Path(args.wipe_free_space).resolve()
        if is_drive_ssd(drive_path) and not args.ignore_ssd_warning:
            logger.warn("CRITICAL WARNING: Target is an SSD. Wiping free space on flash media is ineffective.")
            if input("Type 'I UNDERSTAND' to proceed: ").strip() != "I UNDERSTAND":
                return 1
        success = wipe_free_space(args.wipe_free_space, schedule, CHUNK_SIZE, logger)
        return 0 if success else 1
        
    if args.hardware_erase is not None:
        logger.warn(f"!!! DISK OBLITERATION WARNING FOR DISK {args.hardware_erase} !!!")
        if input("Type 'NUKEDRIVE' to authorize firmware erase: ").strip() != "NUKEDRIVE":
            return 1
        success = hardware_erase(args.hardware_erase, logger, args.dry_run)
        return 0 if success else 1
        
    if args.physical_drive is not None:
        logger.warn(f"!!! RAW OVERWRITE WARNING FOR DISK {args.physical_drive} !!!")
        if input("Type 'NUKEDRIVE' to authorize sector overwrite: ").strip() != "NUKEDRIVE":
            return 1
        success = wipe_physical_drive(args.physical_drive, schedule, CHUNK_SIZE, logger, args.dry_run)
        return 0 if success else 1

    # GUI Fallback
    target_raw = args.target
    if target_raw is None:
        root = tk.Tk(); root.withdraw()
        if args.gui_folder:
            target_raw = filedialog.askdirectory(title="Select Folder to Secure Wipe")
            args.recursive, args.force = True, True
        elif args.gui_file:
            target_raw = filedialog.askopenfilename(title="Select File to Secure Wipe")
        else:
            target_raw = filedialog.askopenfilename() or filedialog.askdirectory()
            if target_raw: args.recursive, args.force = True, True
        if not target_raw: return 0

    try:
        target_path = Path(target_raw).resolve()
    except OSError as exc:
        logger.error(f"Cannot resolve target: {exc}"); return 2

    # Blast-Radius Safety Check
    try:
        assert_not_critical(target_path, args.override_safety)
    except SafetyError as exc:
        logger.warn(str(exc))
        if input("Type 'OVERRIDE' to bypass Blast-Radius Protection: ").strip() == "OVERRIDE":
            args.override_safety = True
        else:
            return 2

    if target_path.exists() and is_drive_ssd(target_path) and not args.ignore_ssd_warning:
        logger.warn("CRITICAL WARNING: Target is an SSD.")
        if input("Type 'I UNDERSTAND' to proceed: ").strip() != "I UNDERSTAND": return 1

    # Execute Wipe Workload
    if target_path.is_dir():
        try:
            assert_force_for_directory(target_path, args.force)
        except SafetyError as exc:
            logger.error(str(exc)); return 2
        targets = collect_files(target_path, args.recursive, logger)
        if not targets: return 0
    else:
        targets = [target_path]

    logger.info(f"  Targets : {len(targets)} file(s)")
    if args.parallel:
        logger.info(f"  Parallel: ACTIVE ({os.cpu_count() or 4} workers, {CHUNK_SIZE/1024/1024:.0f} MB buffer limit)")
    logger.info("")

    success_count, failure_count = 0, 0
    
    def secure_wipe_worker(tgt_path: Path) -> bool:
        return wipe_file(str(tgt_path), schedule, CHUNK_SIZE, logger, args.no_rename, args.dry_run)

    if args.parallel:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for ok in executor.map(secure_wipe_worker, targets):
                if ok: success_count += 1
                else: failure_count += 1
    else:
        for tgt in targets:
            if secure_wipe_worker(tgt): success_count += 1
            else: failure_count += 1

    if target_path.is_dir() and args.recursive and not args.dry_run:
        wipe_directory_metadata(target_path, args.no_rename, logger)

    logger.info(f"Complete - [+] {success_count} succeeded  [X] {failure_count} failed")
    
    if HAS_CRYPTOGRAPHY and not args.dry_run:
        try:
            for handler in logger._audit.handlers: handler.flush()
            sign_audit_log(args.log, logger)
        except Exception as e:
            logger.warn(f"Failed to cryptographically sign log: {e}")

    return 0 if failure_count == 0 else 1

if __name__ == "__main__":
    sys.exit(execute_cli())
