import logging
import sys
import os
import json
import datetime
from pathlib import Path

try:
    from colorama import Fore, Style
    COLOR = True
except ImportError:
    COLOR = False


class StructuredAuditLogger:
    """
    Dual-channel logger: human-readable stdout + structured JSON audit file.
    Replacing the fragile tab-separated format with machine-parsable JSON.
    """

    def __init__(self, log_path: str, verbose: bool = False, dry_run: bool = False):
        self.log_path = log_path
        self.verbose = verbose
        self.dry_run = dry_run

        # ── Console Handler ──
        self._console = logging.getLogger("secure_wipe.console")
        self._console.setLevel(logging.DEBUG if verbose else logging.INFO)
        if not self._console.handlers:
            ch = logging.StreamHandler(sys.stdout)
            ch.setFormatter(logging.Formatter("%(message)s"))
            self._console.addHandler(ch)

        # ── JSON File Handler ──
        self._audit = logging.getLogger("secure_wipe.audit")
        self._audit.setLevel(logging.DEBUG)
        if not self._audit.handlers:
            fh = logging.FileHandler(log_path, encoding="utf-8")
            # Raw string output, we format as JSON before handing to the logger
            fh.setFormatter(logging.Formatter("%(message)s"))
            self._audit.addHandler(fh)

    def _ts(self) -> str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"

    def _colorize(self, msg: str, color_code: str) -> str:
        if COLOR:
            return f"{color_code}{msg}{Style.RESET_ALL}"
        return msg

    def _record(self, level: str, path: str, passes: int, status: str, detail: str = "") -> None:
        """
        Record a structured JSON event to the audit log.
        Paths are converted to strings to ensure JSON serializability.
        """
        event = {
            "timestamp": self._ts(),
            "level": level,
            "target_path": str(path),
            "passes_completed": passes,
            "status": status,
            "detail": detail,
            "dry_run": self.dry_run
        }
        self._audit.info(json.dumps(event))

    # ── Public Console API ──

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

    # ── Public Audit API ──

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
        self._record("INFO", path, passes, "SIMULATED", "No data modified")
        self.info(self._colorize(
            f"[DRY-RUN] Would wipe: {path}  [{passes} pass(es)]",
            Fore.MAGENTA if COLOR else ""
        ))
