import platform
from pathlib import Path

# ── Blast-Radius: system-critical directory deny-list ────────────────────────
CRITICAL_PATHS_UNIX = frozenset({
    "/", "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin",
    "/lib", "/lib64", "/usr/lib", "/usr/lib64",
    "/etc", "/boot", "/dev", "/proc", "/sys", "/run",
    "/var", "/var/log", "/tmp",
    "/root", "/home", "/snap", "/opt",
})

CRITICAL_PATHS_WINDOWS = frozenset({
    "C:\\", "C:\\Windows", "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64", "C:\\Program Files",
    "C:\\Program Files (x86)", "C:\\ProgramData",
})

IS_WINDOWS = platform.system() == "Windows"
CRITICAL_PATHS = CRITICAL_PATHS_WINDOWS if IS_WINDOWS else CRITICAL_PATHS_UNIX

class SafetyError(RuntimeError):
    """Raised when a target violates blast-radius or safety constraints."""
    pass

def assert_not_critical(path: Path, override_safety: bool = False) -> None:
    """
    Unconditionally reject any path that matches or is an ancestor of a
    system-critical directory. This is the primary blast-radius guard.
    """
    if override_safety:
        return
    path_str = str(path).rstrip("\\" if IS_WINDOWS else "/")

    if path_str in CRITICAL_PATHS:
        raise SafetyError(f"SAFETY ABORT: '{path}' is a protected system directory.")

    for critical in CRITICAL_PATHS:
        try:
            path.relative_to(critical)
            raise SafetyError(
                f"SAFETY ABORT: '{path}' resides inside protected system directory '{critical}'."
            )
        except ValueError:
            pass

def assert_force_for_directory(path: Path, force: bool) -> None:
    """
    Directories (especially non-empty ones) require --force to prevent
    accidental recursive wipes from ambiguous globs or path mistakes.
    """
    if path.is_dir() and not force:
        raise SafetyError(
            f"'{path}' is a directory. Pass --force to confirm recursive wipe."
        )

def collect_files(root: Path, recursive: bool, logger) -> list:
    """
    Collect all regular files under `root`. Does not follow directory symlinks.
    """
    targets = []
    if not root.is_dir():
        targets.append(root)
        return targets

    for entry in (root.rglob("*") if recursive else root.iterdir()):
        if entry.is_symlink() or entry.is_file():
            targets.append(entry)
            
    return targets
