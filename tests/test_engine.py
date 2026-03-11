import os
import pytest
from pathlib import Path

from viper_core.logger import StructuredAuditLogger
from viper_core.engine import (
    obfuscate_filename,
    truncate_and_unlink,
    wipe_file,
    CHUNK_SIZE
)

@pytest.fixture
def temp_logger(tmp_path):
    log_file = tmp_path / "test_engine_audit.json"
    logger = StructuredAuditLogger(str(log_file), verbose=False, dry_run=False)
    yield logger
    for h in list(logger._audit.handlers):
        h.close()
        logger._audit.removeHandler(h)
    for h in list(logger._console.handlers):
        h.close()
        logger._console.removeHandler(h)

@pytest.fixture
def dummy_file(tmp_path):
    target = tmp_path / "sensitive_data.txt"
    target.write_bytes(b"A" * 1024 * 1024)  # 1 MB of dummy data
    yield target
    if target.exists():
        target.unlink()

def test_obfuscate_filename_no_rename(dummy_file, temp_logger):
    """Ensure --no-rename leaves the original filename intact."""
    result = obfuscate_filename(dummy_file, temp_logger, no_rename=True)
    assert result == dummy_file
    assert dummy_file.exists()

def test_obfuscate_filename_renames_to_single_char(dummy_file, temp_logger):
    """Ensure iterational renaming ends up with a single-character filename before deletion."""
    original_parent = dummy_file.parent
    result = obfuscate_filename(dummy_file, temp_logger, no_rename=False)
    
    assert result != dummy_file
    assert not dummy_file.exists()
    assert result.exists()
    assert len(result.name) == 1
    assert result.parent == original_parent

def test_truncate_and_unlink_destroys_file(dummy_file, temp_logger):
    """Ensure the truncate-then-unlink methodology leaves nothing behind."""
    truncate_and_unlink(dummy_file, temp_logger)
    assert not dummy_file.exists()

def test_wipe_file_dry_run(dummy_file, temp_logger):
    """Ensure --dry-run does not modify the target file."""
    original_size = dummy_file.stat().st_size
    original_mtime = dummy_file.stat().st_mtime
    
    schedule = [("byte", 0x00)]
    success = wipe_file(str(dummy_file), schedule, CHUNK_SIZE, temp_logger, no_rename=False, dry_run=True)
    
    assert success is True
    assert dummy_file.exists()
    assert dummy_file.stat().st_size == original_size
    assert dummy_file.stat().st_mtime == original_mtime

def test_wipe_file_full_execution(dummy_file, temp_logger):
    """Execute a full sanitization pass and assert destruction."""
    schedule = [("byte", 0x00), ("byte", 0xFF), ("csprng", None)]
    success = wipe_file(str(dummy_file), schedule, CHUNK_SIZE, temp_logger, no_rename=False, dry_run=False)
    
    assert success is True
    # The file should be completely gone, along with any renamed variants
    assert not dummy_file.exists()
    
    # Verify no single-character random files were left in the parent directory
    leftovers = list(dummy_file.parent.glob("?"))
    assert len(leftovers) == 0
