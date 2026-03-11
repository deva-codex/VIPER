import os
import json
import pytest
from pathlib import Path

from viper_core.logger import StructuredAuditLogger
from viper_core.crypto import (
    get_random_generator,
    sign_audit_log,
    verify_audit_log,
    HAS_CRYPTOGRAPHY
)

@pytest.fixture
def temp_logger(tmp_path):
    log_file = tmp_path / "test_audit.json"
    logger = StructuredAuditLogger(str(log_file), verbose=True, dry_run=False)
    yield logger
    for h in logger._audit.handlers:
        h.close()
    for h in logger._console.handlers:
        h.close()

def test_csprng_generator_chunk_size():
    """Verify the AES-CTR generator produces exact byte lengths."""
    gen = get_random_generator()
    chunk1 = gen.chunk(1024)
    chunk2 = gen.chunk(5)
    
    assert len(chunk1) == 1024
    assert len(chunk2) == 5
    assert chunk1[:5] != chunk2  # Extremely low probability of collision

def test_csprng_generator_deterministic_instance():
    """Ensure generators don't share identical CTR states (which would output identical streams)."""
    gen1 = get_random_generator()
    gen2 = get_random_generator()
    
    assert gen1.chunk(16) != gen2.chunk(16)

@pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="cryptography package not installed")
def test_audit_log_signing_and_verification(tmp_path, temp_logger):
    """Test the full RSA-PSS signature lifecycle for audit logs."""
    log_path = tmp_path / "test_audit.json"
    
    # Write some pseudo-events to the log
    temp_logger.audit_success(path="/fake/path1", passes=3)
    temp_logger.audit_failure(path="/fake/path2", passes=1, detail="Access Denied")
    
    # Close and detach all handlers to fully release Windows file locks
    for h in list(temp_logger._audit.handlers):
        h.flush()
        h.close()
        temp_logger._audit.removeHandler(h)
    for h in list(temp_logger._console.handlers):
        h.close()
        temp_logger._console.removeHandler(h)
        
    assert log_path.exists()
    
    # Sign it
    sign_audit_log(str(log_path), temp_logger)
    sig_path = tmp_path / "test_audit.json.sig"
    
    assert sig_path.exists()
    assert (tmp_path / "viper_private.pem").exists()
    assert (tmp_path / "viper_public.pem").exists()
    
    # Verify valid signature
    is_valid = verify_audit_log(str(log_path), temp_logger)
    assert is_valid is True

@pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="cryptography package not installed")
def test_audit_log_tamper_detection(tmp_path, temp_logger):
    """Ensure verification fails if the log file is modified after signing."""
    log_path = tmp_path / "test_audit.json"
    
    temp_logger.audit_success(path="/secure/file", passes=3)
    # Close and detach all handlers to fully release Windows file locks
    for h in list(temp_logger._audit.handlers):
        h.flush()
        h.close()
        temp_logger._audit.removeHandler(h)
    for h in list(temp_logger._console.handlers):
        h.close()
        temp_logger._console.removeHandler(h)
        
    sign_audit_log(str(log_path), temp_logger)
    
    # Tamper with the log file
    with open(log_path, "a") as f:
        f.write("\n" + json.dumps({"level": "SUCCESS", "target_path": "/fake/tampered/file"}))
        
    is_valid = verify_audit_log(str(log_path), temp_logger)
    assert is_valid is False
