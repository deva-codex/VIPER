import os
from pathlib import Path
from tempfile import gettempdir

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

import secrets
from .logger import StructuredAuditLogger


class SecureRandomGenerator:
    """
    Provides cryptographically secure pseudorandom bytes.
    Uses cryptography (AES-CTR) if available for speed, otherwise falls back to os.urandom.
    """
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


def get_random_generator() -> SecureRandomGenerator:
    """Factory method to get a new deterministic instance instead of relying on globals."""
    return SecureRandomGenerator()


def sign_audit_log(log_path: str, logger: StructuredAuditLogger, password: bytes = None) -> None:
    """
    Hash the log file and sign it with an RSA private key.
    Generates an encrypted PEM using BestAvailableEncryption if a password is provided.
    """
    if not HAS_CRYPTOGRAPHY:
        logger.warn("cryptography package missing. Audit logs cannot be signed.")
        return

    # Store signature keys in a consistent location (e.g., alongside the log or temp dir)
    log_dir = Path(log_path).parent
    private_key_path = log_dir / "viper_private.pem"
    public_key_path = log_dir / "viper_public.pem"

    if not private_key_path.exists():
        logger.info("Generating new RSA-2048 key pair for audit log signatures...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Apply strict encryption to the private key instead of storing plain-text
        encryption_alg = (
            serialization.BestAvailableEncryption(password) 
            if password else serialization.NoEncryption()
        )

        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_alg
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
                password=password,
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


def verify_audit_log(log_path: str, logger: StructuredAuditLogger) -> bool:
    """Verify an audit log using the corresponding .sig file and public key."""
    sig_path = f"{log_path}.sig"
    log_dir = Path(log_path).parent
    public_key_path = log_dir / "viper_public.pem"

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
        logger.success(f"CRYPTOGRAPHIC VERIFICATION PASSED: The audit log '{log_path}' is authentic.")
        return True
    except Exception as e:
        logger.error(f"CRYPTOGRAPHIC VERIFICATION FAILED: The audit log '{log_path}' has been tampered with!")
        return False
