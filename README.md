# VIPER Data Sanitization Suite

VIPER is a military-grade, Python-based data obliteration and forensic sanitization utility designed for Windows operating systems. It was built to exceed the hardware limitations of standard software wipers by interfacing directly with the Windows Cryptography APIs, NTFS Master File Table (MFT), and SSD firmware controllers.

## Features

- **Multi-Process Shredding:** Utilizes `concurrent.futures` and `psutil` to dynamically cap RAM allocation to 50% while obliterating hundreds of files in parallel.
- **DoD & NIST Compliance:** Integrates DoD 5220.22-M (3-pass), NIST 800-88 (1-pass), and Gutmann (35-pass) sanitization standards using AES-256 CSPRNG (Cryptographically Secure Pseudo-Random Number Generator).
- **Physical Disk Wiping:** Direct sector access (`\\.\PhysicalDriveX`) to zero-fill raw hard drives, bypassing the filesystem completely.
- **Hardware Crypto-Erase:** Interacts with undocumented Windows PowerShell APIs to trigger SSD firmware Sanitize & Block Erase commands.
- **BitLocker Bit-Shredding Fallback:** If an SSD's firmware relies on a freeze-lock to block sanitization, VIPER automatically wraps the full volume in BitLocker XTS-AES-256 encryption using an instantly discarded key, reducing the SSD to cryptographic white noise.
- **Hidden Alternate Data Stream (ADS) Crushing:** Queries the Windows `ctypes` bindings to isolate and wipe hidden NTFS Alternate Data Streams attached to a target before sweeping the parent file.
- **Cryptographically Signed Audits:** Validates forensically-sound audit trails by generating a local RSA-2048 keypair, hashing the operational log via SHA-256, and mathematically signing it via PKCS-PSS (`viper_audit.log.sig`).
- **Deep System Purgatory:** Purges active RAM memory pages with CSPRNG noise and enforces `ClearPageFileAtShutdown` registry policies to decouple forensic traces.
- **Automated WinPE `.ISO` Generator:** Includes an intelligent build script that hooks into the Microsoft ADK to compile a completely autonomous bootable Windows PE operating system.

## Quick Start

1. Install Python 3.10+ (Ensure it's added to your PATH).
2. Install dependencies:
   ```bash
   pip install psutil cryptography colorama
   ```
3. Run the interactive Control Center Launcher (requires Administrator privileges for disk access):
   - Double-click `VIPER_Launcher.bat`

### Command-Line Arguments
If you prefer to bypass the launcher, `viper.py` is fully scriptable. Run `python viper.py --help` for the complete API. 

## Notice / Liability
**Use with extreme caution.** VIPER is an enterprise-grade destruct utility. When executing Physical Disk or SSD Hardware Erase commands, data is obliterated instantaneously and irreversibly.

There is no recovery.
