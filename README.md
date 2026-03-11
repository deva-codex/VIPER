<div align="center">

# 🐍 VIPER 
### Military-Grade Data Sanitization & Forensic Obliteration Suite

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg?logo=python&logoColor=white)](#)
[![OS](https://img.shields.io/badge/OS-Windows--10%20%7C%2011-0078D6.svg?logo=windows&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](#)

*VIPER is an advanced, weaponized data-shredding utility designed to definitively destroy sensitive information beyond the recovery capabilities of modern digital forensics.*

</div>

---

## ⚡ Overview

Standard operating system "deletes" merely un-index a file from the Master File Table, leaving the binary data completely intact on the physical disk. Commercial software wipers often fail to account for hardware-level caching, wear-leveling in SSDs, and covert payload structures like Alternate Data Streams (ADS).

**VIPER** is built to bridge this gap. By aggressively interfacing directly with the Windows Cryptography APIs, the NTFS architecture, and raw storage firmware controllers, VIPER ensures cryptographic annihilation of your data. 

**There is no recovery.**

---

## 🚀 Enterprise Features

### 🛡️ Core Sanitization Strategies
* **DoD & NIST Compliance**: Natively executes **DoD 5220.22-M** (3-pass), **NIST 800-88** (1-pass), and **Gutmann** (35-pass) sanitization standards.
* **CSPRNG Overwriting**: Utilizes AES-256 CTR encryption streams from the `cryptography` library to generate massive volumes of Cryptographically Secure Pseudo-Random noise at >1GB/s.
* **Direct Sector Wiping**: Opens raw `\\.\PhysicalDriveX` file descriptors to overwrite platters directly, bypassing the OS filesystem completely.

### 💾 Solid State Drive (SSD) Intelligence
* **Firmware Crypto-Erase**: Actively detects NVMe/SSDs and uses native Windows Storage APIs to send undocumented **Block Erase** and **Sanitize** commands directly to the drive controller.
* **Bit-Shredding Fallback**: If a motherboard BIOS places a "Firmware Freeze Lock" on the SSD, VIPER automatically wraps the entire volume in **BitLocker XTS-AES-256** encryption using a thrown-away key, immediately degrading the flash cells into unpredictable white noise.

### 🕵️‍♂️ Forensic Decoupling & Stealth
* **Hidden Data Destruction**: Uses low-level Windows `ctypes` bindings to hunt down and individually shred hidden **NTFS Alternate Data Streams (ADS)** attached to target files.
* **Deep System Purgatory**: Selectively allocates >95% of available physical RAM to flush cached secrets, and enforces `ClearPageFileAtShutdown` registry policies to decouple the hibernation cache.
* **MFT & Slack Space Scrubbing**: Chains native Windows `cipher /w` commands to eradicate unallocated cluster tips and Master File Table metadata.

### 🔐 Cryptographic Non-Repudiation
* **Signed Audits**: End-to-end logging tracking every byte overwritten, verified mathematically via **RSA-2048 PKCS-PSS** digital signatures to prevent audit tampering.

### 💿 Standalone Deployment
* **Automated WinPE Builder**: A powerful Python orchestrator that hooks into the Microsoft ADK to compile a fully bootable, autonomous **VIPER Windows PE Operating System (.ISO)**, allowing you to obliterate a host computer offline.

---

## 🛠️ Installation & Usage

**Prerequisites:** 
- Python 3.10+ (Added to system PATH)
- Windows 10 or 11 (Requires Administrator Privileges for physical disk access)

### 1. Clone & Install
```bash
git clone https://github.com/your-username/VIPER.git
cd VIPER
pip install -r requirements.txt  # Or manually install: psutil cryptography colorama
```

### 2. Launch the Control Center
For the easiest experience with a highly polished ASCII Terminal UI, run the included batch launcher as **Administrator**:
```cmd
VIPER_Launcher.bat
```

### 3. Command Line Interface
If you prefer automation and scripting without the GUI, `viper.py` operates beautifully via CLI:
```powershell
# Wipe a specific file using the DoD 5220.22-M standard
python viper.py "C:\Secrets\Passwords.kdbx" --standard dod --verbose

# Wipe an entire folder recursively in parallel (utilizing 50% system RAM)
python viper.py "D:\Confidential_Project" --recursive --force --parallel --verbose

# Nuke the entirety of Physical Drive 2 (DANGEROUS)
python viper.py --physical-drive 2 --verbose

# Perform SSD Firmware Sanitize on Disk 1
python viper.py --hardware-erase 1 --verbose

# Cryptographically Verify an Audit Log
python viper.py --verify-log secure_wipe_audit.log
```

---

## ⚠️ Disclaimer & Liability

By using **VIPER**, you acknowledge that this tool is designed for **permanent, irreversible data destruction**. 
Executing `VIPER` on a raw block device or utilizing the `Hardware Erase` vectors will instantly annihilate the partition table and all contained data with zero chance of recovery. 

**The creators and contributors of VIPER assume ZERO liability for accidental data loss, hardware degradation, or system unrecoverability.** Use strictly on hardware you own and intend to sanitize.

---

<div align="center">
  <i>"What is deleted is forgotten. What is shredded never existed."</i>
</div>
