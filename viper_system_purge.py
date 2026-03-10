import os
import sys
import time
import subprocess
import secrets
import logging

try:
    import psutil
except ImportError:
    print("[X] ERROR: The 'psutil' library is required for physical memory purging.")
    print("    Please run: python -m pip install psutil")
    sys.exit(1)

def purge_physical_ram():
    """
    Allocates aggressively up to 95% of available free RAM and overwrites it.
    This forces the OS to flush out unallocated pages containing residual secrets.
    """
    print("\n[+] INITIATING PHYSICAL MEMORY PURGE...")
    
    vm = psutil.virtual_memory()
    available_bytes = vm.available
    target_allocation = int(available_bytes * 0.95)  # Leave 5% for system stability
    
    print(f"    Available RAM: {available_bytes / (1024**3):.2f} GB")
    print(f"    Target Wipe  : {target_allocation / (1024**3):.2f} GB")
    
    chunk_size = 256 * 1024 * 1024  # 256 MB chunks
    buffer_list = []
    
    allocated = 0
    try:
        print("    [>] Allocating and overwriting memory pages (Pass 1: ZERO fill)...")
        while allocated < target_allocation:
            # Allocate 256MB of zeroes
            buffer_list.append(bytearray(chunk_size))
            allocated += chunk_size
            
            # Simple progress bar
            sys.stdout.write(f"\r    Progress: {(allocated / target_allocation) * 100:.1f}%")
            sys.stdout.flush()
            
    except MemoryError:
        print(f"\n    [!] Hit hard memory limit early at {allocated / (1024**3):.2f} GB. Continuing...")
        
    print("\n    [>] Memory allocation reached. Forcing OS page faulting...")
    
    # Overwrite the allocated blocks with CSPRNG data (Pass 2)
    print("    [>] Overwriting memory blocks (Pass 2: CSPRNG fill)...")
    for i in range(len(buffer_list)):
        # We fill with random bytes to scrub the memory pages
        buffer_list[i][:] = os.urandom(len(buffer_list[i]))
        sys.stdout.write(f"\r    Progress: {((i+1) / len(buffer_list)) * 100:.1f}%")
        sys.stdout.flush()

    print("\n    [+] Physical RAM purge completed. Releasing memory back to OS...")
    
    # Release memory
    buffer_list.clear()
    import gc
    gc.collect()
    time.sleep(2) # Give OS a moment to reclaim
    

def destroy_hibernation():
    """Disables Windows Hibernation, destroying hiberfil.sys permanently."""
    print("\n[+] DESTROYING HIBERNATION CACHE (hiberfil.sys)...")
    try:
        cmd = ["powercfg.exe", "-h", "off"]
        subprocess.run(cmd, check=True, capture_output=True)
        print("    [>] Hibernation disabled. 'hiberfil.sys' has been deleted.")
    except Exception as e:
        print(f"    [X] Failed to wipe Hibernation cache. Are you running as Administrator?")


def enforce_pagefile_purge():
    """
    Sets the Windows Registry key to enforce a cryptographic overwrite
    of the Pagefile (pagefile.sys) every time the system shuts down.
    """
    print("\n[+] ENFORCING PAGEFILE OBLITERATION POLICY (pagefile.sys)...")
    try:
        cmd = [
            "REG", "ADD",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
            "/v", "ClearPageFileAtShutdown", "/t", "REG_DWORD", "/d", "1", "/f"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print("    [>] Registry updated: Windows will securely wipe the Pagefile upon next reboot.")
        else:
            print(f"    [X] Failed to update Registry. Run as Administrator! {res.stderr}")
    except Exception as e:
        print(f"    [X] Exception modifying Registry: {e}")


def main():
    if sys.platform != "win32":
        print("[X] ERROR: This system purge utility is designed exclusively for Windows.")
        sys.exit(1)
        
    print("=" * 65)
    print("  VIPER EXTENSION: DEEP SYSTEM MEMORY PURGE MODULE")
    print("=" * 65)
    print("  WARNING: This will aggressively consume system RAM to flush")
    print("  unallocated pages, which may cause system stuttering.")
    print("  It will also modify the registry to wipe the Windows pagefile.")
    print("=" * 65)
    
    confirm = input("\nType 'PURGE' to initiate deep memory sanitization: ")
    if confirm.strip() != "PURGE":
        print("Operation cancelled.")
        sys.exit(0)
        
    destroy_hibernation()
    purge_physical_ram()
    enforce_pagefile_purge()
    
    print("\n=" * 65)
    print("  [+] SYSTEM PURGE COMPLETED SUCCESSFULLY.")
    print("  IMPORTANT: You must REBOOT the PC to fully wipe the Pagefile.")
    print("=" * 65)


if __name__ == "__main__":
    main()
