import os
import sys
import subprocess
import shutil

ADK_PATHS = [
    r"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit",
    r"C:\Program Files (x86)\Windows Kits\11\Assessment and Deployment Kit"
]

def find_adk():
    for base_path in ADK_PATHS:
        copype_path = os.path.join(base_path, r"Windows Preinstallation Environment\copype.cmd")
        if os.path.exists(copype_path):
            return base_path
    return None

def main():
    print("=" * 65)
    print("  VIPER EXTENSION: AUTOMATED WinPE BOOTABLE ISO BUILDER")
    print("=" * 65)
    
    adk_path = find_adk()
    
    if not adk_path:
        print("[X] CRITICAL ERROR: Windows Assessment and Deployment Kit (ADK) not found.")
        print("    VIPER relies on the Microsoft ADK to compile a custom bootable OS.")
        print("\n    To use this feature, you must install:")
        print("    1. Windows ADK (Deployment Tools)")
        print("    2. Windows PE add-on for the ADK")
        print("\n    Download from: https://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install")
        sys.exit(1)
        
    print(f"[+] Detected Windows ADK at: {adk_path}")
    
    pe_env_path = os.path.join(adk_path, r"Windows Preinstallation Environment")
    copype_cmd = os.path.join(pe_env_path, "copype.cmd")
    makemedia_cmd = os.path.join(pe_env_path, "MakeWinPEMedia.cmd")
    
    work_dir = r"C:\VIPER_WinPE_Workspace"
    iso_out = r"C:\VIPER_Bootable.iso"
    
    if os.path.exists(work_dir):
        print(f"    [!] Cleaning up old workspace at {work_dir}...")
        try:
            shutil.rmtree(work_dir)
        except Exception as e:
            print(f"    [X] Failed to delete old workspace: {e}. Are you running as Administrator?")
            sys.exit(1)
            
    if os.path.exists(iso_out):
        os.remove(iso_out)
        
    print(f"\n[>] STEP 1: Copying base WinPE amd64 framework into {work_dir}...")
    res = subprocess.run(f'cmd /c "{copype_cmd} amd64 {work_dir}"', capture_output=True)
    if res.returncode != 0:
        print(f"[X] copype failed: {res.stderr}")
        sys.exit(1)
        
    # Instead of injecting Python natively (which is complex and requires portables), 
    # we inject a setup batch script to launch VIPER from the USB drive the user booted from.
    print(f"\n[>] STEP 2: Injecting VIPER auto-launch payload into startnet.cmd...")
    startnet_path = os.path.join(work_dir, r"media\windows\system32\startnet.cmd")
    try:
        with open(startnet_path, "a") as f:
            f.write("\r\n")
            f.write("echo ===========================================\r\n")
            f.write("echo    VIPER PRE-INSTALLATION ENVIRONMENT\r\n")
            f.write("echo ===========================================\r\n")
            f.write("echo Searching available drives for VIPER tools...\r\n")
            f.write("for %%I in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (\r\n")
            f.write("    if exist %%I:\\viper.py (\r\n")
            f.write("        echo Found VIPER suite on %%I:\\\r\n")
            f.write("        %%I:\r\n")
            f.write("        if exist %%I:\\python\\python.exe (\r\n")
            f.write("            %%I:\\python\\python.exe viper.py\r\n")
            f.write("        ) else (\r\n")
            f.write("            echo ERROR: Portable Python not found at %%I:\\python\\\r\n")
            f.write("        )\r\n")
            f.write("        exit /B\r\n")
            f.write("    )\r\n")
            f.write(")\r\n")
            f.write("echo VIPER drive not found. Dropping to command prompt.\r\n")
    except Exception as e:
        print(f"[X] Failed to modify startnet.cmd: {e}")
        sys.exit(1)
        
    print(f"\n[>] STEP 3: Compiling final bootable ISO to {iso_out}...")
    res = subprocess.run(f'cmd /c "{makemedia_cmd} /ISO {work_dir} {iso_out}"', capture_output=True)
    if res.returncode == 0:
        print(f"\n[+] SUCCESS! Bootable ISO created at: {iso_out}")
        print("    To use this ISO:")
        print("    1. Flash VIPER_Bootable.iso to a USB drive using Rufus.")
        print("    2. Copy 'viper.py' and an embedded Python runtime ('python' folder) to the root of that same USB.")
        print("    3. Boot a PC from the USB. VIPER will automatically launch.")
    else:
        print(f"[X] MakeWinPEMedia failed. Are you running as Administrator?")

if __name__ == "__main__":
    main()
