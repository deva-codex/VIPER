@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul

:: ==========================================
:: VIPER CLI Menu Launcher
:: ==========================================
title VIPER - Control Center
color 0F

:: UAC Escalation
net session >nul 2>&1
if %errorLevel% == 0 (
    goto gotAdmin
) else (
    echo [INFO] Requesting Administrative Privileges for Advanced Features...
    goto UACPrompt
)

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "cmd.exe", "/k ""%~s0""", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

:: Ensure Python is available
python --version >nul 2>&1
if !errorlevel! NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo Please install Python and check the "Add Python to PATH" box before using.
    pause
    exit /b
)

:: --- COOL LOADING SEQUENCE ---
cls
echo.
echo     [ INITIALIZING VIPER PROTOCOL ]
echo.
echo   Loading Cryptographic Engine...
echo   [████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒] 20%%
timeout /nobreak /t 1 >nul
cls
echo.
echo     [ INITIALIZING VIPER PROTOCOL ]
echo.
echo   Loading Cryptographic Engine...      [ OK ]
echo   Mapping Physical Drives...
echo   [████████▒▒▒▒▒▒▒▒▒▒▒▒] 40%%
timeout /nobreak /t 1 >nul
cls
echo.
echo     [ INITIALIZING VIPER PROTOCOL ]
echo.
echo   Loading Cryptographic Engine...      [ OK ]
echo   Mapping Physical Drives...           [ OK ]
echo   Securing Memory Buffer...
echo   [████████████▒▒▒▒▒▒▒▒] 60%%
timeout /nobreak /t 1 >nul
cls
echo.
echo     [ INITIALIZING VIPER PROTOCOL ]
echo.
echo   Loading Cryptographic Engine...      [ OK ]
echo   Mapping Physical Drives...           [ OK ]
echo   Securing Memory Buffer...            [ OK ]
echo   Resolving UI Components...
echo   [████████████████▒▒▒▒] 80%%
timeout /nobreak /t 1 >nul
cls
echo.
echo     [ INITIALIZING VIPER PROTOCOL ]
echo.
echo   Loading Cryptographic Engine...      [ OK ]
echo   Mapping Physical Drives...           [ OK ]
echo   Securing Memory Buffer...            [ OK ]
echo   Resolving UI Components...           [ OK ]
echo   [████████████████████] 100%%
echo.
echo.
ping 127.0.0.1 -n 2 >nul
cls

:: --- RAPID BLINKING "SYSTEM READY" ANIMATION ---
for /l %%x in (1, 1, 3) do (
    cls
    echo.
    echo.
    echo.
    echo.
    echo.
    echo.
    echo.
    echo.
    echo.
    echo.
    echo                       [ S Y S T E M   R E A D Y ]
    ping 127.0.0.1 -n 2 >nul
    cls
    ping 127.0.0.1 -n 2 >nul
)


:MENU
color 0F
cls
echo.
echo.
echo           ____    ____  ____  ____   ________  _______     
echo          ^|_   \  /   _^|^|_  _^|^|_  _^| ^|_   __  ^|^|_   __ \    
echo            \   \/   /    ^| ^|    ^| ^|    ^| ^|_ \_^|  ^| ^|__) ^|   
echo             \      /     ^| ^|    ^| ^|    ^|  _^| _   ^|  __ /    
echo              \    /     _^| ^|_  _^| ^|_  _^| ^|__/ ^| _^| ^|  \ \_  
echo               \__/     ^|_____^|^|_____^|^|________^|^|____^| ^|___^| 
echo.
echo.
echo          ─────────────────────────────────────────────────────
echo               MILITARY-GRADE DATA SANITIZATION UTILITY
echo          ─────────────────────────────────────────────────────
echo.
echo.
echo           :: STANDARD OPERATIONS
echo.
echo              [ 1 ]  Wipe a File              - GUI, Parallel Processing
echo              [ 2 ]  Wipe a Folder            - GUI, Recursive, Parallel
echo              [ 3 ]  Wipe Free Space          - Wipe Drive Slack ^& MFT
echo              [ 4 ]  DoD 5220.22-M Standard   - File/Folder Targeted Wipe
echo.
echo.
echo           :: ENTERPRISE RAW DISK (DANGEROUS)
echo.
echo              [ 5 ]  Hardware Secure Erase    - For SSDs ^& NVMe
echo              [ 6 ]  Physical Block Overwrite - For Raw HDD Sectors
echo.
echo.
echo           :: SYSTEM
echo.
echo              [ 8 ]  System Memory Purge      - RAM ^& Pagefile Wipe
echo              [ 9 ]  Build Bootable VIPER OS  - Requires ADK (.ISO)
echo              [ 0 ]  EXIT COMPONENT
echo.
echo.
echo          ─────────────────────────────────────────────────────
echo.
set /p opt="              COMMAND REQUIRED [0-9] > "

if "%opt%"=="1" goto FILE
if "%opt%"=="2" goto FOLDER
if "%opt%"=="3" goto FREE
if "%opt%"=="4" goto DOD
if "%opt%"=="5" goto HDERASE
if "%opt%"=="6" goto PHYSDISK
if "%opt%"=="8" goto SYSPURGE
if "%opt%"=="9" goto BOOTBUILD
if "%opt%"=="0" exit

goto MENU

:FILE
cls
echo.
echo.
echo          [ ACTION: SECURE FILE WIPE ]
echo          ──────────────────────────────
echo.
python viper.py --gui-file --verbose --parallel
echo.
pause
goto MENU

:FOLDER
cls
echo.
echo.
echo          [ ACTION: RECURSIVE DIRECTORY OBLITERATION ]
echo          ──────────────────────────────────────────────
echo.
python viper.py --gui-folder --verbose --recursive --force --parallel
echo.
pause
goto MENU

:FREE
cls
echo.
echo.
echo          [ ACTION: FREE SPACE ^& MFT SLACK WIPING ]
echo          ───────────────────────────────────────────
echo.
set /p drv="             Enter Drive Letter to Wipe (e.g. C:\) > "
if "!drv!"=="" goto MENU
python viper.py --wipe-free-space !drv! --verbose
echo.
pause
goto MENU

:DOD
cls
echo.
echo.
echo          [ ACTION: DoD 5220.22-M STANDARD WIPE ]
echo          ─────────────────────────────────────────
echo.
python viper.py --standard dod --verbose --parallel
echo.
pause
goto MENU

:HDERASE
cls
echo.
echo.
echo          [ CRITICAL ACTION: HARDWARE CRYPTOGRAPHIC ERASE ]
echo          ───────────────────────────────────────────────────
echo.
echo          WARNING: This will instantly annihilate the solid state drive.
echo.
set /p dnum="             Target Physical Disk Number (e.g. 1, 2) > "
if "!dnum!"=="" goto MENU
python viper.py --hardware-erase !dnum!
echo.
pause
goto MENU

:SYSPURGE
cls
echo.
echo.
echo          [ SYSTEM ACTION: DEEP MEMORY PURGE ]
echo          ───────────────────────────────────────
echo.
python viper_system_purge.py
echo.
pause
goto MENU

:BOOTBUILD
cls
echo.
echo.
echo          [ SYSTEM ACTION: WINPE ISO BUILDER ]
echo          ───────────────────────────────────────
echo.
python build_winpe_viper.py
echo.
pause
goto MENU

:PHYSDISK
cls
echo.
echo.
echo          [ CRITICAL ACTION: PHYSICAL DRIVE OVERWRITE ]
echo          ───────────────────────────────────────────────
echo.
echo          WARNING: This raw block format bypasses all partitions.
echo.
set /p pnum="             Target Physical Disk Number (e.g. 1, 2) > "
if "!pnum!"=="" goto MENU
python viper.py --physical-drive !pnum! --verbose
echo.
pause
goto MENU
