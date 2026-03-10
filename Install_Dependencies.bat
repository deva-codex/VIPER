@echo off
setlocal EnableDelayedExpansion

title VIPER - Dependency Installer
color 0B

echo =========================================================
echo       VIPER UTILITY - PREREQUISITE INSTALLER
echo =========================================================
echo.
echo Checking system requirements...
echo.

:: 1. Check for Python installation
python --version >nul 2>&1
if !errorlevel! NEQ 0 (
    echo [ERROR] Python is not installed or not added to your system PATH!
    echo Please download and install Python from https://www.python.org/downloads/
    echo IMPORTANT: Make sure to check the box "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
) else (
    for /f "tokens=*" %%F in ('python --version') do set "PYVER=%%F"
    echo [+] Python detected: !PYVER!
)

:: 2. Check for pip
pip --version >nul 2>&1
if !errorlevel! NEQ 0 (
    echo [ERROR] PIP (Python Package Installer) is not installed.
    echo Please repair your Python installation and ensure pip is included.
    echo.
    pause
    exit /b 1
) else (
    echo [+] PIP is installed and active.
)

echo.
echo ---------------------------------------------------------
echo Installing required third-party Python modules...
echo ---------------------------------------------------------
echo.

:: 3. Define Requirements
set "ALL_INSTALLED=true"
set "REQUIREMENTS=cryptography psutil colorama"

:: 4. Install Requirements
for %%pkg in (%REQUIREMENTS%) do (
    pip show %%pkg >nul 2>&1
    if !errorlevel! NEQ 0 (
        set "ALL_INSTALLED=false"
        echo [*] Installing %%pkg...
        pip install %%pkg
        if !errorlevel! NEQ 0 (
            echo [!] Failed to install %%pkg! Check your internet connection.
        ) else (
            echo [+] %%pkg installed successfully!
        )
    ) else (
        echo [+] Module '%%pkg' is already installed.
    )
)

echo.
echo =========================================================
if "!ALL_INSTALLED!"=="true" (
    echo [ SUCCESS ] All prerequisites are already installed!
    echo             Your system is fully ready to use VIPER.
) else (
    echo [ SUCCESS ] Missing dependencies have been downloaded and installed!
    echo             Your system is now ready to use VIPER.
)
echo =========================================================
echo.
echo You can now safely launch "VIPER_Launcher.bat".
echo.
pause
