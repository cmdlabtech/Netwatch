@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
echo Building netwatch for Windows...

pip install pyinstaller anthropic flask pillow pefile --quiet

echo Generating icon.ico...
python make_icon.py
if errorlevel 1 ( echo ERROR: icon generation failed & exit /b 1 )

rem ─────────────────────────────────────────────────────────────────────
rem Locate Wireshark install (source of tshark.exe + DLLs to bundle).
rem ─────────────────────────────────────────────────────────────────────
set "WIRESHARK_DIR="
if exist "%ProgramFiles%\Wireshark\tshark.exe"      set "WIRESHARK_DIR=%ProgramFiles%\Wireshark"
if exist "%ProgramFiles(x86)%\Wireshark\tshark.exe" set "WIRESHARK_DIR=%ProgramFiles(x86)%\Wireshark"
if not defined WIRESHARK_DIR (
    echo ERROR: Wireshark not found in Program Files. Install Wireshark on the build machine
    echo        from https://www.wireshark.org/ — tshark.exe and its DLLs will be bundled.
    exit /b 1
)
echo Using Wireshark from: %WIRESHARK_DIR%

rem ─────────────────────────────────────────────────────────────────────
rem Locate Npcap redistributable installer.
rem Provide it as tools\npcap-installer.exe (download from https://npcap.com/).
rem ─────────────────────────────────────────────────────────────────────
set "NPCAP_INSTALLER=%~dp0tools\npcap-installer.exe"
if not exist "%NPCAP_INSTALLER%" (
    echo ERROR: Npcap installer not found at tools\npcap-installer.exe
    echo        Download the redistributable from https://npcap.com/#download
    echo        and save it to that path before rebuilding.
    exit /b 1
)
echo Using Npcap installer: %NPCAP_INSTALLER%

rem ─────────────────────────────────────────────────────────────────────
rem Build in a local temp dir (Parallels shared drives block PE resource patching)
rem ─────────────────────────────────────────────────────────────────────
set BUILD_DIR=%TEMP%\netwatch_build
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%"
copy /y netwatch.py "%BUILD_DIR%\netwatch.py" >nul
copy /y icon.ico    "%BUILD_DIR%\icon.ico"    >nul

rem Stage bundled tools/wireshark and tools/npcap-installer.exe under the build dir
mkdir "%BUILD_DIR%\tools"
mkdir "%BUILD_DIR%\tools\wireshark"
echo Copying Wireshark binaries...
xcopy /e /i /q /y "%WIRESHARK_DIR%\*" "%BUILD_DIR%\tools\wireshark\" >nul

rem ─────────────────────────────────────────────────────────────────────
rem Trim the Wireshark dir down to what tshark actually needs.
rem The GUI (Wireshark.exe + Qt) and translations dominate the size; netwatch
rem only uses tshark/dumpcap/mergecap, so the rest is dead weight that just
rem slows the PyInstaller --onefile bootloader's startup extraction.
rem ─────────────────────────────────────────────────────────────────────
echo Trimming Wireshark dir (removing GUI + translations + help)...
del /q "%BUILD_DIR%\tools\wireshark\Wireshark.exe"          >nul 2>&1
del /q "%BUILD_DIR%\tools\wireshark\Logray.exe"             >nul 2>&1
del /q "%BUILD_DIR%\tools\wireshark\stratoshark.exe"        >nul 2>&1
del /q "%BUILD_DIR%\tools\wireshark\Qt6*.dll"               >nul 2>&1
del /q "%BUILD_DIR%\tools\wireshark\opus.dll"               >nul 2>&1
del /q "%BUILD_DIR%\tools\wireshark\*.html"                 >nul 2>&1
del /q "%BUILD_DIR%\tools\wireshark\*.pdf"                  >nul 2>&1
rmdir /s /q "%BUILD_DIR%\tools\wireshark\iconengines"       >nul 2>&1
rmdir /s /q "%BUILD_DIR%\tools\wireshark\imageformats"      >nul 2>&1
rmdir /s /q "%BUILD_DIR%\tools\wireshark\platforms"         >nul 2>&1
rmdir /s /q "%BUILD_DIR%\tools\wireshark\styles"            >nul 2>&1
rmdir /s /q "%BUILD_DIR%\tools\wireshark\translations"      >nul 2>&1
rmdir /s /q "%BUILD_DIR%\tools\wireshark\help"              >nul 2>&1
rmdir /s /q "%BUILD_DIR%\tools\wireshark\extcap"            >nul 2>&1
rem Show the resulting size for sanity
for /f "tokens=3" %%A in ('dir /s /-c "%BUILD_DIR%\tools\wireshark" ^| find "File(s)"') do set WS_SIZE=%%A
echo Trimmed Wireshark bundle size: %WS_SIZE% bytes

copy /y "%NPCAP_INSTALLER%" "%BUILD_DIR%\tools\npcap-installer.exe" >nul

pushd "%BUILD_DIR%"
python -m PyInstaller --onefile --name netwatch --icon icon.ico --clean ^
    --add-data "tools\wireshark;tools\wireshark" ^
    --add-data "tools\npcap-installer.exe;tools" ^
    netwatch.py
popd

rem stamp_icon.py is overlay-aware: it snapshots the PyInstaller PKG archive
rem before calling BeginUpdateResource/EndUpdateResource and re-appends it
rem after, so we get a properly multi-size icon AND a working bundled exe.
echo Stamping multi-size icon (overlay-preserving)...
python stamp_icon.py "%BUILD_DIR%\dist\netwatch.exe" "%BUILD_DIR%\icon.ico"
if errorlevel 1 ( echo ERROR: icon stamp failed & exit /b 1 )

rem Copy result back
if not exist "%~dp0dist" mkdir "%~dp0dist"
copy /y "%BUILD_DIR%\dist\netwatch.exe" "%~dp0dist\netwatch.exe" >nul

rem Flush Explorer icon cache so the new icon shows immediately
echo Refreshing icon cache...
taskkill /f /im explorer.exe >nul 2>&1
del /a /f /q "%localappdata%\IconCache.db" >nul 2>&1
del /a /f /q "%localappdata%\Microsoft\Windows\Explorer\iconcache_*.db" >nul 2>&1
start "" explorer.exe

echo.
echo Done -^> dist\netwatch.exe
endlocal
