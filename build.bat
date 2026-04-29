@echo off
setlocal
cd /d "%~dp0"
echo Building netwatch for Windows...

pip install pyinstaller anthropic flask pillow pefile --quiet

echo Generating icon.ico...
python make_icon.py
if errorlevel 1 ( echo ERROR: icon generation failed & exit /b 1 )

rem Build in a local temp dir (Parallels shared drives block PE resource patching)
set BUILD_DIR=%TEMP%\netwatch_build
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%"
copy /y netwatch.py "%BUILD_DIR%\netwatch.py" >nul
copy /y icon.ico    "%BUILD_DIR%\icon.ico"    >nul

pushd "%BUILD_DIR%"
python -m PyInstaller --onefile --name netwatch --icon icon.ico --clean netwatch.py
popd

rem Verify the icon is actually in the exe
echo Verifying icon in exe...
python -c "import pefile, sys; pe=pefile.PE(r'%BUILD_DIR%\dist\netwatch.exe'); ids=[e.id for e in pe.DIRECTORY_ENTRY_RESOURCE.entries] if hasattr(pe,'DIRECTORY_ENTRY_RESOURCE') else []; print('RT_ICON embedded OK' if 3 in ids else 'WARNING: RT_ICON NOT FOUND - stamping manually')"

rem Stamp icon directly via Win32 API as a guaranteed fallback
python stamp_icon.py "%BUILD_DIR%\dist\netwatch.exe" "%BUILD_DIR%\icon.ico"

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
