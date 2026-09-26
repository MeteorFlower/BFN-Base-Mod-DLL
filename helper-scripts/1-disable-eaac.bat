@echo off
REM ===========================================================================
REM  BFN Base Mod - step 1: disable EAAC and install RtWorkQ.dll
REM
REM  What this does:
REM    1. Finds your Plants vs. Zombies: Battle for Neighborville folder
REM    2. Renames EAAntiCheat.GameServiceLauncher.exe -> .exe.bak  (EAAC off)
REM    3. Copies the RtWorkQ.dll shipped NEXT TO THIS SCRIPT into the game folder
REM
REM  Run 2-enable-eaac.bat to undo everything.
REM
REM  The script asks for administrator rights because it renames and copies
REM  files inside the game folder.
REM ===========================================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title BFN Base Mod - disable EAAC

REM ---- self-elevate -------------------------------------------------------
REM  NOTE: -ArgumentList must be LEFT OUT when there is no argument. Passing an
REM  empty string makes PowerShell reject the call ("The argument is null or
REM  empty"), the elevated copy never starts, and the window just vanishes.
net session >nul 2>&1
if errorlevel 1 (
  echo [*] Requesting administrator rights...
  if "%~1"=="" (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  ) else (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%~1' -Verb RunAs"
  )
  if errorlevel 1 (
    echo.
    echo [X] Could not restart with administrator rights.
    echo     Right-click this file and choose "Run as administrator".
    echo.
    pause
  )
  exit /b
)

set "SRC=%~dp0RtWorkQ.dll"
set "OLD=%~dp0stale"
set "G="

echo ============================================================
echo   BFN Base Mod - step 1
echo   DISABLE EAAC  +  install RtWorkQ.dll
echo ============================================================
echo.

REM ---- our own payload must be here ---------------------------------------
if not exist "%SRC%" (
  echo [X] RtWorkQ.dll is missing.
  echo     It must sit in the SAME folder as this .bat:
  echo         %~dp0
  echo     Make sure you extracted the whole archive, not just the .bat files.
  echo.
  pause
  exit /b 1
)

REM ---- locate the game -----------------------------------------------------
call :detect "%~1"
if not defined G (
  echo [X] Could not find Plants vs. Zombies: Battle for Neighborville.
  echo.
  echo     You can tell this script where it is - either:
  echo       a^) drag the game folder onto this .bat file, or
  echo       b^) run it from a command prompt:  1-disable-eaac.bat "D:\path\to\game"
  echo.
  echo     The folder is the one that contains PVZBattleforNeighborville.exe.
  echo     In the EA app: click the game - Manage - View Properties -
  echo     Install Location - Open Folder.
  echo.
  pause
  exit /b 1
)
echo [OK] Game folder:
echo      %G%
echo.

set "EXE=%G%\EAAntiCheat.GameServiceLauncher.exe"
set "BAK=%EXE%.bak"
set "DST=%G%\RtWorkQ.dll"

REM ---- the game must be closed (otherwise the files are locked) -----------
call :assertGameClosed
if errorlevel 1 exit /b 1

echo ------------------------------------------------------------
echo  Step 1/2 : disable EAAC
echo ------------------------------------------------------------
if not exist "%EXE%" goto :NO_EXE

if exist "%BAK%" (
  echo [i] Both the .exe and a .bak are present. Removing the stray .bak.
  del /f /q "%BAK%"
  if exist "%BAK%" (
    echo [X] Could not delete the .bak. Close the game and retry.
    pause
    exit /b 1
  )
)

ren "%EXE%" "EAAntiCheat.GameServiceLauncher.exe.bak"
if errorlevel 1 (
  echo [X] Rename FAILED. Close the game and the EA app, then retry.
  pause
  exit /b 1
)
echo [OK] EAAC disabled.
goto :RTW

:NO_EXE
if exist "%BAK%" (
  echo [i] EAAC is already disabled - nothing to do.
) else (
  echo [X] Neither the EAAC launcher nor its .bak exists.
  echo     This does not look like a normal install. Aborting.
  pause
  exit /b 1
)

:RTW
echo.
echo ------------------------------------------------------------
echo  Step 2/2 : install RtWorkQ.dll
echo ------------------------------------------------------------
if not exist "%DST%" goto :COPY

call :cmp "%DST%" "%SRC%"
if "!MATCH!"=="1" (
  echo [i] RtWorkQ.dll is already the correct one. Refreshing it.
  goto :COPY
)

echo [i] A different RtWorkQ.dll is already there.
echo     Moving it to stale\ first (nothing is deleted).
if not exist "%OLD%" mkdir "%OLD%"
move /y "%DST%" "%OLD%\RtWorkQ.dll.bak" >nul
if exist "%DST%" (
  echo [X] Could not move it aside. Close the game and retry.
  pause
  exit /b 1
)

:COPY
copy /y "%SRC%" "%DST%" >nul
if errorlevel 1 (
  echo [X] Could not install RtWorkQ.dll.
  pause
  exit /b 1
)
echo [OK] RtWorkQ.dll installed.

echo.
echo ============================================================
echo   Done. EAAC is OFF and RtWorkQ.dll is in place.
echo ============================================================
echo.
echo   Next steps:
echo     1. Install the Base Mod .fbmod with Frosty Mod Manager
echo        (if you have not already), then launch the game from Frosty.
echo     2. A log appears next to the game EXE:  autooffline_log.txt
echo.
echo   To undo: run 2-enable-eaac.bat
echo.
pause
exit /b 0


REM ===========================================================================
REM  Subroutines
REM ===========================================================================

:assertGameClosed
REM NOTE: findstr is called by its FULL PATH on purpose. If a stray find/findstr
REM from another toolchain is earlier on PATH, a bare "find" can resolve to the
REM wrong binary and the check silently always passes.
tasklist /fi "imagename eq PVZBattleforNeighborville.exe" /nh 2>nul | "%SystemRoot%\System32\findstr.exe" /i /c:"PVZBattleforNeighborville.exe" >nul
if not errorlevel 1 (
  echo [X] The game is running. Close it, then run this script again.
  echo.
  pause
  exit /b 1
)
tasklist /fi "imagename eq EAAntiCheat.GameServiceLauncher.exe" /nh 2>nul | "%SystemRoot%\System32\findstr.exe" /i /c:"EAAntiCheat" >nul
if not errorlevel 1 (
  echo [X] The EA anti-cheat launcher is running. Close the game / EA app, then retry.
  echo.
  pause
  exit /b 1
)
exit /b 0

REM ---- :detect [dragAndDropPath] -> sets G --------------------------------
:detect
set "G="

REM 1) explicit path (drag & drop onto the .bat)
if not "%~1"=="" (
  call :try "%~1"
  if defined G goto :eof
  call :try "%~1\PVZ Battle for Neighborville"
  if defined G goto :eof
)

REM 2) Steam: registered Steam path, then its libraryfolders.vdf
set "STEAM="
for /f "tokens=2,*" %%A in ('reg query "HKCU\Software\Valve\Steam" /v SteamPath 2^>nul') do set "STEAM=%%B"
if not defined STEAM for /f "tokens=2,*" %%A in ('reg query "HKLM\SOFTWARE\WOW6432Node\Valve\Steam" /v InstallPath 2^>nul') do set "STEAM=%%B"
if defined STEAM (
  set "STEAM=!STEAM:/=\!"
  call :try "!STEAM!\steamapps\common\PVZ Battle for Neighborville"
  if defined G goto :eof
  if exist "!STEAM!\steamapps\libraryfolders.vdf" (
    for /f "usebackq tokens=2 delims=	 " %%P in (`findstr /i /c:"\"path\"" "!STEAM!\steamapps\libraryfolders.vdf" 2^>nul`) do (
      if not defined G (
        set "LIB=%%~P"
        set "LIB=!LIB:\\=\!"
        call :try "!LIB!\steamapps\common\PVZ Battle for Neighborville"
      )
    )
    if defined G goto :eof
  )
)

REM 3) EA app / Origin install registry
for %%K in (
  "HKLM\SOFTWARE\WOW6432Node\Electronic Arts\EA Games\PVZ Battle for Neighborville"
  "HKLM\SOFTWARE\Electronic Arts\EA Games\PVZ Battle for Neighborville"
  "HKCU\SOFTWARE\Electronic Arts\EA Games\PVZ Battle for Neighborville"
  "HKLM\SOFTWARE\WOW6432Node\Electronic Arts\PVZ Battle for Neighborville"
  "HKLM\SOFTWARE\Electronic Arts\PVZ Battle for Neighborville"
) do (
  if not defined G (
    set "ED="
    for /f "tokens=2,*" %%A in ('reg query %%K /v "Install Dir" 2^>nul') do set "ED=%%B"
    if defined ED call :try "!ED!"
  )
)
if defined G goto :eof

REM 4) common locations on every drive letter
for %%D in (C D E F G H I) do (
  if exist "%%D:\" (
    call :try "%%D:\SteamLibrary\steamapps\common\PVZ Battle for Neighborville"
    call :try "%%D:\Steam\steamapps\common\PVZ Battle for Neighborville"
    call :try "%%D:\Games\Steam\steamapps\common\PVZ Battle for Neighborville"
    call :try "%%D:\Program Files (x86)\Steam\steamapps\common\PVZ Battle for Neighborville"
    call :try "%%D:\Program Files\Steam\steamapps\common\PVZ Battle for Neighborville"
    call :try "%%D:\Program Files (x86)\EA Games\PVZ Battle for Neighborville"
    call :try "%%D:\Program Files\EA Games\PVZ Battle for Neighborville"
    call :try "%%D:\Program Files (x86)\Electronic Arts\PVZ Battle for Neighborville"
    call :try "%%D:\Program Files\Electronic Arts\PVZ Battle for Neighborville"
    call :try "%%D:\EA Games\PVZ Battle for Neighborville"
    call :try "%%D:\Games\PVZ Battle for Neighborville"
  )
)
goto :eof

REM ---- :try <folder> -> sets G when the game EXE is inside -----------------
:try
if defined G goto :eof
if "%~1"=="" goto :eof
if exist "%~1\PVZBattleforNeighborville.exe" set "G=%~1"
goto :eof

REM ---- :cmp <a> <b> -> sets MATCH=1 when byte-identical --------------------
REM  Size first, then certutil MD5. Never "fc /b" - far too slow on big files.
:cmp
set "MATCH=0"
set "HA=" & set "HB=" & set "SA=" & set "SB="
for %%A in ("%~1") do set "SA=%%~zA"
for %%B in ("%~2") do set "SB=%%~zB"
if not "%SA%"=="%SB%" goto :eof
for /f "skip=1 delims=" %%H in ('certutil -hashfile "%~1" MD5 2^>nul') do if not defined HA set "HA=%%H"
for /f "skip=1 delims=" %%H in ('certutil -hashfile "%~2" MD5 2^>nul') do if not defined HB set "HB=%%H"
if not defined HA goto :eof
if not defined HB goto :eof
if "%HA%"=="%HB%" set "MATCH=1"
goto :eof
