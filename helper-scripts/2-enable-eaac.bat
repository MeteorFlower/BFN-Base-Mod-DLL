@echo off
REM ===========================================================================
REM  BFN Base Mod - step 2: re-enable EAAC and remove the mod's files
REM
REM  What this does:
REM    1. Finds your Plants vs. Zombies: Battle for Neighborville folder
REM    2. Renames EAAntiCheat.GameServiceLauncher.exe.bak -> .exe  (EAAC back on)
REM    3. Removes RtWorkQ.dll - but ONLY if it is byte-identical to the copy
REM       shipped next to this script. Anything else is moved to stale\ instead
REM       of being deleted, so nothing of yours is ever lost.
REM    4. Removes CryptBase.dll (a Frosty Mod Manager leftover that EAAC dislikes)
REM
REM  After this you are back to a clean, online-capable install:
REM  Rux shop and online play work again.
REM
REM  The script asks for administrator rights because it renames and deletes
REM  files inside the game folder.
REM ===========================================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title BFN Base Mod - enable EAAC

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
echo   BFN Base Mod - step 2
echo   ENABLE EAAC  +  remove RtWorkQ.dll / CryptBase.dll
echo ============================================================
echo.

REM ---- locate the game -----------------------------------------------------
call :detect "%~1"
if not defined G (
  echo [X] Could not find Plants vs. Zombies: Battle for Neighborville.
  echo.
  echo     You can tell this script where it is - either:
  echo       a^) drag the game folder onto this .bat file, or
  echo       b^) run it from a command prompt:  2-enable-eaac.bat "D:\path\to\game"
  echo.
  echo     The folder is the one that contains PVZBattleforNeighborville.exe.
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
set "CB=%G%\CryptBase.dll"

REM ---- the game must be closed (otherwise the files are locked) -----------
call :assertGameClosed
if errorlevel 1 exit /b 1

echo ------------------------------------------------------------
echo  Step 1/3 : re-enable EAAC
echo ------------------------------------------------------------
if not exist "%EXE%" goto :NO_EXE

echo [i] The EAAC launcher is already in place - EAAC is enabled.
if exist "%BAK%" (
  echo [i] A leftover .bak is also present. Removing it.
  del /f /q "%BAK%"
  if exist "%BAK%" echo [!] Could not delete the .bak. Close the game and retry.
)
goto :RTW

:NO_EXE
if not exist "%BAK%" (
  echo [!] Neither the EAAC launcher nor its .bak exists.
  echo     This does not look like a normal install. Aborting.
  pause
  exit /b 1
)
ren "%BAK%" "EAAntiCheat.GameServiceLauncher.exe"
if errorlevel 1 (
  echo [!] Rename FAILED. Close the game and the EA app, then retry.
  pause
  exit /b 1
)
echo [OK] EAAC enabled - online play and the Rux shop work again.

:RTW
echo.
echo ------------------------------------------------------------
echo  Step 2/3 : remove RtWorkQ.dll
echo ------------------------------------------------------------
if not exist "%DST%" (
  echo [i] RtWorkQ.dll is not present - nothing to remove.
  goto :CB
)

if not exist "%SRC%" (
  echo [!] RtWorkQ.dll next to this script is missing, so we cannot verify
  echo     whether the one in the game folder is ours.
  echo     Moving it to stale\ instead of deleting it.
  if not exist "%OLD%" mkdir "%OLD%"
  move /y "%DST%" "%OLD%\RtWorkQ.dll.bak" >nul
  if exist "%DST%" (
    echo [!] Could not move it aside. Close the game and retry.
    pause
    exit /b 1
  )
  echo [OK] Moved to stale\.
  goto :CB
)

call :cmp "%DST%" "%SRC%"
if "!MATCH!"=="1" (
  del /f /q "%DST%"
  if exist "%DST%" (
    echo [!] Could not delete RtWorkQ.dll. Close the game and retry.
    pause
    exit /b 1
  )
  echo [OK] RtWorkQ.dll removed.
) else (
  echo [!] That RtWorkQ.dll is NOT ours - leaving it alone.
  echo     Moving it to stale\ instead of deleting it.
  if not exist "%OLD%" mkdir "%OLD%"
  move /y "%DST%" "%OLD%\RtWorkQ.dll.bak" >nul
  if exist "%DST%" (
    echo [!] Could not move it aside. Close the game and retry.
    pause
    exit /b 1
  )
  echo [OK] Moved to stale\.
)

:CB
echo.
echo ------------------------------------------------------------
echo  Step 3/3 : remove CryptBase.dll
echo ------------------------------------------------------------
if not exist "%CB%" (
  echo [i] CryptBase.dll is not present - nothing to remove.
  goto :DONE
)

del /f /q "%CB%"
if exist "%CB%" (
  echo [!] Could not delete CryptBase.dll. Close the game and retry.
  pause
  exit /b 1
)
echo [OK] CryptBase.dll removed.
echo     (Frosty Mod Manager re-adds it the next time it launches the game.)

:DONE
echo.
echo ============================================================
echo   Done. EAAC is ON and no mod files are left in the game folder.
echo ============================================================
echo.
echo   Online play and the Rux shop are available again.
echo   Run 1-disable-eaac.bat whenever you want to use the Base Mod.
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
