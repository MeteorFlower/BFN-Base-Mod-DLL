@echo off
REM ===========================================================================
REM  BFN Base Mod - step 3: delete the local save
REM
REM  What this does:
REM    1. Finds your Plants vs. Zombies: Battle for Neighborville folder
REM    2. Deletes autooffline_save.json
REM
REM  The mod keeps a local record of your loadout - which of the five skin
REM  parts (main set, hat, glasses, shoes, mouth) and which perks you have
REM  equipped - for each of the three loadout slots, and puts them back on every
REM  launch. That record lives in autooffline_save.json next to RtWorkQ.dll.
REM
REM  It is a record of what is equipped, not of what you own. Unlocks, items and
REM  progress are not stored and are not touched by this script.
REM
REM  Deleting the file makes the next launch start with an empty record, so
REM  whatever is equipped then is captured again from scratch.
REM
REM  Nothing else is touched: the mod, the game files and the log stay as they
REM  are. Run 1-disable-eaac.bat to remove the mod itself.
REM
REM  The script asks for administrator rights because it deletes a file inside
REM  the game folder.
REM ===========================================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title BFN Base Mod - clear the local save

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
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '\"%~1\"' -Verb RunAs"
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

set "G="
set "SAVENAME=autooffline_save.json"

echo ============================================================
echo   BFN Base Mod - step 3
echo   CLEAR the local save
echo ============================================================
echo.

REM ---- locate the game -----------------------------------------------------
call :detect "%~1"
if not defined G (
  echo [X] Could not find Plants vs. Zombies: Battle for Neighborville.
  echo.
  echo     You can tell this script where it is - either:
  echo       a^) drag the game folder onto this .bat file, or
  echo       b^) run it from a command prompt:  3-clear-save.bat "D:\path\to\game"
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

set "SAVE=%G%\%SAVENAME%"

REM ---- the game must be closed (the save is written while it runs) --------
call :assertGameClosed
if errorlevel 1 exit /b 1

if not exist "%SAVE%" (
  echo [i] There is no local save. Nothing to delete.
  echo.
  pause
  exit /b 0
)

echo ------------------------------------------------------------
echo  About to delete
echo    %SAVE%
echo ------------------------------------------------------------
echo  Your saved loadout for all three slots will be forgotten.
echo  This only records which skins and perks are equipped: nothing you own,
echo  nothing you unlocked, and no progress is stored in this file.
echo  The next launch will capture whatever is equipped at that moment.
echo.
set "ANSWER="
set /p "ANSWER=Delete it? [y/N] "
if /i not "%ANSWER%"=="y" (
  echo.
  echo [i] Cancelled. Nothing was changed.
  echo.
  pause
  exit /b 0
)

del /f /q "%SAVE%" >nul 2>&1
if exist "%SAVE%" (
  echo [X] Could not delete the save file.
  echo     Close the game and the EA app, then retry.
  pause
  exit /b 1
)
echo [OK] Local save deleted.

if exist "%SAVE%.tmp" del /f /q "%SAVE%.tmp" >nul 2>&1

echo.
echo ============================================================
echo   Done. The next launch starts with an empty save.
echo ============================================================
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
  echo     (The mod writes the save while the game is running.^)
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
    for /f "usebackq tokens=* delims=" %%P in (`findstr /i /c:"\"path\"" "!STEAM!\steamapps\libraryfolders.vdf" 2^>nul`) do (
      if not defined G (
        set "LIB=%%P"
        set LIB=!LIB:*"path"=!
        set LIB=!LIB:"=!
        for /f "tokens=*" %%Q in ("!LIB!") do set "LIB=%%~Q"
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
    for /f "tokens=3,*" %%A in ('reg query %%K /v "Install Dir" 2^>nul') do set "ED=%%B"
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
