@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Find DeepSeek Harness on Windows without hard-coded user names.
rem Optional override: set DEEPSEEK_HARNESS_PATH=C:\custom\DeepSeek Harness

set "FOUND_EXE="
set "OVERRIDE=%DEEPSEEK_HARNESS_PATH%"
if defined OVERRIDE (
  if exist "%OVERRIDE%\DeepSeek Harness.exe" set "FOUND_EXE=%OVERRIDE%\DeepSeek Harness.exe"
  if not defined FOUND_EXE if exist "%OVERRIDE%" for %%O in ("%OVERRIDE%") do if /I "%%~xO"==".exe" set "FOUND_EXE=%%~fO"
)

if not defined FOUND_EXE call :check "%LOCALAPPDATA%\Programs\DeepSeek Harness\DeepSeek Harness.exe"
if not defined FOUND_EXE call :check "%ProgramFiles%\DeepSeek Harness\DeepSeek Harness.exe"
if not defined FOUND_EXE call :check "%ProgramFiles(x86)%\DeepSeek Harness\DeepSeek Harness.exe"
if not defined FOUND_EXE call :check "%LOCALAPPDATA%\DeepSeek Harness\DeepSeek Harness.exe"
if not defined FOUND_EXE call :check "%USERPROFILE%\scoop\apps\deepseek-harness\current\DeepSeek Harness.exe"
if not defined FOUND_EXE call :check "%USERPROFILE%\scoop\apps\deepseek-harness\current\DeepSeek-Harness.exe"

if not defined FOUND_EXE for /f "delims=" %%P in ('where "DeepSeek Harness.exe" 2^>nul') do if not defined FOUND_EXE set "FOUND_EXE=%%~fP"
if not defined FOUND_EXE for /f "delims=" %%P in ('where deepseek-harness.exe 2^>nul') do if not defined FOUND_EXE set "FOUND_EXE=%%~fP"

if not defined FOUND_EXE (
  echo DeepSeek Harness installation not found.
  exit /b 1
)

for %%F in ("%FOUND_EXE%") do set "FOUND_EXE=%%~fF"
for %%D in ("%FOUND_EXE%") do set "FOUND_DIR=%%~dpD"
if "%FOUND_DIR:~-1%"=="\" set "FOUND_DIR=%FOUND_DIR:~0,-1%"

echo %FOUND_DIR%
exit /b 0

:check
if exist "%~1" set "FOUND_EXE=%~1"
exit /b 0
