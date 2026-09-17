@echo off
rem ============================================================
rem dimenData build script (MSVC, zero third-party dependency)
rem usage: build.cmd             -> build and run all unit tests
rem        build.cmd app         -> build hwfp.exe
rem        build.cmd smoke       -> build and run smoke (merged collect)
rem        build.cmd fuzz [N] [seed] -> build and run deterministic fuzz (default 200000 rounds)
rem        build.cmd dll         -> build hwfp.dll (C ABI integration library)
rem        build.cmd dlltest     -> build hwfp.dll and run integration consumer
rem        build.cmd clean       -> remove build dir and stray .obj files
rem note: no CMake on this machine; cl invoked directly.
rem       keep this file ASCII-only (cmd parses it under GBK).
rem       source paths use FORWARD slashes on purpose: the editor
rem       toolchain corrupts "\f","\r" sequences in batch files.
rem ============================================================
setlocal
set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
  for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
)
if not exist "%VCVARS%" (
  echo [build] vcvars64.bat not found
  exit /b 1
)
call "%VCVARS%" >nul 2>&1
where cl >nul 2>&1 || (
  echo [build] cl.exe not in PATH
  exit /b 1
)
cd /d "%~dp0"
if not exist build mkdir build

set "CFLAGS=/nologo /EHsc /std:c++17 /utf-8 /W3 /O2 /MT /Isrc /I."
set "SOURCES=src/core/field.cpp src/core/channel_registry.cpp src/core/merger.cpp src/core/collector_manager.cpp src/core/collect_runner.cpp src/core/json.cpp src/core/config.cpp src/fingerprint/sha256.cpp src/fingerprint/fingerprint_engine.cpp src/license/crypto.cpp src/license/license.cpp src/channels/smbios_parser.cpp src/channels/smbios_channel.cpp src/channels/registry_parser.cpp src/channels/registry_channel.cpp src/channels/native_util.cpp src/channels/native_channel.cpp src/channels/wmi_channel.cpp src/channels/wmi_util.cpp"
set "LINKLIBS=wbemuuid.lib bcrypt.lib tbs.lib iphlpapi.lib ole32.lib oleaut32.lib advapi32.lib"

if "%~1"=="dll" (
  if not exist build\dll mkdir build\dll
  cl %CFLAGS% /LD /Fo:build\dll\ %SOURCES% src/cli/report.cpp src/dll/hwfp_dll.cpp /Fe:build/hwfp.dll /link %LINKLIBS%
  if errorlevel 1 exit /b 1
  echo [build] build/hwfp.dll OK
  exit /b 0
)

if "%~1"=="dlltest" goto build_dlltest

if "%~1"=="clean" (
  if exist build rmdir /s /q build
  del /q *.obj 2>nul
  echo [build] cleaned
  exit /b 0
)

rem fuzz/smoke run a built exe and must propagate its exit code. That has to
rem happen at top level (outside parens): %errorlevel% inside a ( ) block
rem expands at parse time and would swallow the exe's failure code.
if "%~1"=="fuzz" goto build_fuzz
if "%~1"=="smoke" goto build_smoke

if "%~1"=="app" (
  cl %CFLAGS% /Fo:build\ %SOURCES% src/cli/report.cpp src/cli/main.cpp /Fe:build/hwfp.exe /link %LINKLIBS%
  if errorlevel 1 exit /b 1
  echo [build] build/hwfp.exe OK
  exit /b 0
)

rem ---- unit tests ----
cl %CFLAGS% /Fo:build\ %SOURCES% tests/test_main.cpp tests/test_core.cpp tests/test_smbios.cpp tests/test_registry.cpp tests/test_native.cpp tests/test_wmi.cpp tests/test_merger.cpp tests/test_fingerprint.cpp tests/test_config_json.cpp tests/test_license.cpp src/cli/report.cpp /Fe:build/hwfp_test.exe
if errorlevel 1 exit /b 1

build\hwfp_test.exe
exit /b %errorlevel%

:build_dlltest
rem always rebuild the dll: a stale hwfp.dll silently fails new export contracts
call :build_dll_only
if errorlevel 1 exit /b 1
cl %CFLAGS% /Fo:build\ tools/dll_consumer.cpp build/hwfp.lib /Fe:build/hwfp_dll_consumer.exe
if errorlevel 1 exit /b 1
build\hwfp_dll_consumer.exe
exit /b %errorlevel%

:build_dll_only
if not exist build\dll mkdir build\dll
cl %CFLAGS% /LD /Fo:build\dll\ %SOURCES% src/cli/report.cpp src/dll/hwfp_dll.cpp /Fe:build/hwfp.dll /link %LINKLIBS%
if errorlevel 1 (
  echo [build] build/hwfp.dll FAILED
  exit /b 1
)
echo [build] build/hwfp.dll OK
exit /b 0

:build_fuzz
cl %CFLAGS% /Fo:build\ %SOURCES% src/cli/report.cpp tools/fuzz_main.cpp /Fe:build/hwfp_fuzz.exe
if errorlevel 1 exit /b 1
build\hwfp_fuzz.exe %~2 %~3
exit /b %errorlevel%

:build_smoke
cl %CFLAGS% /Fo:build\ %SOURCES% tools/smoke_main.cpp /Fe:build/hwfp_smoke.exe
if errorlevel 1 exit /b 1
build\hwfp_smoke.exe
exit /b %errorlevel%
