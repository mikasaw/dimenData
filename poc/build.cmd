@echo off
rem Build M1 POC with MSVC (VS 18 Insiders first, then vswhere fallback)
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
cl /nologo /EHsc /std:c++17 /utf-8 /W3 /O2 /MT poc_main.cpp poc_smbios.cpp poc_wmi.cpp poc_registry.cpp poc_native.cpp /Fe:poc_hwfp.exe /link wbemuuid.lib bcrypt.lib tbs.lib iphlpapi.lib ole32.lib oleaut32.lib advapi32.lib
