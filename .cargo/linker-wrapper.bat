@echo off
setlocal enabledelayedexpansion
for /f "usebackq delims=" %%i in (`rustc --print sysroot`) do set SYSROOT=%%i
if not defined SYSROOT (
  echo Failed to determine Rust sysroot via `rustc --print sysroot`.>&2
  exit /b 1
)
set TOOLCHAIN_LIB=%SYSROOT%\lib\rustlib\x86_64-pc-windows-msvc\lib
if not exist "%TOOLCHAIN_LIB%" (
  echo Rust Windows target libraries not found at "%TOOLCHAIN_LIB%".>&2
  echo Please ensure the `x86_64-pc-windows-msvc` target is installed.>&2
  exit /b 1
)
set LLD=%SYSROOT%\bin\rust-lld.exe
if not exist "%LLD%" (
  set LLD=%SYSROOT%\lib\rustlib\x86_64-pc-windows-msvc\bin\lld-link.exe
)
if not exist "%LLD%" (
  echo Unable to locate `rust-lld.exe` inside the Rust toolchain.>&2
  exit /b 1
)
"%LLD%" /LIBPATH:"%TOOLCHAIN_LIB%" %*
exit /b %ERRORLEVEL%
