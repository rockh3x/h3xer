@echo off
REM H3XER Build Script for Windows
REM Requires: CUDA Toolkit 12.x, Visual Studio 2019+, CMake 3.18+

echo.
echo ========================================
echo   H3XER - RAR5 Password Recovery Tool
echo   Windows Build Script
echo ========================================
echo.

REM Check for CUDA
where nvcc >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] CUDA Toolkit not found. Please install CUDA 12.x
    exit /b 1
)

REM Display CUDA version
echo [*] CUDA Compiler:
nvcc --version | findstr "release"
echo.

REM Create build directory
if not exist build mkdir build
cd build

REM Configure with CMake
echo [*] Configuring with CMake...
cmake .. -G "Visual Studio 17 2022" -A x64
if %ERRORLEVEL% neq 0 (
    echo [ERROR] CMake configuration failed
    cd ..
    exit /b 1
)

REM Build
echo.
echo [*] Building Release configuration...
cmake --build . --config Release
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed
    cd ..
    exit /b 1
)

cd ..

echo.
echo ========================================
echo   Build completed successfully!
echo   Binary: build\Release\h3xer.exe
echo ========================================
echo.

REM Quick test
echo [*] Testing binary...
if exist build\Release\h3xer.exe (
    build\Release\h3xer.exe -h
)
