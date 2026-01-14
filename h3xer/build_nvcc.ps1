# H3XER Build for Windows (without CMake)
# Requires: CUDA Toolkit with nvcc in PATH

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================"
Write-Host "  H3XER Build Script (Direct NVCC)"
Write-Host "========================================"
Write-Host ""

# Check for nvcc
$nvcc = Get-Command nvcc -ErrorAction SilentlyContinue
if (-not $nvcc) {
    Write-Host "[ERROR] nvcc not found. Please install CUDA Toolkit and add to PATH" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Using: $($nvcc.Source)"
nvcc --version | Select-String "release"
Write-Host ""

# Create build directory
if (-not (Test-Path "build")) {
    New-Item -ItemType Directory -Path "build" | Out-Null
}

# Compiler flags
$ARCH = "-arch=sm_86"  # RTX 30xx/40xx
$FLAGS = "-O3 --use_fast_math $ARCH -std=c++17 --expt-relaxed-constexpr"
$INCLUDE = "-I./include"

Write-Host "[*] Building h3xer.exe..."
$cmd = "nvcc $FLAGS $INCLUDE -o build/h3xer.exe src/main.cu"
Write-Host "    $cmd"
Invoke-Expression $cmd

Write-Host "[*] Building h3xer_test.exe..."
$cmd = "nvcc $FLAGS $INCLUDE -o build/h3xer_test.exe src/test_crypto.cu"
Invoke-Expression $cmd

Write-Host "[*] Building h3xer_extract.exe..."
$cmd = "cl /O2 /EHsc /std:c++17 /I./include /Fe:build/h3xer_extract.exe src/h3xer_extract.cpp"
Invoke-Expression $cmd 2>$null
if (-not $?) {
    # Try with g++ if cl fails
    $cmd = "g++ -O3 -std=c++17 -I./include -o build/h3xer_extract.exe src/h3xer_extract.cpp"
    Invoke-Expression $cmd
}

Write-Host ""
Write-Host "========================================"
Write-Host "  Build Complete!"
Write-Host "========================================"
Write-Host ""
Write-Host "Binaries in ./build/"
Write-Host "  - h3xer.exe       (main cracker)"
Write-Host "  - h3xer_test.exe  (crypto tests)"  
Write-Host "  - h3xer_extract.exe (hash extractor)"
Write-Host ""
Write-Host "Run: .\build\h3xer.exe -b  (benchmark)"
