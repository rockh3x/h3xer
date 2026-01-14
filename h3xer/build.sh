#!/bin/bash
# H3XER Build Script for Linux
# Requires: CUDA Toolkit 12.x, GCC 9+, CMake 3.18+

set -e

echo ""
echo "========================================"
echo "  H3XER - RAR5 Password Recovery Tool"
echo "  Linux Build Script"
echo "========================================"
echo ""

# Check for CUDA
if ! command -v nvcc &> /dev/null; then
    echo "[ERROR] CUDA Toolkit not found. Please install CUDA 12.x"
    exit 1
fi

echo "[*] CUDA Compiler:"
nvcc --version | grep release
echo ""

# Create build directory
mkdir -p build
cd build

# Configure with CMake
echo "[*] Configuring with CMake..."
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
echo ""
echo "[*] Building..."
make -j$(nproc)

cd ..

echo ""
echo "========================================"
echo "  Build completed successfully!"
echo "  Binary: build/h3xer"
echo "========================================"
echo ""

# Quick test
echo "[*] Testing binary..."
if [ -f build/h3xer ]; then
    ./build/h3xer -h
fi
