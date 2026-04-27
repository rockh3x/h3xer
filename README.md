Disclaimer: This tool is for educational purposes and password recovery only. The author is not responsible for any illegal use of this tool. Do not use this tool on files you do not own or do not have permission to access.


# H3XER - High-Performance RAR5 Password Recovery

```
  ██╗  ██╗██████╗ ██╗  ██╗███████╗██████╗ 
  ██║  ██║╚════██╗╚██╗██╔╝██╔════╝██╔══██╗
  ███████║ █████╔╝ ╚███╔╝ █████╗  ██████╔╝
  ██╔══██║ ╚═══██╗ ██╔██╗ ██╔══╝  ██╔══██╗
  ██║  ██║██████╔╝██╔╝ ██╗███████╗██║  ██║
  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

**CUDA-accelerated RAR5 password recovery for RTX 30/40/50 series.**

## Features

- 🔥 Pure CUDA (no CPU bottleneck)
- 🎭 Mask / Dictionary / Brute-force attacks
- 🔄 Rule engine (l33t, capitalize, etc.)
- 💾 Session save/restore
- 🔐 RAR5: PBKDF2-SHA256 (32768 iter) + AES-256

## Build

```powershell
# Windows (CMake)
.\build.bat

# Windows (direct nvcc)
.\build_nvcc.ps1

# Linux
make
```

## Usage

```bash
h3xer -f archive.rar -m "?l?l?l?l?d?d"  # Mask
h3xer -f archive.rar -d rockyou.txt      # Dictionary
h3xer -f archive.rar -i 4:6              # Brute-force
h3xer -b                                  # Benchmark
h3xer_extract archive.rar                # Extract hash
```

## Mask Charsets

| Char | Set | Count |
|------|-----|-------|
| `?l` | a-z | 26 |
| `?u` | A-Z | 26 |
| `?d` | 0-9 | 10 |
| `?a` | a-zA-Z0-9 | 62 |
| `?s` | Special | 33 |

## Performance

| GPU | Keys/sec |
|-----|----------|
| RTX 4090 | ~50K |
| RTX 4080 | ~35K |
| RTX 3090 | ~40K |

## Files

```
include/  sha256.cuh pbkdf2.cuh aes.cuh kernel.cuh
          candidate.cuh rules.cuh session.h rar5_parser.h
src/      main.cu h3xer_extract.cpp test_crypto.cu
```

## License

For authorized password recovery only.

## Research Citation

@misc{patel2026h3xer,
  author       = {Patel, Vivek},
  title        = {H3XER: CUDA-Accelerated Password Recovery for Encrypted Archives},
  year         = 2026,
  publisher    = {Zenodo},
  doi          = {(https://doi.org/10.5281/zenodo.19814983)},
  url          = {https://doi.org/10.5281/zenodo.19814983}
}
