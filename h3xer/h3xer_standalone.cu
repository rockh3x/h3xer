/*
 * H3XER - RAR5 Password Recovery Tool (Single-File Version)
 *
 * COMPILE: nvcc -O3 --use_fast_math -arch=sm_86 -o h3xer.exe
 * h3xer_standalone.cu RUN:     h3xer.exe -b (benchmark) h3xer.exe -m
 * "?l?l?l?l?d?d"            (mask attack) h3xer.exe -f archive.rar -m "?l?l?l"
 * (with archive)
 */

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cuda_runtime.h>

// ============================================================================
// CONSTANTS
// ============================================================================

#define RAR5_ITERATIONS 32768
#define MAX_PASSWORD 128
#define MAX_MASK 32
#define THREADS 256

// SHA-256 round constants
__constant__ uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// AES S-box and inverse
__constant__ uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

__constant__ uint8_t ISBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

__constant__ uint8_t RCON[11] = {0,    1,    2,    4,    8,   0x10,
                                 0x20, 0x40, 0x80, 0x1b, 0x36};

// ============================================================================
// STRUCTURES
// ============================================================================

struct MaskPos {
  uint8_t chars[256];
  uint8_t count;
};

__constant__ uint8_t g_salt[16];
__constant__ uint8_t g_check[16];
__constant__ uint8_t g_pswcheck[8];
__constant__ uint32_t g_has_pswcheck;
__constant__ MaskPos g_mask[MAX_MASK];
__constant__ uint32_t g_mask_len;

__device__ uint32_t g_found;
__device__ uint8_t g_password[MAX_PASSWORD];
__device__ uint32_t g_password_len;

// ============================================================================
// SHA-256
// ============================================================================

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define EP1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

__device__ uint32_t be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}

__device__ void be32_store(uint8_t *p, uint32_t v) {
  p[0] = v >> 24;
  p[1] = v >> 16;
  p[2] = v >> 8;
  p[3] = v;
}

__device__ void sha256_compress(uint32_t *h, const uint8_t *blk) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++)
    w[i] = be32(blk + i * 4);
  for (int i = 16; i < 64; i++)
    w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6],
           hh = h[7];
  for (int i = 0; i < 64; i++) {
    uint32_t t1 = hh + EP1(e) + CH(e, f, g) + K[i] + w[i];
    uint32_t t2 = EP0(a) + MAJ(a, b, c);
    hh = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  h[0] += a;
  h[1] += b;
  h[2] += c;
  h[3] += d;
  h[4] += e;
  h[5] += f;
  h[6] += g;
  h[7] += hh;
}

__device__ void sha256(const uint8_t *data, uint32_t len, uint8_t *out) {
  uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  uint8_t buf[64];
  uint32_t buflen = 0;
  uint64_t total = len;
  while (len >= 64) {
    sha256_compress(h, data);
    data += 64;
    len -= 64;
  }
  for (uint32_t i = 0; i < len; i++)
    buf[i] = data[i];
  buflen = len;
  buf[buflen++] = 0x80;
  if (buflen > 56) {
    while (buflen < 64)
      buf[buflen++] = 0;
    sha256_compress(h, buf);
    buflen = 0;
  }
  while (buflen < 56)
    buf[buflen++] = 0;
  uint64_t bits = total * 8;
  be32_store(buf + 56, (uint32_t)(bits >> 32));
  be32_store(buf + 60, (uint32_t)bits);
  sha256_compress(h, buf);
  for (int i = 0; i < 8; i++)
    be32_store(out + i * 4, h[i]);
}

__device__ void hmac_sha256(const uint8_t *key, uint32_t klen,
                            const uint8_t *data, uint32_t dlen, uint8_t *out) {
  uint8_t ipad[64], opad[64], kb[32];
  if (klen > 64) {
    sha256(key, klen, kb);
    key = kb;
    klen = 32;
  }
  for (int i = 0; i < 64; i++) {
    ipad[i] = (i < klen) ? (key[i] ^ 0x36) : 0x36;
    opad[i] = (i < klen) ? (key[i] ^ 0x5c) : 0x5c;
  }
  uint8_t tmp[96];
  for (int i = 0; i < 64; i++)
    tmp[i] = ipad[i];
  for (uint32_t i = 0; i < dlen; i++)
    tmp[64 + i] = data[i];
  uint8_t inner[32];
  sha256(tmp, 64 + dlen, inner);
  for (int i = 0; i < 64; i++)
    tmp[i] = opad[i];
  for (int i = 0; i < 32; i++)
    tmp[64 + i] = inner[i];
  sha256(tmp, 96, out);
}

// ============================================================================
// PBKDF2
// ============================================================================

__device__ void pbkdf2(const uint8_t *pwd, uint32_t plen, const uint8_t *salt,
                       uint8_t *out) {
  uint8_t saltblk[20];
  for (int i = 0; i < 16; i++)
    saltblk[i] = salt[i];
  saltblk[16] = 0;
  saltblk[17] = 0;
  saltblk[18] = 0;
  saltblk[19] = 1;
  uint8_t u[32], t[32];
  hmac_sha256(pwd, plen, saltblk, 20, u);
  for (int i = 0; i < 32; i++)
    t[i] = u[i];
  for (uint32_t iter = 2; iter <= RAR5_ITERATIONS; iter++) {
    hmac_sha256(pwd, plen, u, 32, u);
    for (int i = 0; i < 32; i++)
      t[i] ^= u[i];
  }
  for (int i = 0; i < 32; i++)
    out[i] = t[i];
}

// ============================================================================
// AES-256
// ============================================================================

__device__ void aes_expand(const uint8_t *key, uint32_t *rk) {
  for (int i = 0; i < 8; i++)
    rk[i] = be32(key + i * 4);
  for (int i = 8; i < 60; i++) {
    uint32_t t = rk[i - 1];
    if (i % 8 == 0) {
      t = ((uint32_t)SBOX[(t >> 16) & 0xff] << 24) |
          ((uint32_t)SBOX[(t >> 8) & 0xff] << 16) |
          ((uint32_t)SBOX[t & 0xff] << 8) | (uint32_t)SBOX[(t >> 24) & 0xff];
      t ^= ((uint32_t)RCON[i / 8] << 24);
    } else if (i % 8 == 4) {
      t = ((uint32_t)SBOX[(t >> 24) & 0xff] << 24) |
          ((uint32_t)SBOX[(t >> 16) & 0xff] << 16) |
          ((uint32_t)SBOX[(t >> 8) & 0xff] << 8) | (uint32_t)SBOX[t & 0xff];
    }
    rk[i] = rk[i - 8] ^ t;
  }
}

__device__ uint8_t gfmul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  for (int i = 0; i < 8; i++) {
    if (b & 1)
      p ^= a;
    uint8_t hi = a & 0x80;
    a <<= 1;
    if (hi)
      a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

__device__ void aes_decrypt(const uint32_t *rk, const uint8_t *in,
                            uint8_t *out) {
  uint8_t s[16];
  for (int i = 0; i < 16; i++)
    s[i] = in[i];
  for (int i = 0; i < 4; i++) {
    uint32_t k = rk[56 + i];
    s[4 * i] ^= k >> 24;
    s[4 * i + 1] ^= (k >> 16) & 0xff;
    s[4 * i + 2] ^= (k >> 8) & 0xff;
    s[4 * i + 3] ^= k & 0xff;
  }
  for (int r = 13; r >= 1; r--) {
    uint8_t t = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = s[1];
    s[1] = t;
    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;
    t = s[3];
    s[3] = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = t;
    for (int i = 0; i < 16; i++)
      s[i] = ISBOX[s[i]];
    for (int i = 0; i < 4; i++) {
      uint32_t k = rk[r * 4 + i];
      s[4 * i] ^= k >> 24;
      s[4 * i + 1] ^= (k >> 16) & 0xff;
      s[4 * i + 2] ^= (k >> 8) & 0xff;
      s[4 * i + 3] ^= k & 0xff;
    }
    for (int c = 0; c < 4; c++) {
      uint8_t a = s[4 * c], b = s[4 * c + 1], cc = s[4 * c + 2],
              d = s[4 * c + 3];
      s[4 * c] =
          gfmul(0x0e, a) ^ gfmul(0x0b, b) ^ gfmul(0x0d, cc) ^ gfmul(0x09, d);
      s[4 * c + 1] =
          gfmul(0x09, a) ^ gfmul(0x0e, b) ^ gfmul(0x0b, cc) ^ gfmul(0x0d, d);
      s[4 * c + 2] =
          gfmul(0x0d, a) ^ gfmul(0x09, b) ^ gfmul(0x0e, cc) ^ gfmul(0x0b, d);
      s[4 * c + 3] =
          gfmul(0x0b, a) ^ gfmul(0x0d, b) ^ gfmul(0x09, cc) ^ gfmul(0x0e, d);
    }
  }
  uint8_t t = s[13];
  s[13] = s[9];
  s[9] = s[5];
  s[5] = s[1];
  s[1] = t;
  t = s[2];
  s[2] = s[10];
  s[10] = t;
  t = s[6];
  s[6] = s[14];
  s[14] = t;
  t = s[3];
  s[3] = s[7];
  s[7] = s[11];
  s[11] = s[15];
  s[15] = t;
  for (int i = 0; i < 16; i++)
    s[i] = ISBOX[s[i]];
  for (int i = 0; i < 4; i++) {
    uint32_t k = rk[i];
    s[4 * i] ^= k >> 24;
    s[4 * i + 1] ^= (k >> 16) & 0xff;
    s[4 * i + 2] ^= (k >> 8) & 0xff;
    s[4 * i + 3] ^= k & 0xff;
  }
  for (int i = 0; i < 16; i++)
    out[i] = s[i];
}

// ============================================================================
// VERIFICATION
// ============================================================================

__device__ bool verify(const uint8_t *key) {
  uint8_t data[48];
  for (int i = 0; i < 16; i++)
    data[i] = g_salt[i];
  for (int i = 0; i < 32; i++)
    data[16 + i] = key[i];
  uint8_t hash[32];
  sha256(data, 48, hash);
  if (g_has_pswcheck) {
    for (int i = 0; i < 8; i++)
      if (hash[i] != g_pswcheck[i])
        return false;
    return true;
  }
  return true;
}

// ============================================================================
// KERNEL
// ============================================================================

__global__ void crack_kernel(uint64_t start, uint64_t count) {
  uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  uint64_t total = gridDim.x * blockDim.x;
  if (g_found)
    return;

  for (uint64_t idx = start + tid; idx < start + count; idx += total) {
    if (g_found)
      return;

    uint8_t pwd[MAX_PASSWORD];
    uint32_t len = g_mask_len;
    uint64_t tmp = idx;
    for (int p = len - 1; p >= 0; p--) {
      uint8_t c = g_mask[p].count;
      pwd[p] = g_mask[p].chars[tmp % c];
      tmp /= c;
    }

    uint8_t dk[32];
    pbkdf2(pwd, len, g_salt, dk);

    if (verify(dk)) {
      if (atomicCAS(&g_found, 0, 1) == 0) {
        g_password_len = len;
        for (uint32_t i = 0; i < len; i++)
          g_password[i] = pwd[i];
      }
      return;
    }
  }
}

__global__ void bench_kernel(uint64_t n) {
  uint8_t pwd[8] = {'t', 'e', 's', 't', '1', '2', '3', '4'};
  uint8_t salt[16] = {0};
  uint8_t dk[32];
  for (uint64_t i = 0; i < n; i++) {
    pwd[0] = (uint8_t)(threadIdx.x + i);
    pbkdf2(pwd, 8, salt, dk);
  }
}

// ============================================================================
// HOST
// ============================================================================

void show_banner() {
  printf("\n");
  printf("  ╔═══════════════════════════════════════════════════╗\n");
  printf("  ║        H3XER - RAR5 Password Recovery             ║\n");
  printf("  ║           CUDA GPU Accelerated                    ║\n");
  printf("  ╚═══════════════════════════════════════════════════╝\n\n");
}

void show_menu() {
  printf("  ┌─────────────────────────────────────┐\n");
  printf("  │  Select an option:                  │\n");
  printf("  ├─────────────────────────────────────┤\n");
  printf("  │  [1] Crack RAR5 archive             │\n");
  printf("  │  [2] Benchmark GPU                  │\n");
  printf("  │  [3] Show mask help                 │\n");
  printf("  │  [4] Exit                           │\n");
  printf("  └─────────────────────────────────────┘\n");
  printf("\n  Enter choice: ");
}

void show_mask_help() {
  printf("\n");
  printf("  ╔═══════════════════════════════════════════════════╗\n");
  printf("  ║              Mask Attack Help                     ║\n");
  printf("  ╠═══════════════════════════════════════════════════╣\n");
  printf("  ║  Charset placeholders:                            ║\n");
  printf("  ║    ?l = lowercase letters (a-z)                   ║\n");
  printf("  ║    ?u = uppercase letters (A-Z)                   ║\n");
  printf("  ║    ?d = digits (0-9)                              ║\n");
  printf("  ║    ?a = alphanumeric (a-zA-Z0-9)                  ║\n");
  printf("  ║    ?s = special characters                        ║\n");
  printf("  ╠═══════════════════════════════════════════════════╣\n");
  printf("  ║  Examples:                                        ║\n");
  printf("  ║    ?l?l?l?l     = 4-char lowercase (aaaa-zzzz)    ║\n");
  printf("  ║    pass?d?d?d   = 'pass' + 3 digits               ║\n");
  printf("  ║    ?u?l?l?l?d?d = Capital + 3 lower + 2 digits    ║\n");
  printf("  ╚═══════════════════════════════════════════════════╝\n\n");
}

void wait_exit() {
  printf("\nPress Enter to continue...");
  getchar();
}

void clear_input() {
  int c;
  while ((c = getchar()) != '\n' && c != EOF)
    ;
}

void read_line(char *buffer, int max_len) {
  if (fgets(buffer, max_len, stdin)) {
    // Remove trailing newline
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n')
      buffer[len - 1] = '\0';
  }
}

int run_interactive_mode() {
  show_banner();

  int dev;
  if (cudaGetDevice(&dev) != cudaSuccess) {
    printf("[!] No CUDA GPU detected!\n");
    wait_exit();
    return 1;
  }
  cudaDeviceProp prop;
  cudaGetDeviceProperties(&prop, dev);
  printf("[+] GPU: %s (%d SMs, %.1f GB)\n\n", prop.name,
         prop.multiProcessorCount,
         prop.totalGlobalMem / (1024.0 * 1024 * 1024));

  int blocks = prop.multiProcessorCount * 4;

  while (true) {
    show_menu();

    int choice;
    if (scanf("%d", &choice) != 1) {
      clear_input();
      continue;
    }
    clear_input();

    if (choice == 4) {
      printf("\n  Goodbye!\n");
      return 0;
    }

    if (choice == 2) {
      // Benchmark
      printf("\n[*] Running benchmark...\n");
      bench_kernel<<<blocks, THREADS>>>(1);
      cudaDeviceSynchronize();
      auto t1 = std::chrono::high_resolution_clock::now();
      bench_kernel<<<blocks, THREADS>>>(50);
      cudaDeviceSynchronize();
      auto t2 = std::chrono::high_resolution_clock::now();
      double sec = std::chrono::duration<double>(t2 - t1).count();
      double keys = (double)blocks * THREADS * 50 / sec;

      printf("\n");
      printf("  ╔═══════════════════════════════════════╗\n");
      printf("  ║         Benchmark Results             ║\n");
      printf("  ╠═══════════════════════════════════════╣\n");
      printf("  ║  Speed:     %'15.0f keys/sec  ║\n", keys);
      printf("  ║  4-char:    %15.1f sec      ║\n", 456976 / keys);
      printf("  ║  6-char:    %15.1f hours    ║\n", 308915776 / keys / 3600);
      printf("  ╚═══════════════════════════════════════╝\n");
      wait_exit();
      continue;
    }

    if (choice == 3) {
      show_mask_help();
      wait_exit();
      continue;
    }

    if (choice == 1) {
      // Crack mode
      char filepath[512];
      char mask[256];

      printf("\n  ┌─────────────────────────────────────┐\n");
      printf("  │         RAR5 Cracking Setup         │\n");
      printf("  └─────────────────────────────────────┘\n\n");

      printf("  Enter RAR file path (or 'demo' for test):\n  > ");
      read_line(filepath, sizeof(filepath));

      if (strlen(filepath) == 0 || strcmp(filepath, "demo") == 0) {
        printf("  [*] Using demo mode (test salt)\n");
      } else {
        printf("  [*] Target: %s\n", filepath);
        // TODO: Parse RAR5 file here
      }

      printf("\n  Enter mask pattern (e.g. ?l?l?l?l or pass?d?d):\n  > ");
      read_line(mask, sizeof(mask));

      if (strlen(mask) == 0) {
        strcpy(mask, "?l?l?l?l");
        printf("  [*] Using default: %s\n", mask);
      }

      // Parse mask
      MaskPos mpos[MAX_MASK];
      uint32_t mlen = 0;
      uint64_t keyspace = 1;
      const char *p = mask;
      while (*p && mlen < MAX_MASK) {
        MaskPos &m = mpos[mlen];
        if (*p == '?' && *(p + 1)) {
          char t = *(p + 1);
          if (t == 'l') {
            memcpy(m.chars, "abcdefghijklmnopqrstuvwxyz", 26);
            m.count = 26;
          } else if (t == 'u') {
            memcpy(m.chars, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26);
            m.count = 26;
          } else if (t == 'd') {
            memcpy(m.chars, "0123456789", 10);
            m.count = 10;
          } else if (t == 'a') {
            memcpy(m.chars,
                   "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"
                   "789",
                   62);
            m.count = 62;
          } else {
            m.chars[0] = t;
            m.count = 1;
          }
          p += 2;
        } else {
          m.chars[0] = *p;
          m.count = 1;
          p++;
        }
        keyspace *= m.count;
        mlen++;
      }

      printf("\n  ╔═══════════════════════════════════════╗\n");
      printf("  ║           Attack Summary              ║\n");
      printf("  ╠═══════════════════════════════════════╣\n");
      printf("  ║  Mask:      %-25s  ║\n", mask);
      printf("  ║  Length:    %-25u  ║\n", mlen);
      printf("  ║  Keyspace:  %-25llu  ║\n", (unsigned long long)keyspace);
      printf("  ╚═══════════════════════════════════════╝\n\n");

      printf("  Start cracking? (y/n): ");
      char confirm[10];
      read_line(confirm, sizeof(confirm));
      if (confirm[0] != 'y' && confirm[0] != 'Y') {
        printf("  [*] Cancelled\n");
        wait_exit();
        continue;
      }

      // Setup and crack
      uint8_t salt[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                          9, 10, 11, 12, 13, 14, 15, 16};
      uint8_t check[16] = {0};
      uint32_t has_pswcheck = 0;

      cudaMemcpyToSymbol(g_salt, salt, 16);
      cudaMemcpyToSymbol(g_check, check, 16);
      cudaMemcpyToSymbol(g_has_pswcheck, &has_pswcheck, 4);
      cudaMemcpyToSymbol(g_mask, mpos, sizeof(MaskPos) * mlen);
      cudaMemcpyToSymbol(g_mask_len, &mlen, 4);
      uint32_t zero = 0;
      cudaMemcpyToSymbol(g_found, &zero, 4);

      printf("\n[*] Cracking %llu candidates...\n",
             (unsigned long long)keyspace);

      auto t1 = std::chrono::high_resolution_clock::now();
      uint64_t batch = (uint64_t)blocks * THREADS * 8;

      for (uint64_t i = 0; i < keyspace; i += batch) {
        uint64_t n = (keyspace - i < batch) ? keyspace - i : batch;
        crack_kernel<<<blocks, THREADS>>>(i, n);
        cudaDeviceSynchronize();

        uint32_t found;
        cudaMemcpyFromSymbol(&found, g_found, 4);
        if (found) {
          uint8_t pwd[MAX_PASSWORD];
          uint32_t len;
          cudaMemcpyFromSymbol(pwd, g_password, MAX_PASSWORD);
          cudaMemcpyFromSymbol(&len, g_password_len, 4);
          auto t2 = std::chrono::high_resolution_clock::now();
          double sec = std::chrono::duration<double>(t2 - t1).count();

          printf("\n");
          printf("  ╔═══════════════════════════════════════╗\n");
          printf("  ║          PASSWORD FOUND!              ║\n");
          printf("  ╠═══════════════════════════════════════╣\n");
          printf("  ║  Password: %-26.*s  ║\n", len, pwd);
          printf("  ║  Time:     %-26.2f  ║\n", sec);
          printf("  ╚═══════════════════════════════════════╝\n");
          wait_exit();
          continue;
        }

        double pct = 100.0 * (i + n) / keyspace;
        printf("\r  [");
        int bar = (int)(pct / 5);
        for (int j = 0; j < 20; j++)
          printf(j < bar ? "█" : "░");
        printf("] %.1f%%", pct);
        fflush(stdout);
      }

      printf("\n\n  [!] Password not found in keyspace\n");
      wait_exit();
      continue;
    }
  }

  return 0;
}

int main(int argc, char **argv) {
  // Interactive mode if no arguments
  if (argc == 1) {
    return run_interactive_mode();
  }

  int dev;
  cudaGetDevice(&dev);
  cudaDeviceProp prop;
  cudaGetDeviceProperties(&prop, dev);
  printf("\n  H3XER - RAR5 Password Recovery\n");
  printf("  ================================\n\n");
  printf("[+] GPU: %s (%d SMs)\n", prop.name, prop.multiProcessorCount);

  int blocks = prop.multiProcessorCount * 4;

  // Parse args
  bool bench = false;
  const char *mask = nullptr;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-b") == 0)
      bench = true;
    else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc)
      mask = argv[++i];
    else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      show_help();
      return 0;
    }
  }

  if (bench) {
    printf("[*] Benchmarking...\n");
    bench_kernel<<<blocks, THREADS>>>(1);
    cudaDeviceSynchronize();
    auto t1 = std::chrono::high_resolution_clock::now();
    bench_kernel<<<blocks, THREADS>>>(50);
    cudaDeviceSynchronize();
    auto t2 = std::chrono::high_resolution_clock::now();
    double sec = std::chrono::duration<double>(t2 - t1).count();
    double keys = (double)blocks * THREADS * 50 / sec;
    printf("[+] Speed: %.0f keys/sec\n", keys);
    printf("[+] 4-char: %.1f sec\n", 456976 / keys);
    printf("[+] 6-char: %.1f hours\n", 308915776 / keys / 3600);
    return 0;
  }

  // Setup mask
  MaskPos mpos[MAX_MASK];
  uint32_t mlen = 0;
  uint64_t keyspace = 1;
  const char *p = mask ? mask : "?l?l?l?l";
  while (*p && mlen < MAX_MASK) {
    MaskPos &m = mpos[mlen];
    if (*p == '?' && *(p + 1)) {
      char t = *(p + 1);
      if (t == 'l') {
        memcpy(m.chars, "abcdefghijklmnopqrstuvwxyz", 26);
        m.count = 26;
      } else if (t == 'u') {
        memcpy(m.chars, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26);
        m.count = 26;
      } else if (t == 'd') {
        memcpy(m.chars, "0123456789", 10);
        m.count = 10;
      } else if (t == 'a') {
        memcpy(m.chars,
               "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
               62);
        m.count = 62;
      } else {
        m.chars[0] = t;
        m.count = 1;
      }
      p += 2;
    } else {
      m.chars[0] = *p;
      m.count = 1;
      p++;
    }
    keyspace *= m.count;
    mlen++;
  }

  // Demo salt
  uint8_t salt[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  uint8_t check[16] = {0};
  uint32_t has_pswcheck = 0;

  cudaMemcpyToSymbol(g_salt, salt, 16);
  cudaMemcpyToSymbol(g_check, check, 16);
  cudaMemcpyToSymbol(g_has_pswcheck, &has_pswcheck, 4);
  cudaMemcpyToSymbol(g_mask, mpos, sizeof(MaskPos) * mlen);
  cudaMemcpyToSymbol(g_mask_len, &mlen, 4);
  uint32_t zero = 0;
  cudaMemcpyToSymbol(g_found, &zero, 4);

  printf("[+] Mask: %s (%llu candidates)\n", mask ? mask : "?l?l?l?l",
         (unsigned long long)keyspace);
  printf("[*] Cracking...\n");

  auto t1 = std::chrono::high_resolution_clock::now();
  uint64_t batch = (uint64_t)blocks * THREADS * 8;

  for (uint64_t i = 0; i < keyspace; i += batch) {
    uint64_t n = (keyspace - i < batch) ? keyspace - i : batch;
    crack_kernel<<<blocks, THREADS>>>(i, n);
    cudaDeviceSynchronize();

    uint32_t found;
    cudaMemcpyFromSymbol(&found, g_found, 4);
    if (found) {
      uint8_t pwd[MAX_PASSWORD];
      uint32_t len;
      cudaMemcpyFromSymbol(pwd, g_password, MAX_PASSWORD);
      cudaMemcpyFromSymbol(&len, g_password_len, 4);
      auto t2 = std::chrono::high_resolution_clock::now();
      double sec = std::chrono::duration<double>(t2 - t1).count();
      printf("\n[+] FOUND: %.*s (%.2f sec)\n", len, pwd, sec);
      return 0;
    }

    double pct = 100.0 * (i + n) / keyspace;
    printf("\r[*] %.1f%%", pct);
    fflush(stdout);
  }

  printf("\n[!] Not found\n");
  return 1;
}
