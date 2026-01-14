/*
 * H3XER - AES-256 Implementation for CUDA
 * Optimized for password verification (single block decrypt)
 */

#ifndef H3XER_AES_CUH
#define H3XER_AES_CUH

#include "h3xer_types.cuh"

namespace h3xer {

// AES-256 expanded key: 15 round keys * 4 words = 60 words
struct Aes256Key {
  uint32_t rd_key[60];
};

__device__ void aes256_set_decrypt_key(const uint8_t *key, Aes256Key *aeskey) {
  uint32_t *rk = aeskey->rd_key;

  // Load initial key as big-endian words
  for (int i = 0; i < 8; i++) {
    rk[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16) |
            ((uint32_t)key[4 * i + 2] << 8) | key[4 * i + 3];
  }

  // Key expansion
  for (int i = 8; i < 60; i++) {
    uint32_t temp = rk[i - 1];
    if (i % 8 == 0) {
      // RotWord + SubWord + Rcon
      temp = ((uint32_t)AES_SBOX[(temp >> 16) & 0xff] << 24) |
             ((uint32_t)AES_SBOX[(temp >> 8) & 0xff] << 16) |
             ((uint32_t)AES_SBOX[temp & 0xff] << 8) |
             (uint32_t)AES_SBOX[(temp >> 24) & 0xff];
      temp ^= ((uint32_t)AES_RCON[i / 8] << 24);
    } else if (i % 8 == 4) {
      // SubWord only
      temp = ((uint32_t)AES_SBOX[(temp >> 24) & 0xff] << 24) |
             ((uint32_t)AES_SBOX[(temp >> 16) & 0xff] << 16) |
             ((uint32_t)AES_SBOX[(temp >> 8) & 0xff] << 8) |
             (uint32_t)AES_SBOX[temp & 0xff];
    }
    rk[i] = rk[i - 8] ^ temp;
  }
}

__device__ uint8_t gf_mul(uint8_t a, uint8_t b) {
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

__device__ void aes256_decrypt_block(const Aes256Key *key, const uint8_t *in,
                                     uint8_t *out) {
  uint8_t state[16];
  const uint32_t *rk = key->rd_key;

  // Load input
  for (int i = 0; i < 16; i++)
    state[i] = in[i];

  // Add last round key (round 14)
  for (int i = 0; i < 4; i++) {
    uint32_t k = rk[56 + i];
    state[4 * i] ^= (k >> 24);
    state[4 * i + 1] ^= (k >> 16) & 0xff;
    state[4 * i + 2] ^= (k >> 8) & 0xff;
    state[4 * i + 3] ^= k & 0xff;
  }

  // 13 main rounds (13 down to 1)
  for (int round = 13; round >= 1; round--) {
    // Inverse ShiftRows
    uint8_t t;
    // Row 1: shift right by 1
    t = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = t;
    // Row 2: shift right by 2
    t = state[2];
    state[2] = state[10];
    state[10] = t;
    t = state[6];
    state[6] = state[14];
    state[14] = t;
    // Row 3: shift right by 3 (= left by 1)
    t = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = t;

// Inverse SubBytes using precomputed inverse S-box (O(1) lookup!)
#pragma unroll
    for (int i = 0; i < 16; i++) {
      state[i] = AES_ISBOX[state[i]];
    }

    // AddRoundKey
    for (int i = 0; i < 4; i++) {
      uint32_t k = rk[round * 4 + i];
      state[4 * i] ^= (k >> 24);
      state[4 * i + 1] ^= (k >> 16) & 0xff;
      state[4 * i + 2] ^= (k >> 8) & 0xff;
      state[4 * i + 3] ^= k & 0xff;
    }

    // Inverse MixColumns
    for (int c = 0; c < 4; c++) {
      uint8_t s0 = state[4 * c], s1 = state[4 * c + 1], s2 = state[4 * c + 2],
              s3 = state[4 * c + 3];
      state[4 * c] = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^
                     gf_mul(0x09, s3);
      state[4 * c + 1] = gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^
                         gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
      state[4 * c + 2] = gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^
                         gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
      state[4 * c + 3] = gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^
                         gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
    }
  }

  // Final round (no MixColumns)
  // Inverse ShiftRows
  uint8_t t;
  t = state[13];
  state[13] = state[9];
  state[9] = state[5];
  state[5] = state[1];
  state[1] = t;
  t = state[2];
  state[2] = state[10];
  state[10] = t;
  t = state[6];
  state[6] = state[14];
  state[14] = t;
  t = state[3];
  state[3] = state[7];
  state[7] = state[11];
  state[11] = state[15];
  state[15] = t;

// Inverse SubBytes
#pragma unroll
  for (int i = 0; i < 16; i++) {
    state[i] = AES_ISBOX[state[i]];
  }

  // Add first round key (round 0)
  for (int i = 0; i < 4; i++) {
    uint32_t k = rk[i];
    state[4 * i] ^= (k >> 24);
    state[4 * i + 1] ^= (k >> 16) & 0xff;
    state[4 * i + 2] ^= (k >> 8) & 0xff;
    state[4 * i + 3] ^= k & 0xff;
  }

  for (int i = 0; i < 16; i++)
    out[i] = state[i];
}

__device__ void aes256_cbc_decrypt_block(const Aes256Key *key,
                                         const uint8_t *iv, const uint8_t *in,
                                         uint8_t *out) {
  uint8_t dec[16];
  aes256_decrypt_block(key, in, dec);
#pragma unroll
  for (int i = 0; i < 16; i++)
    out[i] = dec[i] ^ iv[i];
}

} // namespace h3xer
#endif
