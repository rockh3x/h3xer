/*
 * H3XER - PBKDF2-HMAC-SHA256 for RAR5
 * Optimized GPU implementation
 */

#ifndef H3XER_PBKDF2_CUH
#define H3XER_PBKDF2_CUH

#include "sha256.cuh"

namespace h3xer {

/*
 * PBKDF2-HMAC-SHA256 implementation for RAR5
 * RAR5 uses 32768 iterations (2^15), 16-byte salt, 32-byte output key
 *
 * DK = T1 || T2 || ... where Ti = F(Password, Salt, c, i)
 * F(Password, Salt, c, i) = U1 ^ U2 ^ ... ^ Uc
 * U1 = HMAC(Password, Salt || INT(i))
 * U2 = HMAC(Password, U1)
 * ...
 * Uc = HMAC(Password, Uc-1)
 */

__device__ void pbkdf2_sha256_rar5(const uint8_t *password,
                                   uint32_t password_len, const uint8_t *salt,
                                   uint32_t salt_len, uint32_t iterations,
                                   uint8_t *out, uint32_t dklen) {
  uint8_t u[32];          // Current U value
  uint8_t t[32];          // Accumulated T value (XOR of all U's)
  uint8_t salt_block[64]; // Salt || INT(i)

  uint32_t block_count = (dklen + 31) / 32;

  for (uint32_t block = 1; block <= block_count; block++) {
    // Prepare salt || INT(block) in big-endian
    for (uint32_t i = 0; i < salt_len && i < 60; i++) {
      salt_block[i] = salt[i];
    }
    salt_block[salt_len] = (block >> 24) & 0xff;
    salt_block[salt_len + 1] = (block >> 16) & 0xff;
    salt_block[salt_len + 2] = (block >> 8) & 0xff;
    salt_block[salt_len + 3] = block & 0xff;

    // U1 = HMAC(password, salt || INT(block))
    hmac_sha256(password, password_len, salt_block, salt_len + 4, u);

    // T = U1
    for (int i = 0; i < 32; i++)
      t[i] = u[i];

    // Iterate: U_i = HMAC(password, U_{i-1}), T ^= U_i
    for (uint32_t iter = 2; iter <= iterations; iter++) {
      hmac_sha256(password, password_len, u, 32, u);
      for (int i = 0; i < 32; i++)
        t[i] ^= u[i];
    }

    // Copy T to output
    uint32_t offset = (block - 1) * 32;
    uint32_t copy_len = (offset + 32 <= dklen) ? 32 : (dklen - offset);
    for (uint32_t i = 0; i < copy_len; i++) {
      out[offset + i] = t[i];
    }
  }
}

// Optimized version that precomputes HMAC inner/outer states
// This is 2x faster by avoiding redundant key XOR operations
__device__ void pbkdf2_sha256_rar5_fast(const uint8_t *password,
                                        uint32_t password_len,
                                        const uint8_t *salt, uint8_t *out) {
  // For RAR5: 16-byte salt, 32768 iterations, 32-byte output
  uint8_t k_ipad[64], k_opad[64];
  uint8_t keybuf[32];
  const uint8_t *key = password;
  uint32_t keylen = password_len;

  // Hash key if longer than 64 bytes
  if (keylen > 64) {
    sha256(password, password_len, keybuf);
    key = keybuf;
    keylen = 32;
  }

  // Precompute padded keys
  for (uint32_t i = 0; i < 64; i++) {
    k_ipad[i] = (i < keylen) ? (key[i] ^ 0x36) : 0x36;
    k_opad[i] = (i < keylen) ? (key[i] ^ 0x5c) : 0x5c;
  }

  // Precompute inner hash states (avoid recomputing ipad hash)
  Sha256State ipad_state;
  sha256_init(&ipad_state);
  sha256_update(&ipad_state, k_ipad, 64);

  Sha256State opad_state;
  sha256_init(&opad_state);
  sha256_update(&opad_state, k_opad, 64);

  // Prepare salt || INT(1)
  uint8_t salt_block[20];
  for (int i = 0; i < 16; i++)
    salt_block[i] = salt[i];
  salt_block[16] = 0;
  salt_block[17] = 0;
  salt_block[18] = 0;
  salt_block[19] = 1;

  // U1 = HMAC(password, salt || INT(1))
  uint8_t u[32], t[32], inner[32];
  Sha256State ctx = ipad_state;
  sha256_update(&ctx, salt_block, 20);
  sha256_final(&ctx, inner);

  ctx = opad_state;
  sha256_update(&ctx, inner, 32);
  sha256_final(&ctx, u);

  for (int i = 0; i < 32; i++)
    t[i] = u[i];

  // Iterations 2 to 32768
  for (uint32_t iter = 2; iter <= RAR5_PBKDF2_ITERATIONS; iter++) {
    ctx = ipad_state;
    sha256_update(&ctx, u, 32);
    sha256_final(&ctx, inner);

    ctx = opad_state;
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, u);

    for (int i = 0; i < 32; i++)
      t[i] ^= u[i];
  }

  for (int i = 0; i < 32; i++)
    out[i] = t[i];
}

} // namespace h3xer
#endif
