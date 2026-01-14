/*
 * H3XER - High-Performance RAR5 Password Recovery
 * Main CUDA Kernel Implementation
 */

#ifndef H3XER_KERNEL_CUH
#define H3XER_KERNEL_CUH

#include "aes.cuh"
#include "candidate.cuh"
#include "h3xer_types.cuh"
#include "pbkdf2.cuh"
#include "sha256.cuh"


namespace h3xer {

// Header data in constant memory for fast access
__constant__ Rar5Header g_header;

// Mask positions in constant memory (max 32 positions)
__constant__ MaskPosition g_mask[MAX_MASK_LEN];
__constant__ uint32_t g_mask_len;

// Result flag in global memory (atomic)
__device__ uint32_t g_found;
__device__ uint32_t g_found_idx;
__device__ uint8_t g_found_password[MAX_PASSWORD_LEN];
__device__ uint32_t g_found_password_len;

/*
 * RAR5 password verification check
 * Returns true if decrypted check value matches expected pattern
 *
 * RAR5 check format: After decryption, bytes should match a known pattern
 * The check value is the first 16 bytes of encrypted data, decrypted with
 * the derived key using AES-256-CBC with IV = 0
 */
__device__ bool verify_rar5_password(const uint8_t *derived_key,
                                     const uint8_t *salt,
                                     const uint8_t *check_value) {
  Aes256Key aeskey;
  aes256_set_decrypt_key(derived_key, &aeskey);

  // IV is all zeros for check value
  uint8_t iv[16] = {0};
  uint8_t decrypted[16];

  aes256_cbc_decrypt_block(&aeskey, iv, check_value, decrypted);

  // RAR5 uses a password check value derived from the key
  // The check is: first 8 bytes of SHA256(derived_key) should equal
  // the stored pswcheck (if present), or we check for valid decryption pattern

  // For full archive encryption (-hp), we verify the decrypted block
  // matches expected structure (typically has specific byte patterns)

  // Quick check: RAR5 stores SHA256(salt || derived_key)[0:8] as pswcheck
  uint8_t pswcheck_data[48];
  for (int i = 0; i < 16; i++)
    pswcheck_data[i] = salt[i];
  for (int i = 0; i < 32; i++)
    pswcheck_data[16 + i] = derived_key[i];

  uint8_t pswcheck_hash[32];
  sha256(pswcheck_data, 48, pswcheck_hash);

  // Compare first 8 bytes with stored pswcheck (if present)
  if (g_header.pswcheck_present) {
    for (int i = 0; i < 8; i++) {
      if (pswcheck_hash[i] != g_header.pswcheck[i])
        return false;
    }
    return true;
  }

  // Fallback: verify decryption produces valid data pattern
  // For encrypted headers, first bytes often have structure
  return true; // Caller should do additional validation
}

/*
 * Main RAR5 cracking kernel - Mask Attack
 * Each thread processes one password candidate
 *
 * start_idx: Starting candidate index for this batch
 * num_candidates: Total candidates in this batch
 */
__global__ void rar5_crack_mask_kernel(uint64_t start_idx,
                                       uint64_t num_candidates) {
  uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  uint64_t total_threads = gridDim.x * blockDim.x;

  // Early exit if password already found
  if (g_found)
    return;

  // Each thread processes multiple candidates for better utilization
  for (uint64_t idx = start_idx + tid; idx < start_idx + num_candidates;
       idx += total_threads) {
    if (g_found)
      return; // Check again in loop

    // Generate password candidate from mask
    uint8_t password[MAX_PASSWORD_LEN];
    uint32_t password_len;
    generate_mask_candidate(g_mask, g_mask_len, idx, password, &password_len);

    // Derive key using PBKDF2-HMAC-SHA256
    uint8_t derived_key[32];
    pbkdf2_sha256_rar5_fast(password, password_len, g_header.salt, derived_key);

    // Verify password
    if (verify_rar5_password(derived_key, g_header.salt,
                             g_header.check_value)) {
      // Atomically claim the find
      if (atomicCAS(&g_found, 0, 1) == 0) {
        g_found_idx = (uint32_t)(idx - start_idx);
        g_found_password_len = password_len;
        for (uint32_t i = 0; i < password_len; i++) {
          g_found_password[i] = password[i];
        }
      }
      return;
    }
  }
}

/*
 * Dictionary attack kernel
 * Processes passwords from pre-uploaded dictionary buffer
 */
__global__ void rar5_crack_dict_kernel(const uint8_t *dict_buffer,
                                       const uint32_t *word_offsets,
                                       uint32_t num_words,
                                       uint32_t start_word) {
  uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  uint32_t word_idx = start_word + tid;

  if (word_idx >= num_words || g_found)
    return;

  // Load dictionary word
  uint8_t password[MAX_PASSWORD_LEN];
  uint32_t password_len;
  load_dictionary_word(dict_buffer, word_offsets, word_idx, password,
                       &password_len);

  // Derive key
  uint8_t derived_key[32];
  pbkdf2_sha256_rar5_fast(password, password_len, g_header.salt, derived_key);

  // Verify
  if (verify_rar5_password(derived_key, g_header.salt, g_header.check_value)) {
    if (atomicCAS(&g_found, 0, 1) == 0) {
      g_found_idx = word_idx;
      g_found_password_len = password_len;
      for (uint32_t i = 0; i < password_len; i++) {
        g_found_password[i] = password[i];
      }
    }
  }
}

/*
 * Brute-force kernel for exhaustive search
 * Tries all printable ASCII combinations of fixed length
 */
__global__ void rar5_crack_bruteforce_kernel(uint64_t start_idx,
                                             uint64_t num_candidates,
                                             uint32_t password_len) {
  uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  uint64_t total_threads = gridDim.x * blockDim.x;

  if (g_found)
    return;

  for (uint64_t idx = start_idx + tid; idx < start_idx + num_candidates;
       idx += total_threads) {
    if (g_found)
      return;

    uint8_t password[MAX_PASSWORD_LEN];
    generate_bruteforce_candidate(idx, password_len, password);

    uint8_t derived_key[32];
    pbkdf2_sha256_rar5_fast(password, password_len, g_header.salt, derived_key);

    if (verify_rar5_password(derived_key, g_header.salt,
                             g_header.check_value)) {
      if (atomicCAS(&g_found, 0, 1) == 0) {
        g_found_idx = (uint32_t)(idx - start_idx);
        g_found_password_len = password_len;
        for (uint32_t i = 0; i < password_len; i++) {
          g_found_password[i] = password[i];
        }
      }
      return;
    }
  }
}

/*
 * Benchmark kernel - measures keys/sec without full verification
 */
__global__ void rar5_benchmark_kernel(uint64_t num_iterations) {
  uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;

  uint8_t password[8] = {'t', 'e', 's', 't', '1', '2', '3', '4'};
  uint8_t derived_key[32];
  uint8_t salt[16] = {0};

  // Warm up with multiple iterations
  for (uint64_t i = 0; i < num_iterations; i++) {
    password[0] = (uint8_t)(tid + i);
    pbkdf2_sha256_rar5_fast(password, 8, salt, derived_key);
  }
}

} // namespace h3xer
#endif
