/*
 * H3XER - Hybrid Attack Kernel
 * Dictionary + Rules combination
 */

#ifndef H3XER_HYBRID_CUH
#define H3XER_HYBRID_CUH

#include "aes.cuh"
#include "candidate.cuh"
#include "h3xer_types.cuh"
#include "kernel.cuh"
#include "pbkdf2.cuh"
#include "rules.cuh"
#include "sha256.cuh"


namespace h3xer {

// Predefined rule sets for hybrid attacks
__constant__ RuleChain g_rule_chains[64];
__constant__ uint32_t g_num_rules;

/*
 * Hybrid attack kernel: Dictionary word + Rule transformation
 *
 * Each thread takes a word and applies a rule chain, then tests
 * Total candidates = num_words * num_rules
 */
__global__ void rar5_crack_hybrid_kernel(const uint8_t *dict_buffer,
                                         const uint32_t *word_offsets,
                                         uint32_t num_words) {
  uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  uint32_t total_threads = gridDim.x * blockDim.x;
  uint32_t total_candidates = num_words * g_num_rules;

  if (g_found)
    return;

  for (uint32_t idx = tid; idx < total_candidates; idx += total_threads) {
    if (g_found)
      return;

    // Decode: which word and which rule
    uint32_t word_idx = idx / g_num_rules;
    uint32_t rule_idx = idx % g_num_rules;

    // Load base word
    uint8_t password[MAX_PASSWORD_LEN];
    uint32_t password_len;
    load_dictionary_word(dict_buffer, word_offsets, word_idx, password,
                         &password_len);

    // Apply rule chain
    apply_rule_chain(password, &password_len, g_rule_chains[rule_idx]);

    // Derive key
    uint8_t derived_key[32];
    pbkdf2_sha256_rar5_fast(password, password_len, g_header.salt, derived_key);

    // Verify
    if (verify_rar5_password(derived_key, g_header.salt,
                             g_header.check_value)) {
      if (atomicCAS(&g_found, 0, 1) == 0) {
        g_found_idx = idx;
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
 * Common rule sets for quick hybrid attacks
 */
struct CommonRules {
  // Append common suffixes
  static __device__ RuleChain append_1() {
    RuleChain c = {};
    c.rules[0] = {RULE_APPEND_CHAR, '1', 0};
    c.count = 1;
    return c;
  }
  static __device__ RuleChain append_123() {
    RuleChain c = {};
    c.rules[0] = {RULE_APPEND_CHAR, '1', 0};
    c.rules[1] = {RULE_APPEND_CHAR, '2', 0};
    c.rules[2] = {RULE_APPEND_CHAR, '3', 0};
    c.count = 3;
    return c;
  }
  static __device__ RuleChain append_exclaim() {
    RuleChain c = {};
    c.rules[0] = {RULE_APPEND_CHAR, '!', 0};
    c.count = 1;
    return c;
  }

  // Capitalize + suffix
  static __device__ RuleChain cap_123() {
    RuleChain c = {};
    c.rules[0] = {RULE_CAPITALIZE, 0, 0};
    c.rules[1] = {RULE_APPEND_CHAR, '1', 0};
    c.rules[2] = {RULE_APPEND_CHAR, '2', 0};
    c.rules[3] = {RULE_APPEND_CHAR, '3', 0};
    c.count = 4;
    return c;
  }

  // L33t speak
  static __device__ RuleChain leet() {
    RuleChain c = {};
    c.rules[0] = {RULE_LEET, 0, 0};
    c.count = 1;
    return c;
  }
  static __device__ RuleChain cap_leet() {
    RuleChain c = {};
    c.rules[0] = {RULE_CAPITALIZE, 0, 0};
    c.rules[1] = {RULE_LEET, 0, 0};
    c.count = 2;
    return c;
  }

  // Reverse
  static __device__ RuleChain reverse() {
    RuleChain c = {};
    c.rules[0] = {RULE_REVERSE, 0, 0};
    c.count = 1;
    return c;
  }

  // Duplicate
  static __device__ RuleChain duplicate() {
    RuleChain c = {};
    c.rules[0] = {RULE_DUPLICATE, 0, 0};
    c.count = 1;
    return c;
  }
};

} // namespace h3xer
#endif
