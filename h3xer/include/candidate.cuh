/*
 * H3XER - GPU Password Candidate Generation
 * Mask attack and charset handling
 */

#ifndef H3XER_CANDIDATE_CUH
#define H3XER_CANDIDATE_CUH

#include "h3xer_types.cuh"

namespace h3xer {

// Predefined charsets for mask attacks
// ?l = lowercase, ?u = uppercase, ?d = digits, ?s = special, ?a = all printable
__constant__ uint8_t CHARSET_LOWER[26] = {
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
__constant__ uint8_t CHARSET_UPPER[26] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
__constant__ uint8_t CHARSET_DIGIT[10] = {'0', '1', '2', '3', '4',
                                          '5', '6', '7', '8', '9'};
__constant__ uint8_t CHARSET_SPECIAL[33] = {
    ' ', '!', '"',  '#', '$', '%', '&', '\'', '(', ')', '*',
    '+', ',', '-',  '.', '/', ':', ';', '<',  '=', '>', '?',
    '@', '[', '\\', ']', '^', '_', '`', '{',  '|', '}', '~'};

// MaskPosition is defined in h3xer_types.cuh

/*
 * Generate password candidate from index using mask attack
 * Each thread computes its candidate based on global index
 *
 * mask_positions: Array of charset definitions per position
 * mask_len: Number of positions in mask
 * idx: Global candidate index
 * out: Output password buffer
 */
__device__ void generate_mask_candidate(const MaskPosition *mask_positions,
                                        uint32_t mask_len, uint64_t idx,
                                        uint8_t *out, uint32_t *out_len) {
  // Convert index to password using mixed-radix representation
  // Position 0 is rightmost (changes fastest)
  for (int32_t pos = mask_len - 1; pos >= 0; pos--) {
    uint8_t count = mask_positions[pos].count;
    out[pos] = mask_positions[pos].charset[idx % count];
    idx /= count;
  }
  *out_len = mask_len;
}

/*
 * Calculate total keyspace for a mask
 */
__host__ __device__ uint64_t
calculate_mask_keyspace(const MaskPosition *mask_positions, uint32_t mask_len) {
  uint64_t total = 1;
  for (uint32_t i = 0; i < mask_len; i++) {
    total *= mask_positions[i].count;
  }
  return total;
}

/*
 * Generate incremental brute-force candidate (all printable ASCII)
 * Useful for simple exhaustive search
 */
__device__ void generate_bruteforce_candidate(uint64_t idx, uint32_t length,
                                              uint8_t *out) {
  const uint8_t base = 95; // Printable ASCII: 32-126
  for (int32_t pos = length - 1; pos >= 0; pos--) {
    out[pos] = 32 + (idx % base);
    idx /= base;
  }
}

/*
 * Load dictionary word from global memory
 * Words stored as length-prefixed strings in packed buffer
 */
__device__ void load_dictionary_word(const uint8_t *dict_buffer,
                                     const uint32_t *word_offsets,
                                     uint32_t word_idx, uint8_t *out,
                                     uint32_t *out_len) {
  uint32_t offset = word_offsets[word_idx];
  *out_len = dict_buffer[offset];
  for (uint32_t i = 0; i < *out_len && i < MAX_PASSWORD_LEN; i++) {
    out[i] = dict_buffer[offset + 1 + i];
  }
}

} // namespace h3xer
#endif
