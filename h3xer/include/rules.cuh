/*
 * H3XER - Rule-based Password Mutations
 * Applies transformation rules to base words
 */

#ifndef H3XER_RULES_CUH
#define H3XER_RULES_CUH

#include "h3xer_types.cuh"

namespace h3xer {

// Rule operations
enum RuleOp : uint8_t {
  RULE_NOOP = 0,     // No operation
  RULE_LOWER,        // Lowercase all
  RULE_UPPER,        // Uppercase all
  RULE_CAPITALIZE,   // Capitalize first
  RULE_TOGGLE,       // Toggle case
  RULE_REVERSE,      // Reverse string
  RULE_DUPLICATE,    // Duplicate: word -> wordword
  RULE_APPEND_CHAR,  // Append character
  RULE_PREPEND_CHAR, // Prepend character
  RULE_APPEND_NUM,   // Append number 0-9999
  RULE_LEET,         // l33t speak substitution
  RULE_ROTATE_LEFT,  // Rotate left
  RULE_ROTATE_RIGHT, // Rotate right
  RULE_DELETE_FIRST, // Delete first char
  RULE_DELETE_LAST,  // Delete last char
};

// Single rule with optional argument
struct Rule {
  RuleOp op;
  uint8_t arg;   // Character or number argument
  uint16_t arg2; // Extended argument (for append_num range)
};

// Rule chain (up to 8 rules applied sequentially)
struct RuleChain {
  Rule rules[8];
  uint8_t count;
};

// Apply single rule to password in-place
__device__ void apply_rule(uint8_t *password, uint32_t *len, const Rule &rule) {
  uint32_t L = *len;

  switch (rule.op) {
  case RULE_LOWER:
    for (uint32_t i = 0; i < L; i++) {
      if (password[i] >= 'A' && password[i] <= 'Z')
        password[i] += 32;
    }
    break;

  case RULE_UPPER:
    for (uint32_t i = 0; i < L; i++) {
      if (password[i] >= 'a' && password[i] <= 'z')
        password[i] -= 32;
    }
    break;

  case RULE_CAPITALIZE:
    if (L > 0 && password[0] >= 'a' && password[0] <= 'z')
      password[0] -= 32;
    for (uint32_t i = 1; i < L; i++) {
      if (password[i] >= 'A' && password[i] <= 'Z')
        password[i] += 32;
    }
    break;

  case RULE_TOGGLE:
    for (uint32_t i = 0; i < L; i++) {
      if (password[i] >= 'A' && password[i] <= 'Z')
        password[i] += 32;
      else if (password[i] >= 'a' && password[i] <= 'z')
        password[i] -= 32;
    }
    break;

  case RULE_REVERSE:
    for (uint32_t i = 0; i < L / 2; i++) {
      uint8_t t = password[i];
      password[i] = password[L - 1 - i];
      password[L - 1 - i] = t;
    }
    break;

  case RULE_DUPLICATE:
    if (L * 2 <= MAX_PASSWORD_LEN) {
      for (uint32_t i = 0; i < L; i++)
        password[L + i] = password[i];
      *len = L * 2;
    }
    break;

  case RULE_APPEND_CHAR:
    if (L < MAX_PASSWORD_LEN) {
      password[L] = rule.arg;
      *len = L + 1;
    }
    break;

  case RULE_PREPEND_CHAR:
    if (L < MAX_PASSWORD_LEN) {
      for (uint32_t i = L; i > 0; i--)
        password[i] = password[i - 1];
      password[0] = rule.arg;
      *len = L + 1;
    }
    break;

  case RULE_LEET:
    for (uint32_t i = 0; i < L; i++) {
      switch (password[i]) {
      case 'a':
      case 'A':
        password[i] = '4';
        break;
      case 'e':
      case 'E':
        password[i] = '3';
        break;
      case 'i':
      case 'I':
        password[i] = '1';
        break;
      case 'o':
      case 'O':
        password[i] = '0';
        break;
      case 's':
      case 'S':
        password[i] = '5';
        break;
      case 't':
      case 'T':
        password[i] = '7';
        break;
      }
    }
    break;

  case RULE_ROTATE_LEFT:
    if (L > 1) {
      uint8_t first = password[0];
      for (uint32_t i = 0; i < L - 1; i++)
        password[i] = password[i + 1];
      password[L - 1] = first;
    }
    break;

  case RULE_ROTATE_RIGHT:
    if (L > 1) {
      uint8_t last = password[L - 1];
      for (uint32_t i = L - 1; i > 0; i--)
        password[i] = password[i - 1];
      password[0] = last;
    }
    break;

  case RULE_DELETE_FIRST:
    if (L > 1) {
      for (uint32_t i = 0; i < L - 1; i++)
        password[i] = password[i + 1];
      *len = L - 1;
    }
    break;

  case RULE_DELETE_LAST:
    if (L > 1)
      *len = L - 1;
    break;

  default:
    break;
  }
}

// Apply entire rule chain
__device__ void apply_rule_chain(uint8_t *password, uint32_t *len,
                                 const RuleChain &chain) {
  for (uint8_t i = 0; i < chain.count; i++) {
    apply_rule(password, len, chain.rules[i]);
  }
}

// Common rule chains
__device__ RuleChain make_append_123() {
  RuleChain c = {};
  c.rules[0] = {RULE_APPEND_CHAR, '1', 0};
  c.rules[1] = {RULE_APPEND_CHAR, '2', 0};
  c.rules[2] = {RULE_APPEND_CHAR, '3', 0};
  c.count = 3;
  return c;
}

__device__ RuleChain make_capitalize_leet() {
  RuleChain c = {};
  c.rules[0] = {RULE_CAPITALIZE, 0, 0};
  c.rules[1] = {RULE_LEET, 0, 0};
  c.count = 2;
  return c;
}

} // namespace h3xer
#endif
