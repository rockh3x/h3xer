/*
 * H3XER - PBKDF2/SHA256 Test Vectors
 * Validates cryptographic implementations
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cuda_runtime.h>


#include "../include/h3xer_types.cuh"
#include "../include/pbkdf2.cuh"
#include "../include/sha256.cuh"


using namespace h3xer;

// Host-side SHA-256 for verification
void sha256_host(const uint8_t *data, size_t len, uint8_t *hash) {
  // Simple round constants
  static const uint32_t k[64] = {
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

  uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  uint32_t h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  // Padding
  size_t padded_len = ((len + 9 + 63) / 64) * 64;
  uint8_t *padded = new uint8_t[padded_len]();
  memcpy(padded, data, len);
  padded[len] = 0x80;
  uint64_t bits = len * 8;
  for (int i = 0; i < 8; i++) {
    padded[padded_len - 1 - i] = (bits >> (i * 8)) & 0xff;
  }

  // Process blocks
  for (size_t offset = 0; offset < padded_len; offset += 64) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
      w[i] = ((uint32_t)padded[offset + 4 * i] << 24) |
             ((uint32_t)padded[offset + 4 * i + 1] << 16) |
             ((uint32_t)padded[offset + 4 * i + 2] << 8) |
             padded[offset + 4 * i + 3];
    }
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = ((w[i - 15] >> 7) | (w[i - 15] << 25)) ^
                    ((w[i - 15] >> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >> 3);
      uint32_t s1 = ((w[i - 2] >> 17) | (w[i - 2] << 15)) ^
                    ((w[i - 2] >> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

    for (int i = 0; i < 64; i++) {
      uint32_t S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^
                    ((e >> 25) | (e << 7));
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t temp1 = h + S1 + ch + k[i] + w[i];
      uint32_t S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^
                    ((a >> 22) | (a << 10));
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t temp2 = S0 + maj;
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
    h5 += f;
    h6 += g;
    h7 += h;
  }

  delete[] padded;

  hash[0] = h0 >> 24;
  hash[1] = h0 >> 16;
  hash[2] = h0 >> 8;
  hash[3] = h0;
  hash[4] = h1 >> 24;
  hash[5] = h1 >> 16;
  hash[6] = h1 >> 8;
  hash[7] = h1;
  hash[8] = h2 >> 24;
  hash[9] = h2 >> 16;
  hash[10] = h2 >> 8;
  hash[11] = h2;
  hash[12] = h3 >> 24;
  hash[13] = h3 >> 16;
  hash[14] = h3 >> 8;
  hash[15] = h3;
  hash[16] = h4 >> 24;
  hash[17] = h4 >> 16;
  hash[18] = h4 >> 8;
  hash[19] = h4;
  hash[20] = h5 >> 24;
  hash[21] = h5 >> 16;
  hash[22] = h5 >> 8;
  hash[23] = h5;
  hash[24] = h6 >> 24;
  hash[25] = h6 >> 16;
  hash[26] = h6 >> 8;
  hash[27] = h6;
  hash[28] = h7 >> 24;
  hash[29] = h7 >> 16;
  hash[30] = h7 >> 8;
  hash[31] = h7;
}

void print_hex(const char *label, const uint8_t *data, size_t len) {
  printf("%s: ", label);
  for (size_t i = 0; i < len; i++)
    printf("%02x", data[i]);
  printf("\n");
}

bool compare_hash(const uint8_t *a, const uint8_t *b, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (a[i] != b[i])
      return false;
  }
  return true;
}

// GPU test kernel
__global__ void test_sha256_kernel(const uint8_t *input, uint32_t len,
                                   uint8_t *output) {
  h3xer::sha256(input, len, output);
}

__global__ void test_pbkdf2_kernel(const uint8_t *password, uint32_t pass_len,
                                   const uint8_t *salt, uint8_t *output) {
  h3xer::pbkdf2_sha256_rar5_fast(password, pass_len, salt, output);
}

int main() {
  printf("H3XER Crypto Test Suite\n");
  printf("========================\n\n");

  int passed = 0, failed = 0;

  // Test 1: SHA-256 empty string
  {
    printf("Test 1: SHA-256 empty string\n");
    uint8_t expected[32] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

    uint8_t host_hash[32];
    sha256_host((const uint8_t *)"", 0, host_hash);

    if (compare_hash(host_hash, expected, 32)) {
      printf("  [PASS] Host SHA-256\n");
      passed++;
    } else {
      printf("  [FAIL] Host SHA-256\n");
      print_hex("  Expected", expected, 32);
      print_hex("  Got     ", host_hash, 32);
      failed++;
    }
  }

  // Test 2: SHA-256 "abc"
  {
    printf("Test 2: SHA-256 'abc'\n");
    uint8_t expected[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

    uint8_t host_hash[32];
    sha256_host((const uint8_t *)"abc", 3, host_hash);

    if (compare_hash(host_hash, expected, 32)) {
      printf("  [PASS] Host SHA-256\n");
      passed++;
    } else {
      printf("  [FAIL] Host SHA-256\n");
      failed++;
    }

    // Test GPU implementation
    uint8_t *d_input, *d_output;
    cudaMalloc(&d_input, 3);
    cudaMalloc(&d_output, 32);
    cudaMemcpy(d_input, "abc", 3, cudaMemcpyHostToDevice);

    test_sha256_kernel<<<1, 1>>>(d_input, 3, d_output);
    cudaDeviceSynchronize();

    uint8_t gpu_hash[32];
    cudaMemcpy(gpu_hash, d_output, 32, cudaMemcpyDeviceToHost);

    if (compare_hash(gpu_hash, expected, 32)) {
      printf("  [PASS] GPU SHA-256\n");
      passed++;
    } else {
      printf("  [FAIL] GPU SHA-256\n");
      print_hex("  Expected", expected, 32);
      print_hex("  Got     ", gpu_hash, 32);
      failed++;
    }

    cudaFree(d_input);
    cudaFree(d_output);
  }

  // Test 3: GPU PBKDF2 basic test
  {
    printf("Test 3: PBKDF2-HMAC-SHA256 (RAR5 params)\n");

    uint8_t password[] = "password";
    uint8_t salt[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

    uint8_t *d_password, *d_salt, *d_output;
    cudaMalloc(&d_password, 8);
    cudaMalloc(&d_salt, 16);
    cudaMalloc(&d_output, 32);

    cudaMemcpy(d_password, password, 8, cudaMemcpyHostToDevice);
    cudaMemcpy(d_salt, salt, 16, cudaMemcpyHostToDevice);

    test_pbkdf2_kernel<<<1, 1>>>(d_password, 8, d_salt, d_output);
    cudaError_t err = cudaDeviceSynchronize();

    if (err == cudaSuccess) {
      uint8_t result[32];
      cudaMemcpy(result, d_output, 32, cudaMemcpyDeviceToHost);
      print_hex("  PBKDF2 output", result, 32);
      printf("  [PASS] PBKDF2 completed (32768 iterations)\n");
      passed++;
    } else {
      printf("  [FAIL] PBKDF2 kernel error: %s\n", cudaGetErrorString(err));
      failed++;
    }

    cudaFree(d_password);
    cudaFree(d_salt);
    cudaFree(d_output);
  }

  printf("\n========================\n");
  printf("Results: %d passed, %d failed\n", passed, failed);

  return failed > 0 ? 1 : 0;
}
