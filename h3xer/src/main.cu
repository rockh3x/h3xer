/*
 * H3XER - RAR5 Password Recovery Tool
 * Complete Host-side Driver with RAR5 Parser Integration
 */

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cuda_runtime.h>
#include <fstream>
#include <string>
#include <vector>

#include "../include/h3xer_types.cuh"
#include "../include/kernel.cuh"
#include "../include/rar5_parser.h"

using namespace h3xer;

// CUDA error checking macro
#define CUDA_CHECK(call)                                                       \
  do {                                                                         \
    cudaError_t err = call;                                                    \
    if (err != cudaSuccess) {                                                  \
      fprintf(stderr, "[!] CUDA Error %s:%d: %s\n", __FILE__, __LINE__,        \
              cudaGetErrorString(err));                                        \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

// Configuration
struct Config {
  std::string archive_path;
  std::string mask;
  std::string dictionary_path;
  std::string rules_file;
  int gpu_id = -1;
  bool benchmark = false;
  bool verbose = false;
  uint32_t min_len = 1;
  uint32_t max_len = 8;
};

/*
 * Dictionary Manager
 * Loads and manages wordlist for dictionary attacks
 */
class DictionaryManager {
public:
  bool load(const std::string &path) {
    std::ifstream file(path);
    if (!file.is_open()) {
      fprintf(stderr, "[!] Cannot open dictionary: %s\n", path.c_str());
      return false;
    }

    std::string line;
    size_t total_bytes = 0;

    while (std::getline(file, line)) {
      if (line.empty() || line.length() > MAX_PASSWORD_LEN)
        continue;

      // Remove trailing \r if present
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }

      m_words.push_back(line);
      total_bytes += line.length() + 1;
    }

    printf("[+] Loaded %zu words from dictionary (%.2f MB)\n", m_words.size(),
           total_bytes / (1024.0 * 1024.0));

    return !m_words.empty();
  }

  size_t size() const { return m_words.size(); }
  const std::string &operator[](size_t idx) const { return m_words[idx]; }

  // Pack words into GPU-friendly format
  bool upload_to_gpu(uint8_t **d_buffer, uint32_t **d_offsets) {
    if (m_words.empty())
      return false;

    // Calculate total size
    std::vector<uint32_t> offsets;
    std::vector<uint8_t> packed;

    for (const auto &word : m_words) {
      offsets.push_back((uint32_t)packed.size());
      packed.push_back((uint8_t)word.length());
      packed.insert(packed.end(), word.begin(), word.end());
    }

    // Upload to GPU
    CUDA_CHECK(cudaMalloc(d_buffer, packed.size()));
    CUDA_CHECK(cudaMemcpy(*d_buffer, packed.data(), packed.size(),
                          cudaMemcpyHostToDevice));

    CUDA_CHECK(cudaMalloc(d_offsets, offsets.size() * sizeof(uint32_t)));
    CUDA_CHECK(cudaMemcpy(*d_offsets, offsets.data(),
                          offsets.size() * sizeof(uint32_t),
                          cudaMemcpyHostToDevice));

    return true;
  }

private:
  std::vector<std::string> m_words;
};

/*
 * H3xer Cracker Class
 * Manages GPU resources and cracking operations
 */
class H3xerCracker {
public:
  H3xerCracker()
      : m_device_id(0), m_total_candidates(0), m_processed(0),
        m_d_dict_buffer(nullptr), m_d_dict_offsets(nullptr) {
    memset(&m_header, 0, sizeof(m_header));
    memset(&m_crypt_header, 0, sizeof(m_crypt_header));
  }

  ~H3xerCracker() { cleanup(); }

  bool initialize(int device_id = -1) {
    int device_count;
    CUDA_CHECK(cudaGetDeviceCount(&device_count));

    if (device_count == 0) {
      fprintf(stderr, "[!] No CUDA-capable devices found\n");
      return false;
    }

    // Select best device or use specified
    if (device_id >= 0) {
      m_device_id = device_id;
    } else {
      m_device_id = 0;
      int max_sm = 0;
      for (int i = 0; i < device_count; i++) {
        cudaDeviceProp prop;
        CUDA_CHECK(cudaGetDeviceProperties(&prop, i));
        int sm = prop.multiProcessorCount;
        if (sm > max_sm) {
          max_sm = sm;
          m_device_id = i;
        }
      }
    }

    CUDA_CHECK(cudaSetDevice(m_device_id));
    CUDA_CHECK(cudaGetDeviceProperties(&m_device_prop, m_device_id));

    printf("[+] GPU %d: %s (CC %d.%d, %d SMs, %.1f GB)\n", m_device_id,
           m_device_prop.name, m_device_prop.major, m_device_prop.minor,
           m_device_prop.multiProcessorCount,
           m_device_prop.totalGlobalMem / (1024.0 * 1024.0 * 1024.0));

    // Optimal launch config
    m_blocks = m_device_prop.multiProcessorCount * 4;
    m_threads = THREADS_PER_BLOCK;

    return true;
  }

  bool load_archive(const std::string &path) {
    printf("[*] Parsing RAR5 archive: %s\n", path.c_str());

    if (!parse_rar5_header(path.c_str(), &m_crypt_header)) {
      return false;
    }

    // Copy to internal header structure
    memcpy(m_header.salt, m_crypt_header.salt, RAR5_SALT_SIZE);
    memcpy(m_header.check_value, m_crypt_header.check_value, RAR5_CHECK_SIZE);
    memset(m_header.iv, 0, AES_BLOCK_SIZE);

    if (m_crypt_header.pswcheck_present) {
      memcpy(m_header.pswcheck, m_crypt_header.pswcheck, 8);
      m_header.pswcheck_present = 1;
      printf("[+] Password check value present\n");
    } else {
      m_header.pswcheck_present = 0;
    }

    // Upload to GPU constant memory
    CUDA_CHECK(cudaMemcpyToSymbol(g_header, &m_header, sizeof(Rar5Header)));

    return true;
  }

  bool load_header_manual(const uint8_t *salt, const uint8_t *check_value,
                          const uint8_t *pswcheck = nullptr) {
    memcpy(m_header.salt, salt, RAR5_SALT_SIZE);
    memcpy(m_header.check_value, check_value, RAR5_CHECK_SIZE);
    memset(m_header.iv, 0, AES_BLOCK_SIZE);

    if (pswcheck) {
      memcpy(m_header.pswcheck, pswcheck, 8);
      m_header.pswcheck_present = 1;
    } else {
      m_header.pswcheck_present = 0;
    }

    CUDA_CHECK(cudaMemcpyToSymbol(g_header, &m_header, sizeof(Rar5Header)));
    return true;
  }

  bool setup_mask(const char *mask_pattern) {
    m_mask_len = 0;
    m_total_candidates = 1;

    const char *p = mask_pattern;
    while (*p && m_mask_len < MAX_MASK_LEN) {
      MaskPosition &pos = m_mask_positions[m_mask_len];

      if (*p == '?' && *(p + 1)) {
        char type = *(p + 1);
        switch (type) {
        case 'l':
          memcpy(pos.charset, "abcdefghijklmnopqrstuvwxyz", 26);
          pos.count = 26;
          break;
        case 'u':
          memcpy(pos.charset, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26);
          pos.count = 26;
          break;
        case 'd':
          memcpy(pos.charset, "0123456789", 10);
          pos.count = 10;
          break;
        case 'a':
          memcpy(
              pos.charset,
              "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
              62);
          pos.count = 62;
          break;
        case 's':
          memcpy(pos.charset, " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 33);
          pos.count = 33;
          break;
        case 'b': // binary (all bytes 0-255)
          for (int i = 0; i < 256; i++)
            pos.charset[i] = (uint8_t)i;
          pos.count = 256;
          break;
        case 'h': // hex lowercase
          memcpy(pos.charset, "0123456789abcdef", 16);
          pos.count = 16;
          break;
        case 'H': // hex uppercase
          memcpy(pos.charset, "0123456789ABCDEF", 16);
          pos.count = 16;
          break;
        default:
          pos.charset[0] = type;
          pos.count = 1;
        }
        p += 2;
      } else {
        pos.charset[0] = *p;
        pos.count = 1;
        p++;
      }

      m_total_candidates *= pos.count;
      m_mask_len++;
    }

    CUDA_CHECK(cudaMemcpyToSymbol(g_mask, m_mask_positions,
                                  sizeof(MaskPosition) * m_mask_len));
    CUDA_CHECK(cudaMemcpyToSymbol(g_mask_len, &m_mask_len, sizeof(uint32_t)));

    printf("[+] Mask: %s (%u positions, %llu candidates)\n", mask_pattern,
           m_mask_len, (unsigned long long)m_total_candidates);

    return true;
  }

  bool setup_dictionary(const std::string &path) {
    if (!m_dict.load(path)) {
      return false;
    }

    if (!m_dict.upload_to_gpu(&m_d_dict_buffer, &m_d_dict_offsets)) {
      return false;
    }

    m_total_candidates = m_dict.size();
    return true;
  }

  bool run_mask_attack() {
    printf("[*] Starting mask attack (%llu candidates)...\n",
           (unsigned long long)m_total_candidates);

    reset_found_flag();
    auto start_time = std::chrono::high_resolution_clock::now();
    uint64_t batch_size = (uint64_t)m_blocks * m_threads * 8;

    for (uint64_t idx = 0; idx < m_total_candidates; idx += batch_size) {
      uint64_t remaining = m_total_candidates - idx;
      uint64_t current_batch = std::min(remaining, batch_size);

      rar5_crack_mask_kernel<<<m_blocks, m_threads>>>(idx, current_batch);
      CUDA_CHECK(cudaDeviceSynchronize());

      if (check_found()) {
        return report_result(start_time);
      }

      m_processed = idx + current_batch;
      print_progress(start_time);
    }

    print_exhausted(start_time);
    return false;
  }

  bool run_dictionary_attack() {
    if (!m_d_dict_buffer) {
      fprintf(stderr, "[!] No dictionary loaded\n");
      return false;
    }

    printf("[*] Starting dictionary attack (%zu words)...\n", m_dict.size());

    reset_found_flag();
    auto start_time = std::chrono::high_resolution_clock::now();
    uint32_t batch_size = m_blocks * m_threads;

    for (uint32_t idx = 0; idx < m_dict.size(); idx += batch_size) {
      uint32_t current_batch =
          std::min((uint32_t)(m_dict.size() - idx), batch_size);

      rar5_crack_dict_kernel<<<m_blocks, m_threads>>>(
          m_d_dict_buffer, m_d_dict_offsets, (uint32_t)m_dict.size(), idx);
      CUDA_CHECK(cudaDeviceSynchronize());

      if (check_found()) {
        return report_result(start_time);
      }

      m_processed = idx + current_batch;
      print_progress(start_time);
    }

    print_exhausted(start_time);
    return false;
  }

  bool run_bruteforce(uint32_t min_len, uint32_t max_len) {
    printf("[*] Starting brute-force attack (length %u-%u)...\n", min_len,
           max_len);

    reset_found_flag();
    auto start_time = std::chrono::high_resolution_clock::now();
    uint64_t batch_size = (uint64_t)m_blocks * m_threads * 8;

    for (uint32_t len = min_len; len <= max_len; len++) {
      // 95^len candidates for printable ASCII
      uint64_t keyspace = 1;
      for (uint32_t i = 0; i < len; i++)
        keyspace *= 95;

      printf("[*] Trying length %u (%llu candidates)...\n", len,
             (unsigned long long)keyspace);

      for (uint64_t idx = 0; idx < keyspace; idx += batch_size) {
        uint64_t current_batch = std::min(keyspace - idx, batch_size);

        rar5_crack_bruteforce_kernel<<<m_blocks, m_threads>>>(
            idx, current_batch, len);
        CUDA_CHECK(cudaDeviceSynchronize());

        if (check_found()) {
          return report_result(start_time);
        }

        m_processed += current_batch;
        m_total_candidates = keyspace;
        print_progress(start_time);
      }
    }

    print_exhausted(start_time);
    return false;
  }

  void run_benchmark() {
    printf("[*] Benchmarking PBKDF2-HMAC-SHA256 performance...\n\n");

    // Warm up
    rar5_benchmark_kernel<<<m_blocks, m_threads>>>(1);
    CUDA_CHECK(cudaDeviceSynchronize());

    auto start = std::chrono::high_resolution_clock::now();

    uint64_t iterations = 50; // Each thread does this many PBKDF2 ops
    rar5_benchmark_kernel<<<m_blocks, m_threads>>>(iterations);
    CUDA_CHECK(cudaDeviceSynchronize());

    auto end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();

    uint64_t total_keys = (uint64_t)m_blocks * m_threads * iterations;
    double keys_per_sec = total_keys / elapsed;
    double hash_rate = (keys_per_sec * RAR5_PBKDF2_ITERATIONS) / 1e6;

    printf("  Kernel Config: %d blocks x %d threads\n", m_blocks, m_threads);
    printf("  Elapsed Time:  %.3f seconds\n", elapsed);
    printf("  Keys Tested:   %llu\n", (unsigned long long)total_keys);
    printf("  ─────────────────────────────────\n");
    printf("  Speed:         %.0f keys/sec\n", keys_per_sec);
    printf("  PBKDF2 Rate:   %.2f MH/s\n", hash_rate);
    printf("  ─────────────────────────────────\n\n");

    // Estimate crack times
    printf("  Estimated crack times:\n");
    printf("  4-char lowercase: %.1f sec\n",
           (26.0 * 26 * 26 * 26) / keys_per_sec);
    printf("  6-char lowercase: %.1f hours\n",
           (pow(26, 6)) / keys_per_sec / 3600);
    printf("  8-char lowercase: %.1f days\n",
           (pow(26, 8)) / keys_per_sec / 86400);
    printf("\n");
  }

private:
  void reset_found_flag() {
    uint32_t zero = 0;
    CUDA_CHECK(cudaMemcpyToSymbol(g_found, &zero, sizeof(uint32_t)));
  }

  bool check_found() {
    uint32_t found;
    CUDA_CHECK(cudaMemcpyFromSymbol(&found, g_found, sizeof(uint32_t)));
    return found != 0;
  }

  void print_progress(std::chrono::high_resolution_clock::time_point start) {
    static auto last_update = std::chrono::high_resolution_clock::now();
    auto now = std::chrono::high_resolution_clock::now();

    // Update at most every 500ms
    if (std::chrono::duration<double>(now - last_update).count() < 0.5)
      return;
    last_update = now;

    double elapsed = std::chrono::duration<double>(now - start).count();
    if (elapsed < 0.1)
      return;

    double keys_per_sec = m_processed / elapsed;
    double percent = 100.0 * m_processed / m_total_candidates;
    double eta = (m_total_candidates - m_processed) / keys_per_sec;

    printf("\r[*] %.2f%% | %llu/%llu | %.0f k/s | ETA: %.0fs    ", percent,
           (unsigned long long)m_processed,
           (unsigned long long)m_total_candidates, keys_per_sec, eta);
    fflush(stdout);
  }

  bool report_result(std::chrono::high_resolution_clock::time_point start) {
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();

    uint8_t password[MAX_PASSWORD_LEN];
    uint32_t password_len;

    CUDA_CHECK(
        cudaMemcpyFromSymbol(password, g_found_password, MAX_PASSWORD_LEN));
    CUDA_CHECK(cudaMemcpyFromSymbol(&password_len, g_found_password_len,
                                    sizeof(uint32_t)));

    printf("\n\n");
    printf("╔════════════════════════════════════════╗\n");
    printf("║         PASSWORD FOUND!                ║\n");
    printf("╠════════════════════════════════════════╣\n");
    printf("║  Password: %-28.*s║\n", password_len, password);
    printf("║  Length:   %-28u║\n", password_len);
    printf("║  Time:     %-24.2f sec ║\n", elapsed);
    printf("║  Speed:    %-24.0f k/s ║\n", m_processed / elapsed);
    printf("╚════════════════════════════════════════╝\n\n");

    // Save to file
    FILE *fp = fopen("h3xer_found.txt", "a");
    if (fp) {
      fprintf(fp, "%.*s\n", password_len, password);
      fclose(fp);
      printf("[+] Password saved to h3xer_found.txt\n");
    }

    return true;
  }

  void print_exhausted(std::chrono::high_resolution_clock::time_point start) {
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();
    printf("\n[!] Keyspace exhausted. %llu candidates in %.2f sec (%.0f k/s)\n",
           (unsigned long long)m_total_candidates, elapsed,
           m_total_candidates / elapsed);
  }

  void cleanup() {
    if (m_d_dict_buffer)
      cudaFree(m_d_dict_buffer);
    if (m_d_dict_offsets)
      cudaFree(m_d_dict_offsets);
    cudaDeviceReset();
  }

private:
  int m_device_id;
  cudaDeviceProp m_device_prop;

  Rar5Header m_header;
  Rar5CryptHeader m_crypt_header;
  MaskPosition m_mask_positions[MAX_MASK_LEN];
  uint32_t m_mask_len;

  DictionaryManager m_dict;
  uint8_t *m_d_dict_buffer;
  uint32_t *m_d_dict_offsets;

  uint64_t m_total_candidates;
  uint64_t m_processed;

  int m_blocks;
  int m_threads;
};

void print_banner() {
  printf("\n");
  printf("  ██╗  ██╗██████╗ ██╗  ██╗███████╗██████╗ \n");
  printf("  ██║  ██║╚════██╗╚██╗██╔╝██╔════╝██╔══██╗\n");
  printf("  ███████║ █████╔╝ ╚███╔╝ █████╗  ██████╔╝\n");
  printf("  ██╔══██║ ╚═══██╗ ██╔██╗ ██╔══╝  ██╔══██╗\n");
  printf("  ██║  ██║██████╔╝██╔╝ ██╗███████╗██║  ██║\n");
  printf("  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n");
  printf("  RAR5 Password Recovery v1.0 - CUDA\n\n");
}

void print_usage(const char *prog) {
  printf("Usage: %s [options]\n\n", prog);
  printf("Attack Modes:\n");
  printf("  -m <mask>       Mask attack (?l?u?d?a?s?b?h?H)\n");
  printf("  -d <wordlist>   Dictionary attack\n");
  printf("  -i <min:max>    Brute-force with length range\n\n");
  printf("Target:\n");
  printf("  -f <file.rar>   RAR5 archive to crack\n\n");
  printf("Options:\n");
  printf("  -g <id>         GPU device ID (default: auto)\n");
  printf("  -b              Benchmark mode\n");
  printf("  -v              Verbose output\n");
  printf("  -h              Show this help\n\n");
  printf("Mask Charsets:\n");
  printf("  ?l = a-z       ?u = A-Z       ?d = 0-9\n");
  printf("  ?a = a-zA-Z0-9 ?s = special   ?h = 0-9a-f\n");
  printf("  ?H = 0-9A-F    ?b = 0x00-0xff\n\n");
  printf("Examples:\n");
  printf("  %s -f secret.rar -m \"?l?l?l?l?d?d\"\n", prog);
  printf("  %s -f secret.rar -d rockyou.txt\n", prog);
  printf("  %s -f secret.rar -i 4:6\n", prog);
  printf("  %s -b\n", prog);
}

Config parse_args(int argc, char *argv[]) {
  Config cfg;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
      cfg.archive_path = argv[++i];
    } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
      cfg.mask = argv[++i];
    } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
      cfg.dictionary_path = argv[++i];
    } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
      if (sscanf(argv[++i], "%u:%u", &cfg.min_len, &cfg.max_len) != 2) {
        fprintf(stderr, "[!] Invalid length format. Use -i min:max\n");
      }
    } else if (strcmp(argv[i], "-g") == 0 && i + 1 < argc) {
      cfg.gpu_id = atoi(argv[++i]);
    } else if (strcmp(argv[i], "-b") == 0) {
      cfg.benchmark = true;
    } else if (strcmp(argv[i], "-v") == 0) {
      cfg.verbose = true;
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      print_usage(argv[0]);
      exit(0);
    }
  }

  return cfg;
}

int main(int argc, char *argv[]) {
  print_banner();

  Config cfg = parse_args(argc, argv);
  H3xerCracker cracker;

  if (!cracker.initialize(cfg.gpu_id)) {
    return 1;
  }

  // Benchmark mode
  if (cfg.benchmark) {
    cracker.run_benchmark();
    return 0;
  }

  // Load archive (required for attacks)
  if (cfg.archive_path.empty()) {
    // Demo mode with dummy header
    printf("[*] No archive specified - using demo mode\n");
    uint8_t salt[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t check[16] = {0};
    cracker.load_header_manual(salt, check);
  } else {
    if (!cracker.load_archive(cfg.archive_path)) {
      fprintf(stderr, "[!] Failed to parse archive\n");
      return 1;
    }
  }

  // Run attack based on mode
  if (!cfg.mask.empty()) {
    cracker.setup_mask(cfg.mask.c_str());
    cracker.run_mask_attack();
  } else if (!cfg.dictionary_path.empty()) {
    cracker.setup_dictionary(cfg.dictionary_path);
    cracker.run_dictionary_attack();
  } else if (cfg.min_len > 0 && cfg.max_len >= cfg.min_len) {
    cracker.run_bruteforce(cfg.min_len, cfg.max_len);
  } else {
    // Default: 4-char lowercase demo
    printf("[*] No attack mode specified - running demo\n");
    cracker.setup_mask("?l?l?l?l");
    cracker.run_mask_attack();
  }

  return 0;
}
