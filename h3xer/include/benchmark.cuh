/*
 * H3XER - Benchmarking Utilities
 * For profiling and optimization
 */

#ifndef H3XER_BENCHMARK_CUH
#define H3XER_BENCHMARK_CUH

#include <cstdio>
#include <cuda_runtime.h>


namespace h3xer {

// GPU timing using CUDA events
class GpuTimer {
public:
  GpuTimer() {
    cudaEventCreate(&m_start);
    cudaEventCreate(&m_stop);
  }

  ~GpuTimer() {
    cudaEventDestroy(m_start);
    cudaEventDestroy(m_stop);
  }

  void start() { cudaEventRecord(m_start, 0); }

  void stop() {
    cudaEventRecord(m_stop, 0);
    cudaEventSynchronize(m_stop);
  }

  float elapsed_ms() {
    float ms;
    cudaEventElapsedTime(&ms, m_start, m_stop);
    return ms;
  }

private:
  cudaEvent_t m_start, m_stop;
};

// Benchmark statistics
struct BenchStats {
  double keys_per_sec;
  double hash_rate_mh; // Million PBKDF2 hashes/sec
  double time_4char;   // Time for 4-char lowercase
  double time_6char;   // Time for 6-char lowercase
  double time_8char;   // Time for 8-char lowercase
};

inline void print_bench_stats(const BenchStats &stats) {
  printf("\n");
  printf("╔═══════════════════════════════════════╗\n");
  printf("║        H3XER Benchmark Results        ║\n");
  printf("╠═══════════════════════════════════════╣\n");
  printf("║  Keys/sec:      %'18.0f   ║\n", stats.keys_per_sec);
  printf("║  PBKDF2 Rate:   %15.2f MH/s  ║\n", stats.hash_rate_mh);
  printf("╠═══════════════════════════════════════╣\n");
  printf("║  Estimated crack times:               ║\n");
  printf("║    4-char lower: %14.1f sec  ║\n", stats.time_4char);
  printf("║    6-char lower: %12.1f hours  ║\n", stats.time_6char / 3600);
  printf("║    8-char lower: %13.1f days  ║\n", stats.time_8char / 86400);
  printf("╚═══════════════════════════════════════╝\n\n");
}

// Calculate estimated crack times
inline BenchStats calculate_stats(double keys_per_sec) {
  BenchStats s;
  s.keys_per_sec = keys_per_sec;
  s.hash_rate_mh = (keys_per_sec * 32768) / 1e6; // 32768 PBKDF2 iterations

  // Keyspace sizes for lowercase a-z
  double ks_4 = 26.0 * 26 * 26 * 26;                     // 456,976
  double ks_6 = 26.0 * 26 * 26 * 26 * 26 * 26;           // 308,915,776
  double ks_8 = 26.0 * 26 * 26 * 26 * 26 * 26 * 26 * 26; // 208,827,064,576

  s.time_4char = ks_4 / keys_per_sec;
  s.time_6char = ks_6 / keys_per_sec;
  s.time_8char = ks_8 / keys_per_sec;

  return s;
}

// Print GPU info
inline void print_gpu_info(int device_id) {
  cudaDeviceProp prop;
  cudaGetDeviceProperties(&prop, device_id);

  printf("\n");
  printf("GPU: %s\n", prop.name);
  printf("  Compute:     %d.%d\n", prop.major, prop.minor);
  printf("  SMs:         %d\n", prop.multiProcessorCount);
  printf("  Memory:      %.1f GB\n",
         prop.totalGlobalMem / (1024.0 * 1024 * 1024));
  printf("  Clock:       %d MHz\n", prop.clockRate / 1000);
  printf("  Mem Clock:   %d MHz\n", prop.memoryClockRate / 1000);
  printf("  Bus Width:   %d bit\n", prop.memoryBusWidth);
  printf("  L2 Cache:    %d KB\n", prop.l2CacheSize / 1024);
  printf("\n");
}

} // namespace h3xer
#endif
