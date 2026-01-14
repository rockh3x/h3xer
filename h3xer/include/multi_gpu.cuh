/*
 * H3XER - Multi-GPU Support
 * Distributes work across multiple NVIDIA GPUs
 */

#ifndef H3XER_MULTI_GPU_CUH
#define H3XER_MULTI_GPU_CUH

#include <cstdio>
#include <cuda_runtime.h>
#include <thread>
#include <vector>


namespace h3xer {

struct GpuInfo {
  int id;
  char name[256];
  int sm_count;
  size_t memory_bytes;
  int compute_major;
  int compute_minor;
  float relative_power; // Normalized performance weight
};

class MultiGpuManager {
public:
  bool init() {
    int count;
    cudaGetDeviceCount(&count);
    if (count == 0)
      return false;

    float total_power = 0;
    for (int i = 0; i < count; i++) {
      cudaDeviceProp prop;
      cudaGetDeviceProperties(&prop, i);

      GpuInfo info;
      info.id = i;
      strncpy(info.name, prop.name, 255);
      info.sm_count = prop.multiProcessorCount;
      info.memory_bytes = prop.totalGlobalMem;
      info.compute_major = prop.major;
      info.compute_minor = prop.minor;

      // Estimate relative power based on SM count and compute capability
      info.relative_power = (float)info.sm_count *
                            (info.compute_major + info.compute_minor * 0.1f);
      total_power += info.relative_power;

      m_gpus.push_back(info);
    }

    // Normalize weights
    for (auto &gpu : m_gpus) {
      gpu.relative_power /= total_power;
    }

    return true;
  }

  size_t gpu_count() const { return m_gpus.size(); }
  const GpuInfo &gpu(int idx) const { return m_gpus[idx]; }

  void print_info() const {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════╗\n");
    printf("║               Available GPUs (%zu total)               ║\n",
           m_gpus.size());
    printf("╠═══════════════════════════════════════════════════════╣\n");

    for (const auto &g : m_gpus) {
      printf("║ [%d] %-40s      ║\n", g.id, g.name);
      printf("║     CC %d.%d | %3d SMs | %5.1f GB | %5.1f%% work    ║\n",
             g.compute_major, g.compute_minor, g.sm_count,
             g.memory_bytes / (1024.0 * 1024 * 1024), g.relative_power * 100);
    }
    printf("╚═══════════════════════════════════════════════════════╝\n\n");
  }

  // Distribute keyspace across GPUs based on relative power
  void distribute_work(uint64_t total_candidates, std::vector<uint64_t> &starts,
                       std::vector<uint64_t> &counts) const {
    starts.resize(m_gpus.size());
    counts.resize(m_gpus.size());

    uint64_t offset = 0;
    for (size_t i = 0; i < m_gpus.size(); i++) {
      starts[i] = offset;
      if (i == m_gpus.size() - 1) {
        counts[i] = total_candidates - offset;
      } else {
        counts[i] = (uint64_t)(total_candidates * m_gpus[i].relative_power);
      }
      offset += counts[i];
    }
  }

private:
  std::vector<GpuInfo> m_gpus;
};

// Thread worker for multi-GPU execution
struct GpuWorker {
  int gpu_id;
  uint64_t start_idx;
  uint64_t num_candidates;
  bool found;
  uint8_t password[128];
  uint32_t password_len;

  void run(); // Implemented in main.cu
};

} // namespace h3xer
#endif
