/*
 * H3XER - Progress Display
 * Real-time status and ETA calculations
 */

#ifndef H3XER_PROGRESS_CUH
#define H3XER_PROGRESS_CUH

#include <chrono>
#include <cstdint>
#include <cstdio>


namespace h3xer {

class ProgressDisplay {
public:
  void start(uint64_t total) {
    m_total = total;
    m_done = 0;
    m_start_time = std::chrono::high_resolution_clock::now();
    m_last_update = m_start_time;
  }

  void update(uint64_t done) {
    m_done = done;

    auto now = std::chrono::high_resolution_clock::now();
    double since_update =
        std::chrono::duration<double>(now - m_last_update).count();

    // Update display max every 250ms
    if (since_update < 0.25)
      return;
    m_last_update = now;

    display();
  }

  void finish(bool found) {
    display();
    printf("\n");
    if (!found) {
      printf("[!] Keyspace exhausted - password not found\n");
    }
  }

private:
  void display() {
    auto now = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(now - m_start_time).count();

    double percent = 100.0 * m_done / m_total;
    double keys_per_sec = (elapsed > 0.1) ? m_done / elapsed : 0;
    double remaining = m_total - m_done;
    double eta_sec = (keys_per_sec > 0) ? remaining / keys_per_sec : 0;

    // Build progress bar
    int bar_width = 30;
    int filled = (int)(bar_width * m_done / m_total);

    printf("\r[");
    for (int i = 0; i < bar_width; i++) {
      if (i < filled)
        printf("█");
      else if (i == filled)
        printf("▓");
      else
        printf("░");
    }
    printf("] ");

    printf("%5.1f%% ", percent);
    printf("%.0f k/s ", keys_per_sec / 1000);

    // Format ETA
    if (eta_sec < 60) {
      printf("ETA: %.0fs", eta_sec);
    } else if (eta_sec < 3600) {
      printf("ETA: %.0fm", eta_sec / 60);
    } else if (eta_sec < 86400) {
      printf("ETA: %.1fh", eta_sec / 3600);
    } else {
      printf("ETA: %.1fd", eta_sec / 86400);
    }

    printf("     ");
    fflush(stdout);
  }

  uint64_t m_total;
  uint64_t m_done;
  std::chrono::high_resolution_clock::time_point m_start_time;
  std::chrono::high_resolution_clock::time_point m_last_update;
};

// Format large numbers with commas
inline void format_number(uint64_t n, char *buf, size_t buf_size) {
  if (n < 1000) {
    snprintf(buf, buf_size, "%llu", (unsigned long long)n);
  } else if (n < 1000000) {
    snprintf(buf, buf_size, "%.1fK", n / 1000.0);
  } else if (n < 1000000000) {
    snprintf(buf, buf_size, "%.1fM", n / 1000000.0);
  } else if (n < 1000000000000ULL) {
    snprintf(buf, buf_size, "%.1fB", n / 1000000000.0);
  } else {
    snprintf(buf, buf_size, "%.1fT", n / 1000000000000.0);
  }
}

// Format time duration
inline void format_duration(double seconds, char *buf, size_t buf_size) {
  if (seconds < 60) {
    snprintf(buf, buf_size, "%.1f sec", seconds);
  } else if (seconds < 3600) {
    snprintf(buf, buf_size, "%.1f min", seconds / 60);
  } else if (seconds < 86400) {
    snprintf(buf, buf_size, "%.1f hours", seconds / 3600);
  } else if (seconds < 86400 * 365) {
    snprintf(buf, buf_size, "%.1f days", seconds / 86400);
  } else {
    snprintf(buf, buf_size, "%.1f years", seconds / (86400 * 365));
  }
}

} // namespace h3xer
#endif
