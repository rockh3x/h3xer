/*
 * H3XER - Session Save/Restore
 * Allows resuming interrupted cracking sessions
 */

#ifndef H3XER_SESSION_H
#define H3XER_SESSION_H

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace h3xer {

// Session state for saving/restoring progress
struct Session {
  char archive_path[512];    // Target archive
  char attack_mode[32];      // "mask", "dict", "bruteforce"
  char mask[256];            // Mask pattern (if mask attack)
  char dict_path[512];       // Dictionary path (if dict attack)
  uint64_t candidates_total; // Total keyspace
  uint64_t candidates_done;  // Completed candidates
  uint32_t password_len_min; // For bruteforce
  uint32_t password_len_max;
  uint32_t password_len_cur; // Current length being tested
  uint8_t salt[16];          // Archive salt
  uint8_t check_value[16];   // Archive check value
  uint32_t timestamp;        // Last update time
  uint32_t version;          // Session format version
};

constexpr uint32_t SESSION_VERSION = 1;

// Save session to file
inline bool save_session(const char *path, const Session &session) {
  FILE *fp = fopen(path, "wb");
  if (!fp)
    return false;

  Session s = session;
  s.version = SESSION_VERSION;

  size_t written = fwrite(&s, sizeof(Session), 1, fp);
  fclose(fp);

  return written == 1;
}

// Load session from file
inline bool load_session(const char *path, Session &session) {
  FILE *fp = fopen(path, "rb");
  if (!fp)
    return false;

  size_t read = fread(&session, sizeof(Session), 1, fp);
  fclose(fp);

  if (read != 1)
    return false;
  if (session.version != SESSION_VERSION) {
    fprintf(stderr, "[!] Session version mismatch\n");
    return false;
  }

  return true;
}

// Print session summary
inline void print_session(const Session &s) {
  double progress = 100.0 * s.candidates_done / s.candidates_total;

  printf("Session Info:\n");
  printf("  Archive:    %s\n", s.archive_path);
  printf("  Attack:     %s\n", s.attack_mode);

  if (strcmp(s.attack_mode, "mask") == 0) {
    printf("  Mask:       %s\n", s.mask);
  } else if (strcmp(s.attack_mode, "dict") == 0) {
    printf("  Dictionary: %s\n", s.dict_path);
  } else if (strcmp(s.attack_mode, "bruteforce") == 0) {
    printf("  Length:     %u-%u (current: %u)\n", s.password_len_min,
           s.password_len_max, s.password_len_cur);
  }

  printf("  Progress:   %.2f%% (%llu / %llu)\n", progress,
         (unsigned long long)s.candidates_done,
         (unsigned long long)s.candidates_total);
  printf("  Salt:       ");
  for (int i = 0; i < 16; i++)
    printf("%02x", s.salt[i]);
  printf("\n");
}

// Default session file path
inline const char *get_default_session_path() { return "h3xer.session"; }

} // namespace h3xer
#endif
