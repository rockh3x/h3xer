/*
 * H3XER - RAR5 Archive Header Parser
 * Extracts cryptographic parameters from RAR5 archives
 */

#ifndef H3XER_RAR5_PARSER_H
#define H3XER_RAR5_PARSER_H

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace h3xer {

// RAR5 signature: Rar!\x1a\x07\x01\x00
const uint8_t RAR5_SIGNATURE[] = {0x52, 0x61, 0x72, 0x21,
                                  0x1a, 0x07, 0x01, 0x00};

// RAR5 header types
enum Rar5HeaderType {
  RAR5_HEAD_MAIN = 1,
  RAR5_HEAD_FILE = 2,
  RAR5_HEAD_SERVICE = 3,
  RAR5_HEAD_CRYPT = 4,
  RAR5_HEAD_ENDARC = 5
};

// RAR5 encryption header data
struct Rar5CryptHeader {
  uint8_t salt[16];          // PBKDF2 salt
  uint8_t check_value[16];   // Encrypted check bytes
  uint8_t pswcheck[8];       // Optional password check value
  uint32_t pswcheck_present; // 1 if pswcheck is available
  uint32_t kdf_count;        // log2(iterations) - 1, default 15 = 32768 iters
  bool use_tweaked_checksum; // RAR 5.0+ uses tweaked checksum
};

// Read vint (variable-length integer) from buffer
inline uint64_t read_vint(const uint8_t *data, size_t *bytes_read) {
  uint64_t result = 0;
  size_t shift = 0;
  size_t count = 0;

  do {
    result |= ((uint64_t)(data[count] & 0x7f)) << shift;
    shift += 7;
    count++;
  } while (data[count - 1] & 0x80 && count < 10);

  *bytes_read = count;
  return result;
}

/*
 * Parse RAR5 archive and extract encryption parameters
 * Returns true if encryption header found and parsed successfully
 */
inline bool parse_rar5_header(const char *filepath, Rar5CryptHeader *crypt) {
  FILE *fp = fopen(filepath, "rb");
  if (!fp) {
    fprintf(stderr, "[!] Cannot open file: %s\n", filepath);
    return false;
  }

  // Read signature
  uint8_t sig[8];
  if (fread(sig, 1, 8, fp) != 8) {
    fclose(fp);
    return false;
  }

  // Verify RAR5 signature
  if (memcmp(sig, RAR5_SIGNATURE, 8) != 0) {
    fprintf(stderr, "[!] Not a RAR5 archive (wrong signature)\n");
    fclose(fp);
    return false;
  }

  printf("[+] Valid RAR5 signature found\n");

  // Read headers until we find encryption header
  uint8_t header_buf[4096];
  bool found_crypt = false;

  while (!feof(fp) && !found_crypt) {
    long header_pos = ftell(fp);

    // Read header CRC (4 bytes)
    uint32_t header_crc;
    if (fread(&header_crc, 4, 1, fp) != 1)
      break;

    // Read header size (vint)
    uint8_t vint_buf[10];
    if (fread(vint_buf, 1, 10, fp) < 1)
      break;

    size_t vint_len;
    uint64_t header_size = read_vint(vint_buf, &vint_len);

    // Seek back and read full header
    fseek(fp, header_pos + 4, SEEK_SET);

    size_t to_read =
        (header_size < sizeof(header_buf)) ? header_size : sizeof(header_buf);
    if (fread(header_buf, 1, to_read, fp) != to_read)
      break;

    // Parse header type
    size_t offset = vint_len;
    uint64_t header_type = read_vint(header_buf + offset, &vint_len);
    offset += vint_len;

    // Parse header flags
    uint64_t header_flags = read_vint(header_buf + offset, &vint_len);
    offset += vint_len;

    printf("[*] Header type: %lu, flags: 0x%lx\n", header_type, header_flags);

    // Check for encryption header
    if (header_type == RAR5_HEAD_CRYPT) {
      printf("[+] Found encryption header!\n");

      // Parse encryption record
      // Format: KDF count (1 byte) + salt (16 bytes) + check value (12+ bytes)

      if (offset + 1 + 16 + 16 <= header_size) {
        crypt->kdf_count = header_buf[offset];
        offset++;

        memcpy(crypt->salt, header_buf + offset, 16);
        offset += 16;

        // Check if pswcheck is present (flag bit)
        if (header_flags & 0x01) {
          // Has pswcheck (8 bytes)
          memcpy(crypt->pswcheck, header_buf + offset, 8);
          crypt->pswcheck_present = 1;
          offset += 8;
        } else {
          crypt->pswcheck_present = 0;
        }

        // Read encrypted check value
        memcpy(crypt->check_value, header_buf + offset, 16);

        found_crypt = true;

        printf("[+] KDF iterations: 2^%u = %u\n", crypt->kdf_count + 1,
               1u << (crypt->kdf_count + 1));
        printf("[+] Salt: ");
        for (int i = 0; i < 16; i++)
          printf("%02x", crypt->salt[i]);
        printf("\n");
      }
    }

    // Move to next header
    fseek(fp, header_pos + 4 + header_size, SEEK_SET);
  }

  fclose(fp);

  if (!found_crypt) {
    fprintf(stderr,
            "[!] No encryption header found. Archive may not be encrypted.\n");
    return false;
  }

  return true;
}

/*
 * Quick check if file is encrypted RAR5
 */
inline bool is_encrypted_rar5(const char *filepath) {
  FILE *fp = fopen(filepath, "rb");
  if (!fp)
    return false;

  uint8_t sig[8];
  if (fread(sig, 1, 8, fp) != 8) {
    fclose(fp);
    return false;
  }

  fclose(fp);

  // Check RAR5 signature
  return memcmp(sig, RAR5_SIGNATURE, 8) == 0;
}

} // namespace h3xer

#endif // H3XER_RAR5_PARSER_H
