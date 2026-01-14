/*
 * H3XER - RAR5 Hash Extractor
 * Extracts cryptographic parameters from RAR5 archives
 * Similar to rar2john but outputs in h3xer format
 */

#include <cstdint>
#include <cstdio>
#include <cstring>


#include "../include/rar5_parser.h"

using namespace h3xer;

void print_hex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
}

void print_usage(const char *prog) {
  printf("H3XER Hash Extractor\n");
  printf("Usage: %s <archive.rar>\n\n", prog);
  printf("Extracts RAR5 encryption parameters for external cracking.\n");
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  const char *filepath = argv[1];
  Rar5CryptHeader crypt;

  printf("[*] Extracting from: %s\n\n", filepath);

  if (!parse_rar5_header(filepath, &crypt)) {
    fprintf(stderr, "[!] Failed to extract encryption parameters\n");
    return 1;
  }

  printf("\n");
  printf("╔════════════════════════════════════════════════════════════════════"
         "╗\n");
  printf("║                    RAR5 Encryption Parameters                      "
         " ║\n");
  printf("╠════════════════════════════════════════════════════════════════════"
         "╣\n");
  printf("║ Salt (16 bytes):                                                   "
         "║\n");
  printf("║   ");
  print_hex(crypt.salt, 16);
  printf("                                 ║\n");
  printf("║                                                                    "
         "║\n");
  printf("║ Check Value (16 bytes):                                            "
         "║\n");
  printf("║   ");
  print_hex(crypt.check_value, 16);
  printf("                                 ║\n");
  printf("║                                                                    "
         "║\n");
  printf(
      "║ PBKDF2 Iterations: 2^%u = %u                                     ║\n",
      crypt.kdf_count + 1, 1u << (crypt.kdf_count + 1));

  if (crypt.pswcheck_present) {
    printf("║                                                                  "
           "  ║\n");
    printf("║ PswCheck (8 bytes):                                              "
           "  ║\n");
    printf("║   ");
    print_hex(crypt.pswcheck, 8);
    printf("                                         ║\n");
  }
  printf("╚════════════════════════════════════════════════════════════════════"
         "╝\n\n");

  // Print in various formats
  printf("H3XER format:\n");
  printf("  --salt=");
  print_hex(crypt.salt, 16);
  printf("\n");
  printf("  --check=");
  print_hex(crypt.check_value, 16);
  printf("\n");
  if (crypt.pswcheck_present) {
    printf("  --pswcheck=");
    print_hex(crypt.pswcheck, 8);
    printf("\n");
  }
  printf("\n");

  // Hashcat-style format (mode 13000 for RAR5)
  printf("Hashcat format (mode 13000):\n");
  printf("  $rar5$16$");
  print_hex(crypt.salt, 16);
  printf("$%u$", 1u << (crypt.kdf_count + 1));
  print_hex(crypt.check_value, 16);
  if (crypt.pswcheck_present) {
    printf("$8$");
    print_hex(crypt.pswcheck, 8);
  }
  printf("\n\n");

  // C array format for testing
  printf("C Array format (for testing):\n");
  printf("  uint8_t salt[16] = {");
  for (int i = 0; i < 16; i++)
    printf("0x%02x%s", crypt.salt[i], i < 15 ? "," : "");
  printf("};\n");
  printf("  uint8_t check[16] = {");
  for (int i = 0; i < 16; i++)
    printf("0x%02x%s", crypt.check_value[i], i < 15 ? "," : "");
  printf("};\n");
  if (crypt.pswcheck_present) {
    printf("  uint8_t pswcheck[8] = {");
    for (int i = 0; i < 8; i++)
      printf("0x%02x%s", crypt.pswcheck[i], i < 7 ? "," : "");
    printf("};\n");
  }
  printf("\n");

  return 0;
}
