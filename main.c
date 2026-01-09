#include <ctype.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define STEP 30
#define DIGITS 6

const char *BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static inline int base32_char_value(char c) {
  c = toupper(c);
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= '2' && c <= '7') return c - '2' + 26;
  return -1;
}

static int base32_decode(const char *encoded, uint8_t *out, int max_out_len) {
  int buffer = 0, bits_left = 0;
  int count = 0;
  for (size_t i = 0; i < strlen(encoded); i++) {
    int val = base32_char_value(encoded[i]);
    if (val < 0) continue;  // skip padding or invalid chars
    buffer <<= 5;
    buffer |= val & 0x1F;
    bits_left += 5;
    if (bits_left >= 8) {
      if (count >= max_out_len) return -1;
      bits_left -= 8;
      out[count++] = (buffer >> bits_left) & 0xFF;
    }
  }
  return count;
}

static uint32_t totp(uint8_t *secret, int secret_len, time_t t) {
  uint64_t counter = t / STEP;
  uint8_t buf[8];
  for (int i = 7; i >= 0; i--) {
    buf[i] = counter & 0xFF;
    counter >>= 8;
  }

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;
  HMAC(EVP_sha1(), secret, secret_len, buf, 8, hash, &hash_len);

  int offset = hash[hash_len - 1] & 0x0F;
  uint32_t bin = ((hash[offset] & 0x7F) << 24) | ((hash[offset + 1] & 0xFF) << 16) |
                 ((hash[offset + 2] & 0xFF) << 8) | (hash[offset + 3] & 0xFF);

  uint32_t mod = 1;
  for (int i = 0; i < DIGITS; i++) mod *= 10;

  return bin % mod;
}

static void remove_spaces(char *s) {
  char *d = s;
  do {
    while (*d == ' ') ++d;
  } while ((*s++ = *d++));
}

int main() {
  char secret_str[128];
  if (!fgets(secret_str, sizeof(secret_str), stdin)) {
    fprintf(stderr, "Failed to read secret from stdin\n");
    return 1;
  }

  remove_spaces(secret_str);
  for (size_t i = 0; i < strlen(secret_str); i++) {
    secret_str[i] = toupper(secret_str[i]);
  }

  uint8_t secret[64];
  int secret_len = base32_decode(secret_str, secret, sizeof(secret));
  if (secret_len <= 0) {
    fprintf(stderr, "Invalid Base32 secret\n");
    return 1;
  }

  printf("Ctrl+C to exit.\n");

  uint64_t last_counter = (uint64_t)-1;
  uint32_t current_code = 0;

  while (1) {
    time_t now = time(NULL);
    uint64_t counter = now / STEP;

    if (counter != last_counter) {
      last_counter = counter;
      current_code = totp(secret, secret_len, now);
    }

    int remaining = STEP - (now % STEP);

    char readable[8];
    char code_str[DIGITS + 1];
    snprintf(code_str, sizeof(code_str), "%06u", current_code);
    snprintf(readable, sizeof(readable), "%.3s-%.3s", code_str, code_str + 3);
    printf("\rExpires in: %2ds | Code: %s", remaining, readable);

    fflush(stdout);

    sleep(1);
  }

  return 0;
}
