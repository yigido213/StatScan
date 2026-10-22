#include <stdint.h>
#include <stddef.h>
extern int printf(const char *, ...); extern int snprintf(char *, size_t, const char *, ...); extern int puts(const char *);
extern void *malloc(size_t); extern void *calloc(size_t, size_t); extern void free(void *); extern void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
extern size_t strlen(const char *); extern char *strcpy(char *, const char *); extern void *memcpy(void *, const void *, size_t); extern void *memset(void *, int, size_t);
extern double floor(double); extern float sqrtf(float); extern int isalpha(int);
typedef struct { uint32_t a[4]; } state;
static uint32_t rotl(uint32_t x, int r) { return (x << r) | (x >> (32 - r)); }
static void mix(state *s, const uint8_t *in, size_t n) { for (size_t i = 0; i < n; i++) { s->a[i & 3] = rotl(s->a[i & 3] ^ in[i], (int)(i % 13) + 1) + s->a[(i + 1) & 3]; } }
static int parse(const char *s, int *out) { int v = 0, neg = 0; if (*s == '-') { neg = 1; s++; } if (!*s) return 0; while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0'); *out = neg ? -v : v; return *s == 0; }
static unsigned char *xorbuf(unsigned char *d, size_t n, unsigned char k) { for (size_t i = 0; i < n; i++) d[i] ^= k + (unsigned char)i; return d; }
static int64_t sdiv(int64_t a, int64_t b) { return b ? a / b + a % b : 0; }
static uint32_t udiv(uint32_t a, uint32_t b) { return b ? a / b + a % b : 0; }
static int bits(uint64_t x) { int c = 0; while (x) { c += x & 1; x >>= 1; } return c; }
static short sh(short a, short b) { return (short)(a * b + (a >> 2)); }
static int cmpst(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return (unsigned char)*a - (unsigned char)*b; }
int main(int argc, char **argv) {
  state s = {{1, 2, 3, 4}}; uint8_t data[200]; int v = 0;
  for (int i = 0; i < 200; i++) data[i] = (uint8_t)(i * 31 + 7);
  mix(&s, data, sizeof data); xorbuf(data, 100, 0x5a);
  if (argc > 1 && parse(argv[1], &v)) printf("v=%d\n", v);
  printf("%08x %08x %d %lld %u %d %d %d\n", s.a[0], s.a[1], bits(s.a[2]), (long long)sdiv(v, 7), udiv(s.a[3], 9), sh((short)v, 3), cmpst("abc", argv[0]), (int)(data[5] > 3 ? data[9] : data[10]));
  char *m = calloc(1, 4096); memcpy(m, data, 100); long z = 0; for (int i = 0; i < 100; i++) z += m[i] * (i + 1); free(m);
  return (int)(z & 0x7f);
}
