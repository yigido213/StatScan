#include <stdint.h>
#include <stddef.h>
extern int printf(const char *, ...); extern int snprintf(char *, size_t, const char *, ...); extern int puts(const char *);
extern void *malloc(size_t); extern void *calloc(size_t, size_t); extern void free(void *); extern void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
extern size_t strlen(const char *); extern char *strcpy(char *, const char *); extern void *memcpy(void *, const void *, size_t); extern void *memset(void *, int, size_t);
extern double floor(double); extern float sqrtf(float); extern int isalpha(int);
struct node { int v; struct node *next; double w; char name[16]; };
static int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
static unsigned hash(const char *s) { unsigned h = 5381; while (*s) h = h * 33 + (unsigned char)*s++; return h; }
static int cmp(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }
static double mean(const double *x, int n) { double s = 0; for (int i = 0; i < n; i++) s += x[i]; return n ? s / n : 0.0; }
static int sw(int x) { switch (x) { case 0: return 10; case 1: return 22; case 2: return 31; case 3: return 47; case 4: return 5; case 5: return 69; case 6: return 71; default: return -1; } }
static long long mul64(long long a, long long b) { return a * b + (a >> 3) - (b << 2); }
static uint8_t crc(const uint8_t *p, size_t n) { uint8_t c = 0xff; while (n--) { c ^= *p++; for (int k = 0; k < 8; k++) c = (c & 0x80) ? (c << 1) ^ 0x31 : c << 1; } return c; }
static void rev(char *s) { size_t n = strlen(s); for (size_t i = 0; i < n / 2; i++) { char t = s[i]; s[i] = s[n - 1 - i]; s[n - 1 - i] = t; } }
static float fl(float a, float b) { return sqrtf(a * a + b * b) / (b + 1.5f); }
int main(int argc, char **argv) {
  int arr[32]; double d[8]; struct node *h = NULL; char buf[64];
  for (int i = 0; i < 32; i++) arr[i] = (i * 7919) % 101;
  qsort(arr, 32, sizeof(int), cmp);
  for (int i = 0; i < 8; i++) d[i] = i * 1.25;
  for (int i = 0; i < argc; i++) { struct node *n = malloc(sizeof *n); n->v = i; n->w = d[i & 7]; n->next = h; snprintf(n->name, 16, "n%d", i); h = n; }
  strcpy(buf, argc > 1 ? argv[1] : "hello world"); rev(buf);
  unsigned long long big = 0x123456789abcdefULL; big = big * 31 + hash(buf);
  printf("%d %u %f %lld %d %u %f %llu\n", fib(argc + 10), hash(buf), mean(d, 8), mul64(argc, 12345678901LL), sw(argc), crc((uint8_t *)buf, strlen(buf)), (double)fl(3.0f, 4.0f), big);
  for (struct node *p = h; p; p = p->next) printf("%s %d %.2f\n", p->name, p->v, p->w);
  if (isalpha(buf[0])) puts("alpha"); else puts("other");
  memset(arr, 0, sizeof arr); memcpy(buf, "abc", 4);
  return arr[3] + (int)strlen(buf) + (int)floor(d[2]);
}
