#!/bin/bash
# Yerel kod analizi icin zararsiz PE ornekleri (x64/x86, CRT'li taklit ve CRT'siz). Kullanim: build_native.sh <cikti_dizini>
set -e
OUT=${1:?cikti dizini}; mkdir -p "$OUT"; W=$(mktemp -d); cd "$W"
mkdef() { local name=$1 dll=$2 m=$3; shift 3; { echo "LIBRARY $dll"; echo "EXPORTS"; for f in "$@"; do echo "  $f"; done; } > $name.def; llvm-dlltool -m $m -D $dll -d $name.def -l $name.lib; }
cat > crt.c <<'C'
typedef void* H; typedef unsigned long DW;
__declspec(dllimport) H __stdcall GetStdHandle(DW);
__declspec(dllimport) int __stdcall WriteFile(H, const void*, DW, DW*, void*);
__declspec(dllimport) void __stdcall ExitProcess(unsigned);
int argc_g = 1; char** argv_g = 0; char** envp_g = 0;
static int len(const char* s) { int n = 0; while (s[n]) n++; return n; }
__attribute__((noinline)) static int greet(const char* s) { DW w; return WriteFile(GetStdHandle(-11), s, len(s), &w, 0); }
__attribute__((noinline)) int main(int argc, char** argv, char** envp) { if (argc > 3) return 7; greet("hello from tiny exe\n"); greet("second message\n"); return argc; }
__attribute__((noinline)) void __scrt_common_main_seh(void) { int r = main(argc_g, argv_g, envp_g); ExitProcess(r); }
void mainCRTStartup(void) { __scrt_common_main_seh(); }
C
cat > bare.c <<'C'
typedef void* H; typedef unsigned long DW;
__declspec(dllimport) H GetStdHandle(DW);
__declspec(dllimport) int WriteFile(H, const void*, DW, DW*, void*);
__declspec(dllimport) void ExitProcess(unsigned);
void start(void) { DW w; WriteFile(GetStdHandle(-11), "bare entry\n", 11, &w, 0); ExitProcess(0); }
C
mkdef k64 KERNEL32.dll i386:x86-64 GetStdHandle WriteFile ExitProcess
clang --target=x86_64-pc-windows-msvc -nostdlib -ffreestanding -O1 -fno-stack-protector -c crt.c -o crt64.obj
lld-link /subsystem:console /entry:mainCRTStartup /nodefaultlib /out:"$OUT/nat_crt64.exe" crt64.obj k64.lib /manifest:no >/dev/null
clang --target=x86_64-pc-windows-msvc -nostdlib -ffreestanding -O1 -fno-stack-protector -c bare.c -o bare64.obj
lld-link /subsystem:console /entry:start /nodefaultlib /out:"$OUT/nat_bare64.exe" bare64.obj k64.lib /manifest:no >/dev/null
mkdef k32 KERNEL32.dll i386 GetStdHandle@4 WriteFile@20 ExitProcess@4
clang --target=i686-pc-windows-msvc -nostdlib -ffreestanding -O1 -fno-stack-protector -c crt.c -o crt32.obj
lld-link /machine:x86 /subsystem:console /entry:mainCRTStartup /nodefaultlib /out:"$OUT/nat_crt32.exe" crt32.obj k32.lib /manifest:no >/dev/null
echo ok
