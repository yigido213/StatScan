#!/bin/bash
# Zararsiz test ornegi: javaw.exe'ye bellek yazan "istemci" benzeri PE (hook/ag/calma yok). Kullanim: build_pe_java.sh <cikti_dizini>
set -e
OUT=${1:?cikti dizini}; mkdir -p "$OUT"; W=$(mktemp -d); cd "$W"
{ echo "LIBRARY KERNEL32.dll"; echo "EXPORTS"; for f in OpenProcess VirtualAllocEx WriteProcessMemory CreateRemoteThread ExitProcess; do echo "  $f"; done; } > k32.def
llvm-dlltool -m i386:x86-64 -D KERNEL32.dll -d k32.def -l k32.lib
cat > j.c <<'C'
typedef void* H; typedef unsigned long DW;
__declspec(dllimport) H OpenProcess(DW, int, DW);
__declspec(dllimport) void* VirtualAllocEx(H, void*, unsigned long long, DW, DW);
__declspec(dllimport) int WriteProcessMemory(H, void*, const void*, unsigned long long, unsigned long long*);
__declspec(dllimport) H CreateRemoteThread(H, void*, unsigned long long, void*, void*, DW, DW*);
__declspec(dllimport) void ExitProcess(unsigned);
const char target[] = "javaw.exe";
const char note[] = "test sample - harmless";
int main(void){ H p = OpenProcess(0x1F0FFF,0,4); void* m = VirtualAllocEx(p,0,4096,0x3000,0x40); unsigned long long n; WriteProcessMemory(p,m,target,sizeof target,&n); CreateRemoteThread(p,0,0,m,0,0,0); ExitProcess(0); return 0; }
C
clang --target=x86_64-pc-windows-msvc -nostdlib -ffreestanding -O1 -c j.c -o j.obj
lld-link /subsystem:console /entry:main /nodefaultlib /out:"$OUT/pe_javainj.exe" j.obj k32.lib /manifest:no >/dev/null
