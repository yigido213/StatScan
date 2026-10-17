#!/bin/bash
# Gercek PE ornekleri uretir (zararsiz: yalnizca import tablosu ve metinler yapay). Kullanim: build_pe.sh <cikti_dizini>
set -e
OUT=${1:?cikti dizini}; mkdir -p "$OUT"; W=$(mktemp -d); cd "$W"
mkdef() { # ad dll func...
  local name=$1 dll=$2; shift 2; { echo "LIBRARY $dll"; echo "EXPORTS"; for f in "$@"; do echo "  $f"; done; } > $name.def
  llvm-dlltool -m i386:x86-64 -D $dll -d $name.def -l $name.lib
}
mkdef k32 KERNEL32.dll OpenProcess VirtualAllocEx WriteProcessMemory CreateRemoteThread ExitProcess GetProcAddress LoadLibraryA IsDebuggerPresent CreateToolhelp32Snapshot
mkdef ws2 WS2_32.dll socket connect send
mkdef usr USER32.dll SetWindowsHookExA GetAsyncKeyState
cat > inj.c <<'C'
typedef void* H; typedef unsigned long DW;
__declspec(dllimport) H OpenProcess(DW, int, DW);
__declspec(dllimport) void* VirtualAllocEx(H, void*, unsigned long long, DW, DW);
__declspec(dllimport) int WriteProcessMemory(H, void*, const void*, unsigned long long, unsigned long long*);
__declspec(dllimport) H CreateRemoteThread(H, void*, unsigned long long, void*, void*, DW, DW*);
__declspec(dllimport) void ExitProcess(unsigned);
__declspec(dllimport) int IsDebuggerPresent(void);
__declspec(dllimport) unsigned long long socket(int,int,int);
__declspec(dllimport) int connect(unsigned long long, const void*, int);
__declspec(dllimport) void* SetWindowsHookExA(int, void*, void*, DW);
__declspec(dllimport) short GetAsyncKeyState(int);
const char url[] = "http://203.0.113.7/payload.bin";
const char note[] = "test sample - harmless";
int main(void){ H p = OpenProcess(0x1F0FFF,0,4); void* m = VirtualAllocEx(p,0,4096,0x3000,0x40); unsigned long long n; WriteProcessMemory(p,m,url,sizeof url,&n); CreateRemoteThread(p,0,0,m,0,0,0); if(IsDebuggerPresent()) ExitProcess(1); socket(2,1,6); connect(0,note,16); SetWindowsHookExA(13,0,0,0); GetAsyncKeyState(65); return 0; }
C
clang --target=x86_64-pc-windows-msvc -nostdlib -ffreestanding -O1 -c inj.c -o inj.obj
lld-link /subsystem:console /entry:main /nodefaultlib /out:"$OUT/pe_inject.exe" inj.obj k32.lib ws2.lib usr.lib /manifest:no >/dev/null
# surum kaynakli ve manifestli temiz GUI ornegi
cat > ver.rc <<'R'
1 VERSIONINFO
FILEVERSION 1,2,3,4
PRODUCTVERSION 1,2,3,4
BEGIN
 BLOCK "StringFileInfo"
 BEGIN
  BLOCK "040904B0"
  BEGIN
   VALUE "CompanyName", "Example Corp\0"
   VALUE "FileDescription", "Notepad Helper\0"
   VALUE "OriginalFilename", "notepad_helper.exe\0"
   VALUE "ProductName", "Example Product\0"
   VALUE "FileVersion", "1.2.3.4\0"
  END
 END
 BLOCK "VarFileInfo"
 BEGIN
  VALUE "Translation", 0x409, 1200
 END
END
R
cat > hello.c <<'C'
__declspec(dllimport) void ExitProcess(unsigned);
int main(void){ ExitProcess(0); return 0; }
C
clang --target=x86_64-pc-windows-msvc -nostdlib -ffreestanding -c hello.c -o hello.obj
llvm-rc ver.rc -fo ver.res
cat > man.xml <<'M'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="requireAdministrator" uiAccess="false"/></requestedPrivileges></security></trustInfo></assembly>
M
lld-link /subsystem:windows /entry:main /nodefaultlib /out:"$OUT/pe_version.exe" hello.obj k32.lib ver.res /manifest:embed /manifestinput:man.xml >/dev/null 2>&1 || lld-link /subsystem:windows /entry:main /nodefaultlib /out:"$OUT/pe_version.exe" hello.obj k32.lib ver.res >/dev/null
# DLL ornegi
cat > d.c <<'C'
int __declspec(dllexport) Foo(void){ return 1; }
int DllMain(void*a,unsigned b,void*c){ return 1; }
C
clang --target=x86_64-pc-windows-msvc -nostdlib -ffreestanding -c d.c -o d.obj
lld-link /dll /noentry /nodefaultlib /out:"$OUT/pe_lib.dll" d.obj >/dev/null 2>&1 || true
ls -la "$OUT"
