#!/usr/bin/env python3
"""Sentetik Mach-O (arm64/x86-64) ve fat ornekleri: yalnizca yukleme komutlari ve sembol tablosu; calistirilabilir kod yok."""
import struct, sys, os
out = sys.argv[1]; os.makedirs(out, exist_ok=True)
def macho(cpu, undef, dylibs, strings=b'', rwx=False):
    cmds = b''; ncmds = 0
    def seg(name, prot, fileoff, filesize):
        nonlocal cmds, ncmds
        c = struct.pack('<II16sQQQQiiII', 0x19, 72, name.ljust(16, b'\0'), 0, 0x1000, fileoff, filesize, prot, prot, 0, 0)
        cmds += c; ncmds += 1
    seg(b'__PAGEZERO', 0, 0, 0)
    seg(b'__TEXT', 7 if rwx else 5, 0, 0x4000)
    for d in dylibs:
        nm = d.encode() + b'\0'; sz = (24 + len(nm) + 7) & ~7
        cmds += struct.pack('<IIIIII', 0xc, sz, 24, 2, 0x10000, 0x10000) + nm.ljust(sz - 24, b'\0'); ncmds += 1
    strtab = b'\0' + b''.join(('_' + u).encode() + b'\0' for u in undef)
    # sembol tablosu ofseti: baslik(32)+komutlar+symtab komutu(24) sonrasi
    hdr_len = 32 + len(cmds) + 24
    symoff = hdr_len; nsyms = len(undef); stroff = symoff + nsyms * 16
    cmds += struct.pack('<IIIIII', 0x2, 24, symoff, nsyms, stroff, len(strtab)); ncmds += 1
    syms = b''; idx = 1
    for u in undef:
        syms += struct.pack('<IBBHQ', idx, 0x01, 0, 0, 0); idx += len(u) + 2
    hdr = struct.pack('<IiiIIIII', 0xfeedfacf, cpu, 3, 2, ncmds, len(cmds), 0x200085, 0)
    return hdr + cmds + syms + strtab + strings
a = macho(0x0100000c, ['task_for_pid', 'mach_vm_write', 'thread_create_running', 'CGEventTapCreate', 'SecItemCopyMatching', 'CGWindowListCreateImage', 'ptrace'], ['/usr/lib/libSystem.B.dylib', '/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices'],
        b'osascript -e display dialog "Password" with hidden answer ~/Library/LaunchAgents/com.x.plist launchctl load xattr -d com.apple.quarantine /tmp/a security find-generic-password -ga Chrome', rwx=True)
open(os.path.join(out, 'macho_stealer'), 'wb').write(a)
b = macho(0x01000007, ['printf', 'exit'], ['/usr/lib/libSystem.B.dylib'])
open(os.path.join(out, 'macho_hello'), 'wb').write(b)
# fat: CAFEBABE, nfat=2, her giris 20 bayt (BE)
off1 = 0x1000; off2 = off1 + ((len(a) + 0xfff) & ~0xfff)
fat = struct.pack('>II', 0xcafebabe, 2) + struct.pack('>IIIII', 0x0100000c, 0, off1, len(a), 12) + struct.pack('>IIIII', 0x01000007, 3, off2, len(b), 12)
fat = fat.ljust(off1, b'\0') + a; fat = fat.ljust(off2, b'\0') + b
open(os.path.join(out, 'macho_fat'), 'wb').write(fat)
print('ok')
