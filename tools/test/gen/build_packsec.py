#!/usr/bin/env python3
"""Paketleyici/Obfuscation Dedektoru testleri icin SENTETIK ornekler. Calistirilmaz. Kullanim: python3 build_packsec.py <cikti klasoru>
upx.exe (UPX0/UPX1 bolumleri, UPX! dizesi, yuksek entropi, giris noktasi UPX1), vmp.exe (.vmp0), plain.exe (normal .text),
dnobf.exe (ConfuserEx dizesi), obf.jar (1-2 harfli sinif adlari + Allatori dizesi), enc.jar (.class ama CAFEBABE degil), plain.jar, nsis.exe"""
import sys, os, struct, zipfile, random
out = sys.argv[1]; os.makedirs(out, exist_ok=True); random.seed(7)
def pe(secs, extra=b'', ep_sec=0, imports=False):
    hdr = 0x200; n = len(secs); raw = bytearray(hdr); raw[0:2] = b'MZ'; struct.pack_into('<I', raw, 0x3c, 0x80); p = 0x80; raw[p:p + 4] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', raw, p + 4, 0x8664, n, 0x5f000000, 0, 0, 240, 0x22); oh = p + 24
    struct.pack_into('<H', raw, oh, 0x20b)
    va = 0x1000; sp = oh + 240; body = b''; rptr = hdr; eprva = 0
    for i, (name, data, flags, vsize) in enumerate(secs):
        raw[sp:sp + 8] = name.encode().ljust(8, b'\0'); rsz = (len(data) + 0x1ff) & ~0x1ff
        struct.pack_into('<IIIIIIHHI', raw, sp + 8, vsize or len(data), va, rsz, rptr if rsz else 0, 0, 0, 0, 0, flags)
        if i == ep_sec: eprva = va
        body += data.ljust(rsz, b'\0'); rptr += rsz; va += (max(vsize, rsz) + 0xfff) & ~0xfff; sp += 40
    struct.pack_into('<I', raw, oh + 16, eprva); struct.pack_into('<Q', raw, oh + 24, 0x140000000); struct.pack_into('<II', raw, oh + 32, 0x1000, 0x200)
    struct.pack_into('<HH', raw, oh + 40, 6, 0); struct.pack_into('<HH', raw, oh + 48, 6, 0); struct.pack_into('<IIII', raw, oh + 56, va, hdr, 0, 3); struct.pack_into('<I', raw, oh + 108, 16)
    return bytes(raw) + body + extra
rnd = lambda n: bytes(random.getrandbits(8) for _ in range(n))
txt = lambda n: (b'MZ normal code ' + bytes(range(32, 120)) * 30)[:n]
X = 0x60000020; RW = 0xC0000040; RWX = 0xE0000060
open(out + '/upx.exe', 'wb').write(pe([('UPX0', b'', RWX, 0x20000), ('UPX1', rnd(0x3000) + b'UPX!\x0d\x09\x02\x08', RWX, 0x3100), ('.rsrc', b'\0' * 0x200, RW, 0x200)], ep_sec=1))
open(out + '/vmp.exe', 'wb').write(pe([('.text', txt(0x400), X, 0x400), ('.vmp0', rnd(0x2000), RWX, 0x2000), ('.rsrc', b'\0' * 0x200, RW, 0x200)], ep_sec=1))
open(out + '/plain.exe', 'wb').write(pe([('.text', txt(0x800), X, 0x800), ('.rdata', txt(0x400), 0x40000040, 0x400), ('.data', b'\0' * 0x200, RW, 0x200)]))
open(out + '/dnobf.exe', 'wb').write(pe([('.text', txt(0x600) + b'ConfusedByAttribute ConfuserEx v1.0', X, 0x600), ('.rsrc', b'\0' * 0x200, RW, 0x200)]))
open(out + '/nsis.exe', 'wb').write(pe([('.text', txt(0x400) + b'Nullsoft Install System v3.08', X, 0x400), ('.data', b'\0' * 0x200, RW, 0x200)]))
def jar(path, classes, extra=None):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\nMain-Class: a.a\n')
        for name, data in classes.items(): z.writestr(name, data)
        for k, v in (extra or {}).items(): z.writestr(k, v)
cafe = lambda t=b'': b'\xca\xfe\xba\xbe\x00\x00\x00\x34' + b'x' * 40 + t
jar(out + '/obf.jar', {'a/a/%s.class' % c: cafe(b'ALLATORIxDEMO' if i == 0 else b'') for i, c in enumerate('abcdefghijkl')})
jar(out + '/enc.jar', {'com/x/Loader.class': cafe(), 'data/%d.class' % 1: rnd(3000), 'data/2.class': rnd(3000), 'data/3.class': rnd(3000)})
jar(out + '/plain.jar', {'com/example/app/%s.class' % n: cafe() for n in ['Main', 'ConfigLoader', 'UserService', 'NetworkClient', 'Utils', 'Settings', 'Renderer', 'Parser', 'Logger']})
