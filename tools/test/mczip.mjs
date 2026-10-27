// 97-mczip: ZIP okuma/yazma — dis dogrulayicilarla (unzip, python zipfile) ve kotu girdilerle
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { execFileSync, spawnSync } from 'node:child_process'; import { loadEngine } from './engine.mjs';
const E = loadEngine(); let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mz-')); const enc = (s) => new TextEncoder().encode(s);
const big = enc('abc'.repeat(5000)); const rnd = new Uint8Array(3000); for (let i = 0; i < rnd.length; i++) rnd[i] = (i * 7919 + (i >> 3)) & 255;
// kaynak zip: python ile (deflate + stored + utf8 ad)
fs.writeFileSync(dir + '/mk.py', `import zipfile,sys
z=zipfile.ZipFile(sys.argv[1],'w')
z.writestr('pack.mcmeta','{"pack":{"pack_format":4}}',zipfile.ZIP_DEFLATED)
z.writestr('a/big.txt','abc'*5000,zipfile.ZIP_DEFLATED)
z.writestr('a/stored.bin',bytes(range(256)),zipfile.ZIP_STORED)
z.writestr('ü/ğ.txt','merhaba',zipfile.ZIP_DEFLATED)
z.writestr('dir/',b'')
z.close()`);
execFileSync('python3', ['-I', dir + '/mk.py', dir + '/src.zip']);
const src = new Uint8Array(fs.readFileSync(dir + '/src.zip')); const z = E.mzRead(src);
ok(z.entries.length === 5 && z.entries.some((e) => e.isDir), 'okuma: 5 girdi, klasör girdisi tanındı');
const e = (n) => z.entries.find((x) => x.name === n);
ok(new TextDecoder().decode(await E.mzData(z, e('a/big.txt'))) === 'abc'.repeat(5000), 'deflate girdi açıldı + CRC doğrulandı');
ok((await E.mzData(z, e('ü/ğ.txt'))).length === 7, 'UTF-8 adlı girdi okundu');
const out = await E.mzWrite([{ name: 'pack.mcmeta', copy: { zip: z, entry: e('pack.mcmeta') } }, { name: 'a/big.txt', copy: { zip: z, entry: e('a/big.txt') } }, { name: 'a/stored.bin', copy: { zip: z, entry: e('a/stored.bin') } }, { name: 'ü/ğ.txt', nameBytes: e('ü/ğ.txt').nameBytes, utf8: true, copy: { zip: z, entry: e('ü/ğ.txt') } }, { name: 'new/x.json', data: big }, { name: 'new/r.bin', data: rnd }, { name: 'new/tiny.txt', data: enc('hi') }, { name: 'new/empty', data: new Uint8Array(0) }]);
fs.writeFileSync(dir + '/out.zip', out);
const t = spawnSync('unzip', ['-t', dir + '/out.zip']); ok(t.status === 0 && /No errors/.test(t.stdout.toString()), 'unzip -t: hata yok');
fs.writeFileSync(dir + '/chk.py', `import zipfile,sys
z=zipfile.ZipFile(sys.argv[1]); assert z.testzip() is None
d={i.filename:z.read(i) for i in z.infolist()}
assert d['a/big.txt']==b'abc'*5000 and d['ü/ğ.txt']==b'merhaba' and d['new/tiny.txt']==b'hi' and d['new/empty']==b'' and len(d['new/x.json'])==15000 and len(d['new/r.bin'])==3000 and d['a/stored.bin']==bytes(range(256))
print('PYOK',len(d))`);
const p = spawnSync('python3', ['-I', dir + '/chk.py', dir + '/out.zip']); ok(/PYOK 8/.test(p.stdout.toString()), 'python zipfile: içerikler birebir (' + (p.stderr.toString().slice(0, 100)) + ')');
const z2 = E.mzRead(out); ok(z2.entries.length === 8 && z2.entries.find((x) => x.name === 'a/big.txt').csize === e('a/big.txt').csize, 'değişmeyen girdi sıkıştırılmış haliyle kopyalandı (boyut aynı)');
ok(z2.entries.find((x) => x.name === 'new/x.json').method === 8 && z2.entries.find((x) => x.name === 'new/r.bin').method <= 8, 'yeni girdiler yazıldı');
const thr = (f) => { try { f(); return null; } catch (er) { return er.code || 'other:' + er.message; } };
ok(thr(() => E.mzRead(enc('hello'.repeat(10)))) === 'notzip', 'ZIP olmayan dosya reddedildi');
const enc1 = src.slice(); const dv = new DataView(enc1.buffer); { const cd = dv.getUint32(enc1.length - 22 + 16, true); dv.setUint16(cd + 8, 1, true); } ok(thr(() => E.mzRead(enc1)) === 'encrypted', 'şifreli girdi reddedildi');
const trunc = src.slice(0, src.length - 30); ok(thr(() => E.mzRead(trunc)) !== null, 'kesik zip reddedildi');
const z64 = src.slice(); new DataView(z64.buffer).setUint32(z64.length - 22 + 16, 0xffffffff, true); ok(thr(() => E.mzRead(z64)) === 'zip64', 'ZIP64 işareti reddedildi');
fs.writeFileSync(dir + '/dup.py', `import zipfile,sys,warnings
warnings.simplefilter('ignore')
z=zipfile.ZipFile(sys.argv[1],'w'); z.writestr('a','1'); z.writestr('a','2'); z.close()`); execFileSync('python3', ['-I', dir + '/dup.py', dir + '/dup.zip']); ok(thr(() => E.mzRead(new Uint8Array(fs.readFileSync(dir + '/dup.zip')))) === 'dup', 'yinelenen ad reddedildi');
const bd = src.slice(); const ent = z.entries.find((x) => x.name === 'a/big.txt'); bd[ent.dataOff + 5] ^= 0xff; const zb = E.mzRead(bd); let er2 = null; try { await E.mzData(zb, zb.entries.find((x) => x.name === 'a/big.txt')); } catch (er) { er2 = er.code; } ok(er2 === 'bad', 'bozuk veri (CRC/deflate) yakalandı');
fs.rmSync(dir, { recursive: true, force: true }); console.log(bad ? bad + ' HATA' : 'TAMAM'); process.exit(bad ? 1 : 0);
