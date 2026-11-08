// Saf JS .lnk okuyucu testi (readLnkTarget): gecerli, bozuk, kesik dosyalar.
const fs = require('fs'), os = require('os'), path = require('path'); const { readLnkTarget } = require('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { if (!c) { bad++; console.log('FAIL', m); } else console.log('ok', m); };
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lnk-'));
function mk(target, uni) {
  const h = Buffer.alloc(0x4c); h.writeUInt32LE(0x4c, 0); h.writeUInt32LE(2, 0x14); // yalniz HasLinkInfo
  const base = Buffer.from(target + '\0', 'latin1'), suf = Buffer.from('\0', 'latin1'); const hdr = uni ? 0x24 : 0x1c;
  const baseUni = Buffer.from(target + '\0', 'utf16le'), sufUni = Buffer.from('\0', 'utf16le');
  let off = hdr + 0; const li = []; const vol = Buffer.alloc(16); vol.writeUInt32LE(16, 0); // sahte VolumeID
  const volOff = hdr, baseOff = volOff + 16, sufOff = baseOff + base.length; let uOff = sufOff + suf.length;
  const total = uOff + (uni ? baseUni.length + sufUni.length : 0); const b = Buffer.alloc(total);
  b.writeUInt32LE(total, 0); b.writeUInt32LE(hdr, 4); b.writeUInt32LE(1, 8); b.writeUInt32LE(volOff, 12); b.writeUInt32LE(baseOff, 16); b.writeUInt32LE(0, 20); b.writeUInt32LE(sufOff, 24);
  vol.copy(b, volOff); base.copy(b, baseOff); suf.copy(b, sufOff);
  if (uni) { b.writeUInt32LE(uOff, 28); baseUni.copy(b, uOff); b.writeUInt32LE(uOff + baseUni.length, 32); sufUni.copy(b, uOff + baseUni.length); }
  return Buffer.concat([h, b]);
}
const w = (n, d) => { const f = path.join(dir, n); fs.writeFileSync(f, d); return f; };
ok(readLnkTarget(w('a.lnk', mk('C:\\Program Files\\App\\app.exe', false))).target === 'C:\\Program Files\\App\\app.exe', 'ANSI hedef');
ok(readLnkTarget(w('b.lnk', mk('C:\\Üç\\ğ.exe', true))).target === 'C:\\Üç\\ğ.exe', 'Unicode hedef');
ok(readLnkTarget(w('c.lnk', Buffer.from('rastgele cop veri'.repeat(20)))) === null, 'cop veri null');
ok(readLnkTarget(w('d.lnk', mk('C:\\x.exe', false).subarray(0, 0x60))) === null, 'kesik null');
ok(readLnkTarget(w('e.lnk', Buffer.alloc(0))) === null, 'bos null');
const crazy = mk('C:\\x.exe', false); crazy.writeUInt32LE(0xffffff, 0x4c); ok(readLnkTarget(w('f.lnk', crazy)) === null, 'bozuk boyut null');
ok(readLnkTarget(path.join(dir, 'yok.lnk')) === null, 'olmayan dosya null');
for (let i = 0; i < 300; i++) { const r = Buffer.alloc(200 + i); for (let j = 0; j < r.length; j++) r[j] = (i * 31 + j * 7) & 255; r.writeUInt32LE(0x4c, 0); r.writeUInt32LE(i & 3, 0x14); readLnkTarget(w('r.lnk', r)); }
ok(true, '300 rastgele dosya cokmeden okundu');
fs.rmSync(dir, { recursive: true }); process.exit(bad ? 1 : 0);
