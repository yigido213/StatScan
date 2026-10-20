'use strict';
const fs = require('fs'), os = require('os'), path = require('path'); const { createWatcher } = require('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ssw-')); const dl = path.join(root, 'dl'); const out = path.join(root, 'StatScan-Cikti'); fs.mkdirSync(dl); fs.mkdirSync(out);
  const w = createWatcher({ excludeDir: out, maxBytes: 1000, tickMs: 50 });
  ok(w.validate(out) && w.validate(root), 'çıktı klasörü ve onu içeren klasör reddedilir'); ok(w.validate(path.parse(root).root), 'kök dizin reddedilir'); ok(w.validate(path.join(root, 'yok')), 'olmayan klasör reddedilir');
  fs.writeFileSync(path.join(dl, 'eski.exe'), 'old'); const r = w.setFolders([dl, out]); ok(r.folders.length === 1 && r.errors.length === 1, 'yalnızca geçerli klasör izlenir');
  await sleep(100); ok(w.take().item === null, 'eski dosyalar taranmaz');
  fs.writeFileSync(path.join(dl, 'a.crdownload'), 'x'); fs.writeFileSync(path.join(dl, 'a.exe'), 'MZ12'); await sleep(50);
  const early = []; const fd = fs.openSync(path.join(dl, 'b.exe'), 'w'); for (let i = 0; i < 5; i++) { fs.writeSync(fd, 'abc'); w._consider(dl, 'b.exe'); await sleep(40); w._tick(); const t = w.take(); if (t.item) early.push(t.item); } 
  await sleep(300); ok(!early.some((x) => x.name === 'b.exe'), 'yazılırken bekler'); const got = early; for (let i = 0; i < 5; i++) { const t = w.take(); if (t.item) got.push(t.item); }
  ok(got.some((x) => x.name === 'a.exe' && x.bytes && Buffer.from(x.bytes).toString() === 'MZ12'), 'tamamlanan dosya baytlarıyla verilir');
  ok(!got.some((x) => /crdownload/.test(x.name)), 'geçici uzantı yok sayılır');
  fs.closeSync(fd); fs.writeFileSync(path.join(dl, 'big.bin'), Buffer.alloc(2000)); await sleep(300); const bg = w.take().item; ok(bg && bg.tooBig && !bg.bytes, 'büyük dosya taranmaz, not düşer');
  fs.writeFileSync(path.join(out, 'x.exe'), 'MZ'); w._consider(out, 'x.exe'); await sleep(200); ok(w.take().item === null, 'çıktı klasörü dosyaları taranmaz');
  ok(fs.readFileSync(path.join(dl, 'a.exe'), 'utf8') === 'MZ12', 'orijinal dosya değişmedi'); ok(w.log().length > 0, 'günlük tutulur'); w.stop(); fs.rmSync(root, { recursive: true, force: true });
  console.log(bad ? 'BAŞARISIZ ' + bad : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
})();
