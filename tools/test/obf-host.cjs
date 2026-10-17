// harici decompiler koprusu testi (sahte arac ile): node tools/test/obf-host.cjs
const fs = require('fs'), os = require('os'), path = require('path'); const { createObfHost, detectTools } = require('../../app/desktop/obf.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'obft-')); const bin = path.join(tmp, 'bin'); fs.mkdirSync(bin);
  const fake = path.join(bin, 'cfr'); fs.writeFileSync(fake, '#!/bin/sh\n# sahte decompiler: girdiyi yalnizca okur\nout=""; while [ $# -gt 0 ]; do case "$1" in --outputdir) out="$2"; shift;; esac; shift; done\necho "// decompiled" > "$out/Hello.java"\necho done\n'); fs.chmodSync(fake, 0o755);
  const slow = path.join(bin, 'jadx'); fs.writeFileSync(slow, '#!/bin/sh\nsleep 30\n'); fs.chmodSync(slow, 0o755);
  ok(detectTools({ path: bin }).map((t) => t.id).sort().join() === 'cfr,jadx', 'yalnızca kurulu araçlar bulundu (indirme yok)');
  ok(detectTools({ path: '/nonexistent' }).length === 0, 'araç yoksa boş liste');
  let confirmed = 0; const H = createObfHost({ outputRoot: path.join(tmp, 'out'), userToolsDir: path.join(tmp, 'tools'), env: { path: bin }, confirm: async () => { confirmed++; return true; } });
  const data = new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]);
  let r = await H.start({ tool: 'nope', kind: 'jar', data, name: 'a.jar' }); ok(r.error === 'tool', 'bilinmeyen araç kimliği reddedildi');
  r = await H.start({ tool: 'ilspycmd', kind: 'dotnet', data, name: 'a.dll' }); ok(r.error === 'missing', 'kurulu olmayan araç için sessiz kurulum yok: ' + r.message.slice(0, 30));
  r = await H.start({ tool: 'cfr', kind: 'dotnet', data, name: 'a.jar' }); ok(r.error === 'kind', 'uygun olmayan tür reddedildi');
  r = await H.start({ tool: 'cfr', kind: 'jar', data, name: 'a.jar' }); ok(r.state === 'running' && confirmed === 1, 'onay istendi, iş başladı');
  let j; for (let i = 0; i < 50; i++) { j = H.job(r.id); if (j.state !== 'running') break; await new Promise((x) => setTimeout(x, 100)); }
  ok(j.state === 'done' && j.files.some((f) => f.rel === 'Hello.java'), 'sahte decompiler çıktısı ayrı klasörde: ' + j.dir);
  ok(!fs.readdirSync(os.tmpdir()).some((x) => x.startsWith('statscan-obf-') && fs.existsSync(path.join(os.tmpdir(), x, 'input.jar'))), 'geçici girdi temizlendi');
  const dec = createObfHost({ outputRoot: path.join(tmp, 'out'), env: { path: bin }, confirm: async () => false }); r = await dec.start({ tool: 'cfr', kind: 'jar', data, name: 'a.jar' }); ok(r.error === 'declined', 'onay verilmezse çalıştırılmaz');
  r = await H.start({ tool: 'jadx', kind: 'apk', data, name: 'a.apk', timeoutMs: 5000 }); await new Promise((x) => setTimeout(x, 200)); H.cancel(r.id); for (let i = 0; i < 50; i++) { j = H.job(r.id); if (j.state !== 'running') break; await new Promise((x) => setTimeout(x, 100)); } ok(j.state === 'cancelled', 'iptal: iş durduruldu (' + j.state + ')');
  const sv = await H.save({ name: 'x.js', outputs: [{ name: '../../etc/passwd', text: 'a' }, { name: 'a.txt', text: 'b' }, { name: 'a.txt', text: 'c' }] }); ok(sv.ok && sv.files.length === 3 && sv.files.every((f) => !f.name.includes('/')) && sv.dir.startsWith(path.join(tmp, 'out')), 'kaydetme: yol sızdırma yok, çakışma ezilmedi: ' + sv.files.map((f) => f.name).join(','));
  ok(fs.readFileSync(path.join(sv.dir, 'a.txt'), 'utf8') === 'b' && fs.readFileSync(path.join(sv.dir, 'a-2.txt'), 'utf8') === 'c', 'aynı ad ezilmedi');
  fs.rmSync(tmp, { recursive: true, force: true }); console.log(bad ? bad + ' TEST BAŞARISIZ' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
})();
