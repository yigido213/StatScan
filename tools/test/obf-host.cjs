// harici decompiler koprusu testi (sahte arac ile): node tools/test/obf-host.cjs
const fs = require('fs'), os = require('os'), path = require('path'); const { createObfHost, detectTools } = require('../../app/desktop/host.js').obfModule;
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

  // --- yerel kod: IDA / Ghidra (sahte araclar) ---
  const idaDir = path.join(tmp, 'IDA Professional 9.0'); fs.mkdirSync(idaDir);
  const mkIda = (decompiled, withStatus) => { const f = path.join(idaDir, 'idat64'); fs.writeFileSync(f, '#!/bin/sh\n# sahte IDA: girdiyi yalnizca okur\nout="$STATSCAN_OUT"; ls -- "$@" >/dev/null 2>&1\n[ -f statscan_ida.py ] || exit 3\necho "int main(){}" > "$out/decompiled.c"; echo "401000\\tmain\\t8" > "$out/functions.txt"\n' + (withStatus ? 'printf "functions=3\\ndecompiled=' + decompiled + '\\nfailed=1\\nskipped=1\\nhexrays=var\\nerror=\\n" > "$out/_statscan_status.txt"\n' : '') + 'exit 0\n'); fs.chmodSync(f, 0o755); };
  const nat = Buffer.from('MZ' + 'x'.repeat(100)); const natArr = new Uint8Array(nat);
  const mk = (extra) => createObfHost(Object.assign({ outputRoot: path.join(tmp, 'out'), userToolsDir: path.join(tmp, 'tools'), env: { path: '/nonexistent', scanDirs: [tmp], IDADIR: '', GHIDRA_INSTALL_DIR: '' }, confirm: async () => true }, extra || {}));
  const wait = async (H2, id) => { let jj; for (let i = 0; i < 60; i++) { jj = H2.job(id); if (jj.state !== 'running') break; await new Promise((x) => setTimeout(x, 100)); } return jj; };
  mkIda(2, true); let H2 = mk();
  ok(H2.tools().some((t) => t.id === 'ida' && /IDA Professional/.test(t.path)), 'IDA bilinen konumdan bulundu');
  r = await H2.start({ tool: 'ida', kind: 'dotnet', data: natArr, name: 'a.exe' }); ok(r.error === 'kind', 'IDA .NET türü için sunulmuyor');
  r = await H2.start({ tool: 'ida', kind: 'pe', data: natArr, name: 'a.exe' }); j = await wait(H2, r.id); ok(j.state === 'partial' && /2\/3/.test(j.message) && /geri kazanılmış değil/.test(j.message), 'IDA 2/3 fonksiyon: kısmi gösterildi → ' + j.message.slice(0, 50));
  mkIda(3, true); r = await H2.start({ tool: 'ida', kind: 'pe', data: natArr, name: 'a.exe' }); j = await wait(H2, r.id); ok(j.state === 'done' && j.files.some((f) => f.rel === 'decompiled.c'), 'IDA tam çıktı: done');
  mkIda(0, false); r = await H2.start({ tool: 'ida', kind: 'pe', data: natArr, name: 'a.exe' }); j = await wait(H2, r.id); ok(j.state === 'failed' && /durum dosyası yok/.test(j.message), 'durum dosyası yoksa başarılı gösterilmedi');
  mkIda(0, true); r = await H2.start({ tool: 'ida', kind: 'pe', data: natArr, name: 'a.exe' }); j = await wait(H2, r.id); ok(j.state === 'failed', 'hiç fonksiyon decompile edilmediyse başarısız');

  // IDAPython yoksa Hex-Rays toplu moduna dusme
  { const f = path.join(idaDir, 'idat64'); fs.writeFileSync(f, '#!/bin/sh\nfor a in "$@"; do case "$a" in -S*) echo "FATAL ERROR: ${a#-S}: unknown file extension" >&2; exit 1;; -Ohexrays*) printf "//----- (0000000000401000) ------\\nint main(){}\\n//----- (0000000000401100) ------\\nvoid f(){}\\n" > decompiled.c; exit 0;; esac; done\nexit 9\n'); fs.chmodSync(f, 0o755);
    const H4 = mk(); r = await H4.start({ tool: 'ida', kind: 'pe', data: natArr, name: 'a.exe' }); j = await wait(H4, r.id); ok(j.state === 'done' && /2 fonksiyon/.test(j.message) && j.files.some((x) => x.rel === 'decompiled.c'), 'IDAPython yoksa toplu Hex-Rays moduna geçildi: ' + j.state + ' ' + j.message.slice(0, 40)); ok(fs.existsSync(path.join(j.outDir, '_statscan_arac-log.txt')), 'araç kaydı yazıldı');
    fs.writeFileSync(f, '#!/bin/sh\necho "bir hata" >&2\nexit 1\n'); fs.chmodSync(f, 0o755); r = await mk().start({ tool: 'ida', kind: 'pe', data: natArr, name: 'a.exe' }); const H5 = mk(); r = await H5.start({ tool: 'ida', kind: 'pe', data: natArr, name: 'a.exe' }); j = await wait(H5, r.id); ok(j.state === 'failed' && /bir hata/.test(j.message), 'hata ayrıntısı mesajda: ' + j.message.slice(-60)); }
  // paths.json: yalnizca bilinen dosya adi
  fs.mkdirSync(path.join(tmp, 'tools'), { recursive: true }); const evil = path.join(tmp, 'evil.sh'); fs.writeFileSync(evil, '#!/bin/sh\ntouch /tmp/pwned\n'); fs.chmodSync(evil, 0o755);
  fs.writeFileSync(path.join(tmp, 'tools', 'paths.json'), JSON.stringify({ ghidra: evil })); ok(!mk().tools().some((t) => t.id === 'ghidra'), 'paths.json: bilinmeyen dosya adı (evil.sh) reddedildi');
  const gdir = path.join(tmp, 'ghidra_11.0_PUBLIC', 'support'); fs.mkdirSync(gdir, { recursive: true }); const gh = path.join(gdir, 'analyzeHeadless'); fs.writeFileSync(gh, '#!/bin/sh\nout="$STATSCAN_OUT"; [ -f "$1" ] || mkdir -p "$1"\nprintf "functions=2\\ndecompiled=2\\nfailed=0\\nskipped=0\\nerror=\\n" > "$out/_statscan_status.txt"; echo x > "$out/decompiled.c"\n'); fs.chmodSync(gh, 0o755);
  ok(mk().tools().some((t) => t.id === 'ghidra' && /analyzeHeadless$/.test(t.path)), 'Ghidra bilinen konumdan bulundu');
  r = await mk().start({ tool: 'ghidra', kind: 'elf', data: natArr, name: 'a.out' }); const Hg = null; 
  fs.rmSync(path.join(tmp, 'tools', 'paths.json'));
  const H3 = mk(); r = await H3.start({ tool: 'ghidra', kind: 'elf', data: natArr, name: 'a.out' }); j = await wait(H3, r.id); ok(j.state === 'done', 'Ghidra sahte araç: done (' + j.state + ' ' + j.message.slice(0, 40) + ')');
  ok(!fs.existsSync('/tmp/pwned'), 'paths.json ile keyfi komut çalıştırılmadı');
  const sv = await H.save({ name: 'x.js', outputs: [{ name: '../../etc/passwd', text: 'a' }, { name: 'a.txt', text: 'b' }, { name: 'a.txt', text: 'c' }] }); ok(sv.ok && sv.files.length === 3 && sv.files.every((f) => !f.name.includes('/')) && sv.dir.startsWith(path.join(tmp, 'out')), 'kaydetme: yol sızdırma yok, çakışma ezilmedi: ' + sv.files.map((f) => f.name).join(','));
  ok(fs.readFileSync(path.join(sv.dir, 'a.txt'), 'utf8') === 'b' && fs.readFileSync(path.join(sv.dir, 'a-2.txt'), 'utf8') === 'c', 'aynı ad ezilmedi');
  fs.rmSync(tmp, { recursive: true, force: true }); console.log(bad ? bad + ' TEST BAŞARISIZ' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
})();
