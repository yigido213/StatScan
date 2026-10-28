'use strict';
/* Kovan Derleyici (ana surec): dogrulama, JDK bulma, gercek javac/jar/jdeps/jpackage hattı (JDK 17+ gerekir; yoksa atlanir) */
const fs = require('fs'), os = require('os'), path = require('path'), cp = require('child_process');
const { createHost, compileModule } = require('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms)); const B = (s) => Buffer.from(s, 'utf8');
(async () => {
  const dl = fs.mkdtempSync(path.join(os.tmpdir(), 'kc-dl-')); const tmpBefore = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('kovan-java-')).length;
  const mk = (extra) => createHost(Object.assign({ service: { closeAll() {} }, downloadsDir: dl, notify: (t, b) => { mk.last = [t, b]; }, showItemInFolder: (p) => { mk.shown = p; } }, extra || {})).handlers;
  const H = mk(); const V = compileModule.validate;
  const good = { files: [{ name: 'Test.java', bytes: B('public class Test { public static void main(String[] a){ System.out.println("merhaba"); } }') }], mainClass: 'Test', name: 'test', console: 'auto' };
  ok(V(good) === null, 'geçerli istek kabul');
  for (const [m, patch] of [['yol gezintisi adı', { files: [{ name: '../Evil.java', bytes: B('x') }] }], ['.exe dosya', { files: [{ name: 'a.exe', bytes: B('x') }] }], ['boş dosya', { files: [{ name: 'A.java', bytes: B('') }] }], ['aynı ad', { files: [{ name: 'A.java', bytes: B('x') }, { name: 'A.java', bytes: B('y') }] }], ['büyük dosya', { files: [{ name: 'A.java', bytes: Buffer.alloc(3e6, 65) }] }], ['kötü ana sınıf', { mainClass: 'A; calc' }], ['kötü ad', { name: 'a b' }], ['ad ../', { name: '../x' }], ['konsol', { console: 'rm' }], ['dosya yok', { files: [] }]]) ok(V(Object.assign({}, good, patch)) !== null, 'reddedildi: ' + m);
  ok((await H['compile:start']({}, { files: [{ name: '../x.java', bytes: B('x') }], mainClass: 'A', name: 'a' })).error === 'compile', 'start geçersiz isteği reddeder');
  // JDK yok
  const none = mk({ compileOnlyJdkDirs: [] }); let r = await none['compile:start']({}, good); ok(r.error === 'compile' && r.needJdk && /JDK/.test(r.message), 'JDK yoksa açık hata + needJdk');
  const j = await H['compile:jdk'](); if (!j.found) { console.log('SKIP: uygun JDK (17+, jpackage) yok'); console.log(bad ? bad + ' HATA' : 'tüm testler geçti'); process.exit(bad ? 1 : 0); }
  ok(j.best.major >= 17 && j.best.missing.length === 0, 'JDK bulundu: ' + j.best.version);
  const poll = async (id) => { for (let i = 0; i < 600; i++) { const s = await H['compile:job']({}, id); if (s.state !== 'running') return s; await sleep(200); } throw new Error('zaman aşımı'); };
  // derleme hatası
  r = await H['compile:start']({}, { files: [{ name: 'Bad.java', bytes: B('public class Bad { void f( { } }') }], mainClass: 'Bad', name: 'bad' }); let s = await poll(r.id);
  ok(s.state === 'failed' && s.steps.find((x) => x.id === 'javac').status === 'fail' && s.result && /error/.test(s.result.javacOutput) && !/kovan-java-/.test(s.result.javacOutput), 'javac hatası: başarısız, çıktı döner, geçici yol sızmaz');
  ok(!fs.existsSync(path.join(dl, 'Kovan-Derleme', 'bad')), 'hatada çıktı klasörü oluşmadı');
  // basarili (paketli, ayri dosya adi/paket)
  const src = 'package demo.app;\npublic class Greeter { public static void main(String[] a){ System.out.println("merhaba kovan " + a.length); } }';
  r = await H['compile:start']({}, { files: [{ name: 'Greeter.java', bytes: B(src) }], mainClass: 'demo.app.Greeter', name: 'greeter', console: 'auto' }); const second = await H['compile:start']({}, good); ok(second.error === 'compile' && /sürüyor/.test(second.message), 'aynı anda ikinci derleme reddedilir');
  s = await poll(r.id); ok(s.state === 'done' && s.steps.every((x) => x.status === 'ok'), 'tüm adımlar tamam (' + s.state + ')'); if (s.state !== 'done') console.log(s.error, s.log.slice(-800));
  const R = s.result; ok(R && fs.existsSync(R.launcher) && R.outDir.startsWith(path.join(dl, 'Kovan-Derleme')) && fs.existsSync(R.jar), 'çıktı İndirilenler/Kovan-Derleme altında: ' + (R && path.relative(dl, R.outDir)));
  ok(R.modules.includes('java.base') && R.size > 1e6 && !R.gui && R.console, 'modüller çözüldü, konsol uygulaması algılandı (' + R.modules + ', ' + Math.round(R.size / 1e6) + ' MB)');
  const o1 = cp.spawnSync('java', ['-jar', R.jar, 'x'], { encoding: 'utf8', env: Object.assign({}, process.env, { JAVA_TOOL_OPTIONS: '' }) }); ok(/merhaba kovan 1/.test(o1.stdout), 'üretilen JAR çalışır (test kaynağı)');
  if (process.platform !== 'win32') { const o2 = cp.spawnSync(R.launcher, ['a', 'b'], { encoding: 'utf8' }); ok(/merhaba kovan 2/.test(o2.stdout), 'üretilen çalıştırıcı kendi çalışma zamanıyla çalışır (JDK olmadan değil, paketlenmiş runtime)'); }
  ok(mk.last && /Hazır/.test(mk.last[1]), 'hazır bildirimi gönderildi'); await H['compile:open']({}, r.id); ok(mk.shown === R.launcher, 'klasörde göster doğru dosyayı verir');
  // ikinci derleme: ad cakismasi -> -2
  r = await H['compile:start']({}, { files: [{ name: 'Greeter.java', bytes: B(src) }], mainClass: 'demo.app.Greeter', name: 'greeter' }); s = await poll(r.id); ok(s.state === 'done' && /greeter-2$/.test(s.result.outDir), 'aynı ad varsa üzerine yazmaz (greeter-2)');
  // GUI algilama (java.desktop)
  r = await H['compile:start']({}, { files: [{ name: 'Win.java', bytes: B('import javax.swing.*; public class Win { public static void main(String[] a){ if (a.length > 5) new JFrame("x").setVisible(true); } }') }], mainClass: 'Win', name: 'win' }); s = await poll(r.id); ok(s.state === 'done' && s.result.gui === true && /java\.desktop/.test(s.result.modules), 'Swing → pencere uygulaması, java.desktop eklendi');
  const left = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('kovan-java-')).length; ok(left === tmpBefore, 'geçici çalışma klasörleri temizlendi');
  fs.rmSync(dl, { recursive: true, force: true }); console.log(bad ? bad + ' HATA' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.log('FAIL ' + e.stack); process.exit(1); });
