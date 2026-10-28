// Kovan Derleyici arayuzu (Playwright) + GERCEK ana surec islemcileri (JDK 17+ varsa) — kopru exposeFunction ile baglanir
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { createRequire as cr } from 'node:module';
const R = cr(import.meta.url); const { createHost } = R('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const URL = 'file:///home/claude/statscan/app/StatScan.html#/compiler'; const dl = fs.mkdtempSync(path.join(os.tmpdir(), 'ucp-dl-')); const wd = fs.mkdtempSync(path.join(os.tmpdir(), 'ucp-src-'));
const shown = []; const host = createHost({ service: { closeAll() {} }, downloadsDir: dl, notify() {}, showItemInFolder: (p) => shown.push(p) }).handlers;
fs.writeFileSync(wd + '/Test.java', 'public class Test { public static void main(String[] a){ System.out.println("hi"); } }'); fs.writeFileSync(wd + '/Broken.java', 'public class Broken { void f( { } }'); fs.writeFileSync(wd + '/NoMain.java', 'public class NoMain { }'); fs.writeFileSync(wd + '/script.py', 'print(1)'); fs.writeFileSync(wd + '/Other.java', 'public class Different { public static void main(String[] a){} }');
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
// 1) tarayici modu
let ctx = await b.newContext({ viewport: { width: 1280, height: 900 } }); let pg = await ctx.newPage(); const errs = []; pg.on('pageerror', (e) => errs.push(e.message)); await pg.goto(URL); await pg.waitForTimeout(300);
ok(/yalnızca masaüstü/i.test(await pg.textContent('.cp-jdk')), 'tarayıcıda: masaüstü gerekli uyarısı'); await pg.setInputFiles('#cp-file', wd + '/Test.java'); await pg.waitForTimeout(300);
ok(await pg.inputValue('#cp-main') === 'Test' && await pg.inputValue('#cp-name') === 'Test' && await pg.isDisabled('#cp-go'), 'tarayıcıda dosya incelenir, derle düğmesi kapalı');
await pg.setInputFiles('#cp-file', wd + '/script.py'); await pg.waitForTimeout(200); ok(/yalnızca \.java/.test(await pg.textContent('#app-compiler .cv-live')), '.py reddedilir, açıklama var'); await ctx.close();
// 2) masaustu (gercek islemciler)
ctx = await b.newContext({ viewport: { width: 1280, height: 900 } }); await ctx.exposeFunction('__h', async (n, args) => { const a = (args || []).map((x) => (x && x.files ? Object.assign({}, x, { files: x.files.map((f) => Object.assign({}, f, { bytes: Buffer.from(f.bytes) })) }) : x)); return JSON.parse(JSON.stringify((await host[n]({}, ...a)) || null)); });
await ctx.addInitScript(() => { const c = (n) => (...a) => window.__h(n, a.map((x) => (x && x.files ? { ...x, files: x.files.map((f) => ({ ...f, bytes: Array.from(f.bytes) })) } : x))); window.statscanHost = Object.freeze({ desktop: true, compileJdk: c('compile:jdk'), compileStart: c('compile:start'), compileJob: c('compile:job'), compileCancel: c('compile:cancel'), compileOpen: c('compile:open'), storeGet: async () => null, storeSet: async () => ({}), watchSuggest: async () => [], watchLog: async () => ({ log: [], folders: [] }), watchTake: async () => ({ item: null }), watchSet: async () => ({}), status: async () => ({ available: false, reasons: [{ title: 't' }] }), info: async () => ({}), settingsGet: async () => ({ autostart: { supported: false, reason: '' } }) }); });
pg = await ctx.newPage(); pg.on('pageerror', (e) => errs.push(e.message)); await pg.goto(URL); await pg.waitForTimeout(800);
const jdkOk = /JDK hazır/.test(await pg.textContent('.cp-jdk')); if (!jdkOk) { console.log('SKIP: uygun JDK yok:', await pg.textContent('.cp-jdk')); await b.close(); process.exit(bad ? 1 : 0); }
ok(true, 'masaüstü: JDK bulundu → ' + (await pg.textContent('.cp-jdk')).slice(0, 60));
await pg.setInputFiles('#cp-file', wd + '/NoMain.java'); await pg.waitForTimeout(250); ok(/bulunamadı/.test(await pg.textContent('#app-compiler .cv-live')) && await pg.isDisabled('#cp-go'), 'main yoksa derle kapalı + açıklama');
await pg.setInputFiles('#cp-file', wd + '/Other.java'); await pg.waitForTimeout(250); ok(/dosya adıyla/.test(await pg.textContent('.cp-probs')), 'public sınıf/dosya adı uyuşmazlığı önceden uyarılır');
await pg.setInputFiles('#cp-file', wd + '/Broken.java'); await pg.waitForTimeout(250); ok(await pg.isDisabled('#cp-go'), 'main\'i olmayan/bozuk dosya: derle kapalı');
fs.writeFileSync(wd + '/BrokenMain.java', 'public class BrokenMain { public static void main(String[] a) { int x = ; } }'); await pg.setInputFiles('#cp-file', wd + '/BrokenMain.java'); await pg.waitForTimeout(250); await pg.click('#cp-go'); await pg.waitForSelector('#cp-ready, #app-compiler .cp-s.fail', { state: 'attached', timeout: 60000 }); await pg.waitForFunction(() => document.querySelector('#cp-go') && !document.querySelector('#cp-go').disabled, null, { timeout: 60000 });
ok(/başarısız/.test(await pg.textContent('#app-compiler .cv-live')) && /error/.test(await pg.textContent('.cp-log')) && await pg.evaluate(() => document.querySelector('#cp-ready').hidden), 'javac hatası: açıklama + derleyici çıktısı görünür, "hazır" çubuğu yok');
await pg.setInputFiles('#cp-file', wd + '/Test.java'); await pg.waitForTimeout(250); ok(await pg.isEnabled('#cp-go'), 'geçerli dosya: derle açık'); await pg.fill('#cp-name', '1bad name'); ok(await pg.isDisabled('#cp-go'), 'geçersiz uygulama adı: derle kapalı'); await pg.fill('#cp-name', 'demo');
await pg.click('#cp-go'); await pg.waitForSelector('.cp-s.run, .cp-s.ok', { timeout: 20000 }); ok(await pg.isVisible('#cp-cancel'), 'çalışırken İptal görünür');
await pg.waitForFunction(() => !document.querySelector('#cp-ready').hidden, null, { timeout: 90000 });
const rt = await pg.textContent('#cp-ready'); ok(/İndirilmeye hazır/.test(rt) && /Kovan-Derleme/.test(rt) && /demo/.test(rt), 'altta "indirilmeye hazır" çubuğu: ' + rt.slice(0, 90));
const pos = await pg.evaluate(() => { const r = document.querySelector('#cp-ready').getBoundingClientRect(); return [Math.round(r.bottom), innerHeight, getComputedStyle(document.querySelector('#cp-ready')).position]; }); ok(pos[2] === 'fixed' && pos[0] > pos[1] - 40, 'çubuk ekranın altında sabit (' + pos + ')');
ok((await pg.$$eval('.cp-s.ok', (x) => x.length)) === 6, 'altı adım da ✓');
await pg.click('#cp-ready .cv-primary'); await pg.waitForTimeout(150); ok(shown.length === 1 && /demo/.test(shown[0]) && fs.existsSync(shown[0]), '"Klasörü göster" gerçek dosyayı açar');
ok(fs.existsSync(path.join(dl, 'Kovan-Derleme', 'demo')), 'İndirilenler/Kovan-Derleme/demo oluştu');
await pg.click('#cp-ready button:not(.cv-primary)'); ok(await pg.evaluate(() => document.querySelector('#cp-ready').hidden), 'Kapat çubuğu gizler');
await pg.setViewportSize({ width: 380, height: 800 }); await pg.waitForTimeout(150); ok(await pg.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'dar ekranda yatay taşma yok');
ok(errs.length === 0, 'sayfa hatası yok ' + errs.slice(0, 2).join('|'));
await b.close(); fs.rmSync(dl, { recursive: true, force: true }); fs.rmSync(wd, { recursive: true, force: true }); console.log(bad ? bad + ' HATA' : 'TAMAM'); process.exit(bad ? 1 : 0);
