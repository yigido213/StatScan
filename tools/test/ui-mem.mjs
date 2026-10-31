// RAM Analizi arayüz testi (Playwright). Arayüz GERÇEK host koduna (MEMMOD + 102-memscan bulgu motoru) köprüyle bağlanır; Volatility yerine SAHTE vol (tools/test/mem/fake-vol.js) çalışır.
// Çalıştır: node tools/test/ui-mem.mjs   (SHOTS=klasör verilirse ekran görüntüleri oraya yazılır)
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import crypto from 'node:crypto'; import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url)); const ROOT = path.resolve(HERE, '../..');
const { createHost } = createRequire(import.meta.url)(path.join(ROOT, 'app/desktop/host.js')); const engine = createRequire(import.meta.url)(path.join(ROOT, 'app/dyn/statscan-dyn.js')).loadEngine(path.join(ROOT, 'app/StatScan.html'));
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const URL = 'file://' + path.join(ROOT, 'app/StatScan.html'); const SHOTS = process.env.SHOTS || '';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-uimem-')); const bin = path.join(tmp, 'bin'); fs.mkdirSync(bin);
fs.writeFileSync(path.join(bin, 'vol'), '#!/bin/sh\nexec "' + process.execPath + '" "' + path.join(HERE, 'mem/fake-vol.js') + '" "$@"\n'); fs.chmodSync(path.join(bin, 'vol'), 0o755);
const dump = path.join(tmp, 'ornek-dokum.raw'); fs.writeFileSync(dump, crypto.randomBytes(8192)); const dumpSha = crypto.createHash('sha256').update(fs.readFileSync(dump)).digest('hex');
process.env.FAKE_FIX = path.join(HERE, 'mem/fixtures.json'); process.env.FAKE_LOG = path.join(tmp, 'argv.log');
let confirmAns = false; let confirmed = [];
const mkHost = () => createHost({ service: { closeAll() {} }, sys: false, compile: false, mem: { onlyDirs: [bin], engine, chooseDump: async () => dump, chooseVol: async () => path.join(bin, 'vol'), confirm: async (o) => { confirmed.push(o); return confirmAns; } } });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
const CH = ['memTools', 'memChooseVol', 'memChooseDump', 'memStart', 'memJob', 'memCancel', 'memRows', 'memReport'];
async function page(vp, withHost = true, lang = null) {
  const host = mkHost(); const ctx = await b.newContext({ viewport: vp || { width: 1366, height: 900 }, reducedMotion: 'reduce', acceptDownloads: true }); const pg = await ctx.newPage(); pg.errs = []; pg.host = host;
  pg.on('pageerror', (e) => pg.errs.push(e.message)); pg.on('console', (m) => m.type() === 'error' && pg.errs.push(m.text()));
  if (lang) await pg.addInitScript((l) => { try { localStorage.setItem('kovan.lang', l); } catch (e) { /* yok */ } }, lang);
  if (withHost) { const map = { memTools: 'mem:tools', memChooseVol: 'mem:chooseVol', memChooseDump: 'mem:chooseDump', memStart: 'mem:start', memJob: 'mem:job', memCancel: 'mem:cancel', memRows: 'mem:rows', memReport: 'mem:report' };
    await pg.exposeFunction('__h', async (ch, ...a) => { const f = host.handlers[ch]; return f ? JSON.parse(JSON.stringify(await f(null, ...a))) : { error: 'nochan' }; });
    await pg.addInitScript((m) => { const c = (ch, ...a) => window.__h(ch, ...a); const o = { desktop: true, openVirusTotal: () => Promise.resolve({ ok: true }), settingsGet: () => Promise.resolve({ desktop: true, platform: 'linux', version: 'test', autostart: { supported: false, reason: '' }, openAtLogin: false, startMinimized: false, autoUpdate: false, feedUrl: '' }) };
      o.memTools = (f) => c(m.memTools, f === true); o.memChooseVol = () => c(m.memChooseVol); o.memChooseDump = () => c(m.memChooseDump); o.memStart = (r) => c(m.memStart, { layers: r && r.layers, symbols: r && r.symbols === 'allow' ? 'allow' : 'offline', timeoutMin: r && r.timeoutMin }); o.memJob = (i) => c(m.memJob, String(i)); o.memCancel = (i) => c(m.memCancel, String(i)); o.memRows = (i, l, of, li, q) => c(m.memRows, String(i), String(l), Number(of) || 0, Number(li) || 100, String(q || '')); o.memReport = (i, k) => c(m.memReport, String(i), k === 'json' ? 'json' : 'md');
      window.statscanHost = Object.freeze(o); }, map); }
  return pg;
}
const shot = async (pg, name) => { if (SHOTS) { fs.mkdirSync(SHOTS, { recursive: true }); await pg.screenshot({ path: path.join(SHOTS, name + '.png'), fullPage: false }); } };
const noOverflow = (pg) => pg.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1 && document.body.scrollWidth <= window.innerWidth + 1);
const waitRes = (pg, ms) => pg.waitForSelector('#rm-res:not([hidden]) .rm-body', { timeout: ms || 30000 });

// ---------- 0) tarayıcı modu (host yok) ----------
let pg = await page(null, false); await pg.goto(URL + '#/ramanaliz'); await pg.waitForTimeout(300);
ok((await pg.title()) === 'RAM Analizi · Kovan', 'başlık: RAM Analizi · Kovan');
ok(/masaüstü uygulaması gerektirir/.test(await pg.textContent('#app-ramanaliz')) && await pg.evaluate(() => !document.querySelector('#app-ramanaliz #rm-start')), 'tarayıcı modu: nazik uyarı, araç denetimleri yok');
ok(pg.errs.length === 0, 'tarayıcı modunda konsol hatası yok ' + JSON.stringify(pg.errs)); await pg.context().close();

// ---------- 1) kenar çubuğu / Home kaydı ----------
pg = await page(); await pg.goto(URL); await pg.waitForTimeout(300);
ok(await pg.evaluate(() => { const a = document.querySelector('#side-nav a[data-route="ramanaliz"]'); return !!a && a.textContent.trim() === 'RAM Analizi' && a.title === 'RAM Analizi'; }), 'kenar çubuğunda “RAM Analizi”');
ok(await pg.evaluate(() => { const c = document.querySelector('#toolgrid .toolcard[data-open="ramanaliz"]'); return !!c && /Beta · v0\.0\.1/.test(c.textContent); }), 'Home kartı: Beta · v0.0.1');
ok(await pg.evaluate(() => { let e = document.querySelector('#side-nav a[data-route="ramanaliz"]').previousElementSibling; while (e && !e.classList.contains('side-label')) e = e.previousElementSibling; return e && e.textContent === 'Windows'; }), 'kategori: Windows altında');
ok(await pg.evaluate(() => document.querySelectorAll('#toolgrid .toolcard.empty').length) === 1, 'yer tutucu kart hâlâ var (sahte araç eklenmedi)'); await pg.context().close();

// ---------- 2) boşta durum ----------
pg = await page(); await pg.goto(URL + '#/ramanaliz'); await pg.waitForSelector('#rm-toolsline.ok', { timeout: 15000 });
ok(/Volatility 3 bulundu: sürüm 2\.28\.2-fake/.test(await pg.textContent('#rm-toolsline')), 'araç satırı: Volatility 3 bulundu + sürüm');
ok(await pg.evaluate(() => document.querySelector('#rm-start').disabled), 'döküm seçilmeden “Analizi başlat” kapalı');
ok(await pg.evaluate(() => document.querySelector('#rm-install').hidden), 'Volatility bulununca kurulum yönergesi gizli');
const chk = await pg.evaluate(() => [...document.querySelectorAll('#rm-layers input')].map((c) => c.dataset.id + ':' + (c.checked ? 1 : 0)).join(','));
ok(chk === 'info:1,pslist:1,psscan:1,pstree:1,cmdline:1,dlllist:1,ldrmodules:1,malfind:1,netscan:1,svcscan:1,modules:1,driverscan:1,filescan:0,handles:0', 'katmanlar: 12 açık, filescan/handles (ağır) kapalı');
ok(await pg.inputValue('#rm-timeout') === '10' && await pg.evaluate(() => document.querySelector('#rm-sym-off').checked && !document.querySelector('#rm-sym-on').checked), 'varsayılanlar: 10 dk, sembol ağı KAPALI (çevrimdışı)');
ok(/dürüst sınırlar/.test(await pg.textContent('#rm-note')) && /henüz denenmedi/.test(await pg.textContent('#rm-note')), 'beta notu: gerçek Windows/Volatility ile denenmedi yazıyor');
ok(await pg.evaluate(() => { const f = [...document.querySelectorAll('#app-ramanaliz input')]; return f.every((i) => i.labels && i.labels.length || i.getAttribute('aria-label')); }), 'a11y: her giriş alanının etiketi var');
ok(await pg.evaluate(() => !!document.querySelector('#rm-live[role=status][aria-live=polite]') && document.querySelector('#rm-start').tagName === 'BUTTON'), 'a11y: canlı durum bölgesi + gerçek düğmeler'); ok(await noOverflow(pg), 'taşma yok (1366)'); await shot(pg, '1-idle-1366');
await pg.click('#rm-pickdump'); await pg.waitForSelector('#rm-dumpline.ok'); ok(/ornek-dokum\.raw — 8\.0 KB/.test(await pg.textContent('#rm-dumpline')) && !(await pg.textContent('#rm-dumpline')).includes(tmp), 'dosya seçilince ad+boyut görünür, tam yol arayüze gelmez');
ok(await pg.evaluate(() => !document.querySelector('#rm-start').disabled), 'döküm seçilince “Analizi başlat” açılır');

// ---------- 3) tam analiz ----------
confirmed = []; fs.writeFileSync(process.env.FAKE_LOG, ''); await pg.click('#rm-start'); await pg.waitForSelector('#rm-cancel:not([hidden])', { timeout: 5000 }).catch(() => {});
ok(await pg.evaluate(() => document.querySelector('#rm-start').disabled && [...document.querySelectorAll('#rm-layers input, #rm-timeout, #rm-sym input, #rm-pickdump')].every((e) => e.disabled)), 'çalışırken seçenekler kilitli');
await waitRes(pg); await pg.waitForTimeout(150);
ok(confirmed.length === 0 && fs.readFileSync(process.env.FAKE_LOG, 'utf8').trim().split('\n').filter((l) => !l.includes('"-h"')).every((l) => l.includes('--offline')), 'varsayılan: ağ kapalı (--offline), onay penceresi çıkmadı');
const score = +(await pg.textContent('#rm-res .rm-big')).replace(/[^0-9]/g, '').slice(0, -3); ok(score >= 60 && score <= 100, 'genel puan görünür (0-100, yüksek): ' + score);
ok(/Analiz bitti/.test(await pg.textContent('#rm-live')), 'durum: Analiz bitti');
ok(await pg.evaluate(() => document.querySelector('#rm-res .rm-big').getAttribute('role') === 'img' && /Genel şüphe puanı \d+ \/ 100/.test(document.querySelector('#rm-res .rm-big').getAttribute('aria-label'))), 'a11y: puanın erişilebilir adı var');
ok(!/temiz|zararsız/i.test(await pg.textContent('#rm-res .rm-scoretx')), 'puan alanı “temiz” hükmü vermiyor');
const nF = await pg.evaluate(() => document.querySelectorAll('#rm-findings .rm-find').length); ok(nF >= 10, 'bulgu kartları listelendi (' + nF + ')');
ok(await pg.evaluate(() => [...document.querySelectorAll('#rm-findings .rm-find')].some((a) => /gizli|pslist’te yok/i.test(a.textContent) && /rootkitd/.test(a.textContent))), 'gizli süreç bulgusu (rootkitd.exe) var');
ok(await pg.evaluate(() => [...document.querySelectorAll('#rm-findings .rm-find')].filter((a) => /^(Yüksek|Orta|Düşük)/.test(a.textContent) && !a.querySelector('.rm-pts') === false).every((a) => a.querySelector('details summary') && /yanlış pozitif/i.test(a.querySelector('details summary').textContent))), 'her puanlı bulguda “Olası yanlış pozitif” açılır bölümü');
await pg.click('#rm-findings .rm-find:first-child details summary'); ok(await pg.evaluate(() => document.querySelector('#rm-findings .rm-find:first-child details').open && document.querySelector('#rm-findings .rm-find:first-child details p').textContent.length > 30), 'yanlış pozitif açıklaması okunur');
await pg.click('#rm-body .sm-seg [data-v="high"]'); const nH = await pg.evaluate(() => document.querySelectorAll('#rm-findings .rm-find').length); ok(nH > 0 && nH < nF && await pg.evaluate(() => [...document.querySelectorAll('#rm-findings .rm-find')].every((a) => a.classList.contains('high'))), 'önem süzgeci: yalnız “Yüksek” (' + nH + '/' + nF + ')');
ok(await pg.evaluate(() => document.querySelector('#rm-body .sm-seg [data-v="high"]').getAttribute('aria-pressed') === 'true'), 'a11y: süzgeç aria-pressed'); await pg.click('#rm-body .sm-seg [data-v="all"]'); await shot(pg, '2-findings-1366');
// süreçler
await pg.click('#rm-res .sm-tabs [data-v="procs"]'); await pg.waitForSelector('#rm-body .sm-t tbody tr'); const nP = await pg.evaluate(() => document.querySelectorAll('#rm-body .sm-t tbody tr').length);
ok(nP >= 10 && nP <= 1500, 'süreç tablosu dolu (' + nP + ' ≤ 1500)'); ok(await pg.evaluate(() => document.querySelector('#rm-body .sm-t th[aria-sort="descending"]').dataset.k) === 'score' && await pg.evaluate(() => { const v = [...document.querySelectorAll('#rm-body .sm-t tbody tr td:first-child')].map((t) => +t.textContent); return v.every((x, i) => i === 0 || x <= v[i - 1]); }), 'varsayılan sıralama: puana göre azalan');
ok(await pg.evaluate(() => /scvhost\.exe/.test(document.querySelector('#rm-body .sm-t tbody tr:first-child').textContent)), 'en şüpheli süreç en üstte (scvhost.exe)');
await pg.focus('#rm-body .sm-t tbody tr:first-child'); await pg.keyboard.press('Enter'); await pg.waitForSelector('#rm-pdetail:not([hidden])'); ok(await pg.evaluate(() => /Puan gerekçeleri/.test(document.querySelector('#rm-pdetail').textContent) && document.querySelectorAll('#rm-pdetail .sm-why li').length >= 3 && /Temp/.test(document.querySelector('#rm-pdetail').textContent)), 'klavye (Enter): süreç ayrıntısı + puan gerekçeleri');
await pg.fill('#rm-pq', '4200'); await pg.waitForTimeout(100); ok(await pg.evaluate(() => document.querySelectorAll('#rm-body .sm-t tbody tr').length) === 1, 'süreç araması (PID 4200)');
await pg.fill('#rm-pq', ''); await pg.click('#rm-body .sm-t th[data-k="pid"] button'); ok(await pg.evaluate(() => document.querySelector('#rm-body .sm-t th[data-k="pid"]').getAttribute('aria-sort')) === 'descending', 'sütun başlığıyla sıralama (aria-sort)'); await shot(pg, '3-procs-1366');
// katmanlar
await pg.click('#rm-res .sm-tabs [data-v="layers"]'); await pg.waitForSelector('#rm-ltable .sm-t tbody tr'); ok(await pg.evaluate(() => [...document.querySelectorAll('#rm-lsel option')].map((o) => o.value).join(',')) === 'info,pslist,psscan,pstree,cmdline,dlllist,ldrmodules,malfind,netscan,svcscan,modules,driverscan', 'katman seçici: yalnız çalışan 12 katman');
await pg.selectOption('#rm-lsel', 'psscan'); await pg.waitForFunction(() => /\/ 15$/.test(document.querySelector('#rm-pos').textContent)); ok(await pg.evaluate(() => document.querySelectorAll('#rm-ltable .sm-t tbody tr').length) === 15 && await pg.evaluate(() => document.querySelector('#rm-next').disabled && document.querySelector('#rm-prev').disabled), 'psscan: 15 satır, tek sayfa (önceki/sonraki kapalı)');
await pg.fill('#rm-lq', 'rootkitd'); await pg.waitForFunction(() => /1 \/ 1$/.test(document.querySelector('#rm-pos').textContent)); ok(await pg.evaluate(() => /rootkitd/.test(document.querySelector('#rm-ltable').textContent)), 'katmanda arama');
await pg.fill('#rm-lq', ''); await pg.waitForFunction(() => /\/ 15$/.test(document.querySelector('#rm-pos').textContent)); await shot(pg, '4-layers-1366');
// rapor indirme
const [dm] = await Promise.all([pg.waitForEvent('download'), pg.click('#rm-exp-md')]); const mdTxt = fs.readFileSync(await dm.path(), 'utf8'); ok(dm.suggestedFilename() === 'kovan-ram-analizi.md' && /Genel puan: \d+ \/ 100/.test(mdTxt) && /yanlış pozitif/i.test(mdTxt) && !/\btemiz\b/i.test(mdTxt), 'Markdown rapor iniyor (puan + yanlış pozitif; “temiz” yok)');
const [dj] = await Promise.all([pg.waitForEvent('download'), pg.click('#rm-exp-json')]); let js = null; try { js = JSON.parse(fs.readFileSync(await dj.path(), 'utf8')); } catch (e) { /* bozuk */ } ok(js && js.result && js.result.score === score, 'JSON rapor iniyor ve puan aynı');
ok(crypto.createHash('sha256').update(fs.readFileSync(dump)).digest('hex') === dumpSha, 'döküm dosyası değişmedi (SHA-256)'); ok(pg.errs.length === 0, 'konsol/sayfa hatası yok ' + JSON.stringify(pg.errs)); await pg.context().close();

// ---------- 4) çevrimdışı + sembol yok → net hata; onay akışı ----------
process.env.FAKE_MODE = 'symbols'; pg = await page(); await pg.goto(URL + '#/ramanaliz'); await pg.waitForSelector('#rm-toolsline.ok'); await pg.click('#rm-pickdump'); await pg.waitForSelector('#rm-dumpline.ok');
await pg.click('#rm-start'); await pg.waitForFunction(() => /çevrimdışı/.test(document.querySelector('#rm-live').textContent), null, { timeout: 20000 }); const lt = await pg.textContent('#rm-live');
ok(/çevrimdışı önbellekte yok/.test(lt) && /indirilemedi/.test(lt), 'sembol yok: “çevrimdışı önbellekte yok, indirilemedi” açıkça yazar'); ok(await pg.evaluate(() => !document.querySelector('#rm-retry').hidden), '“Sembol indirmeye izin vererek yeniden dene” düğmesi çıkar'); ok(await pg.evaluate(() => document.querySelector('#rm-res').hidden), 'başarısız analizde sonuç alanı yok (sahte puan gösterilmez)');
confirmAns = false; confirmed = []; await pg.click('#rm-retry'); await pg.waitForFunction(() => document.querySelector('#rm-start') && !document.querySelector('#rm-cancel').hidden === false, null, { timeout: 5000 }).catch(() => {}); await pg.waitForFunction(() => /çevrimdışı/.test(document.querySelector('#rm-live').textContent) && !document.querySelector('#rm-start').disabled, null, { timeout: 20000 });
ok(confirmed.length === 1 && /msdl\.microsoft\.com/.test(confirmed[0].message) && /Reddedersen ağ KULLANILMAZ/.test(confirmed[0].message), 'yeniden dene → onay penceresi neyin indirileceğini açıkça söyler');
ok(await pg.evaluate(() => document.querySelector('#rm-sym-on').checked), 'seçim “indirmeye izin iste” olarak kaldı'); confirmAns = true; confirmed = []; await pg.click('#rm-start'); await waitRes(pg, 30000); ok(confirmed.length === 1 && /Analiz bitti/.test(await pg.textContent('#rm-live')), 'onay verilince analiz tamamlanır (ağ izinli)');
ok(/izinli/.test(await pg.textContent('#rm-res .rm-scoretx')), 'sonuç başlığında ağ durumu: izinli'); delete process.env.FAKE_MODE; confirmAns = false; await pg.context().close();

// ---------- 5) iptal ----------
process.env.FAKE_SLEEP_MS = '1200'; pg = await page(); await pg.goto(URL + '#/ramanaliz'); await pg.waitForSelector('#rm-toolsline.ok'); await pg.click('#rm-pickdump'); await pg.waitForSelector('#rm-dumpline.ok'); await pg.click('#rm-start');
await pg.waitForSelector('#rm-steps .cp-s.run', { timeout: 10000 }); ok(await pg.evaluate(() => document.getAnimations().filter((a) => a.effect && a.effect.target && a.effect.target.closest && a.effect.target.closest('#app-ramanaliz')).length) === 0, 'hareket azaltma: araç içinde çalışan animasyon yok');
await pg.click('#rm-cancel'); await pg.waitForFunction(() => /İptal edildi/.test(document.querySelector('#rm-live').textContent), null, { timeout: 10000 }); ok(await pg.evaluate(() => !document.querySelector('#rm-start').disabled && document.querySelector('#rm-cancel').hidden && document.querySelector('#rm-res').hidden), 'iptal: arayüz sıfırlandı, sonuç yok, yeniden başlatılabilir'); delete process.env.FAKE_SLEEP_MS; await pg.context().close();

// ---------- 6) Volatility yok ----------
{ const host = createHost({ service: { closeAll() {} }, sys: false, compile: false, mem: { onlyDirs: [], engine, chooseDump: async () => dump } }); const ctx = await b.newContext({ viewport: { width: 1366, height: 900 }, reducedMotion: 'reduce' }); const p = await ctx.newPage(); p.errs = []; p.on('pageerror', (e) => p.errs.push(e.message));
  await p.exposeFunction('__h', async (ch, ...a) => JSON.parse(JSON.stringify(await host.handlers[ch](null, ...a)))); await p.addInitScript(() => { const c = (ch, ...a) => window.__h(ch, ...a); window.statscanHost = Object.freeze({ desktop: true, memTools: (f) => c('mem:tools', f === true), memChooseVol: () => c('mem:chooseVol'), memChooseDump: () => c('mem:chooseDump'), memStart: (r) => c('mem:start', r), memJob: (i) => c('mem:job', String(i)), memCancel: (i) => c('mem:cancel', String(i)), memRows: () => c('mem:rows'), memReport: () => c('mem:report'), settingsGet: () => Promise.resolve({ desktop: true, platform: 'linux', version: 't', autostart: { supported: false, reason: '' } }) }); });
  await p.goto(URL + '#/ramanaliz'); await p.waitForSelector('#rm-toolsline.warn', { timeout: 15000 }); ok(/bulunamadı/.test(await p.textContent('#rm-toolsline')) && !(await p.evaluate(() => document.querySelector('#rm-install').hidden)) && /pip install volatility3/.test(await p.textContent('#rm-install')), 'Volatility yok: “bulunamadı” + kurulum yönergesi (pip install volatility3)');
  await p.click('#rm-pickdump'); await p.waitForSelector('#rm-dumpline.ok'); ok(await p.evaluate(() => document.querySelector('#rm-start').disabled), 'Volatility yokken analiz başlatılamaz'); await shot(p, '5-novol-1366'); ok(p.errs.length === 0, 'hata yok'); await ctx.close(); }

// ---------- 7) dar ekranlar + İngilizce ----------
for (const vp of [{ width: 900, height: 800 }, { width: 390, height: 800 }]) { pg = await page(vp); await pg.goto(URL + '#/ramanaliz'); await pg.waitForSelector('#rm-toolsline.ok'); await pg.click('#rm-pickdump'); await pg.waitForSelector('#rm-dumpline.ok'); ok(await noOverflow(pg), 'taşma yok (' + vp.width + ', boşta)'); await shot(pg, '6-idle-' + vp.width);
  await pg.click('#rm-start'); await waitRes(pg); ok(await noOverflow(pg), 'taşma yok (' + vp.width + ', sonuç/bulgular)'); await pg.click('#rm-res .sm-tabs [data-v="procs"]'); await pg.waitForSelector('#rm-body .sm-t tbody tr'); ok(await noOverflow(pg), 'taşma yok (' + vp.width + ', süreç tablosu: yalnız tablo kutusu kayar)');
  ok(await pg.evaluate(() => { const w = document.querySelector('#rm-body .sm-wrap'); return w.scrollWidth >= w.clientWidth && getComputedStyle(w).overflowX !== 'visible'; }), 'tablo kendi kutusunda kaydırılır (' + vp.width + ')'); await shot(pg, '7-procs-' + vp.width);
  await pg.click('#rm-res .sm-tabs [data-v="layers"]'); await pg.waitForSelector('#rm-ltable .sm-t tbody tr'); ok(await noOverflow(pg), 'taşma yok (' + vp.width + ', katmanlar)'); ok(pg.errs.length === 0, 'hata yok (' + vp.width + ')'); await pg.context().close(); }
pg = await page({ width: 1366, height: 900 }, true, 'en'); await pg.goto(URL + '#/ramanaliz'); await pg.waitForSelector('#rm-toolsline.ok'); await pg.waitForTimeout(250);
ok((await pg.title()) === 'Memory Analysis · Kovan', 'EN: başlık Memory Analysis'); const trText = await pg.evaluate(() => document.querySelector('#app-ramanaliz').innerText); const tr = trText.match(/[^\n]*[çğıöşüÇĞİÖŞÜ][^\n]*/g) || [];
ok(tr.length === 0, 'EN: araç ekranında çevrilmemiş Türkçe satır yok ' + JSON.stringify(tr.slice(0, 4))); ok(/Start analysis/.test(trText) && /Choose dump…/.test(trText) && /Offline \(default\)/.test(trText), 'EN: ana etiketler İngilizce');
await pg.click('#rm-pickdump'); await pg.waitForSelector('#rm-dumpline.ok'); await pg.click('#rm-start'); await waitRes(pg); const tr2 = (await pg.evaluate(() => [...document.querySelectorAll('#rm-res .rm-scoretx, #rm-res .sm-tabs, #rm-res .rm-row, #rm-res summary, #rm-live, #rm-steps')].map((e) => e.innerText).join('\n'))).match(/[^\n]*[çğıöşüÇĞİÖŞÜ][^\n]*/g) || [];
ok(tr2.length === 0, 'EN: sonuç başlığı/sekmeler/düğmeler/adımlar çevrilmiş ' + JSON.stringify(tr2.slice(0, 4))); await shot(pg, '8-en-result'); await pg.context().close();

// ---------- 8) arayüz yol gönderemez (statik) ----------
const pre = fs.readFileSync(path.join(ROOT, 'app/desktop/preload.js'), 'utf8'); const mm = pre.split('\n').filter((l) => /^\s*mem[A-Z]/.test(l)).join('\n');
ok(/memChooseDump: \(\) => call\('mem:chooseDump'\)/.test(mm) && /memChooseVol: \(\) => call\('mem:chooseVol'\)/.test(mm) && !/\bfile\b|\bpath\b/i.test(mm.replace(/\/\/.*$/gm, '')), 'preload: mem* API dosya yolu parametresi taşımaz (dosya seçimi host dialogunda)');
fs.rmSync(tmp, { recursive: true, force: true }); await b.close(); console.log(bad ? '\n' + bad + ' BAŞARISIZ' : '\nHepsi geçti'); process.exit(bad ? 1 : 0);
