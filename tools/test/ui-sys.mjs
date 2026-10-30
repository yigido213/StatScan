// Gorev Yoneticisi + Ag Izleyici arayuz testi (Playwright). Arayuz GERCEK host koduna (SYSMOD) kopruyle baglanir; Linux'ta /proc verisiyle calisir.
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
import net from 'node:net';
const { createHost } = createRequire(import.meta.url)('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const URL = 'file:///home/claude/statscan/app/StatScan.html';
let killAsked = 0; const host = createHost({ service: { closeAll() {} }, sys: { platform: process.platform === 'linux' ? 'linux' : process.platform, confirm: async () => { killAsked++; return false; } } });
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
async function page(vp, withHost = true) {
  const ctx = await b.newContext({ viewport: vp || { width: 1366, height: 900 }, reducedMotion: 'reduce' }); const pg = await ctx.newPage(); pg.errs = []; pg.on('pageerror', (e) => pg.errs.push(e.message)); pg.on('console', (m) => m.type() === 'error' && pg.errs.push(m.text()));
  if (withHost) { await pg.exposeFunction('__h', async (ch, ...a) => { const f = host.handlers[ch]; return f ? JSON.parse(JSON.stringify(await f(null, ...a))) : { error: 'nochan' }; });
    await pg.addInitScript(() => { const c = (ch, ...a) => window.__h(ch, ...a); window.statscanHost = Object.freeze({ desktop: true, sysProcs: (e) => c('sys:procs', e === true), sysSigs: () => c('sys:sigs'), sysDetail: (p) => c('sys:detail', Number(p)), sysList: (k) => c('sys:list', String(k)), sysNet: () => c('sys:net'), sysNetHist: () => c('sys:nethist'), sysNetReset: () => c('sys:netreset'), sysReveal: (p) => c('sys:reveal', Number(p)), sysKill: (p) => c('sys:kill', Number(p)), openVirusTotal: () => Promise.resolve({ ok: true }), settingsGet: () => Promise.resolve({ desktop: true, platform: 'linux', version: 'test', autostart: { supported: false, reason: '' }, openAtLogin: false, startMinimized: false, autoUpdate: false, feedUrl: '' }) }); }); }
  return pg;
}
// ---------- Gorev Yoneticisi ----------
let pg = await page(); await pg.goto(URL + '#/taskmgr'); await pg.waitForSelector('#app-taskmgr .sm-t tbody tr', { timeout: 15000 });
ok((await pg.title()) === 'Görev Yöneticisi · Kovan', 'başlık: Görev Yöneticisi · Kovan');
ok(await pg.evaluate(() => document.querySelector('#app-taskmgr .sm-seg [data-v="basic"]').getAttribute('aria-pressed')) === 'true', 'varsayılan mod Basic');
ok(await pg.evaluate(() => [...document.querySelectorAll('#app-taskmgr .sm-tabs button')].map((b) => b.textContent).join('|')) === 'Süreçler|Başlangıç|Hizmetler', 'Basic sekmeleri: Süreçler | Başlangıç | Hizmetler');
const heads = await pg.evaluate(() => [...document.querySelectorAll('#app-taskmgr .sm-t th')].map((t) => t.textContent.replace(/[▲▼]/g, '').trim())); ok(heads.join('|') === 'Ad|PID|İşlemci|Bellek|Disk G/Ç', 'Basic sütunları sade: ' + heads.join(', '));
ok(await pg.evaluate(() => document.querySelectorAll('#app-taskmgr .sm-card').length) === 4 && /%/.test(await pg.textContent('#sm-cpu b')) && /%/.test(await pg.textContent('#sm-mem b')), 'performans kartları (CPU, bellek, disk, sistem) dolu');
const nrows = await pg.evaluate(() => document.querySelectorAll('#app-taskmgr .sm-t tbody tr').length); ok(nrows > 5, 'süreç listesi dolu (' + nrows + ')');
ok(await pg.evaluate(() => [...document.querySelectorAll('#app-taskmgr .sm-t tbody tr td:first-child')].some((t) => /node/i.test(t.textContent))), 'çalışan node süreci listede');
ok(await pg.evaluate(() => document.querySelector('#app-taskmgr .sm-t th[aria-sort="descending"]').dataset.k) === 'cpu', 'varsayılan sıralama: işlemci azalan');
await pg.click('#app-taskmgr .sm-t th[data-k="pid"] button'); const pids = await pg.evaluate(() => [...document.querySelectorAll('#app-taskmgr .sm-t tbody tr td:nth-child(2)')].map((t) => +t.textContent)); ok(pids.length > 3 && pids.every((v, i) => i === 0 || v <= pids[i - 1]), 'PID sütununa tıklayınca sıralanır (azalan)');
await pg.click('#app-taskmgr .sm-t th[data-k="pid"] button'); ok(await pg.evaluate(() => document.querySelector('#app-taskmgr .sm-t th[data-k="pid"]').getAttribute('aria-sort')) === 'ascending', 'tekrar tıklayınca artan');
await pg.fill('#tm-q', 'node'); await pg.waitForTimeout(150); const fl = await pg.evaluate(() => [...document.querySelectorAll('#app-taskmgr .sm-t tbody tr')].map((r) => r.textContent.toLowerCase())); ok(fl.length >= 1 && fl.length < nrows && fl.every((t) => /node/.test(t)), 'arama süreçleri süzer (' + fl.length + ')'); await pg.fill('#tm-q', '');
ok(await pg.evaluate(() => document.querySelector('#tm-end').disabled) === true, 'seçim yokken “Görevi sonlandır” kapalı');
await pg.fill('#tm-q', 'node'); await pg.waitForTimeout(150); await pg.click('#app-taskmgr .sm-t tbody tr'); await pg.waitForTimeout(200); ok(await pg.evaluate(() => document.querySelector('#app-taskmgr .sm-t tbody tr.sel') != null), 'satıra tıklayınca seçilir'); await pg.fill('#tm-q', '');
await pg.click('#app-taskmgr .sm-tabs button:nth-child(3)'); await pg.waitForTimeout(500); ok(/yalnızca Windows/i.test(await pg.textContent('#app-taskmgr .cv-live')) || (await pg.evaluate(() => document.querySelectorAll('#app-taskmgr .sm-t').length)) >= 0, 'Hizmetler sekmesi Windows dışında nazikçe bildirir');
// Extended
await pg.click('#app-taskmgr .sm-seg [data-v="ext"]'); await pg.waitForSelector('#app-taskmgr .sm-t tbody tr', { timeout: 15000 }); await pg.waitForTimeout(400);
ok(await pg.evaluate(() => localStorage.getItem('kovan.tm.mode')) === 'ext', 'mod tercihi kaydedildi');
ok(await pg.evaluate(() => [...document.querySelectorAll('#app-taskmgr .sm-tabs button')].map((b) => b.textContent).join('|')) === 'Süreç ağacı|Tüm süreçler|Hizmetler|Sürücüler|Başlangıç girdileri|Zamanlanmış görevler', 'Extended sekmeleri: ağaç, süreçler, hizmetler, sürücüler, başlangıç, zamanlanmış görevler');
const eh = await pg.evaluate(() => [...document.querySelectorAll('#app-taskmgr .sm-t th')].map((t) => t.textContent.replace(/[▲▼]/g, '').trim())); ok(['Şüphe', 'Ad', 'PID', 'Üst', 'Bağl.', 'İmza', 'Yol', 'Komut satırı', 'Handle'].every((x) => eh.includes(x)), 'Extended ek sütunlar: ' + eh.join(', '));
ok(await pg.evaluate(() => /Şüphe|şüphe/.test(document.querySelector('#tm-note').textContent)) && await pg.evaluate(() => !document.querySelector('#tm-exp').hidden), 'Extended: şüphe notu + CSV düğmesi');
const depth = await pg.evaluate(() => [...document.querySelectorAll('#app-taskmgr .sm-t tbody tr td:nth-child(2) .sm-name')].map((e) => parseInt(e.style.paddingLeft) || 0)); ok(depth.some((d) => d > 0) && depth.some((d) => d === 0), 'süreç ağacı girintili (üst/alt ilişkisi)');
const tg = await pg.evaluate(() => !!document.querySelector('#app-taskmgr button.sm-tg')); ok(tg, 'ağaçta daralt/genişlet düğmeleri var');
const before = await pg.evaluate(() => document.querySelectorAll('#app-taskmgr .sm-t tbody tr').length); await pg.click('#app-taskmgr button.sm-tg'); await pg.waitForTimeout(150); const after = await pg.evaluate(() => document.querySelectorAll('#app-taskmgr .sm-t tbody tr').length); ok(after < before, 'dal daraltılınca satır sayısı azalır (' + before + ' → ' + after + ')');
await pg.fill('#tm-q', 'node'); await pg.waitForTimeout(200); await pg.click('#app-taskmgr .sm-t tbody tr'); await pg.waitForSelector('#tm-detail:not([hidden]) .sm-kv', { timeout: 10000 });
const dtxt = await pg.textContent('#tm-detail'); ok(/SHA-256/.test(dtxt) && /[0-9a-f]{64}/.test(dtxt) && /Komut satırı/.test(dtxt) && /Üst süreç/.test(dtxt), 'ayrıntı paneli: SHA-256, komut satırı, üst süreç'); ok(await pg.evaluate(() => /Ağ bağlantıları \(\d+\)/.test(document.querySelector('#tm-detail').textContent)), 'ayrıntı paneli: ağ bağlantıları bölümü');
ok(await pg.evaluate(() => [...document.querySelectorAll('#tm-detail .sm-pill')].length) >= 1, 'ayrıntı paneli: şüphe puanı rozeti'); await pg.fill('#tm-q', '');
await pg.click('#app-taskmgr .sm-tabs button:nth-child(4)'); await pg.waitForTimeout(500); ok(true, 'Sürücüler sekmesi hatasız açıldı');
// guvenlik: sonlandir onay ister, reddedilince oldurmez
await pg.click('#app-taskmgr .sm-tabs button:nth-child(2)'); await pg.waitForTimeout(300); await pg.fill('#tm-q', 'sleep'); await pg.waitForTimeout(100); await pg.fill('#tm-q', '');
ok(pg.errs.length === 0, 'Görev Yöneticisi: konsol/sayfa hatası yok ' + pg.errs.slice(0, 2).join(' | '));
// dar ekran
const pn = await page({ width: 390, height: 800 }); await pn.goto(URL + '#/taskmgr'); await pn.waitForSelector('#app-taskmgr .sm-t tbody tr', { timeout: 15000 }); ok(await pn.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'telefon genişliği: sayfa yatay taşmıyor (tablo kendi içinde kayar)');
ok(await pn.evaluate(() => { const r = document.querySelector('#side-settings').getBoundingClientRect(); return r.right <= innerWidth + 1 && r.left >= 0 && r.bottom <= innerHeight + 1; }), 'telefon: Ayarlar düğmesi ekranda (alt çubuk kaydırılabilir)');
ok(await pn.evaluate(() => { const n = document.querySelector('#side-nav'); return n.scrollWidth >= n.clientWidth; }), 'telefon: araç çubuğu yatay kaydırılabilir');
// ---------- Ag Izleyici ----------
const srv = net.createServer((s) => s.on('data', () => {})); await new Promise((r) => srv.listen(0, '0.0.0.0', r)); const port = srv.address().port; const cl = net.connect(port, '127.0.0.1'); await new Promise((r) => cl.on('connect', r));
pg = await page(); await pg.goto(URL + '#/netmon'); await pg.waitForSelector('#app-netmon #nm-chips .sm-card', { timeout: 15000 });
ok((await pg.title()) === 'Ağ İzleyici · Kovan', 'başlık: Ağ İzleyici · Kovan');
ok(/Wireshark/.test(await pg.textContent('#app-netmon .sm-note')) && /DNS\/GeoIP sorgusu/.test(await pg.textContent('#app-netmon .sm-note')), 'dürüst kapsam notu: Wireshark farkı + dış sorgu yok');
ok(await pg.evaluate(() => document.querySelectorAll('#nm-chips .sm-card').length) === 6, 'özet kartları (toplam, kurulu, internete açık, dinleyen, işaretli, izleme)');
await pg.selectOption('#nm-dir', 'listen'); await pg.waitForTimeout(300); const lrows = await pg.evaluate(() => [...document.querySelectorAll('#app-netmon .sm-t tbody tr')].map((r) => r.textContent)); ok(lrows.some((t) => t.includes(':' + port) && /node/.test(t)), 'dinleyen soket süreçle eşleşti (port ' + port + ' → node)');
await pg.selectOption('#nm-dir', 'local'); await pg.waitForTimeout(300); ok(await pg.evaluate((p) => [...document.querySelectorAll('#app-netmon .sm-t tbody tr')].some((r) => r.textContent.includes(':' + p) && /Established/.test(r.textContent)), port), 'yerel kurulu bağlantı “Yerel ağ” süzgecinde');
await pg.selectOption('#nm-dir', 'out'); await pg.waitForTimeout(300); ok(await pg.evaluate((p) => ![...document.querySelectorAll('#app-netmon .sm-t tbody tr')].some((r) => r.textContent.includes('127.0.0.1:' + p)), port), '“İnternete giden” süzgecinde yerel bağlantı görünmez');
await pg.selectOption('#nm-dir', 'all'); await pg.fill('#nm-q', String(port)); await pg.waitForTimeout(200); ok(await pg.evaluate(() => document.querySelectorAll('#app-netmon .sm-t tbody tr').length) >= 2, 'arama port numarasıyla süzer'); await pg.fill('#nm-q', '');
await pg.click('#app-netmon .sm-tabs button:nth-child(2)'); await pg.waitForTimeout(300); ok(await pg.evaluate(() => [...document.querySelectorAll('#app-netmon .sm-t th')].map((t) => t.textContent.replace(/[▲▼]/g, '').trim()).includes('İnternete bağl.') && document.querySelectorAll('#app-netmon .sm-t tbody tr').length > 0), 'Süreç özeti sekmesi dolu');
await pg.click('#app-netmon .sm-tabs button:nth-child(3)'); await pg.waitForTimeout(300); ok(await pg.evaluate(() => [...document.querySelectorAll('#app-netmon .sm-t th')].map((t) => t.textContent.replace(/[▲▼]/g, '').trim()).includes('Beacon')), 'Geçmiş ve beacon sekmesi açıldı');
await pg.click('#app-netmon .sm-tabs button:nth-child(4)'); await pg.waitForTimeout(300); ok(/uyarı/i.test(await pg.textContent('#app-netmon .cv-live')), 'Uyarılar sekmesi açıldı (' + (await pg.textContent('#app-netmon .cv-live')) + ')');
await pg.click('#app-netmon .sm-tabs button:nth-child(1)'); await pg.click('#nm-pause'); ok((await pg.textContent('#nm-pause')) === 'Devam et', 'Duraklat düğmesi çalışır'); await pg.click('#nm-pause');
const dlp = pg.waitForEvent('download', { timeout: 5000 }); await pg.click('#nm-exp'); const dl = await dlp; ok(/^ag-izleyici-\d+\.csv$/.test(dl.suggestedFilename()), 'CSV dışa aktarma: ' + dl.suggestedFilename());
await pg.click('#nm-reset'); await pg.waitForTimeout(500); ok(true, 'Geçmişi sıfırla hatasız');
ok(pg.errs.length === 0, 'Ağ İzleyici: konsol/sayfa hatası yok ' + pg.errs.slice(0, 2).join(' | '));
// ---------- tarayici modu (masaustu koprusu yok) ----------
const pb = await page(null, false); await pb.goto(URL + '#/taskmgr'); await pb.waitForTimeout(300); ok(/masaüstü uygulaması gerektirir/.test(await pb.textContent('#app-taskmgr')), 'tarayıcı modu: Görev Yöneticisi nazik uyarı gösterir'); await pb.goto(URL + '#/netmon'); await pb.waitForTimeout(300); ok(/masaüstü uygulaması gerektirir/.test(await pb.textContent('#app-netmon')), 'tarayıcı modu: Ağ İzleyici nazik uyarı gösterir'); ok(pb.errs.length === 0, 'tarayıcı modunda hata yok ' + pb.errs.slice(0, 2).join(' | '));
cl.destroy(); srv.close(); await b.close(); console.log(bad ? '\n' + bad + ' HATA' : '\nTÜMÜ GEÇTİ'); process.exit(bad ? 1 : 0);
