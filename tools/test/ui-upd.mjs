// Otomatik guncelleyici arayuz testi (Playwright). Arayuz GERCEK host koduna (UPDMOD) kopruyle baglanir; winget/ikon/Baslat menusu sahte, hicbir sey kurulmaz.
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { pathToFileURL, fileURLToPath } from 'node:url';
const { createHost } = createRequire(import.meta.url)('../../app/desktop/host.js');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..'); const URL = pathToFileURL(path.join(ROOT, 'app/StatScan.html')).href;
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-uiupd-')); const SHOT = process.env.SHOT; if (SHOT) fs.mkdirSync(SHOT, { recursive: true });
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
const mkf = (n) => { const p = path.join(tmp, n); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, 'x'); return p; };
for (const n of ['Discord/Discord', 'Roblox/Roblox Player', 'Steam', 'Spotify', 'Brave']) mkf('sm/Programs/' + n + '.lnk'); mkf('apps/Discord/Discord.exe');
const UP = 'Name     Id               Version   Available   Source\r\n-----------------------------------------------------\r\nDiscord  Discord.Discord  1.0.1     1.0.2       winget\r\n';
const LS = 'Name   Id           Version   Source\r\n--------------------------------------\r\nSteam  Valve.Steam  2.1       winget\r\n';
let calls = []; let applyCode = 0; let slow = 0;
const run = async (args) => { calls.push(args.join(' ')); if (args[0] === 'upgrade' && args[1] === '--id') { if (slow) await new Promise((r) => setTimeout(r, slow)); return { code: applyCode, stdout: applyCode ? 'Installer failed' : 'ok', stderr: '' }; } if (args[0] === 'upgrade') return { code: 0, stdout: UP, stderr: '' }; if (args[0] === 'list') return { code: 0, stdout: /steam/i.test(args[2]) ? LS : 'No installed package', stderr: '' }; return { code: 1, stdout: '', stderr: '' }; };
const mkHost = (dir) => createHost({ service: { closeAll() {} }, flow: { dataDir: dir, platform: 'win32', startMenuDirs: [path.join(tmp, 'sm/Programs')], fileIcon: async () => PNG, chooseApp: async () => null, openPath: async () => '' }, upd: { run, fileIcon: async (p) => (/Roblox/.test(p) ? null : PNG), readShortcut: (p) => (/Discord\.lnk$/.test(p) ? { target: path.join(tmp, 'apps/Discord/Discord.exe') } : null) } });
const MAP = { flowList: 'flow:list', flowAdd: 'flow:add', flowAddWeb: 'flow:addWeb', flowSuggest: 'flow:suggest', flowAddSuggested: 'flow:addSuggested', flowRename: 'flow:rename', flowRemove: 'flow:remove', flowOrder: 'flow:order', flowOpen: 'flow:open', updList: 'upd:list', updDiscover: 'upd:discover', updAdd: 'upd:add', updAddFile: 'upd:addFile', updRemove: 'upd:remove', updCheck: 'upd:check', updApply: 'upd:apply' };
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
async function page(host, { vp = { width: 1366, height: 900 }, en = false, init } = {}) {
  const ctx = await b.newContext({ viewport: vp, reducedMotion: 'reduce' }); const pg = await ctx.newPage(); pg.errs = []; pg.on('pageerror', (e) => pg.errs.push(e.message)); pg.on('console', (m) => { if (m.type() === 'error') pg.errs.push('console: ' + m.text()); });
  await pg.addInitScript((e) => { try { if (e) localStorage.setItem('kovan.lang', 'en'); } catch (x) { /* yok */ } }, en); if (init) await pg.addInitScript(init);
  await pg.exposeFunction('__h', async (ch, ...a) => { const f = host.handlers[ch]; return f ? JSON.parse(JSON.stringify(await f(null, ...a))) : { error: 'nochan' }; });
  await pg.addInitScript((map) => { const o = { desktop: true }; for (const k in map) o[k] = (...a) => window.__h(map[k], ...a.map((x) => (Array.isArray(x) ? x.map(String) : x))); window.statscanHost = Object.freeze(o); }, MAP);
  await pg.goto(URL); await pg.waitForSelector('#kv-upd-bar', { state: 'attached' }); return pg;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const txt = (pg) => pg.evaluate(() => document.querySelector('#kv-upd-pop .upd-body').innerText.replace(/\s+/g, ' ').trim());
const seed = async (name, names) => { const dir = path.join(tmp, name); const h = mkHost(dir); const d = await h.handlers['upd:discover'](null); for (const n of names) await h.handlers['upd:add'](null, d.items.find((i) => i.name === n).sid); return h; };
const tile = (pg, n) => pg.locator('.upd-app', { hasText: n }).first();

// ---------- 1) yerlesim ----------
{
  const h = await seed('a', ['Discord', 'Roblox Player', 'Steam']); const pg = await page(h); await sleep(300);
  const g = await pg.evaluate(() => { const r = (s) => { const e = document.querySelector(s); const b = e.getBoundingClientRect(); return { l: b.left, r: b.right, t: b.top, b: b.bottom, w: b.width, h: b.height, d: getComputedStyle(e).display }; }; return { bar: r('#kv-upd-bar'), flow: r('#kv-flow'), txt: document.querySelector('#kv-upd-bar').innerText.trim(), has: document.querySelector('#app').classList.contains('has-flow') }; });
  ok(g.has && g.bar.d !== 'none' && g.flow.d === 'flex', '1366 px: akis sutunu ve guncelleyici cubugu gorunur');
  ok(g.bar.r <= g.flow.l + 0.5 && g.flow.l - g.bar.r < 40, 'cubuk akis sutununun SOLUNDA ve bitisik (bar.sag=' + g.bar.r.toFixed(0) + ', sutun.sol=' + g.flow.l.toFixed(0) + ')');
  ok(g.bar.t < 20 && g.bar.h <= 40 && g.bar.w < 200, 'kucuk dikdortgen, sag ustte (' + g.bar.w.toFixed(0) + 'x' + g.bar.h.toFixed(0) + ')'); ok(g.txt === 'Otomatik güncelleyici', 'cubuk yazisi: "' + g.txt + '"');
  ok(await pg.evaluate(() => document.querySelector('#kv-upd-pop').getBoundingClientRect().width === 0 || getComputedStyle(document.querySelector('#kv-upd-pop')).display === 'none'), 'baslangicta liste kapali');
  await pg.click('#kv-upd-bar'); await pg.waitForSelector('#kv-upd-pop.on');
  const t = await pg.evaluate(() => [...document.querySelectorAll('#kv-upd-pop .upd-grid .upd-app:not(.upd-add)')].map((e) => ({ nm: e.querySelector('.nm').textContent, img: !!e.querySelector('img'), letter: (e.querySelector('.fl') || {}).textContent || null })));
  ok(t.length === 3 && t[0].nm === 'Discord' && t[0].img && t[1].nm === 'Roblox Player' && !t[1].img && t[1].letter === 'R', 'liste: simge + altinda ad (Discord logolu, simgesiz Roblox harf kutusu) ' + JSON.stringify(t.map((x) => x.nm)));
  ok(await pg.evaluate(() => document.querySelector('#kv-upd-bar').getAttribute('aria-expanded') === 'true'), 'aria-expanded=true'); if (SHOT) await pg.screenshot({ path: path.join(SHOT, 'upd-liste.png') });
  // kontrol: guncelleme VAR
  calls = []; await tile(pg, 'Discord').click(); await pg.waitForFunction(() => /update gelmiş/.test(document.querySelector('#kv-upd-pop .upd-body').innerText)); let s = await txt(pg);
  ok(/Discord için update gelmiş\. Update demek ister misiniz\?/.test(s) && /1\.0\.1 → 1\.0\.2/.test(s), 'Discord: "update gelmiş. Update demek ister misiniz?" + surumler: ' + s);
  if (SHOT) await pg.screenshot({ path: path.join(SHOT, 'upd-var.png') });
  ok(await pg.locator('.upd-pop .cv-btn', { hasText: 'Güncelle' }).count() === 1 && !calls.some((c) => c.includes('--id')), 'onay butonu var; ONAYDAN ONCE guncelleme komutu calismadi');
  slow = 400; await pg.locator('.upd-pop .cv-btn', { hasText: 'Güncelle' }).click(); await sleep(120); s = await txt(pg); ok(/Discord güncelleniyor/.test(s) && await pg.locator('.upd-prog').count() === 1, 'guncellenirken ilerleme gosterilir');
  await pg.waitForFunction(() => /güncellendi/.test(document.querySelector('#kv-upd-pop .upd-body').innerText)); slow = 0;
  ok(calls.some((c) => c === 'upgrade --id Discord.Discord -e --silent --accept-package-agreements --accept-source-agreements --disable-interactivity'), 'onaydan sonra dogru winget komutu calisti');
  await pg.locator('.upd-pop .cv-btn', { hasText: 'Geri' }).click(); ok(await pg.locator('.upd-grid').count() === 1 && await pg.locator('.upd-app .st.ok').count() === 1, 'geri: liste, Discord yesil isaretli');
  // guncelleme yok
  await tile(pg, 'Steam').click(); await pg.waitForFunction(() => /henüz update gelmemiş/.test(document.querySelector('#kv-upd-pop .upd-body').innerText)); s = await txt(pg); ok(/Steam için henüz update gelmemiş\./.test(s), 'Steam: "henüz update gelmemiş": ' + s); if (SHOT) await pg.screenshot({ path: path.join(SHOT, 'upd-yok.png') });
  await pg.locator('.upd-pop .cv-btn', { hasText: 'Geri' }).click();
  // winget bilmiyor
  await tile(pg, 'Roblox').click(); await pg.waitForFunction(() => /bilgisi alınamadı/.test(document.querySelector('#kv-upd-pop .upd-body').innerText)); s = await txt(pg); ok(/Roblox Player için güncelleme bilgisi alınamadı/.test(s) && /kendi kendini güncelliyor/.test(s), 'Roblox: durust "bilgi alinamadi / kendi kendini guncelliyor olabilir"'); await pg.locator('.upd-pop .cv-btn', { hasText: 'Geri' }).click();
  // basarisiz guncelleme
  applyCode = 1603; await tile(pg, 'Discord').click(); await pg.waitForFunction(() => /update gelmiş|henüz update/.test(document.querySelector('#kv-upd-pop .upd-body').innerText)); if (/update gelmiş/.test(await txt(pg))) { await pg.locator('.upd-pop .cv-btn', { hasText: 'Güncelle' }).click(); await pg.waitForFunction(() => /güncellenemedi/.test(document.querySelector('#kv-upd-pop .upd-body').innerText)); ok(/Uygulamayı kapatıp tekrar dene/.test(await txt(pg)), 'basarisiz guncelleme: kisa hata + "kapatip tekrar dene"'); } else ok(true, 'basarisiz guncelleme: Discord zaten guncel (atlandi)'); applyCode = 0;
  await pg.locator('.upd-pop .cv-btn', { hasText: 'Geri' }).click();
  // ekleme
  await pg.locator('.upd-add').click(); await pg.waitForSelector('.upd-find .upd-li'); const li = await pg.evaluate(() => [...document.querySelectorAll('.upd-li')].map((e) => ({ n: e.querySelector('b').textContent, loc: (e.querySelector('small') || {}).textContent || '', dis: e.querySelector('button').disabled })));
  ok(li.length === 5 && li.find((x) => x.n === 'Discord').dis && li.find((x) => x.n === 'Discord').loc === path.join(tmp, 'apps/Discord') && li.find((x) => x.n === 'Spotify' && !x.dis), 'ekleme: Baslat menusu uygulamalari kendisi listelenir, Discord kurulu klasoruyle ("' + li.find((x) => x.n === 'Discord').loc.slice(-14) + '"), ekli olan pasif');
  await pg.fill('.upd-find input', 'spo'); ok(await pg.locator('.upd-li').count() === 1, 'arama: "spo" -> 1 sonuc'); if (SHOT) await pg.screenshot({ path: path.join(SHOT, 'upd-ekle.png') });
  await pg.locator('.upd-li .cv-btn').click(); await sleep(150); ok(/Eklendi/.test(await txt(pg)), 'Spotify eklendi'); await pg.locator('.upd-find .cv-btn', { hasText: 'Geri' }).click();
  ok(await pg.locator('.upd-grid .upd-app:not(.upd-add)').count() === 4 && await pg.locator('.upd-app', { hasText: 'Spotify' }).count() === 1, 'listede 4 uygulama (Spotify dahil)');
  // kaldirma
  await tile(pg, 'Spotify').hover(); await tile(pg, 'Spotify').locator('.rm').click(); await sleep(200); ok(await pg.locator('.upd-app', { hasText: 'Spotify' }).count() === 0, 'kaldir: Spotify listeden gitti');
  // klavye + kapama
  await pg.keyboard.press('Escape'); await sleep(100); ok(!(await pg.evaluate(() => document.querySelector('#kv-upd-pop').classList.contains('on'))) && await pg.evaluate(() => document.activeElement.id === 'kv-upd-bar'), 'Esc: kapanir, odak cubuga doner');
  await pg.focus('#kv-upd-bar'); await pg.keyboard.press('Enter'); await pg.waitForSelector('#kv-upd-pop.on'); await pg.mouse.click(300, 600); await sleep(100); ok(!(await pg.evaluate(() => document.querySelector('#kv-upd-pop').classList.contains('on'))), 'disina tiklayinca kapanir');
  ok(pg.errs.length === 0, 'sayfa hatasi yok ' + pg.errs.join('|'));
  // dar pencere
  await pg.setViewportSize({ width: 1000, height: 800 }); await sleep(150); ok(await pg.evaluate(() => getComputedStyle(document.querySelector('#kv-upd-bar')).display === 'none'), '1000 px: cubuk gizli (akis sutunuyla ayni esik)');
}
// ---------- 2) akis gizliyse cubuk sagda ----------
{
  const h = await seed('b', ['Discord']); const pg = await page(h, { init: () => { try { localStorage.setItem('kovan.flow', '0'); } catch (e) { /* yok */ } } }); await sleep(200);
  const r = await pg.evaluate(() => { const b = document.querySelector('#kv-upd-bar').getBoundingClientRect(); return { right: innerWidth - b.right, d: getComputedStyle(document.querySelector('#kv-upd-bar')).display }; });
  ok(r.d !== 'none' && r.right < 20, 'akis gizliyken cubuk sag kenara yaslanir (' + r.right.toFixed(0) + ' px)');
}
// ---------- 3) bos durum + Ingilizce ----------
{
  const h = await seed('c', []); const pg = await page(h); await pg.click('#kv-upd-bar'); await sleep(200); ok(/Henüz uygulama yok/.test(await txt(pg)), 'bos durum: yonlendirme metni'); await pg.close();
  const h2 = await seed('d', ['Discord', 'Steam']); const pe = await page(h2, { en: true }); await sleep(200);
  ok(await pe.evaluate(() => document.querySelector('#kv-upd-bar').innerText.trim()) === 'Auto updater', 'EN: cubuk "Auto updater"'); await pe.click('#kv-upd-bar'); await tile(pe, 'Discord').click(); await pe.waitForFunction(() => /has an update/.test(document.querySelector('#kv-upd-pop .upd-body').innerText));
  const s = await txt(pe); ok(/Discord has an update\. Do you want to update\?/.test(s) && !/[ğüşıöçĞÜŞİÖÇ]/.test(s), 'EN: guncelleme mesaji Ingilizce, Turkce kalinti yok: ' + s);
  await pe.locator('.upd-pop .cv-btn', { hasText: 'Back' }).click(); await tile(pe, 'Steam').click(); await pe.waitForFunction(() => /No update for/.test(document.querySelector('#kv-upd-pop .upd-body').innerText)); ok(/No update for Steam yet\./.test(await txt(pe)), 'EN: "No update for Steam yet."');
  ok(pe.errs.length === 0, 'EN sayfa hatasi yok ' + pe.errs.join('|'));
}
// ---------- 3b) Ekle hatasi: sessizce kapanmaz, nedeni ekranda; tekrar denenir ----------
{
  const h = await seed('e', []); let fail = true; const orig = h.handlers['upd:discover']; h.handlers['upd:discover'] = async (...a) => (fail ? { error: 'upd', message: 'Deneme hatası' } : orig(...a));
  const pg = await page(h); await pg.click('#kv-upd-bar'); await pg.click('.upd-add'); await pg.waitForFunction(() => /Deneme hatası/.test(document.querySelector('#kv-upd-pop .upd-body').innerText));
  ok(await pg.locator('.upd-msg.bad').count() === 1 && await pg.locator('.upd-grid').count() === 0, 'Ekle hatasi: neden ekranda yazar, sessizce listeye donmez'); fail = false;
  await pg.locator('.upd-pop .cv-btn', { hasText: 'Tekrar dene' }).click(); await pg.waitForSelector('.upd-find .upd-li'); ok(await pg.locator('.upd-li').count() >= 3, 'Tekrar dene: liste geldi');
  ok(pg.errs.length === 0, 'Ekle hatasi: sayfa hatasi yok ' + pg.errs.join('|'));
  const h2 = await seed('f', []); delete h2.handlers['upd:discover']; const p2 = await page(h2); await p2.click('#kv-upd-bar'); await p2.click('.upd-add'); await p2.waitForFunction(() => /başarısız|yeniden aç|Error/.test(document.querySelector('#kv-upd-pop .upd-body').innerText)); ok(await p2.locator('.upd-grid').count() === 0, 'kanal yoksa da ekranda hata gosterilir (cokme yok)');
}
// ---------- 4) masaustu disi: cubuk yok ----------
{ const ctx = await b.newContext({ viewport: { width: 1366, height: 900 } }); const pg = await ctx.newPage(); await pg.goto(URL); await sleep(400); ok(await pg.locator('#kv-upd-bar').count() === 0, 'tarayicida (host yok) cubuk olusmaz'); }
await b.close(); console.log(bad ? '\n' + bad + ' HATA' : '\nTAMAM'); process.exit(bad ? 1 : 0);
