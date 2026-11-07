// Uygulama Akisi arayuz testi (Playwright). Arayuz GERCEK host koduna (FLOWMOD) kopruyle baglanir; dialog/ikon/openPath sahte, hicbir uygulama acilmaz.
// Hareket gercekten olculur: akis yonu (asagi), dongu (alttan cikan ustten girer), uzerine gelince durma, tiklayinca acma, klavye, hareket azaltma, genislik esikleri, EN.
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { pathToFileURL, fileURLToPath } from 'node:url';
const { createHost } = createRequire(import.meta.url)('../../app/desktop/host.js');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..'); const URL = pathToFileURL(path.join(ROOT, 'app/StatScan.html')).href;
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-uiflow-')); const SHOT = process.env.SHOT; if (SHOT) fs.mkdirSync(SHOT, { recursive: true });
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
const mkf = (n) => { const p = path.join(tmp, n); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, 'x'); return p; };
const F = { discord: mkf('apps/Discord.exe'), steam: mkf('apps/Steam.lnk'), medal: mkf('apps/Medal.exe'), lol: mkf('apps/League of Legends.lnk') };
mkf('sm/Programs/Discord/Discord.lnk'); mkf('sm/Programs/Steam.lnk'); mkf('sm/Programs/Spotify.lnk');
let opened = [], ext = [], next = null, openErr = '';
const mkHost = (dir) => createHost({ service: { closeAll() {} }, openExternal: async (u) => { ext.push(u); }, flow: { dataDir: dir, platform: 'win32', startMenuDirs: [path.join(tmp, 'sm/Programs')], chooseApp: async () => next, fileIcon: async (p) => (/Medal|League/.test(p) ? null : PNG), openPath: async (p) => { opened.push(p); return openErr; } } });
const seed = async (name, paths, webs) => { const dir = path.join(tmp, name); const host = mkHost(dir); for (const p of paths) { next = p; await host.handlers['flow:add'](null); } for (const [n, u] of webs || []) await host.handlers['flow:addWeb'](null, n, u); return { host, dir }; };
const MAP = { flowList: 'flow:list', flowAdd: 'flow:add', flowAddWeb: 'flow:addWeb', flowSuggest: 'flow:suggest', flowAddSuggested: 'flow:addSuggested', flowRename: 'flow:rename', flowRemove: 'flow:remove', flowOrder: 'flow:order', flowOpen: 'flow:open' };
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
async function page(host, { vp = { width: 1366, height: 900 }, motion = 'no-preference', en = false, fx = true, init } = {}) {
  const ctx = await b.newContext({ viewport: vp, reducedMotion: motion }); const pg = await ctx.newPage(); pg.errs = []; pg.on('pageerror', (e) => pg.errs.push(e.message)); pg.on('console', (m) => { if (m.type() === 'error') pg.errs.push('console: ' + m.text()); });
  await pg.addInitScript(([e, f]) => { try { if (e) localStorage.setItem('kovan.lang', 'en'); if (!f) localStorage.setItem('kovan.fx', '0'); } catch (x) { /* yok */ } }, [en, fx]);
  if (init) await pg.addInitScript(init);
  if (host) { await pg.exposeFunction('__h', async (ch, ...a) => { const f = host.handlers[ch]; return f ? JSON.parse(JSON.stringify(await f(null, ...a))) : { error: 'nochan' }; });
    await pg.addInitScript((map) => { const c = (ch, ...a) => window.__h(ch, ...a); const o = { desktop: true }; const shape = { flowAddWeb: (n, u) => [String(n || ''), String(u || '')], flowAddSuggested: (s) => [String(s)], flowRename: (i, n) => [String(i), String(n || '')], flowRemove: (i) => [String(i)], flowOrder: (a) => [Array.isArray(a) ? a.map(String) : []], flowOpen: (i) => [String(i)] }; for (const k in map) o[k] = (...a) => c(map[k], ...(shape[k] ? shape[k](...a) : a)); window.statscanHost = Object.freeze(o); }, MAP); }
  await pg.goto(URL); await pg.waitForSelector('#kv-flow', { state: 'attached' }); return pg;
}
const yOf = (pg, sel) => pg.evaluate((s) => { const e = document.querySelector(s); const m = e && /translate3d\(([-\d.]+)px,\s*([-\d.]+)px/.exec(e.style.transform); return m ? parseFloat(m[2]) : null; }, sel);
const state = (pg) => pg.evaluate(() => { const l = document.querySelector('#kv-flow-lane'); const lh = l.clientHeight; const it = [...l.querySelectorAll('.flow-item')].map((e) => { const m = /translate3d\(([-\d.]+)px,\s*([-\d.]+)px/.exec(e.style.transform); return { id: e.dataset.id, y: m ? parseFloat(m[2]) : null, op: parseFloat(e.style.opacity || '1'), clone: e.getAttribute('aria-hidden') === 'true', pe: e.style.pointerEvents }; }); return { lh, it, still: document.querySelector('#kv-flow').classList.contains('still'), shown: getComputedStyle(document.querySelector('#kv-flow')).display }; });
const central = async (pg, id) => { const st = await state(pg); let best = null; for (const e of st.it) if (e.id === id && e.y !== null) { const d = Math.abs(e.y + 36 - st.lh / 2); if (!best || d < best.d) best = { d, e }; } return best && best.e; };
const clickItem = async (pg, id) => { const rect = await pg.evaluate(([i, lh]) => { let best = null; for (const e of document.querySelectorAll('.flow-item[data-id="' + i + '"]')) { const r = e.querySelector('.flow-tile').getBoundingClientRect(); const lr = document.querySelector('#kv-flow-lane').getBoundingClientRect(); const d = Math.abs(r.top + r.height / 2 - (lr.top + lr.height / 2)); if (!best || d < best.d) best = { d, x: r.left + r.width / 2, y: r.top + r.height / 2 }; } return best; }, [id, 0]); await pg.mouse.click(rect.x, rect.y); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- 1) hareket: 3 uygulama + 1 web ----------
{
  const { host } = await seed('motion', [F.discord, F.steam, F.medal], [['Tarayıcı', 'https://ornek.com/']]); const ids = (await host.handlers['flow:list'](null)).apps.map((a) => a.id);
  const pg = await page(host); await pg.waitForFunction(() => document.querySelectorAll('#kv-flow .flow-item').length >= 4); await sleep(500);
  let s = await state(pg);
  ok(s.shown === 'flex' && await pg.evaluate(() => document.querySelector('#app').classList.contains('has-flow')), '1366 px: sutun gorunur (has-flow)');
  ok(!s.still, 'hareket modu: sabit liste DEGIL');
  ok(s.it.length >= 4 && s.it.every((e) => e.y !== null), 'oge sayisi >= uygulama sayisi, hepsi konumlandirilmis (' + s.it.length + ')');
  const real = s.it.filter((e) => !e.clone); ok(real.length === 4, 'gercek (klon olmayan) oge sayisi = 4');
  ok(await pg.evaluate(() => [...document.querySelectorAll('.flow-item')].filter((e) => e.getAttribute('aria-hidden') === 'true').every((e) => e.tabIndex === -1)), 'klonlar aria-hidden + tabindex -1');
  const names = await pg.evaluate(() => [...document.querySelectorAll('.flow-item:not([aria-hidden]) .nm')].map((e) => e.textContent)); ok(names.join() === 'Discord,Steam,Medal,Tarayıcı', 'adlar sirayla: ' + names.join('|'));
  ok(await pg.evaluate(() => document.querySelector('.flow-item img').getAttribute('src').startsWith('data:image/png')) && await pg.evaluate(() => !!document.querySelector('.flow-item .flow-tile.hue .fl')), 'exe ikonu gorunur; ikonsuz (Medal/web) harf kutusuna duser');
  ok(await pg.evaluate(() => document.querySelector('.flow-item').getAttribute('aria-label') === 'Discord uygulamasını aç'), 'erisilebilir ad: "Discord uygulamasini ac"');
  // akis yonu: bir ogenin y'si KESIN artar (asagi); 300 ms'de ~ +4.8 px
  const sel = '.flow-item:not([aria-hidden])'; const a0 = await yOf(pg, sel); await sleep(700); const a1 = await yOf(pg, sel);
  const dy = ((a1 - a0) + 4000) % 4000; ok(dy > 4 && dy < 40, 'akis ASAGI dogru ve yavas: ' + dy.toFixed(1) + ' px / 0.7 sn (~' + (dy / 0.7).toFixed(0) + ' px/sn)');
  ok(s.it.every((e) => e.op >= 0.2 && e.op <= 1), 'opaklik 0.2-1 araliginda (kenarlarda soluk)');
  // derinlik: orta ogeler kenardakilerden buyuk/opak
  const mid = await central(pg, ids[0]); ok(mid && mid.op > 0.9, 'ortadaki oge tam opak');
  // uzerine gelince durur
  await pg.hover('#kv-flow-lane'); await sleep(1700); const h0 = (await state(pg)).it.map((e) => e.y); await sleep(500); const h1 = (await state(pg)).it.map((e) => e.y);
  ok(h0.every((y, i) => Math.abs(y - h1[i]) < 0.6), 'imlec sutundayken akis DURUR (yavasca)');
  await pg.mouse.move(600, 400); await sleep(1400); const r0 = (await state(pg)).it.map((e) => e.y); await sleep(500); const r1 = (await state(pg)).it.map((e) => e.y);
  ok(r0.some((y, i) => Math.abs(y - r1[i]) > 1.5), 'imlec cikinca akis KALDIGI yerden devam eder');
  // dongu: buyuk tekerlek kaydirmasi sonrasi hicbir oge kaybolmaz, esit aralik korunur
  await pg.hover('#kv-flow-lane'); for (const d of [-3000, 5000, -777]) { await pg.mouse.wheel(0, d); await sleep(60); }
  s = await state(pg); const ys = s.it.map((e) => e.y).sort((x, y) => x - y); const lh = s.lh; ok(ys.every((y) => y >= -97 && y < 4000), 'dongu: tum ogeler dongu araliginda');
  const vis = s.it.filter((e) => e.y > -10 && e.y < lh - 40).length; ok(vis >= 3, 'dongu: sutunda hala >=3 gorunur oge (' + vis + ', lane ' + lh + ' px)');
  const gaps = ys.slice(1).map((y, i) => y - ys[i]); ok(Math.max(...gaps) - Math.min(...gaps) < 1, 'dongu: ogeler arasi aralik esit (kayip/cift yok)');
  // tiklayinca acar
  opened = []; await sleep(1700); await clickItem(pg, ids[0]); await pg.waitForFunction(() => document.querySelector('.flow-item.go'), null, { timeout: 3000 });
  ok(opened.length === 1 && opened[0] === F.discord, 'tiklayinca KAYITLI yol openPath ile acilir');
  ok(await pg.evaluate(() => document.querySelector('.flow-item.go .nm').textContent === 'Açılıyor…'), 'acilis geri bildirimi: etiket "Aciliyor…"'); if (SHOT) await pg.screenshot({ path: path.join(SHOT, 'flow-launch.png') });
  await sleep(1400); ok(await pg.evaluate(() => !document.querySelector('.flow-item.go') && [...document.querySelectorAll('.flow-item .nm')].every((e) => e.textContent !== 'Açılıyor…')), 'geri bildirim sonra eski haline doner');
  // web girisi
  ext = []; await sleep(300); await clickItem(pg, ids[3]); await sleep(400); ok(ext.length === 1 && ext[0] === 'https://ornek.com/', 'web girisi https adresiyle acilir');
  // hata
  openErr = 'Erisim engellendi'; await sleep(900); await clickItem(pg, ids[1]); await pg.waitForSelector('.flow-item.err', { timeout: 3000 }); ok(await pg.evaluate(() => /Erisim engellendi/.test((document.querySelector('.toast') || {}).textContent || '')), 'acilamazsa .err + bildirim'); openErr = '';
  // klavye: Tab ile odak ogeyi ortaya getirir
  await pg.mouse.move(10, 10); await sleep(300); await pg.focus('#kv-flow-manage'); await pg.keyboard.press('Shift+Tab'); await sleep(900);
  const fi = await pg.evaluate(() => { const e = document.activeElement; if (!e || !e.classList.contains('flow-item')) return null; const m = /translate3d\(([-\d.]+)px,\s*([-\d.]+)px/.exec(e.style.transform); return { y: parseFloat(m[2]), lh: document.querySelector('#kv-flow-lane').clientHeight, id: e.dataset.id }; });
  ok(!!fi, 'Shift+Tab ile sutundaki bir ogeye odaklanilir'); ok(fi && Math.abs(fi.y + 36 - fi.lh / 2) < 8, 'klavye odagi ogeyi sutunun ORTASINA getirir (y=' + (fi && fi.y.toFixed(0)) + ')');
  ok(await pg.evaluate(() => document.querySelector('#kv-flow-lane').scrollTop === 0), 'odak sutunu kaydirmaz (overflow clip)');
  if (SHOT) { await pg.mouse.move(10, 10); await sleep(600); await pg.screenshot({ path: path.join(SHOT, 'flow-1366.png') }); }
  ok(pg.errs.length === 0, 'sayfa hatasi yok' + (pg.errs.length ? ': ' + pg.errs.join(' | ') : ''));
  // yonetim penceresi
  await pg.click('#kv-flow-manage'); await pg.waitForSelector('#flow-dlg[open]'); await sleep(200);
  ok(await pg.evaluate(() => document.querySelectorAll('#flow-dlg .flow-row').length === 4), 'panel: 4 satir'); ok(!(await pg.evaluate(() => document.querySelector('#flow-dlg').textContent)).includes(tmp), 'panelde dosya yolu YOK');
  ok(await pg.evaluate(() => document.activeElement.classList.contains('flow-first')), 'panel acilinca ilk dugmeye odak'); if (SHOT) await pg.screenshot({ path: path.join(SHOT, 'flow-dialog.png') });
  // akis pencere acikken durur
  const p0 = (await state(pg)).it.map((e) => e.y); await sleep(1800); const p1 = (await state(pg)).it.map((e) => e.y); await sleep(400); const p2 = (await state(pg)).it.map((e) => e.y); ok(p1.every((y, i) => Math.abs(y - p2[i]) < 0.6), 'panel acikken akis durur');
  // yeniden adlandir
  const inp = pg.locator('#flow-dlg .flow-row input').nth(1); await inp.fill('Steam Oyun'); await inp.press('Enter'); await pg.waitForFunction(() => [...document.querySelectorAll('.flow-item:not([aria-hidden]) .nm')].some((e) => e.textContent === 'Steam Oyun')); ok(true, 'ad degisince sutun guncellenir');
  // sirala
  await pg.locator('#flow-dlg .flow-row').nth(0).locator('.dn').click(); await pg.waitForFunction(() => document.querySelector('.flow-item:not([aria-hidden]) .nm').textContent === 'Steam Oyun'); const ord = (await host.handlers['flow:list'](null)).apps.map((a) => a.name).join(); ok(ord === 'Steam Oyun,Discord,Medal,Tarayıcı', 'siralama host\'a kaydedildi: ' + ord);
  ok(await pg.evaluate(() => document.querySelector('#flow-dlg .flow-row:first-of-type .up').disabled), 'ilk satirda "yukari" kapali');
  // kaldir
  await pg.locator('#flow-dlg .flow-row').nth(3).locator('.rm').click(); await pg.waitForFunction(() => document.querySelectorAll('#flow-dlg .flow-row').length === 3); ok((await host.handlers['flow:list'](null)).apps.length === 3, 'kaldirma host\'a kaydedildi');
  // web ekle
  await pg.click('#flow-dlg .flow-bar button[aria-expanded]'); await pg.fill('#flow-dlg .flow-web input[type=text]', 'Medal Web'); await pg.fill('#flow-dlg .flow-web input[type=url]', 'http://guvensiz.com'); await pg.click('#flow-dlg .flow-web button[type=submit]'); await pg.waitForFunction(() => document.querySelector('#flow-dlg .flow-msg.bad'));
  ok(true, 'http adresi reddedilir, hata gorunur'); await pg.fill('#flow-dlg .flow-web input[type=url]', 'https://medal.tv'); await pg.click('#flow-dlg .flow-web button[type=submit]'); await pg.waitForFunction(() => document.querySelectorAll('#flow-dlg .flow-row').length === 4); ok(true, 'https adresi eklenir');
  // dosya ekle (dialog sahte)
  next = F.lol; await pg.click('#flow-dlg .flow-first'); await pg.waitForFunction(() => document.querySelectorAll('#flow-dlg .flow-row').length === 5); ok(true, '"Bilgisayardan ekle" host dialogundan secileni ekler');
  // oneriler
  await pg.click('#flow-dlg .flow-bar button:nth-child(2)'); await pg.waitForSelector('#flow-dlg .flow-sugg button[data-sid]'); const sg = await pg.evaluate(() => [...document.querySelectorAll('#flow-dlg .flow-sugg .srow label')].map((e) => e.textContent).join()); ok(/Discord/.test(sg) && /Steam/.test(sg) && /Spotify/.test(sg), 'oneriler listelenir: ' + sg);
  await pg.locator('#flow-dlg .flow-sugg button[data-sid]:not([disabled])').first().click(); await pg.waitForFunction(() => document.querySelectorAll('#flow-dlg .flow-row').length === 6); ok(true, 'onerilen uygulama eklenir');
  // Escape kapatir, odak geri doner
  await pg.keyboard.press('Escape'); await pg.waitForFunction(() => !document.querySelector('#flow-dlg[open]')); ok(await pg.evaluate(() => document.activeElement.id === 'kv-flow-manage'), 'Escape paneli kapatir, odak yonetim dugmesine doner');
  // ayarlar anahtari + gizle
  await pg.keyboard.press('Control+,'); await pg.waitForSelector('#settings[open]'); ok(await pg.evaluate(() => document.querySelector('#st-flow').checked), 'Ayarlar: "Uygulama Akisi" anahtari acik');
  await pg.evaluate(() => document.querySelector('#st-flow').click()); await sleep(300); ok(await pg.evaluate(() => !document.querySelector('#app').classList.contains('has-flow') && getComputedStyle(document.querySelector('#kv-flow')).display === 'none' && localStorage.getItem('kovan.flow') === '0'), 'anahtar kapatinca sutun gizlenir + tercih saklanir');
  await pg.evaluate(() => document.querySelector('#st-flow').click()); await sleep(500); ok(await pg.evaluate(() => document.querySelector('#app').classList.contains('has-flow') && getComputedStyle(document.querySelector('#kv-flow')).display === 'flex'), 'anahtar acinca sutun geri gelir');
  await pg.evaluate(() => document.querySelector('#st-flowedit').click()); await pg.waitForSelector('#flow-dlg[open]'); await pg.click('#flow-dlg .flow-bar:last-child button'); await sleep(300); ok(await pg.evaluate(() => getComputedStyle(document.querySelector('#kv-flow')).display === 'none' && /gizlendi/.test((document.querySelector('.toast') || {}).textContent || '')), 'panelde "Akisi gizle" sutunu gizler + bilgi verir');
  await pg.keyboard.press('Control+k'); await pg.waitForSelector('#pal:not([hidden])'); await pg.fill('#pal-q', 'Uygulama Akışı'); await sleep(200); const pc = await pg.evaluate(() => [...document.querySelectorAll('#pal-list li, #pal-list [role=option]')].map((e) => e.textContent).join('|')); ok(/Uygulama Akışını göster/.test(pc) && /düzenle/.test(pc), 'komut paleti: "Uygulama Akisini goster" + "duzenle" komutlari'); await pg.keyboard.press('Escape');
  ok(pg.errs.length === 0, 'tum akis sonunda sayfa hatasi yok' + (pg.errs.length ? ': ' + pg.errs.join(' | ') : '')); await pg.context().close();
}
// ---------- 2) cok az uygulama: klonlarla dolu kalir, dongu kopmaz ----------
{
  const { host } = await seed('one', [F.discord]); const pg = await page(host); await pg.waitForFunction(() => document.querySelectorAll('#kv-flow .flow-item').length >= 2); await sleep(400); const s = await state(pg);
  ok(s.it.length >= 2 && s.it.length <= 4 && s.it.filter((e) => !e.clone).length === 1, 'tek uygulama: klonlarla (en fazla 4) sutun dolu kalir (' + s.it.length + ')');
  ok(s.it.filter((e) => e.y > 0 && e.y < s.lh - 60).length >= 1, 'tek uygulamada da sutunda gorunur oge var'); await pg.context().close();
}
// ---------- 3) bos durum ----------
{
  const { host } = await seed('empty', []); const pg = await page(host); await sleep(500);
  ok(await pg.evaluate(() => !!document.querySelector('.flow-empty button')), 'bos durum: "+ Uygulama ekle" kutusu'); await pg.locator('.flow-empty button').click({ force: true }); await pg.waitForSelector('#flow-dlg[open]'); ok(await pg.evaluate(() => /Henüz uygulama yok/.test(document.querySelector('#flow-dlg').textContent)), 'bos durumdan panel acilir'); await pg.context().close();
}
// ---------- 4) hareket azaltma / animasyon kapali: sabit liste ----------
for (const [label, opt] of [['hareketi azalt', { motion: 'reduce' }], ['Arayuz animasyonlari kapali', { fx: false }]]) {
  const { host } = await seed('still-' + label.length, [F.discord, F.steam, F.medal]); const pg = await page(host, opt); await sleep(500); const s = await state(pg);
  ok(s.still && s.it.length === 3 && s.it.every((e) => e.y === null), label + ': akis yerine SABIT liste (klon yok, transform yok)');
  ok(await pg.evaluate(() => getComputedStyle(document.querySelector('.flow-item')).position === 'relative' && getComputedStyle(document.querySelector('.flow'), '::after').animationName === 'none'), label + ': oge static akista, kenar animasyonu kapali');
  opened = []; await pg.click('.flow-item'); await sleep(200); ok(opened.length === 1, label + ': tiklayinca yine acilir'); if (SHOT && label === 'hareketi azalt') await pg.screenshot({ path: path.join(SHOT, 'flow-still.png') }); await pg.context().close();
}
// ---------- 5) genislik esikleri ----------
{
  const { host } = await seed('wide', [F.discord, F.steam]);
  for (const [w, shown] of [[1100, true], [1099, false], [900, false], [390, false]]) { const pg = await page(host, { vp: { width: w, height: 800 } }); await sleep(300); const d = await pg.evaluate(() => ({ disp: getComputedStyle(document.querySelector('#kv-flow')).display, ov: document.documentElement.scrollWidth <= window.innerWidth + 1 })); ok((d.disp === 'flex') === shown, w + ' px: sutun ' + (shown ? 'gorunur' : 'gizli')); ok(d.ov, w + ' px: yatay tasma yok'); await pg.context().close(); }
}
// ---------- 6) tarayici sayfasi (masaustu koprusu yok): sutun hic eklenmez ----------
{ const pg = await page(null).catch(() => null); const ctx = await b.newContext({ viewport: { width: 1366, height: 900 } }); const p2 = await ctx.newPage(); const errs = []; p2.on('pageerror', (e) => errs.push(e.message)); await p2.goto(URL); await sleep(500); ok(await p2.evaluate(() => !document.querySelector('#kv-flow') && window.KovanFlow && window.KovanFlow.supported === false) && errs.length === 0, 'tarayicida (kopru yok) sutun yok, hata yok'); await ctx.close(); if (pg) await pg.context().close(); }
// ---------- 7) English ----------
{
  const { host } = await seed('en', [F.discord, F.medal]); const pg = await page(host, { en: true }); await sleep(500);
  const t = await pg.evaluate(() => ({ al: document.querySelector('.flow-item').getAttribute('aria-label'), mt: document.querySelector('#kv-flow-manage').title, rl: document.querySelector('#kv-flow').getAttribute('aria-label') }));
  ok(t.al === 'Open Discord' && t.mt === 'Edit apps' && t.rl === 'App Flow', 'EN: etiketler Ingilizce (' + JSON.stringify(t) + ')');
  await pg.click('#kv-flow-manage'); await pg.waitForSelector('#flow-dlg[open]'); const dt = await pg.evaluate(() => document.querySelector('#flow-dlg').innerText); ok(!/uygulama|Ekle|Kapat|Önerilen|gizle|Henüz|Bilgisayar|Adres/i.test(dt), 'EN: panelde Turkce kalinti yok'); if (SHOT) await pg.screenshot({ path: path.join(SHOT, 'flow-dialog-en.png') });
  await pg.keyboard.press('Escape'); await pg.keyboard.press('Control+,'); await pg.waitForSelector('#settings[open]'); await sleep(200); ok(/App Flow/.test(await pg.evaluate(() => document.querySelector('#settings').innerText)), 'EN: Ayarlar satiri Ingilizce');
  ok(pg.errs.length === 0, 'EN: sayfa hatasi yok'); await pg.context().close();
}
await b.close(); console.log(bad ? '\n' + bad + ' BASARISIZ' : '\nHepsi gecti'); process.exit(bad ? 1 : 0);
