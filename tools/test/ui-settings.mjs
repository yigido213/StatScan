// Kovan Ayarlar penceresi (Playwright): tarayici modu + sahte masaustu koprusu
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const URL = 'file:///home/claude/statscan/app/StatScan.html'; const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
async function mkpage(init, vp) { const ctx = await b.newContext({ viewport: vp || { width: 1280, height: 900 }, reducedMotion: 'reduce' }); if (init) await ctx.addInitScript(init); const pg = await ctx.newPage(); pg.errs = []; pg.on('pageerror', (e) => pg.errs.push(e.stack.split('\n').slice(0, 3).join(' <- '))); pg.on('console', (m) => { if (m.type() === 'error') pg.errs.push(m.text()); }); await pg.goto(URL); await pg.waitForTimeout(300); return pg; }
const isOpen = (pg) => pg.evaluate(() => document.querySelector('#settings').open);
// 1) tarayici modu
let pg = await mkpage();
ok(await pg.isVisible('#side-settings') && /Ayarlar/.test(await pg.textContent('#side-settings')), 'sol altta Ayarlar düğmesi görünür');
const box = await pg.evaluate(() => { const r = document.querySelector('#side-settings').getBoundingClientRect(); const f = document.querySelector('.side-foot').getBoundingClientRect(); return [r.left, r.bottom, f.top]; }); ok(box[0] < 40 && box[1] <= box[2] + 2 && box[1] > 600, 'düğme sol altta, alt çubuğun üstünde (' + box.map(Math.round) + ')');
await pg.click('#side-settings'); await pg.waitForTimeout(150); ok(await isOpen(pg), 'tıklayınca pencere açıldı');
ok(await pg.isDisabled('#st-login') && await pg.isDisabled('#st-auto') && await pg.isDisabled('#st-check'), 'tarayıcıda masaüstü ayarları kapalı + açıklama');
ok(/yalnızca masaüstü/i.test(await pg.textContent('#settings')), 'tarayıcı modu açıklaması var');
await pg.selectOption('#st-theme', 'light'); ok(await pg.evaluate(() => document.documentElement.dataset.theme === 'light' && localStorage.getItem('statscan-theme') === 'light'), 'tema açık yapıldı ve saklandı');
await pg.setChecked('#st-collapsed', true); ok(await pg.evaluate(() => document.querySelector('#app').classList.contains('collapsed') && localStorage.getItem('kovan.collapsed') === '1'), 'kenar çubuğu daraltıldı');
await pg.fill('#st-name', '  Ada   Lovelace '); await pg.click('#settings .sinline button:first-of-type'); ok((await pg.textContent('#home-title .sr')) === 'Welcome home, Ada Lovelace' && await pg.evaluate(() => localStorage.getItem('kovan.user')) === 'Ada Lovelace', 'kullanıcı adı boşlukları düzeltilerek kaydedildi');
await pg.click('#settings .sinline button:nth-of-type(2)'); ok((await pg.textContent('#home-title .sr')) === 'Welcome home, yigit717', 'varsayılan ada dönüldü');
await pg.setChecked('#st-typing', false); ok(await pg.evaluate(() => localStorage.getItem('kovan.typing')) === '0', 'animasyon tercihi saklandı');
await pg.keyboard.press('Escape'); await pg.waitForTimeout(100); ok(!(await isOpen(pg)) && await pg.evaluate(() => document.activeElement.id) === 'side-settings', 'Esc kapatır, odak düğmeye döner');
await pg.keyboard.press('Control+,'); ok(await isOpen(pg), 'Ctrl+, açar'); await pg.keyboard.press('Control+,'); ok(!(await isOpen(pg)), 'Ctrl+, kapatır');
await pg.keyboard.press('Control+k'); await pg.keyboard.type('ayarlar'); await pg.waitForTimeout(120); ok(/Ayarlar/.test(await pg.textContent('#pal-list')), 'komut paletinde Ayarlar var'); await pg.keyboard.press('Enter'); await pg.waitForTimeout(150); ok(await isOpen(pg) && await pg.evaluate(() => document.querySelector('#pal').hidden), 'paletten açılır, palet kapanır');
// sifirla
await pg.click('#st-reset'); ok(/Emin misin/.test(await pg.textContent('#st-reset')), 'sıfırlama iki adımlı'); await Promise.all([pg.waitForNavigation(), pg.click('#st-reset')]); await pg.waitForTimeout(300);
ok(await pg.evaluate(() => localStorage.getItem('kovan.user') === null && localStorage.getItem('statscan-theme') === null && localStorage.getItem('kovan.typing') === null && localStorage.getItem('kovan.collapsed') === null), 'sıfırlama tercihleri sildi');
ok(pg.errs.length === 0, 'hata yok ' + pg.errs.join('|'));
// kalicilik: yeniden yukleme sonrasi typing kapali ise metin anında tam
const ctx2 = await b.newContext({ viewport: { width: 1280, height: 900 } }); await ctx2.addInitScript(() => { try { localStorage.setItem('kovan.typing', '0'); } catch (e) {} }); const p2 = await ctx2.newPage(); await p2.goto(URL); await p2.waitForTimeout(200); ok((await p2.textContent('#tw .typed')) === 'Welcome home, yigit717', 'animasyon kapalıyken başlık hemen tam');
// 2) sahte masaustu
const fake = () => { window.__calls = []; const st = { openAtLogin: false, startMinimized: false, autoUpdate: true, autostart: { supported: true, reason: '' } }; window.__st = st; window.statscanHost = Object.freeze({ desktop: true, settingsGet: async () => ({ ...st }), settingsSet: async (k, v) => { window.__calls.push([k, v]); if (k === 'openAtLogin' && window.__fail) return { error: 'failed', message: 'OS reddetti' }; st[k] = v; return { ...st }; }, settingsCheckUpdate: async () => { window.__calls.push(['check']); return { ok: true }; }, storeGet: async () => null, storeSet: async () => ({}), watchSuggest: async () => [], watchLog: async () => ({ log: [], folders: [] }), watchTake: async () => ({ item: null }), watchSet: async () => ({}), status: async () => ({ available: false, reasons: [{ title: 'test' }] }), info: async () => ({}) }); };
pg = await mkpage(fake); await pg.click('#side-settings'); await pg.waitForTimeout(250);
ok(!(await pg.isDisabled('#st-login')) && await pg.isDisabled('#st-min') && (await pg.isChecked('#st-auto')), 'masaüstü: ayarlar açık, "simge durumu" giriş kapalıyken kapalı');
await pg.setChecked('#st-login', true); await pg.waitForTimeout(150); ok(await pg.isChecked('#st-login') && !(await pg.isDisabled('#st-min')) && await pg.evaluate(() => window.__st.openAtLogin === true), 'Windows ile başlat açıldı → köprüye gitti');
await pg.setChecked('#st-min', true); await pg.waitForTimeout(100); ok(await pg.evaluate(() => window.__st.startMinimized === true), 'simge durumunda başlat');
await pg.setChecked('#st-auto', false); await pg.waitForTimeout(100); ok(await pg.evaluate(() => window.__st.autoUpdate === false), 'otomatik güncelleme kapatıldı');
await pg.click('#st-check'); await pg.waitForTimeout(100); ok(await pg.evaluate(() => window.__calls.some((c) => c[0] === 'check')), 'şimdi denetle köprüyü çağırdı');
await pg.evaluate(() => { window.__fail = true; }); await pg.setChecked('#st-login', false).catch(() => {}); await pg.waitForTimeout(200); ok(await pg.isChecked('#st-login') && /OS reddetti/.test(await pg.textContent('#settings')), 'OS reddederse anahtar geri döner ve hata gösterilir');
ok(pg.errs.length === 0, 'masaüstü modunda hata yok ' + pg.errs.join('|'));
// desteklenmeyen
pg = await mkpage(() => { window.statscanHost = Object.freeze({ desktop: true, settingsGet: async () => ({ openAtLogin: false, startMinimized: false, autoUpdate: true, autostart: { supported: false, reason: 'Geliştirme modunda' } }), settingsSet: async () => ({}), settingsCheckUpdate: async () => ({}), storeGet: async () => null, storeSet: async () => ({}), watchSuggest: async () => [], watchLog: async () => ({ log: [], folders: [] }), watchTake: async () => ({ item: null }), watchSet: async () => ({}), status: async () => ({ available: false, reasons: [{ title: 'test' }] }), info: async () => ({}) }); });
await pg.click('#side-settings'); await pg.waitForTimeout(250); ok(await pg.isDisabled('#st-login') && /Geliştirme modunda/.test(await pg.textContent('#settings')), 'desteklenmeyen ortam: anahtar kapalı, neden yazıyor');
// 3) dar ekran + daraltilmis
pg = await mkpage(null, { width: 380, height: 760 }); ok(await pg.isVisible('#side-settings'), 'dar ekranda Ayarlar alt çubukta görünür'); await pg.click('#side-settings'); await pg.waitForTimeout(150); ok(await isOpen(pg) && await pg.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && document.querySelector('#settings').getBoundingClientRect().right <= innerWidth + 1), 'dar ekranda pencere taşmıyor');
pg = await mkpage(() => { try { localStorage.setItem('kovan.collapsed', '1'); } catch (e) {} }); ok(await pg.isVisible('#side-settings') && !(await pg.isVisible('#side-settings span')), 'daraltılmışken yalnızca simge');
await b.close(); console.log(bad ? bad + ' HATA' : 'TAMAM'); process.exit(bad ? 1 : 0);
