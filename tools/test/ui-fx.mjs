// Kovan animasyon testi (Playwright): animasyonlar gercekten calisiyor mu, "hareketi azalt" ve Ayarlar anahtari onlari kapatiyor mu,
// dalga/egilme/palet/kenar cubugu gecisleri, yatay tasma ve konsol hatasi yok mu.
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..'); const URL = 'file://' + path.join(ROOT, 'app/StatScan.html');
const SHOTS = process.env.SHOTS || ''; if (SHOTS) fs.mkdirSync(SHOTS, { recursive: true });
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
async function page(opts, vp, init) { const ctx = await b.newContext(Object.assign({ viewport: vp || { width: 1280, height: 860 }, reducedMotion: 'no-preference' }, opts || {})); if (init) await ctx.addInitScript(init); const pg = await ctx.newPage(); pg.errs = []; pg.on('pageerror', (e) => pg.errs.push(e.message)); pg.on('console', (m) => m.type() === 'error' && pg.errs.push(m.text())); return pg; }
const an = (pg, sel, pseudo) => pg.evaluate(([s, p]) => { const e = document.querySelector(s); return e ? getComputedStyle(e, p || null).animationName : 'YOK'; }, [sel, pseudo]);
const shot = async (pg, n) => { if (SHOTS) await pg.screenshot({ path: path.join(SHOTS, n + '.png') }); };

// 1) animasyonlar acik
let pg = await page(); await pg.goto(URL + '#/home'); await pg.waitForTimeout(120);
ok(!(await pg.evaluate(() => document.documentElement.hasAttribute('data-fx'))), 'varsayılan: data-fx yok (animasyonlar açık)');
await shot(pg, '01-acilis-120ms'); await pg.waitForTimeout(500); await shot(pg, '02-acilis-620ms');
ok((await an(pg, '#app-home')).includes('kview'), 'Home görünümü kview ile giriyor (' + await an(pg, '#app-home') + ')');
ok(/kcard/.test(await an(pg, '#toolgrid > .toolcard')), 'araç kartları kcard ile giriyor');
ok(/kdots/.test(await an(pg, '#app-home', '::before')), 'Home arka plan noktaları akıyor (kdots)');
ok(/korb/.test(await an(pg, '#app-home', '::after')), 'Home arka plan ışığı hareket ediyor (korb)');
ok(/khex/.test(await an(pg, '.side-brand svg path')), 'logo altıgenleri çiziliyor (khex)');
ok(/kside/.test(await an(pg, '.side-nav > .nav-item')), 'kenar çubuğu öğeleri kayarak geliyor (kside)');
await pg.waitForTimeout(3200);
ok(/ksheen/.test(await an(pg, '#tw .typed')), 'başlıkta parlama süpürmesi (ksheen)');
ok(await pg.evaluate(() => document.querySelector('#tw .typed').textContent === 'Welcome home, ' + (document.querySelector('#home-title .sr').textContent.replace('Welcome home, ', ''))), 'parlama metni bozmuyor');
ok(/kdot/.test(await an(pg, '.toolcard .chip', '::before')), '"Hazır" noktası nabız atıyor (kdot)');
// kart: fare ile egilme + isik
const card = pg.locator('#toolgrid .toolcard:not(.empty)').first(); const bb = await card.boundingBox();
await pg.mouse.move(bb.x + bb.width * 0.85, bb.y + bb.height * 0.2); await pg.waitForTimeout(250);
const tv = await card.evaluate((e) => ({ rx: e.style.getPropertyValue('--rx'), ry: e.style.getPropertyValue('--ry'), mx: e.style.getPropertyValue('--mx') }));
ok(parseFloat(tv.rx) > 0 && parseFloat(tv.ry) > 0, 'karta fareyle gelince eğilme değerleri yazıldı (' + JSON.stringify(tv) + ')');
ok(/matrix3d|matrix/.test(await card.evaluate((e) => getComputedStyle(e).transform)), 'kart gerçekten dönüşüm uyguluyor');
await shot(pg, '03-kart-hover');
await pg.mouse.move(5, 5); await pg.waitForTimeout(250); ok(await card.evaluate((e) => e.style.getPropertyValue('--rx') === ''), 'fare ayrılınca eğilme sıfırlandı');
// dalga
await pg.click('#home-search'); await pg.waitForTimeout(60); ok(await pg.evaluate(() => !document.querySelector('#pal').hidden), 'palet açıldı');
ok(await pg.evaluate(() => document.querySelector('#pal').classList.contains('kopen')), 'palet açılırken kopen sınıfı (satırlar sırayla geliyor)');
ok(/kpal/.test(await an(pg, '#pal .pal-box')), 'palet kutusu yaylanarak açılıyor (kpal)'); await shot(pg, '04-palet');
await pg.keyboard.press('Escape'); await pg.waitForTimeout(800);
ok(await pg.evaluate(() => !document.querySelector('#pal').classList.contains('kopen')), 'palet kapanınca kopen sınıfı kalktı');
let rip = 0; const sb = await pg.locator('#home-search').boundingBox(); await pg.mouse.move(sb.x + 20, sb.y + 10); await pg.mouse.down(); await pg.waitForTimeout(80);
rip = await pg.evaluate(() => document.querySelectorAll('.kfx-rip').length); await pg.mouse.up(); ok(rip >= 1, 'düğmeye basınca dalga oluştu (' + rip + ')');
await pg.keyboard.press('Escape'); await pg.waitForTimeout(900); ok(await pg.evaluate(() => document.querySelectorAll('.kfx-rip').length) === 0, 'dalga bitince DOM’dan silindi');
// sayfa gecisi
await pg.click('#side-nav a[data-route="statscan"]'); await pg.waitForTimeout(80); ok(/kview/.test(await an(pg, '#app-statscan')), 'araç değişince yeni görünüm kview ile geliyor'); await shot(pg, '05-statscan-gecis');
await pg.click('#tab-info'); await pg.waitForTimeout(60); ok(/kview/.test(await an(pg, '#view-info')), 'StatScan sekme geçişi animasyonlu');
// tema gecisi
await pg.click('#side-theme'); ok(await pg.evaluate(() => document.documentElement.classList.contains('kfade')), 'tema değişirken yumuşak geçiş sınıfı (kfade) var'); await pg.waitForTimeout(900);
ok(await pg.evaluate(() => !document.documentElement.classList.contains('kfade')), 'geçiş bitince kfade kalktı');
// kenar cubugu daralma: ara degerler
await pg.click('#side-nav a[data-route="home"]'); await pg.waitForTimeout(100);
await pg.click('#side-toggle'); await pg.waitForTimeout(110); const mid = await pg.evaluate(() => Math.round(document.querySelector('.side').getBoundingClientRect().width));
await pg.waitForTimeout(600); const end = await pg.evaluate(() => Math.round(document.querySelector('.side').getBoundingClientRect().width));
ok(mid > 68 && mid < 220, 'daralma animasyonlu: ara genişlik ' + mid + 'px'); ok(end === 68, 'daralma 68px’te bitti (' + end + ')'); await shot(pg, '06-daralmis');
await pg.click('#side-toggle'); await pg.waitForTimeout(700); ok(await pg.evaluate(() => Math.round(document.querySelector('.side').getBoundingClientRect().width)) === 220, 'genişleyince 220px');
// Ayarlar anahtari
await pg.keyboard.press('Control+,'); await pg.waitForTimeout(150); const hasSet = await pg.evaluate(() => !!document.querySelector('#st-fx'));
if (!hasSet) await pg.click('#side-settings'); await pg.waitForTimeout(250);
ok(await pg.evaluate(() => !!document.querySelector('#st-fx') && document.querySelector('#st-fx').checked), 'Ayarlar: "Arayüz animasyonları" anahtarı var ve açık'); await shot(pg, '07-ayarlar');
ok(/kpop/.test(await an(pg, '#settings')), 'ayar penceresi animasyonla açılıyor');
await pg.click('#st-fx'); await pg.waitForTimeout(100);
ok(await pg.evaluate(() => document.documentElement.getAttribute('data-fx') === 'off' && localStorage.getItem('kovan.fx') === '0'), 'anahtar kapatılınca data-fx="off" ve tercih kaydedildi');
ok((await an(pg, '.side-brand svg path')) === 'none' && (await an(pg, '#toolgrid > .toolcard')) === 'none', 'kapalıyken animasyon adları none');
await pg.click('#st-fx'); await pg.waitForTimeout(80); ok(await pg.evaluate(() => !document.documentElement.hasAttribute('data-fx') && localStorage.getItem('kovan.fx') === null), 'tekrar açılınca geri döndü');
ok(pg.errs.length === 0, 'konsol/sayfa hatası yok ' + pg.errs.slice(0, 2).join(' | '));

// 2) kalici kapali tercih
pg = await page({}, null, () => { try { localStorage.setItem('kovan.fx', '0'); } catch (e) { /* yoksay */ } }); await pg.goto(URL + '#/home'); await pg.waitForTimeout(200);
ok(await pg.evaluate(() => document.documentElement.getAttribute('data-fx') === 'off'), 'kayıtlı tercih (kovan.fx=0) açılışta uygulandı');
for (const [sel, ps] of [['#app-home'], ['#app-home', '::before'], ['#app-home', '::after'], ['.side-brand svg path'], ['.side-nav > .nav-item'], ['#toolgrid > .toolcard'], ['.facts > li']]) ok((await an(pg, sel, ps)) === 'none', 'animasyonlar kapalı: ' + sel + (ps || '') + ' → none');
ok(await pg.evaluate(() => [...document.querySelectorAll('#toolgrid > .toolcard, .facts > li, #app-home .lead')].every((e) => getComputedStyle(e).opacity === '1' && getComputedStyle(e).transform === 'none')), 'kapalıyken kartlar, bilgi kutuları ve metin tam görünür, kaymış değil');
await pg.click('#home-search'); ok(!(await pg.evaluate(() => document.querySelector('#pal').classList.contains('kopen'))), 'kapalıyken palet efekti yok');
const sb2 = await pg.locator('#home-search').boundingBox(); await pg.keyboard.press('Escape');
await pg.mouse.move(sb2.x + 20, sb2.y + 10); await pg.mouse.down(); await pg.waitForTimeout(60); ok(await pg.evaluate(() => document.querySelectorAll('.kfx-rip').length) === 0, 'kapalıyken dalga yok'); await pg.mouse.up();

// 3) sistem "hareketi azalt"
pg = await page({ reducedMotion: 'reduce' }); await pg.goto(URL + '#/home'); await pg.waitForTimeout(200);
for (const [sel, ps] of [['#app-home'], ['#app-home', '::before'], ['.side-brand svg path'], ['#toolgrid > .toolcard'], ['#tw .typed']]) ok((await an(pg, sel, ps)) === 'none', 'hareketi azalt: ' + sel + (ps || '') + ' → none');
ok(await pg.evaluate(() => getComputedStyle(document.querySelector('#tw .typed')).webkitTextFillColor !== 'rgba(0, 0, 0, 0)'), 'hareketi azalt: başlık metni saydam değil (görünür)');

// 4) dar ekranlarda tasma yok (animasyon sirasinda dahil)
for (const wd of [1280, 980, 760, 390]) {
  pg = await page({}, { width: wd, height: 820 }); await pg.goto(URL + '#/home'); let worst = 0;
  for (let i = 0; i < 8; i++) { await pg.waitForTimeout(150); worst = Math.max(worst, await pg.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)); }
  ok(worst <= 1, wd + 'px: animasyon sırasında yatay taşma yok (' + worst + ')'); if (wd === 390) await shot(pg, '08-telefon');
  await pg.click('#side-nav a[data-route="statscan"]'); await pg.waitForTimeout(100); ok((await pg.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)) <= 1, wd + 'px: StatScan geçişinde taşma yok');
  ok(pg.errs.length === 0, wd + 'px: konsol hatası yok');
}
await b.close(); console.log(bad ? '\n' + bad + ' BAŞARISIZ' : '\nTAMAM'); process.exit(bad ? 1 : 0);
