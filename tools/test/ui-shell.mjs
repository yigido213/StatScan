// Kovan kabugu testi (Playwright): Home, harf harf yazma, hareket azaltma, kenar cubugu, StatScan gecisi, dar ekran
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const URL = 'file:///home/claude/statscan/app/StatScan.html'; const FULL = 'Welcome home, yigit717';
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
async function page(opts, vp) { const ctx = await b.newContext(Object.assign({ viewport: vp || { width: 1280, height: 900 } }, opts || {})); const pg = await ctx.newPage(); pg.errs = []; pg.on('pageerror', (e) => pg.errs.push(e.message)); pg.on('console', (m) => m.type() === 'error' && pg.errs.push(m.text())); return pg; }
const typed = (pg) => pg.textContent('#tw .typed');
// 1) normal hareket: yazma animasyonu
let pg = await page({ reducedMotion: 'no-preference' }); await pg.goto(URL);
ok((await pg.title()) === 'Home · Kovan', 'başlık: Home · Kovan');
ok(await pg.evaluate(() => !document.querySelector('#app-home').hidden && document.querySelector('#app-statscan').hidden), 'açılışta Home görünür, StatScan gizli');
ok(await pg.evaluate(() => document.querySelector('#side-nav a[aria-current="page"]').dataset.route) === 'home', 'kenar çubuğunda Home seçili');
const navTxt = await pg.evaluate(() => [...document.querySelectorAll('#side-nav .nav-item')].map((a) => a.textContent.trim())); ok(JSON.stringify(navTxt) === JSON.stringify(['Home', 'StatScan']), 'kenar çubuğu: Home + StatScan (' + navTxt.join(', ') + ')');
const seen = []; for (let i = 0; i < 14; i++) { seen.push((await typed(pg)).length); await pg.waitForTimeout(120); }
ok(seen[0] < FULL.length && seen.some((n) => n > 0 && n < FULL.length), 'metin harf harf beliriyor (' + seen.slice(0, 8).join(',') + '…)'); ok(seen.every((n, i) => i === 0 || n >= seen[i - 1]), 'uzunluk yalnızca artıyor (geri gitmiyor)');
await pg.waitForTimeout(2600); ok((await typed(pg)) === FULL, 'tamamlanınca tam metin: "' + (await typed(pg)) + '"'); ok(await pg.evaluate(() => document.querySelector('#tw').classList.contains('done')), 'bitince imleç kalktı, metin sabit');
const st = await pg.evaluate(() => { const c = getComputedStyle(document.querySelector('#home-title')); return [c.fontWeight, c.fontStyle]; }); ok(+st[0] >= 700 && st[1] === 'italic', 'başlık kalın + eğik (' + st.join(' ') + ')');
const w = await pg.evaluate(() => { const r = document.querySelector('#home-title').getBoundingClientRect(); return [r.left, r.top]; }); ok(w[0] < 400 && w[1] < 200, 'başlık sol üstte (' + w.map(Math.round).join(',') + ')');
ok(await pg.evaluate(() => document.querySelector('#toolgrid .toolcard[data-open="statscan"]') && document.querySelectorAll('#toolgrid .toolcard.empty').length === 1), 'Home: StatScan kartı + boş yer tutucu (sahte araç yok)');
ok(await pg.evaluate(() => document.querySelectorAll('#toolgrid button.toolcard').length) === 1, 'tıklanabilir yalnızca 1 araç kartı');
// 2) StatScan'e gecis
await pg.click('#side-nav a[data-route="statscan"]'); await pg.waitForTimeout(200);
ok(await pg.evaluate(() => document.querySelector('#app-home').hidden && !document.querySelector('#app-statscan').hidden && location.hash === '#/statscan'), 'StatScan seçilince StatScan açıldı (#/statscan)');
ok((await pg.title()) === 'StatScan · Kovan', 'başlık: StatScan · Kovan');
ok(await pg.evaluate(() => !!document.querySelector('#drop') && !!document.querySelector('#file') && !!document.querySelector('#tab-info') && document.querySelectorAll('input[name]').length > 0), 'StatScan arayüzü (bırakma alanı, dosya girişi, mod seçimi, Bilgi sekmesi) yerinde');
await pg.click('#tab-info'); ok(await pg.evaluate(() => !document.querySelector('#view-info').hidden), 'StatScan içi Bilgi sekmesi hâlâ çalışıyor');
await pg.click('#side-nav a[data-route="home"]'); await pg.waitForTimeout(150); ok(await pg.evaluate(() => !document.querySelector('#app-home').hidden && document.querySelector('#app-statscan').hidden), 'Home geri dönüş'); ok((await typed(pg)) === FULL, 'Home’a dönüşte animasyon tekrarlanmadı, metin sabit');
await pg.goBack(); await pg.waitForTimeout(150); ok(await pg.evaluate(() => !document.querySelector('#app-statscan').hidden), 'tarayıcı geri tuşu rotayı izliyor');
await pg.goto(URL + '#/home'); await pg.evaluate(() => { location.hash = '#/yok'; }); await pg.waitForTimeout(100); ok(await pg.evaluate(() => !document.querySelector('#app-home').hidden), 'bilinmeyen rota → Home');
await pg.goto(URL + '#bilgi'); ok(await pg.evaluate(() => !document.querySelector('#app-statscan').hidden && !document.querySelector('#view-info').hidden), 'eski #bilgi bağlantısı StatScan Bilgi sekmesini açıyor');
ok(pg.errs.length === 0, 'konsol/sayfa hatası yok ' + pg.errs.slice(0, 2).join(' | '));
// 3) hareket azaltma
pg = await page({ reducedMotion: 'reduce' }); await pg.goto(URL); ok((await typed(pg)) === FULL && await pg.evaluate(() => document.querySelector('#tw').classList.contains('done')), 'hareket azaltma: yazı anında tam, animasyon yok');
ok(await pg.evaluate(() => getComputedStyle(document.querySelector('#tw .caret')).display) === 'none', 'hareket azaltma: yanıp sönen imleç yok');
// 4) tema dugmesi + dar ekranlar
pg = await page({ reducedMotion: 'reduce' }); await pg.goto(URL); const t0 = await pg.evaluate(() => document.documentElement.dataset.theme || ''); await pg.click('#side-theme'); ok((await pg.evaluate(() => document.documentElement.dataset.theme || '')) !== t0, 'kenar çubuğundaki Tema düğmesi temayı değiştiriyor');
for (const [wd, name] of [[1280, 'masaüstü'], [980, 'orta'], [760, 'tablet'], [390, 'telefon']]) {
  pg = await page({ reducedMotion: 'reduce' }, { width: wd, height: 800 }); await pg.goto(URL);
  for (const hash of ['#/home', '#/statscan']) { await pg.evaluate((h) => { location.hash = h; }, hash); await pg.waitForTimeout(80); const ov = await pg.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth); ok(ov <= 1, name + ' ' + wd + 'px ' + hash + ': yatay taşma yok (' + ov + ')'); }
  const sb = await pg.evaluate(() => { const r = document.querySelector('.side').getBoundingClientRect(); return { w: r.width, h: r.height, top: r.top, vh: innerHeight }; });
  if (wd >= 900) ok(Math.abs(sb.w - 220) < 2 && sb.h >= sb.vh - 2, name + ': dikey sütun (' + Math.round(sb.w) + 'x' + Math.round(sb.h) + ')'); else ok(sb.w >= wd - 2 && sb.h < 100 && sb.top > sb.vh - 110, name + ': alt gezinme çubuğuna dönüştü (' + Math.round(sb.h) + 'px)');
  await pg.evaluate(() => { location.hash = '#/home'; }); await pg.waitForTimeout(80); await pg.click('#side-nav a[data-route="statscan"]'); await pg.waitForTimeout(80); ok(await pg.evaluate(() => !document.querySelector('#app-statscan').hidden), name + ': StatScan’e geçiş çalışıyor');
}
await b.close(); console.log(bad ? 'BAŞARISIZ ' + bad : 'TAMAM'); process.exit(bad ? 1 : 0);
