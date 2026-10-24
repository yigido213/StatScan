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

// 5) ana menu 2: daraltma, komut paleti, kullanici adi
{
  const ctx = await b.newContext({ viewport: { width: 1280, height: 800 }, reducedMotion: 'reduce' }); const p = await ctx.newPage(); const errs = []; p.on('pageerror', (e) => errs.push(e.message)); await p.goto(URL);
  const sw = () => p.evaluate(() => Math.round(document.querySelector('.side').getBoundingClientRect().width));
  ok(await sw() === 220, 'kenar çubuğu genişken 220px'); await p.click('#side-toggle'); await p.waitForTimeout(100); ok(await sw() === 68, 'daraltınca 68px (' + await sw() + ')');
  ok(await p.evaluate(() => document.querySelector('#side-toggle').getAttribute('aria-expanded')) === 'false', 'aria-expanded=false'); ok(await p.evaluate(() => [...document.querySelectorAll('.nav-item')].every((a) => a.title && a.getBoundingClientRect().width > 40)), 'daraltılmış halde bağlantılar tooltip (title) taşıyor');
  await p.reload(); ok(await sw() === 68, 'daraltma tercihi yeniden yüklemede korundu'); await p.click('#side-toggle'); ok(await sw() === 220, 'tekrar genişletildi');
  // palet
  await p.keyboard.press('Control+k'); ok(await p.evaluate(() => !document.querySelector('#pal').hidden && document.activeElement.id === 'pal-q'), 'Ctrl+K paleti açtı, odak arama kutusunda');
  ok((await p.locator('#pal-list [role=option]').count()) >= 5, 'palet komutları listeliyor'); await p.keyboard.type('bilgi'); ok((await p.locator('#pal-list [role=option]').count()) === 1, '"bilgi" yazınca süzüldü (1 sonuç)');
  await p.keyboard.press('Enter'); await p.waitForTimeout(150); ok(await p.evaluate(() => document.querySelector('#pal').hidden && !document.querySelector('#app-statscan').hidden && !document.querySelector('#view-info').hidden), 'Enter: StatScan Bilgi sekmesi açıldı, palet kapandı');
  await p.keyboard.press('Control+k'); await p.keyboard.type('zzzzqq'); ok(await p.evaluate(() => /Eşleşen komut yok/.test(document.querySelector('#pal-list').textContent)), 'eşleşme yoksa açıkça söyleniyor'); await p.keyboard.press('Escape'); ok(await p.evaluate(() => document.querySelector('#pal').hidden), 'Esc paleti kapattı');
  await p.keyboard.press('Control+k'); await p.keyboard.type('home'); await p.keyboard.press('ArrowDown'); await p.keyboard.press('ArrowUp'); await p.keyboard.press('Enter'); await p.waitForTimeout(100); ok(await p.evaluate(() => !document.querySelector('#app-home').hidden), 'palet ile Home’a gidildi');
  // kullanici adi
  await p.click('#name-edit'); await p.fill('#name-in', 'Test Kullanıcı'); await p.keyboard.press('Enter'); await p.waitForTimeout(100);
  ok(await p.evaluate(() => document.querySelector('#tw .typed').textContent === 'Welcome home, Test Kullanıcı' && document.querySelector('#home-title .sr').textContent === 'Welcome home, Test Kullanıcı' && document.querySelector('#tw .ghost').textContent === 'Welcome home, Test Kullanıcı'), 'ad değişti: başlık, ekran okuyucu ve yer tutucu metni güncel');
  await p.reload(); ok((await p.textContent('#tw .typed')) === 'Welcome home, Test Kullanıcı', 'ad yeniden yüklemede korundu');
  await p.click('#name-edit'); await p.click('#name-reset'); ok((await p.textContent('#tw .typed')) === FULL, 'Varsayılan: yigit717’ye döndü'); await p.reload(); ok((await p.textContent('#tw .typed')) === FULL, 'varsayılan yeniden yüklemede korundu');
  await p.click('#name-edit'); await p.fill('#name-in', '<img src=x onerror=alert(1)>'); await p.keyboard.press('Enter'); ok(await p.evaluate(() => !document.querySelector('#home-title img') && document.querySelector('#tw .typed').textContent.includes('<img')), 'ad HTML olarak yorumlanmıyor (güvenli metin)');
  ok(errs.length === 0, 'ana menü 2: sayfa hatası yok ' + errs.slice(0, 2).join('|')); await ctx.close();
  const c2 = await b.newContext({ viewport: { width: 390, height: 800 }, reducedMotion: 'reduce' }); const q = await c2.newPage(); await q.goto(URL);
  ok(await q.evaluate(() => getComputedStyle(document.querySelector('#side-toggle')).display === 'none' && !document.querySelector('.app').classList.contains('collapsed')), 'telefonda daraltma düğmesi yok, alt çubuk tam'); await q.keyboard.press('Control+k'); ok(await q.evaluate(() => !document.querySelector('#pal').hidden), 'telefonda da klavye ile palet açılıyor'); await c2.close();
}

await b.close(); console.log(bad ? 'BAŞARISIZ ' + bad : 'TAMAM'); process.exit(bad ? 1 : 0);
