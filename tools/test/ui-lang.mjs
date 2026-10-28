// Kovan dil secenegi (Playwright): TR varsayilan degismez, EN secilince Kovan arayuzu cevrilir, kalicidir, sifirlama TR'ye doner
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const URL = 'file:///home/claude/statscan/app/StatScan.html'; const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
const ctx = await b.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' }); const pg = await ctx.newPage(); const errs = []; pg.on('pageerror', (e) => errs.push(String(e)));
await pg.goto(URL); await pg.waitForTimeout(300);
ok(await pg.evaluate(() => document.documentElement.lang) === 'tr' && /Ayarlar/.test(await pg.textContent('#side-settings')), 'varsayılan: Türkçe');
ok(/dört araç/.test(await pg.textContent('#app-home .lead')), 'Home metni dört araç');
await pg.click('#side-settings'); await pg.waitForTimeout(150); ok(await pg.inputValue('#st-lang') === 'tr', 'dil seçici Türkçe');
await Promise.all([pg.waitForNavigation(), pg.selectOption('#st-lang', 'en')]); await pg.waitForTimeout(500);
ok(await pg.evaluate(() => document.documentElement.lang) === 'en' && await pg.evaluate(() => localStorage.getItem('kovan.lang')) === 'en', 'EN seçildi ve saklandı');
ok(await pg.evaluate(() => document.querySelector('#settings').open) && await pg.inputValue('#st-lang') === 'en', 'yenilemeden sonra Ayarlar yeniden açıldı');
ok(/Appearance/.test(await pg.textContent('#settings')) && /Start with Windows/.test(await pg.textContent('#settings')), 'Ayarlar İngilizce');
await pg.keyboard.press('Escape'); await pg.waitForTimeout(100);
ok(/Settings/.test(await pg.textContent('#side-settings')) && /Tools/.test(await pg.textContent('.side')), 'kenar çubuğu İngilizce');
ok(/four tools/.test(await pg.textContent('#app-home .lead')) && /Compiler/.test(await pg.textContent('#toolgrid')), 'Home İngilizce');
ok((await pg.title()).startsWith('Home'), 'başlık');
const roots = { texpack: '#app-texpack', modconv: '#app-modconv', compiler: '#app-compiler' };
for (const [id, sel] of Object.entries(roots)) { await pg.evaluate((i) => { location.hash = '#/' + i; }, id); await pg.waitForTimeout(250);
  const left = await pg.evaluate((s) => { const out = []; const w = document.createTreeWalker(document.querySelector(s), NodeFilter.SHOW_TEXT); let n; while ((n = w.nextNode())) { const t = n.nodeValue.trim(); if (t && /[çğıöşüÇĞİÖŞÜ]/.test(t) && !n.parentElement.closest('pre,textarea,script,style,[hidden]')) out.push(t.slice(0, 80)); } return out; }, sel);
  ok(left.length === 0, id + ': Türkçe kalıntı yok ' + left.join(' | ')); }
await pg.keyboard.press('Control+k'); await pg.keyboard.type('compiler'); await pg.waitForTimeout(150); ok(/Open Compiler/.test(await pg.textContent('#pal-list')), 'palet İngilizce arıyor');
await pg.keyboard.press('Escape');
ok(errs.length === 0, 'hata yok ' + errs.join('|'));
// kalicilik + sifirlama
await pg.reload(); await pg.waitForTimeout(300); ok(await pg.evaluate(() => document.documentElement.lang) === 'en' && /Tools/.test(await pg.textContent('.side')), 'yeniden yüklemede EN kalır');
await pg.click('#side-settings'); await pg.waitForTimeout(150); await pg.click('#st-reset'); await Promise.all([pg.waitForNavigation(), pg.click('#st-reset')]); await pg.waitForTimeout(300);
ok(await pg.evaluate(() => document.documentElement.lang) === 'tr' && /Araçlar/.test(await pg.textContent('.side')), 'sıfırlama Türkçe’ye döndürür');
console.log(bad ? 'BAŞARISIZ ' + bad : 'TAMAM'); await b.close(); process.exit(bad ? 1 : 0);
