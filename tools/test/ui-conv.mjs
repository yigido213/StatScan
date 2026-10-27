// Kovan donusturucu arayuzleri (Playwright): dosya sec -> algila -> donustur -> indir -> cikti dogrula
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { spawnSync } from 'node:child_process'; import { loadEngine } from './engine.mjs';
const E = loadEngine(); let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const enc = (s) => new TextEncoder().encode(s); const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'uc-'));
const T = 'assets/minecraft/textures/';
const pack = await E.mzWrite([['pack.mcmeta', '{"pack":{"pack_format":3,"description":"x"}}'], [T + 'blocks/dirt.png', 'PNGd'], [T + 'items/apple.png', 'PNGa']].map(([name, d]) => ({ name, data: enc(d) })));
const mod = await E.mzWrite([['fabric.mod.json', JSON.stringify({ id: 'foo', version: '1.0', depends: { minecraft: '~1.20' } })], ['a/B.class', new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61])]].map(([name, d]) => ({ name, data: typeof d === 'string' ? enc(d) : d })));
fs.writeFileSync(dir + '/pack.zip', pack); fs.writeFileSync(dir + '/mod.jar', mod); fs.writeFileSync(dir + '/bad.zip', enc('not a zip at all, definitely'.repeat(3))); fs.writeFileSync(dir + '/nomc.zip', await E.mzWrite([{ name: 'a.txt', data: enc('x') }]));
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
const ctx = await b.newContext({ viewport: { width: 1200, height: 900 }, acceptDownloads: true }); const pg = await ctx.newPage(); const errs = []; pg.on('pageerror', (e) => errs.push(e.message)); pg.on('console', (m) => { if (m.type() === 'error') errs.push(m.text()); });
await pg.goto('file:///home/claude/statscan/app/StatScan.html'); await pg.waitForTimeout(300);
ok((await pg.textContent('#side-ver')) === 'beta 0.0.3', 'kenar çubuğu sürümü: beta 0.0.3');
ok((await pg.textContent('#home-facts')).includes('beta 0.0.3'), 'Home: Kovan beta 0.0.3');
// doku paketi
await pg.click('#side-nav a[data-route="texpack"]'); await pg.waitForTimeout(150); ok(await pg.evaluate(() => !document.querySelector("#app-texpack").hidden && document.querySelector("#app-home").hidden), "doku paketi sayfası açıldı");
ok((await pg.title()) === 'Doku paketi dönüştürücü · Kovan', 'başlık');
await pg.setInputFiles('#tp-file', dir + '/bad.zip'); await pg.waitForTimeout(300); ok(/ZIP|zip/.test(await pg.textContent('#app-texpack .cv-live')) && (await pg.isDisabled('#app-texpack .cv-primary')), 'ZIP olmayan dosya: açık hata, buton kapalı');
await pg.setInputFiles('#tp-file', dir + '/nomc.zip'); await pg.waitForTimeout(300); ok(/pack\.mcmeta/.test(await pg.textContent('#app-texpack .cv-live')), 'pack.mcmeta yok: açık hata');
await pg.setInputFiles('#tp-file', dir + '/pack.zip'); await pg.waitForTimeout(400); ok(await pg.inputValue('#tp-src') === '1.11' && /pack_format/.test(await pg.textContent('#app-texpack .cv-info')), 'kaynak sürüm 1.11 algılandı');
await pg.selectOption('#tp-dst', '1.21.4'); await pg.click('#app-texpack .cv-primary:not(.cv-actions *)'); await pg.waitForSelector('#app-texpack .cv-res:not([hidden])', { timeout: 8000 });
const [dl] = await Promise.all([pg.waitForEvent('download'), pg.click('#app-texpack .cv-actions .cv-primary')]); const p1 = dir + '/' + dl.suggestedFilename(); await dl.saveAs(p1); ok(dl.suggestedFilename() === 'pack-1.21.4.zip', 'indirilen ad: ' + dl.suggestedFilename());
ok(spawnSync('unzip', ['-t', p1]).status === 0, 'indirilen zip geçerli'); const lst = spawnSync('unzip', ['-Z1', p1]).stdout.toString(); ok(/textures\/block\/dirt\.png/.test(lst) && /textures\/item\/apple\.png/.test(lst) && !/textures\/blocks\//.test(lst), 'dokular yeniden adlandırıldı');
const [dr] = await Promise.all([pg.waitForEvent('download'), pg.click('#app-texpack .cv-actions .cv-btn:not(.cv-primary)')]); await dr.saveAs(dir + '/r.md'); ok(/1\.11.*1\.21\.4/s.test(fs.readFileSync(dir + '/r.md', 'utf8')), 'rapor indirildi');
// mod
await pg.click('#side-nav a[data-route="modconv"]'); await pg.waitForTimeout(150);
await pg.setInputFiles('#mc-file', dir + '/mod.jar'); await pg.waitForTimeout(400); ok(/fabric/.test(await pg.textContent('#app-modconv .cv-info')), 'mod algılandı (fabric)');
await pg.selectOption('#mc-dst', '1.21.4'); await pg.click('#app-modconv .cv-primary:not(.cv-actions *)'); await pg.waitForSelector('#app-modconv .cv-res:not([hidden])', { timeout: 8000 });
ok(/GARANTİ ETMEZ/.test(await pg.textContent('#app-modconv .cv-res')), 'mod: çalışma garantisi yok uyarısı sonuçta görünür (risk bölümü)');
const [dm] = await Promise.all([pg.waitForEvent('download'), pg.click('#app-modconv .cv-actions .cv-primary')]); const p2 = dir + '/' + dm.suggestedFilename(); await dm.saveAs(p2); ok(dm.suggestedFilename() === 'mod-1.21.4.jar' && spawnSync('unzip', ['-p', p2, 'fabric.mod.json']).stdout.toString().includes('>=1.21.4'), 'mod jar indirildi ve bildirim güncel');
// dar ekran taşma
await pg.setViewportSize({ width: 380, height: 800 }); await pg.waitForTimeout(150); ok(await pg.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'dar ekranda yatay taşma yok');
await pg.click('#side-nav a[data-route="texpack"]').catch(() => {});
// palet
await pg.setViewportSize({ width: 1200, height: 900 }); await pg.keyboard.press('Control+k'); await pg.keyboard.type('mod'); await pg.waitForTimeout(150); ok(/Mod sürüm ayarlayıcı/.test(await pg.textContent('#pal')), 'komut paletinde araç görünür');
ok(errs.length === 0, 'konsol/sayfa hatası yok ' + errs.slice(0, 2).join('|'));
await b.close(); fs.rmSync(dir, { recursive: true, force: true }); console.log(bad ? bad + ' HATA' : 'TAMAM'); process.exit(bad ? 1 : 0);
