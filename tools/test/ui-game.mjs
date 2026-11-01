// Oyun Ayarlayici arayuz testi (Playwright). Arayuz GERCEK host koduna (GAMEMOD) kopruyle baglanir; sahte Steam kutuphanesi + sahte surec listesi kullanilir.
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
const { createHost } = createRequire(import.meta.url)('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const URL = 'file:///home/claude/statscan/app/StatScan.html';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-uigame-')); const W = (p, t) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, t); };
const steam = path.join(tmp, 'Steam'); const acf = (id, n) => '"AppState"\n{\n "appid" "' + id + '"\n "name" "' + n + '"\n "installdir" "' + n + '"\n}\n';
W(path.join(steam, 'steamapps', 'libraryfolders.vdf'), '"libraryfolders" { "0" { "path" "' + steam.replace(/\\/g, '\\\\') + '" } }');
W(path.join(steam, 'steamapps', 'appmanifest_1.acf'), acf(1, 'Resident Evil Requiem')); W(path.join(steam, 'steamapps', 'appmanifest_2.acf'), acf(2, 'Rocket League'));
const reDir = path.join(steam, 'steamapps', 'common', 'Resident Evil Requiem'); const cfg = path.join(reDir, 'config.ini'); fs.mkdirSync(path.join(steam, 'steamapps', 'common', 'Rocket League', 'EasyAntiCheat'), { recursive: true });
const setCfg = (s, t, r) => (fs.mkdirSync(reDir, { recursive: true }), fs.writeFileSync(cfg, '[Setting]\nShadowQuality=' + s + '\nTextureQuality=' + t + '\nResolution=' + r + '\nFOV=90\n')); setCfg(2, 2, '1920x1080');
let procs = []; let confirms = 0;
const host = createHost({ service: { closeAll() {} }, game: { platform: 'win32', dataDir: path.join(tmp, 'data'), steamRoots: [steam], epicManifestDir: path.join(tmp, 'noepic'), riotRoots: [], listProcs: async () => procs, pmDirs: [], run: async () => '', confirm: async () => { confirms++; return true; } } });
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
async function page(vp, withHost = true) {
  const ctx = await b.newContext({ viewport: vp || { width: 1366, height: 900 }, reducedMotion: 'reduce' }); const pg = await ctx.newPage(); pg.errs = []; pg.on('pageerror', (e) => pg.errs.push(e.message));
  if (withHost) { await pg.exposeFunction('__h', async (ch, ...a) => { const f = host.handlers[ch]; return f ? JSON.parse(JSON.stringify(await f(null, ...a))) : { error: 'nochan' }; });
    await pg.addInitScript(() => { const c = (ch, ...a) => window.__h(ch, ...a); const o = { desktop: true }; const m = { gameScan: 'game:scan', gameRunning: 'game:running', gameDetectAll: 'game:detectAll', gameConfig: 'game:config', gameUseConfig: 'game:useConfig', gameChooseConfig: 'game:chooseConfig', gameSnap: 'game:snap', gameSnapClear: 'game:snapClear', gamePlan: 'game:plan', gameApply: 'game:apply', gameRestore: 'game:restore', gameTarget: 'game:target', gameHw: 'game:hw', gameEstimate: 'game:estimate', gamePm: 'game:pm', gameChoosePm: 'game:choosePm', gameMeasureStart: 'game:measure:start', gameMeasureJob: 'game:measure:job', gameMeasureCancel: 'game:measure:cancel' }; for (const k in m) o[k] = (...a) => c(m[k], ...a); window.statscanHost = Object.freeze(o); }); }
  return pg;
}
// tarayici (masaustu koprusu yok)
let pg = await page(null, false); await pg.goto(URL + '#/oyunayar'); await pg.waitForTimeout(400);
ok(/masaüstü uygulaması gerektirir/.test(await pg.textContent('#app-oyunayar')), 'tarayıcıda: masaüstü gerekir notu, çökme yok'); ok(pg.errs.length === 0, 'tarayıcıda: sayfa hatası yok'); await pg.context().close();

pg = await page(); await pg.goto(URL + '#/oyunayar'); await pg.waitForSelector('#og-list .og-game', { timeout: 15000 });
ok((await pg.title()) === 'Oyun Ayarlayıcı · Kovan', 'başlık: Oyun Ayarlayıcı · Kovan');
ok(await pg.evaluate(() => document.querySelector('.nav-item[href="#/oyunayar"], .nav-item[data-open="oyunayar"]') != null), 'kenar çubuğunda araç görünür');
const games = await pg.evaluate(() => [...document.querySelectorAll('#og-list .og-game')].map((x) => ({ n: x.querySelector('.og-gname').textContent, dis: x.disabled, t: x.textContent })));
ok(games.length === 2 && games.find((g) => g.n === 'Resident Evil Requiem' && !g.dis) && games.find((g) => g.n === 'Rocket League' && g.dis && /anti-cheat/.test(g.t)), 'liste: RE seçilebilir, Rocket League anti-cheat ile devre dışı');
ok(await pg.evaluate(() => document.querySelector('#og-note').textContent.includes('Anti-cheat’li oyunlara') && document.querySelector('#og-note').textContent.includes('denenmedi')), 'dürüst sınırlar notu görünür');
await pg.waitForFunction(() => /bulundu ve seçildi/.test(document.querySelector('#og-detect').textContent), null, { timeout: 12000 }); ok(/1 oyunda bulundu ve seçildi/.test(await pg.textContent('#og-detect')) && /1 oyun anti-cheat nedeniyle atlandı/.test(await pg.textContent('#og-detect')), 'otomatik arama özeti: RE bulundu+seçildi, anti-cheat’li oyun atlandı');
ok(await pg.evaluate(() => /ayar dosyası otomatik bulundu/.test([...document.querySelectorAll('#og-list .og-game')].find((x) => x.querySelector('.og-gname').textContent === 'Resident Evil Requiem').textContent)), 'liste: RE etiketi “ayar dosyası otomatik bulundu”');
ok(await pg.evaluate(() => document.querySelector('#og-cfg').hidden && document.querySelector('#og-learn').hidden), 'oyun seçilmeden ayar bölümleri gizli');

// oyun calisinca otomatik algila
procs = [{ pid: 7, name: 'REQUIEM.exe', path: path.join(reDir, 'REQUIEM.exe') }]; W(path.join(reDir, 'REQUIEM.exe'), 'x');
await pg.waitForFunction(() => /Oynuyorsun: Resident Evil Requiem/.test(document.querySelector('#og-now').textContent), null, { timeout: 12000 }); ok(true, 'otomatik algılama: çalışan RE “Oynuyorsun” olarak görünür');
await pg.waitForSelector('#og-cfg:not([hidden])', { timeout: 8000 }); ok(await pg.evaluate(() => document.querySelector('.og-game.sel .og-gname').textContent) === 'Resident Evil Requiem', 'otomatik algılama: oyun kendiliğinden seçildi');
ok(await pg.evaluate(() => /config\.ini/.test(document.querySelector('#og-cands').textContent)), 'ayar dosyası adayı: config.ini bulundu');
await pg.waitForSelector('#og-learn:not([hidden])'); ok(/otomatik bulundu/.test(await pg.textContent('#og-cfgline')) && /puan/.test(await pg.textContent('#og-cands')), 'ayar dosyası kendiliğinden seçili (“otomatik bulundu”), adayda puan görünür'); await pg.click('#og-use'); await pg.waitForTimeout(300); ok(/Seçili:/.test(await pg.textContent('#og-cfgline')) && /Çözünürlük anahtarı bulundu: 1920×1080/.test(await pg.textContent('#og-cfgline')), 'ayar dosyası seçildi; çözünürlük anahtarı 1920×1080 olarak bulundu');
ok(await pg.evaluate(() => /oyun şu an çalışıyor/i.test(document.querySelector('#og-runwarn') ? document.querySelector('#og-runwarn').textContent : '')), 'uyarı: oyun açıkken ayar değiştirilmeyeceği söylenir');

// oyun kapaninca ogret
procs = []; await pg.waitForFunction(() => !document.querySelector('#og-runwarn'), null, { timeout: 12000 });
setCfg(0, 0, '1920x1080'); await pg.click('#og-learn [data-p="low"]'); await pg.waitForSelector('#og-learn [data-p="low"].og-saved'); setCfg(3, 4, '1920x1080'); await pg.click('#og-learn [data-p="ultra"]'); await pg.waitForSelector('#og-learn [data-p="ultra"].og-saved');
ok(await pg.evaluate(() => document.querySelectorAll('#og-keys li').length) === 2, 'öğretme: Düşük + Ultra kaydedilince 2 kalite satırı öğrenildi (Shadow, Texture)');
setCfg(2, 2, '1920x1080'); const before = fs.readFileSync(cfg, 'utf8');

// manuel: onizle + uygula
await pg.selectOption('#og-preset', 'low'); await pg.selectOption('#og-res', '1280x720'); await pg.click('#og-preview'); await pg.waitForSelector('#og-plan .og-planbox');
ok(/3 satır değişecek/.test(await pg.textContent('#og-plan')) && fs.readFileSync(cfg, 'utf8') === before, 'önizleme: 3 satır gösterilir, dosyaya yazılmaz');
await pg.click('#og-doapply'); await pg.waitForFunction(() => /Uygulandı: 3 satır/.test(document.querySelector('#og-live').textContent), null, { timeout: 8000 });
const after = fs.readFileSync(cfg, 'utf8'); ok(/ShadowQuality=0/.test(after) && /TextureQuality=0/.test(after) && /Resolution=1280x720/.test(after) && /FOV=90/.test(after) && confirms === 1, 'uygula: dosya güncellendi, FOV korundu, host onay penceresi 1 kez açıldı');
await pg.waitForSelector('#og-backlist'); ok(await pg.evaluate(() => document.querySelectorAll('#og-backlist li').length) === 1 && /ORİJİNAL/.test(await pg.textContent('#og-backlist')), 'yedek listesi: orijinal yedek görünür');
await pg.click('#og-restore-orig'); await pg.waitForFunction(() => /Geri yüklendi: orijinal/.test(document.querySelector('#og-live').textContent), null, { timeout: 8000 }); ok(fs.readFileSync(cfg, 'utf8') === before, 'geri yükleme: orijinal dosya birebir döndü');

// hedef FPS modu
await pg.click('#og-apply .sm-seg [data-v="target"]'); await pg.waitForSelector('#og-fps'); await pg.fill('#og-fps', '60'); await pg.click('#og-est-btn'); await pg.waitForSelector('#og-est .cp-jdk');
ok(/Tahmini ön ayar/.test(await pg.textContent('#og-est')) && await pg.evaluate(() => document.querySelectorAll('#og-est li').length) >= 1, 'hedef FPS: donanıma göre öneri gerekçeleriyle görünür');
ok(/PresentMon bulunamadı/.test(await pg.textContent('#og-pmline')) && await pg.evaluate(() => document.querySelector('#og-measure-btn').disabled), 'PresentMon yok: durum görünür, “FPS ölç” kapalı');
ok(/PresentMon nasıl kurulur/.test(await pg.textContent('#og-pm')), 'PresentMon yönergesi açık');

// anti-cheat'li surec calisirken
procs = [{ pid: 9, name: 'RocketLeague.exe', path: 'C:\\x\\RocketLeague.exe' }]; await pg.waitForFunction(() => /Anti-cheat’li oyun algılandı/.test(document.querySelector('#og-now').textContent), null, { timeout: 12000 }); ok(true, 'anti-cheat’li süreç çalışınca uyarı şeridi “dokunulmaz” der');
ok(pg.errs.length === 0, 'sayfa hatası yok (' + pg.errs.join('|') + ')');

// duyarlilik + klavye + EN
for (const w of [900, 390]) { const p2 = await page({ width: w, height: 800 }); await p2.goto(URL + '#/oyunayar'); await p2.waitForSelector('#og-list .og-game'); ok(await p2.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), w + ' px: yatay taşma yok'); await p2.context().close(); }
await pg.focus('#og-list .og-game:not([disabled])'); ok(await pg.evaluate(() => document.activeElement.classList.contains('og-game')), 'klavye: oyun düğmesi odaklanabilir');
await pg.evaluate(() => localStorage.setItem('kovan.lang', 'en')); const pe = await page(); await pe.addInitScript(() => { try { localStorage.setItem('kovan.lang', 'en'); } catch (e) { /* yok */ } }); await pe.goto(URL + '#/oyunayar'); await pe.waitForSelector('#og-list .og-game'); await pe.waitForTimeout(300);
ok(/Game Tuner/.test(await pe.textContent('#side-nav')), 'English: kenar çubuğu “Game Tuner”'); ok(/Rescan/.test(await pe.textContent('#og-rescan')) && /Find settings files again/.test(await pe.textContent('#og-redetect')), 'English: düğmeler çevrildi');
fs.rmSync(tmp, { recursive: true, force: true }); await b.close(); console.log(bad ? '\n' + bad + ' BAŞARISIZ' : '\nTÜMÜ GEÇTİ'); process.exit(bad ? 1 : 0);
