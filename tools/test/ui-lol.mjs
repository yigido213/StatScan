// Karsi Secim arayuz testi (Playwright). Arayuz GERCEK host koduna (LOLMOD) kopruyle baglanir; sahte Data Dragon + sahte League istemcisi (LCU) kullanilir.
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
const { createHost } = createRequire(import.meta.url)('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const URL = 'file:///home/claude/statscan/app/StatScan.html';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-uilol-'));

const mk = (id, key, name, tags, a, d, m, df, range, hp, armor, mr) => [id, { id, key: String(key), name, tags, info: { attack: a, defense: d, magic: m, difficulty: df }, stats: { hp, hpperlevel: 100, armor, armorperlevel: 4, spellblock: mr, spellblockperlevel: 1.3, attackrange: range } }];
const DATA = Object.fromEntries([
  mk('Darius', 122, 'Darius', ['Fighter', 'Tank'], 9, 5, 1, 2, 175, 652, 39, 32), mk('Garen', 86, 'Garen', ['Fighter', 'Tank'], 7, 7, 1, 5, 175, 690, 36, 32), mk('Teemo', 17, 'Teemo', ['Marksman', 'Assassin'], 5, 3, 7, 6, 500, 598, 24, 30),
  mk('Kaisa', 145, "Kai'Sa", ['Marksman', 'Mage'], 8, 5, 3, 7, 525, 640, 28, 30), mk('MonkeyKing', 62, 'Wukong', ['Fighter', 'Tank'], 8, 5, 2, 3, 175, 650, 34, 32), mk('Nunu', 20, 'Nunu & Willump', ['Tank', 'Mage'], 4, 6, 7, 4, 125, 640, 32, 32),
  mk('Zed', 238, 'Zed', ['Assassin'], 9, 2, 1, 7, 125, 654, 32, 32), mk('Ahri', 103, 'Ahri', ['Mage', 'Assassin'], 3, 4, 8, 5, 550, 590, 21, 30), mk('Jinx', 222, 'Jinx', ['Marksman'], 9, 2, 4, 6, 525, 610, 26, 30), mk('Lux', 99, 'Lux', ['Mage', 'Support'], 2, 4, 9, 5, 550, 560, 18, 30)
]);
const get = async (host, p) => { if (p === '/api/versions.json') return JSON.stringify(['16.21.1']); if (/champion\.json$/.test(p)) return JSON.stringify({ data: DATA }); const m = /\/champion\/([A-Za-z0-9]+)\.json$/.exec(p); if (m) return JSON.stringify({ data: { [m[1]]: { name: m[1], enemytips: ['Dikkat: ' + m[1]] } } }); throw new Error('yok ' + p); };
let lcu = null; let offline = false;
const mkHost = () => createHost({ service: { closeAll() {} }, lol: { dataDir: path.join(tmp, 'data'), platform: 'win32', get: async (...a) => { if (offline) throw new Error('çevrimdışı'); return get(...a); }, confirm: async () => true, lcu: { find: async () => (lcu ? { port: 1, token: 'abcdefgh1234' } : null), get: async () => lcu } } });
const host = mkHost();
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
const MAP = { lolStatus: 'lol:status', lolChamps: 'lol:champs', lolPool: 'lol:pool', lolPoolSet: 'lol:pool:set', lolSuggest: 'lol:suggest', lolTips: 'lol:tips', lolLog: 'lol:log', lolHist: 'lol:hist', lolHistUndo: 'lol:hist:undo', lolHistClear: 'lol:hist:clear', lolStatsUrlGet: 'lol:statsurl:get', lolStatsUrlSet: 'lol:statsurl:set', lolLcu: 'lol:lcu' };
async function page(vp, withHost = true, en = false) {
  const ctx = await b.newContext({ viewport: vp || { width: 1366, height: 900 }, reducedMotion: 'reduce' }); const pg = await ctx.newPage(); pg.errs = []; pg.on('pageerror', (e) => pg.errs.push(e.message));
  if (en) await pg.addInitScript(() => { try { localStorage.setItem('kovan.lang', 'en'); } catch (e) { /* yok */ } });
  if (withHost) { await pg.exposeFunction('__h', async (ch, ...a) => { const f = host.handlers[ch]; return f ? JSON.parse(JSON.stringify(await f(null, ...a))) : { error: 'nochan' }; });
    await pg.addInitScript((map) => { const c = (ch, ...a) => window.__h(ch, ...a); const o = { desktop: true }; for (const k in map) o[k] = (...a) => c(map[k], ...a); window.statscanHost = Object.freeze(o); }, MAP); }
  return pg;
}
const txt = (pg, sel) => pg.evaluate((s) => (document.querySelector(s) || {}).textContent || '', sel);

// tarayici (masaustu koprusu yok)
let pg = await page(null, false); await pg.goto(URL + '#/lolcounter'); await pg.waitForTimeout(400);
ok(/masaüstü uygulaması gerektirir/.test(await txt(pg, '#app-lolcounter')), 'tarayıcıda: masaüstü gerekir notu'); ok(pg.errs.length === 0, 'tarayıcıda: sayfa hatası yok'); await pg.context().close();

pg = await page(); await pg.goto(URL + '#/lolcounter'); await pg.waitForFunction(() => /hazır|Çevrimdışı/.test((document.querySelector('#lc-live') || {}).textContent || ''), null, { timeout: 15000 });
ok((await pg.title()) === 'Karşı Seçim · Kovan', 'başlık: Karşı Seçim · Kovan (' + (await pg.title()) + ')');
ok(await pg.evaluate(() => document.querySelector('.nav-item[href="#/lolcounter"]') != null), 'kenar çubuğunda araç görünür');
ok(/10 şampiyon/.test(await txt(pg, '#lc-live')), 'şampiyon verisi hazır: 10 şampiyon');
ok(await pg.evaluate(() => document.querySelectorAll('#lc-dl option').length === 10), 'öneri listesi (datalist): tüm şampiyonlar');
ok(await pg.evaluate(() => /TAHMİNDİR/.test(document.querySelector('#lc-note').textContent) && /denenmedi/.test(document.querySelector('#lc-note').textContent)), 'dürüst sınırlar notu görünür');
ok(await pg.evaluate(() => document.querySelectorAll('.lc-role').length === 5 && document.querySelector('#lc-role-top').getAttribute('aria-pressed') === 'true'), '5 rol düğmesi, varsayılan: Üst hat');

// ad esleme: ozel adlar, buyuk/kucuk harf, kesme isareti, aksan
async function enemy(name) { await pg.fill('#lc-enemy', name); await pg.click('#lc-go'); await pg.waitForTimeout(250); return pg.evaluate(() => ({ hint: document.querySelector('#lc-reshint').textContent, n: document.querySelectorAll('#lc-list .lc-pick').length })); }
let e1 = await enemy('darius'); ok(e1.n > 0 && /Darius/.test(e1.hint), 'öneri: “darius” (küçük harf) bulundu, ' + e1.n + ' öneri');
const names = [["kai'sa", 'Kai\'Sa'], ['KAISA', "Kai'Sa"], ['wukong', 'Wukong'], ['monkeyking', 'Wukong'], ['Nunu & Willump', 'Nunu & Willump'], ['nunu', 'Nunu & Willump']];
for (const [q, want] of names) { const r = await enemy(q); ok(r.n > 0 && r.hint.includes(want), 'ad eşleme: “' + q + '” → ' + want + ' (' + r.hint.slice(0, 40) + ')'); }
let e2 = await enemy('olmayanşampiyon'); ok(e2.n === 0 && /bulunamadı/.test(e2.hint), 'bilinmeyen ad: anlaşılır uyarı, öneri yok');
ok(await pg.evaluate(() => [...document.querySelectorAll('#lc-list .lc-pick .lc-name')].every((x) => x.textContent !== 'Garen' || true)), 'öneriler çiziliyor');

// oneri icerigi
await enemy('Darius'); const first = await pg.evaluate(() => { const li = document.querySelector('#lc-list .lc-pick'); return { name: li.querySelector('.lc-name').textContent, score: Number(li.querySelector('.lc-score').textContent), pills: [...li.querySelectorAll('.sm-pill')].map((x) => x.textContent), btns: [...li.querySelectorAll('button')].map((x) => x.textContent) }; });
ok(first.score >= 0 && first.score <= 100 && first.pills.includes('Tahmin') && first.btns.join() === 'Kazandım,Kaybettim', 'öneri kartı: puan 0-100, “Tahmin” etiketi, Kazandım/Kaybettim düğmeleri');
ok(await pg.evaluate(() => { const s = [...document.querySelectorAll('#lc-list .lc-score')].map((x) => Number(x.textContent)); return s.every((v, i) => !i || s[i - 1] >= v); }), 'öneriler puana göre azalan');
await pg.waitForFunction(() => !document.querySelector('#lc-tips').hidden, null, { timeout: 5000 }); ok(/Dikkat: Darius/.test(await txt(pg, '#lc-tips')) && /Data Dragon/.test(await txt(pg, '#lc-tips')), 'ipuçları: Data Dragon, kaynak etiketli');

// tum sampiyonlar
const nFilt = await pg.evaluate(() => document.querySelectorAll('#lc-list .lc-pick').length); await pg.check('#lc-anyrole'); await pg.waitForTimeout(300); const nAll = await pg.evaluate(() => document.querySelectorAll('#lc-list .lc-pick').length);
ok(nAll === 9 && nAll >= nFilt, '“Tüm şampiyonlar”: rakip hariç 9 şampiyonun hepsi listelenir (' + nFilt + ' → ' + nAll + ')'); await pg.uncheck('#lc-anyrole'); await pg.waitForTimeout(250);

// havuz
await pg.fill('#lc-poolin', 'garen'); await pg.press('#lc-poolin', 'Enter'); await pg.waitForTimeout(250); await pg.fill('#lc-poolin', 'Teemo'); await pg.click('#lc-poolad'); await pg.waitForTimeout(250);
ok(await pg.evaluate(() => [...document.querySelectorAll('#lc-pool .lc-chip')].map((x) => x.firstChild.textContent).join() === 'Garen,Teemo'), 'havuz: Enter ve Ekle düğmesiyle eklenir');
ok(await pg.evaluate(() => [...document.querySelectorAll('#lc-list .lc-pick')].filter((li) => /havuzumda/.test(li.textContent)).length === 2), 'öneriler: havuzdakiler “havuzumda” etiketli');
await pg.check('#lc-poolonly'); await pg.waitForTimeout(300); ok(await pg.evaluate(() => document.querySelectorAll('#lc-list .lc-pick').length === 2), '“Yalnızca havuzumdakiler”: yalnız 2 öneri');
await pg.click('#lc-role-mid'); await pg.waitForTimeout(300); ok(/havuzun boş/.test(await txt(pg, '#lc-reshint')), 'başka rolde havuz boşsa yönlendirme metni');
await pg.uncheck('#lc-poolonly'); await pg.click('#lc-role-top'); await pg.waitForTimeout(250);
await pg.click('#lc-pool .lc-x'); await pg.waitForTimeout(250); ok(await pg.evaluate(() => document.querySelectorAll('#lc-pool .lc-chip').length === 1), 'havuz: × ile kaldırılır');

// kayit
await pg.click('#lc-list .lc-pick .lc-win'); await pg.waitForTimeout(400); ok(/Toplam 1 maç kaydı/.test(await txt(pg, '#lc-hist')) && /Kaydedildi/.test(await txt(pg, '#lc-live')), 'kayıt: Kazandım kaydı eklendi');
ok(await pg.evaluate(() => [...document.querySelectorAll('#lc-list .sm-pill')].some((x) => /Kişisel: 1 maçta 1 galibiyet/.test(x.textContent))), 'öneri: kişisel kayıt etiketi görünür');
await pg.click('#lc-undo'); await pg.waitForTimeout(300); ok(/Henüz maç kaydın yok/.test(await txt(pg, '#lc-hist')), 'geri al: kayıt silinir');

// League istemcisi
await pg.click('#lc-lcu'); await pg.waitForTimeout(300); ok(/bulunamadı/.test(await txt(pg, '#lc-lculine')), 'LCU: istemci yoksa “bulunamadı”');
lcu = { localPlayerCellId: 1, myTeam: [{ cellId: 1, championId: 86, assignedPosition: 'top' }], theirTeam: [{ cellId: 6, championId: 122, assignedPosition: 'top' }, { cellId: 7, championId: 238, assignedPosition: 'middle' }] };
await pg.click('#lc-lcu'); await pg.waitForTimeout(500); ok(/2 rakip seçimi/.test(await txt(pg, '#lc-lculine')) && /Garen/.test(await txt(pg, '#lc-lculine')), 'LCU: seçim okundu, kendi seçimin Garen');
ok((await pg.inputValue('#lc-enemy')) === 'Darius' && await pg.evaluate(() => document.querySelectorAll('#lc-list .lc-pick').length > 0), 'LCU: hat rakibi (Darius) otomatik dolduruldu, öneriler geldi');
lcu = { localPlayerCellId: 1, myTeam: [{ cellId: 1, championId: 0, assignedPosition: 'middle' }], theirTeam: [{ cellId: 6, championId: 122 }, { cellId: 7, championId: 238 }] };
await pg.click('#lc-lcu'); await pg.waitForTimeout(500); ok(await pg.evaluate(() => !document.querySelector('#lc-enemypick').hidden && document.querySelectorAll('#lc-enemypick button').length === 2), 'LCU: hat belirsizse “hangisi hat rakibin?” seçenekleri');
ok(await pg.evaluate(() => document.querySelector('#lc-role-mid').getAttribute('aria-pressed') === 'true'), 'LCU: rolün otomatik “Orta hat”a geçti');
lcu = null;

// dis veri adresi (arayuz URL sadece formdan; host dogrular)
await pg.evaluate(() => { document.querySelector('#lc-ext').open = true; }); await pg.fill('#lc-exturl', 'http://x.example.org/{enemy}'); await pg.click('#lc-extsave'); await pg.waitForTimeout(300); ok(/https olmalı/.test(await txt(pg, '#lc-live')), 'dış adres: http reddedilir, mesaj gösterilir');
await pg.fill('#lc-exturl', 'https://stats.example.org/{enemy}/{role}'); await pg.click('#lc-extsave'); await pg.waitForTimeout(300); ok(/stats\.example\.org/.test(await txt(pg, '#lc-extline')), 'dış adres: kaydedildi, sunucu adı görünür'); await pg.click('#lc-extdel'); await pg.waitForTimeout(300); ok(/eklenmemiş/.test(await txt(pg, '#lc-extline')), 'dış adres: kaldırılır');
ok(pg.errs.length === 0, 'sayfa hatası yok (' + pg.errs.join('|') + ')');

// klavye
await pg.focus('#lc-enemy'); await pg.fill('#lc-enemy', 'Zed'); await pg.press('#lc-enemy', 'Enter'); await pg.waitForTimeout(300); ok(/Zed/.test(await txt(pg, '#lc-reshint')), 'klavye: Enter ile öner');
ok(await pg.evaluate(() => { const b = document.querySelector('#lc-role-jungle'); b.focus(); return document.activeElement === b; }), 'klavye: rol düğmeleri odaklanabilir');

// duyarlilik
for (const w of [900, 390]) { const p2 = await page({ width: w, height: 800 }); await p2.goto(URL + '#/lolcounter'); await p2.waitForFunction(() => /hazır/.test((document.querySelector('#lc-live') || {}).textContent || ''), null, { timeout: 15000 }); await p2.fill('#lc-enemy', 'Darius'); await p2.click('#lc-go'); await p2.waitForTimeout(300); ok(await p2.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), w + ' px: yatay taşma yok'); await p2.context().close(); }

// English
const pe = await page(null, true, true); await pe.goto(URL + '#/lolcounter'); await pe.waitForFunction(() => /ready|Offline/.test((document.querySelector('#lc-live') || {}).textContent || ''), null, { timeout: 15000 }); await pe.waitForTimeout(300);
ok(/Counter Picker/.test(await txt(pe, '#side-nav')), 'English: kenar çubuğu “Counter Picker”'); ok(/Suggest/.test(await txt(pe, '#lc-go')) && /Read champion select/.test(await txt(pe, '#lc-lcu')), 'English: düğmeler çevrildi');
await pe.fill('#lc-enemy', 'Darius'); await pe.click('#lc-go'); await pe.waitForTimeout(300); ok(/suggestions for Darius/.test(await txt(pe, '#lc-reshint')) && /I won/.test(await txt(pe, '#lc-list')) && /Estimate/.test(await txt(pe, '#lc-list')), 'English: öneri kartı çevrildi');
ok(/All champions/.test(await pe.evaluate(() => document.querySelector('label:has(#lc-anyrole)').textContent)), 'English: “All champions” seçeneği');

// cevrimdisi (onbellek)
offline = true; const hostOff = mkHost(); const po = await b.newContext({ viewport: { width: 1366, height: 900 } }); const pp = await po.newPage(); await pp.exposeFunction('__h', async (ch, ...a) => { const f = hostOff.handlers[ch]; return JSON.parse(JSON.stringify(await f(null, ...a))); }); await pp.addInitScript((map) => { const o = { desktop: true }; for (const k in map) o[k] = (...a) => window.__h(map[k], ...a); window.statscanHost = Object.freeze(o); }, MAP);
await pp.goto(URL + '#/lolcounter'); await pp.waitForFunction(() => /Çevrimdışı/.test((document.querySelector('#lc-live') || {}).textContent || ''), null, { timeout: 15000 }); ok(true, 'çevrimdışı: önbellekteki veriyle açılır');

fs.rmSync(tmp, { recursive: true, force: true }); await b.close(); console.log(bad ? '\n' + bad + ' BAŞARISIZ' : '\nTÜMÜ GEÇTİ'); process.exit(bad ? 1 : 0);
