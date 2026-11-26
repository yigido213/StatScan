// Blitz mac acilis bindirmesi sayfa testi (Playwright). Sahte statscanHost ile; gercek Electron penceresi DENENMEDI.
import { createRequire } from 'node:module'; const require = createRequire(import.meta.url); const { chromium } = require('playwright');
const { lolModule } = createRequire(import.meta.url)('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const html = lolModule.lolOverlayHtml(10);
const calls = []; let note = '<img src=x onerror="window.__xss=1">Q ile dürt';
const fake = `window.statscanHost={
 lolLive:async()=>({state:'ingame',classic:true,me:{champ:'Ahri'},matchup:{enemy:'Veigar',role:'mid'}}),
 lolChamps:async()=>({champs:[{id:'Ahri',name:'Ahri'},{id:'Veigar',name:'Veigar'}]}),
 lolIcon:async()=>({data:'data:image/png;base64,iVBORw0KGgo='}),
 lolMu:async(o)=>{(window.__calls=window.__calls||[]).push(o.rank);return o.rank==='iron'?{state:'norank'}:{state:'ok',wr:52.34,games:1234,patch:'14.1',items:{core:[{id:3089,name:'<b>Rabadon</b>',games:900}],boots:[{id:3020,name:'Büyücü Pabucu',games:800}]},note:${JSON.stringify(note)}}}};`;
const b = await chromium.launch(); const pg = await b.newPage(); const errs = []; pg.on('pageerror', (e) => errs.push(String(e))); const reqs = []; pg.on('request', (r) => { if (!/^data:|^about:/.test(r.url())) reqs.push(r.url()); });
await pg.setContent(html.replace('<script>', '<script>' + fake + '</script><script>')); await pg.waitForTimeout(400);
ok((await pg.textContent('#t')) === 'Ahri vs Veigar', 'başlık: iki şampiyon adı');
const txt = await pg.textContent('#body'); ok(/%52\.3/.test(txt) && /1234 oyun/.test(txt) && /yama 14\.1/.test(txt), 'oran/oyun/yama görünür');
ok(/<b>Rabadon<\/b>/.test(txt) && /Büyücü Pabucu/.test(txt), 'eşya adı düz metin (HTML işlenmez)');
ok(await pg.evaluate(() => !window.__xss && !document.querySelector('#body b+img, #body img[src="x"]')), 'not alanında XSS çalışmaz (metin olarak)');
ok(/Q ile dürt/.test(txt), 'kişisel not görünür');
await pg.click('#next'); await pg.waitForTimeout(150); ok((await pg.textContent('#rk')) === 'iron', 'rank ›: iron');
ok(/veri yok/.test(await pg.textContent('#body')), 'veri olmayan rankta açıklama');
await pg.click('#prev'); await pg.waitForTimeout(150); ok(/Tüm ranklar/.test(await pg.textContent('#rk')), 'rank ‹: tüm ranklara döner');
ok((await pg.evaluate(() => window.__calls)).join() === 'all,iron,all', 'lolMu doğru rankla çağrıldı');
await pg.click('#pin'); await pg.waitForTimeout(2300); ok(/Sabit/.test(await pg.textContent('#pin')) && /10 sn/.test(await pg.textContent('#cd')), 'sabitleyince geri sayım durur');
ok(reqs.length === 0, 'ağ isteği yok: ' + reqs.join(','));
ok(!errs.length, 'sayfa hatası yok ' + errs.join('|'));

// ---- Tab altin farki sayfasi
{ const gh = lolModule.lolGoldHtml(); const G = { state: 'ok', mySide: 'red', mine: { gold: 20125, kills: 8 }, enemy: { gold: 23950, kills: 16 }, diff: -3825, guessed: true, wikiUsed: true, ddragonUsed: true, lanes: [
  { role: 'top', mine: { name: 'Darius', gold: 4000, me: true }, enemy: { name: '<img src=x onerror="window.__xss2=1">', gold: 3500 }, diff: 500 }, { role: 'jungle', mine: { name: 'Sion', gold: 3000 }, enemy: { name: 'Ornn', gold: 4100 }, diff: -1100 } ] };
  const p2 = await b.newPage(); const e2 = []; const r2 = []; p2.on('pageerror', (e) => e2.push(String(e))); p2.on('request', (r) => { if (!/^data:|^about:/.test(r.url())) r2.push(r.url()); });
  await p2.setViewportSize({ width: 302, height: 422 });
  await p2.setContent(gh.replace('<script>', '<script>window.__gold=' + JSON.stringify(G) + ';window.statscanHost={lolGold:async()=>window.__gold,onLolGoldVisibility:f=>{window.__goldVisible=f}};</script><script>'));
  ok(!(await p2.locator('.hud').isVisible()), 'Tab: önceden hazırlanan pencerenin içeriği başlangıçta gizli');
  const shown = await p2.evaluate(() => { window.__goldVisible(true, window.__gold); return !document.body.hidden && document.querySelector('#gl').textContent === '20.125' && !document.getAnimations().length; });
  ok(shown, 'Tab: hazır veriler aynı karede animasyonsuz gösterilir');
  ok((await p2.locator('#ft').textContent()).includes('LoL Wiki · Data Dragon'), 'Tab: hesapta kullanılan eşya fiyatı kaynakları görünür');
  ok((await p2.textContent('#gl')) === '20.125' && (await p2.textContent('#gr')) === '23.950' && (await p2.textContent('#df')) === '3.825', 'altın sayfası: iki takım toplamı + ortada fark');
  ok((await p2.getAttribute('#lead', 'data-side')) === 'blue' && (await p2.textContent('#ar')) === '▶', 'altın sayfası: mavi öndeyken fark mavi + ok sağa');
  ok((await p2.textContent('#kl')) === '8' && (await p2.textContent('#kr')) === '16', 'altın sayfası: kill skoru');
  ok(await p2.evaluate(() => {
    const top = document.querySelector('[data-role="top"]');
    const mid = document.querySelector('[data-role="mid"]');
    return document.querySelector('.hud').getBoundingClientRect().bottom <= top.getBoundingClientRect().top &&
      document.querySelectorAll('.player-row').length === 5 && mid.children.length === 0 &&
      top.querySelector('.player-gold.red').textContent === '4.000' &&
      top.querySelector('.player-gold.blue').textContent === '3.500' &&
      top.querySelector('.player-diff').textContent === '◀ 500';
  }), 'altın sayfası: her oyuncu için ayrı rozet, boş hat diğer satırları kaydırmaz');
  await p2.evaluate(() => {
    const g = window.__gold;
    window.__gold = { ...g, mySide: 'blue', mine: g.enemy, enemy: g.mine, lanes: g.lanes.map(row => ({ ...row, mine: row.enemy, enemy: row.mine })) };
  });
  await p2.waitForSelector('#blueSeal.mine');
  ok(await p2.textContent('#gl') === '20.125' && await p2.textContent('#gr') === '23.950' &&
    await p2.textContent('#df') === '3.825', 'altın sayfası: mavi takımdayken de kırmızı sol, mavi sağ');
  ok(/tahmin/.test(await p2.textContent('#ft')) && /cepteki altın dahil değil/.test(await p2.textContent('#ft')), 'altın sayfası: tahmin + cepteki altın dahil değil notu');
  ok(!/innerHTML|eval\(|fetch\(|XMLHttpRequest/.test(gh) && !/cooldown|bekleme|flash|çarp|\bult\b/i.test(gh), 'altın sayfası: innerHTML/ağ yok, büyü sayacı yok');
  ok(r2.length === 0 && !e2.length, 'altın sayfası: ağ isteği ve sayfa hatası yok ' + r2.join(',') + e2.join('|'));
  if (process.env.SHOT) await p2.screenshot({ path: process.env.SHOT + '/gold.png', scale: 'css' });
  ok(await p2.evaluate(() => { window.__goldVisible(false, null); return document.body.hidden; }), 'Tab: bırakınca içerik hemen gizlenir');
  await p2.close(); }
await b.close(); console.log(bad ? '\n' + bad + ' BAŞARISIZ' : '\nTÜMÜ GEÇTİ'); process.exit(bad ? 1 : 0);
