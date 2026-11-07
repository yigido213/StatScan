// Blitz mac acilis bindirmesi sayfa testi (Playwright). Sahte statscanHost ile; gercek Electron penceresi DENENMEDI.
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
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
await b.close(); console.log(bad ? '\n' + bad + ' BAŞARISIZ' : '\nTÜMÜ GEÇTİ'); process.exit(bad ? 1 : 0);
