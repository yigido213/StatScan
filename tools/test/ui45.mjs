// 4.5 arayuz testi (Playwright): sekmeler, Bilgi icerigi, taramada aciklama yok, aile blogu, pyc dugmesi
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright'); import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url)); const S = process.argv[2] || path.join(here, 'benign'); let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] }); const pg = await b.newPage({ viewport: { width: 1280, height: 900 } });
const errs = []; pg.on('pageerror', (e) => errs.push(e.message)); pg.on('console', (m) => m.type() === 'error' && errs.push(m.text()));
await pg.addInitScript(() => { window.__pyc = []; window.statscanHost = { desktop: true, storeGet: async () => null, storeSet: async () => ({ ok: true }), obfTools: async () => ({ tools: [{ id: 'pycdc', label: 'pycdc', kinds: ['pyc'], path: '/usr/bin/pycdc', via: 'PATH' }] }), obfSave: async () => ({ ok: true, dirToken: 't', dir: '/x', files: [] }), obfStartPyc: async (r) => { window.__pyc.push(r); return { id: 'j1', state: 'running', dirToken: 't' }; }, obfJob: async () => ({ state: 'done', message: 'ok', results: [{}], outDir: '/x/decompiled-pycdc' }), obfCancel: async () => ({ ok: true }) }; });
await pg.goto('file:///home/claude/statscan/app/StatScan.html#/statscan');
ok((await pg.textContent('#app-statscan h1')).includes('4.9'), 'başlıkta sürüm 4.9');
// tarama ekraninda aciklama yazilari yok
const scanText = await pg.evaluate(() => document.querySelector('#view-scan').innerText);
ok(!/sezgisel statik analiz|çalıştırılmaz|kanıtlamaz|her zararlıyı|Yerel · hiçbir/i.test(scanText.replace(/Yerel · hiçbir şey yüklenmez/, '')), 'tarama sekmesinde genel açıklama/uyarı paragrafı yok');
ok(await pg.evaluate(() => document.querySelector('#view-info').hidden), 'Bilgi sekmesi başlangıçta gizli');
await pg.click('#tab-info'); await pg.waitForTimeout(300);
ok(!(await pg.evaluate(() => document.querySelector('#view-info').hidden)) && await pg.evaluate(() => document.querySelector('#view-scan').hidden), 'Bilgi sekmesine geçince tarama gizli');
const info = await pg.evaluate(() => document.querySelector('#view-info').innerText);
ok(/çalıştırmadan inceler/.test(info) && /Her zararlıyı yakalamaz|kanıtlamaz|güvenli olduğunu/.test(info), 'Bilgi: gizlilik/sezgisel analiz açıklaması burada');
ok(await pg.evaluate(() => document.querySelectorAll('#info-methods-body tbody tr').length >= 25), 'Bilgi: yöntem kataloğu tablosu dolu');
ok(/Hiçbir modda yapılmayanlar/.test(info) && /Dijital imza GEÇERLİLİĞİ/.test(info), 'Bilgi: yapılmayanlar saklanmıyor');
ok(await pg.evaluate(() => document.querySelectorAll('#info-modes-body details').length >= 3), 'Bilgi: her mod için çalışan/atlanan listesi');
ok(await pg.evaluate(() => !!document.querySelector('#coverbody') && document.querySelector('#view-info').contains(document.querySelector('#cover')) && document.querySelector('#view-info').contains(document.querySelector('#srcbox'))), 'kapsam ve kaynaklar paneli Bilgi sekmesinde');
await pg.click('#tab-scan');
// tarama: sonuc kartinda genel uyari yok ama gercek durum (analiz defteri/kapsam) var
await pg.setInputFiles('#file', [S + '/pe_javainj.exe']); await pg.waitForSelector('.card', { timeout: 60000 }); await pg.waitForTimeout(2500);
const card = await pg.evaluate(() => document.querySelector('#results').innerText);
ok(!/Bu sezgisel bir statik analizdir|Bu sonuç sezgisel statik analizdir|toplu özettir/.test(card), 'sonuç kartında genel uyarı metni yok');
ok(/Analiz defteri/.test(card) && /Tarama kapsamı/.test(card), 'analiz defteri ve tarama kapsamı (gerçek durum) kartta kalıyor');
ok(await pg.evaluate(() => /Bulanık hash/.test(document.querySelector('#results').innerHTML)), 'analiz defterinde bulanık hash satırı');
await pg.setInputFiles('#file', [S + '/pe_javainj.exe', S + '/pe_chk.exe', S + '/pe_inject.exe', S + '/pe_chk_bad.exe', S + '/pe_lib.dll', S + '/pe_version.exe', S + '/pe_javainj.exe']); await pg.waitForFunction(() => /toplu tarama/i.test(document.querySelector("#results").innerText), null, { timeout: 90000 }); await pg.waitForTimeout(6000);
const bt = await pg.evaluate(() => document.querySelector('#results').innerText); ok(!/toplu özettir/.test(bt), 'toplu özette genel uyarı metni yok');
const fam = pg.locator('summary', { hasText: 'Aile / varyant benzerliği' }); ok(await fam.count() === 1, 'toplu özette aile bloğu'); await fam.click(); await pg.waitForTimeout(800);
const ft = await pg.evaluate(() => [...document.querySelectorAll('details')].find((d) => /Aile \/ varyant/.test(d.textContent)).innerText); ok(/dosyalık grup/.test(ft) && /birebir kopya/.test(ft), 'aile bloğu: aynı dosyanın iki kopyası birebir kopya olarak gruplandı');
// pyc dugmesi: PyInstaller ornegi icin obf
await pg.evaluate(() => { document.querySelector('#results').replaceChildren(); });
await pg.setInputFiles('#file', [S + '/pack/pyi_app.exe']); await pg.waitForSelector('.card', { timeout: 60000 }); await pg.waitForTimeout(2500);
const det = pg.locator('summary', { hasText: 'Obfuscation analizi ve açma' }).first(); await det.click(); await pg.waitForSelector('text=Python kaynağına çevir', { timeout: 30000 }).catch(() => {});
ok(await pg.locator('text=Python kaynağına çevir').count() >= 1, 'PyInstaller sonucunda .pyc → kaynak bölümü');
const btn = pg.getByRole('button', { name: /Çevir \(pycdc\)/ }); ok(await btn.count() === 1, 'kurulu pycdc için “Çevir” düğmesi'); await btn.click(); await pg.waitForTimeout(1800);
const req = await pg.evaluate(() => window.__pyc[0]); ok(req && req.tool === 'pycdc' && req.files.length >= 1 && req.files.every((f) => /\.pyc$/i.test(f.name) && f.bytes.length > 0), 'ana sürece .pyc baytları ve araç kimliği gitti (' + (req ? req.files.length : 0) + ' dosya)');
ok(/Tamamlandı/.test(await pg.evaluate(() => document.querySelector('#results').innerText)), 'iş durumu arayüzde gösterildi');
ok(errs.length === 0, 'konsol/sayfa hatası yok ' + JSON.stringify(errs.slice(0, 3)));
console.log(bad ? bad + ' TEST BAŞARISIZ' : 'tüm testler geçti'); await b.close(); process.exit(bad ? 1 : 0);
