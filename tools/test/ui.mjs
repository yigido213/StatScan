// UI gorsel/islevsel kontrol: node ui.mjs <dosya> <cikti.png> [genislik]
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/');
const { chromium } = require('playwright');
const [file, out, w = '1280'] = process.argv.slice(2);
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] }); const pg = await b.newPage({ viewport: { width: +w, height: 900 } });
const errs = []; pg.on('pageerror', (e) => errs.push('pageerror ' + e.message)); pg.on('console', (m) => { if (m.type() === 'error') errs.push('console ' + m.text()); });
await pg.goto('file:///home/claude/statscan/app/StatScan.html'); await pg.setInputFiles('#file', file); await pg.waitForSelector('.card', { timeout: 60000 }); await pg.waitForTimeout(1500);
await pg.evaluate(() => document.querySelectorAll('details.dtl').forEach((d) => (d.open = true)));
await pg.waitForTimeout(800);
const hasHex = await pg.$('.hexv .hr'); const nLed = await pg.$$eval('.ledger li', (e) => e.length); const nAtt = await pg.$$eval('.chip.att', (e) => e.length); const nBasis = await pg.$$eval('.basis', (e) => e.length);
if (process.env.TABS) { for (const t of ['Entropi haritası', 'Dizeler']) { await pg.click('.itabs button:has-text("' + t + '")'); await pg.waitForTimeout(700); } const nStr = await pg.$$eval('.strrow', (e) => e.length); const nEnt = await pg.$$eval('.entsvg rect', (e) => e.length); console.log('dize', nStr, 'entropi çubuğu', nEnt); if (nStr) { await pg.click('.strrow >> nth=0'); await pg.waitForTimeout(500); console.log('hl', (await pg.$$('.hexv .hl')).length); } }
const loc = await pg.$('.chips2 button[title="Hex görünümünde aç"]'); if (loc) { await loc.click(); await pg.waitForTimeout(500); console.log('loc→hl', (await pg.$$('.hexv .hl')).length); }
console.log('hex', !!hasHex, 'ledger', nLed, 'att', nAtt, 'basis', nBasis, 'errors', JSON.stringify(errs));
await pg.screenshot({ path: out, fullPage: true }); await b.close();
