// obfuscation paneli arayuz testi: node ui-obf.mjs <dosya...>
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/');
const { chromium } = require('playwright');
const files = process.argv.slice(2);
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] }); const pg = await b.newPage({ viewport: { width: 1280, height: 900 }, acceptDownloads: true });
const errs = []; pg.on('pageerror', (e) => errs.push('pageerror ' + e.message)); pg.on('console', (m) => { if (m.type() === 'error') errs.push('console ' + m.text()); });
await pg.goto('file:///home/claude/statscan/app/StatScan.html'); await pg.setInputFiles('#file', files.slice(0, 1)); await pg.waitForSelector('.card', { timeout: 60000 }); await pg.waitForTimeout(800);
await pg.click('summary:has-text("Obfuscation analizi ve açma")'); await pg.waitForSelector('.ofile', { timeout: 30000 }); await pg.waitForTimeout(500);
console.log('ofile', await pg.$$eval('.ofile', (e) => e.length), 'yöntem', await pg.$$eval('.omethods .find', (e) => e.length), 'adım', await pg.$$eval('.dtl .ledger li', (e) => e.length));
console.log('özet:', await pg.$eval('.dtl .summ p', (e) => e.textContent));
await pg.click('.ofile button:has-text("Önizle") >> nth=0'); const prev = await pg.$eval('.ofile pre:not([hidden])', (e) => e.textContent); console.log('önizleme içerir URL:', prev.includes('http://evil.example/payload.exe'));
const [dl] = await Promise.all([pg.waitForEvent('download'), pg.click('button:has-text("Tüm çıktıları .zip indir")')]); console.log('zip:', dl.suggestedFilename()); await dl.saveAs('/tmp/claude-0/uit/out.zip');
await pg.screenshot({ path: process.env.SHOT || '/tmp/claude-0/uit/obf.png', fullPage: true });
console.log('errors', JSON.stringify(errs)); await b.close();
