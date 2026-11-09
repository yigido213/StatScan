// Depodan guncelleme: GERCEK app.js'in acilis devri (repoHandOff) testi; Electron sahte modulle taklit edilir.
// Dogrulanan: dogrulanmis yapi varsa app.js ORADAN baslatilir; kapali ayar/yapi yoksa devretmez; bozuk yapi geri alinir; start() cokerse yeniden baslatma.
const fs = require('fs'); const os = require('os'); const path = require('path'); const crypto = require('crypto'); const Module = require('module');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-boot-')); let n = 0; const fresh = () => { const d = path.join(tmp, 'ud' + (++n)); fs.mkdirSync(d, { recursive: true }); return d; };
let UD = ''; const calls = { relaunch: 0, exit: 0 };
const stub = { app: { getPath: () => UD, requestSingleInstanceLock: () => true, on() {}, whenReady: () => ({ then() {} }), relaunch() { calls.relaunch++; }, exit() { calls.exit++; }, isPackaged: true }, BrowserWindow: function () {}, Menu: {}, dialog: {}, ipcMain: {}, shell: {}, session: {} };
const origLoad = Module._load; Module._load = function (req) { if (req === 'electron') return stub; return origLoad.apply(this, arguments); };
const APP = require('../../app/desktop/app.js'); const { repoModule: R } = require('../../app/desktop/host.js');
const sha1 = (b) => crypto.createHash('sha1').update('blob ' + b.length + '\0').update(b).digest('hex'); const uid = (s) => crypto.createHash('sha1').update(s).digest('hex');
const BASE = { 'StatScan.html': '<html></html>', 'desktop/host.js': "'use strict'; module.exports = {};", 'desktop/preload.js': "'use strict';", 'dyn/statscan-dyn.js': "'use strict';" };
async function stage(appJs) {
  const files = Object.assign({}, BASE, { 'desktop/app.js': appJs }); const ents = Object.keys(files).sort().map((p) => ({ path: p, mode: '100644', type: 'blob', sha: sha1(Buffer.from(files[p])), size: Buffer.byteLength(files[p]) }));
  const appTree = uid('a' + appJs); const rootT = uid('r' + appTree); const commit = uid('c' + rootT); const R0 = '/repos/yigido213/StatScan';
  const net = { getJson: async (u) => { const p = u.replace('https://api.github.com', ''); if (p === R0 + '/git/ref/heads/main') return { object: { sha: commit } }; if (p === R0 + '/git/commits/' + commit) return { tree: { sha: rootT }, message: 'm' };
      if (p === R0 + '/git/trees/' + rootT) return { tree: [{ path: 'app', type: 'tree', mode: '040000', sha: appTree }] }; if (p === R0 + '/git/trees/' + appTree + '?recursive=1') return { tree: ents }; throw new Error('?' + p); },
    getBuf: async (u) => Buffer.from(files[decodeURIComponent(u.split('/' + commit + '/app/')[1])]) };
  UD = fresh(); const r = await R.check(Object.assign({ dataDir: UD }, net)); return Object.assign({ ud: UD }, r);
}
const emptyRoot = () => fresh(); // dyn/ yok: uygulamayla gelen yola dusulurse require hatasi verir (devredilmedigini kanitlar)
const ctxOf = (extra) => Object.assign({ root: emptyRoot(), bundledRoot: emptyRoot(), updater: {}, version: '5.0.24', source: 'bundled', publicKey: '' }, extra || {});

(async () => {
  // 1) saglikli yapi: devredilir
  let s = await stage("'use strict'; module.exports = { start(ctx) { global.__got = ctx; } };"); global.__got = null; const c1 = ctxOf();
  APP.start(c1); const g = global.__got;
  ok(g && g.repoRoot && g.root === g.repoRoot && g.repoRoot.endsWith(path.join('builds', s.tree.slice(0, 12))), 'devir: app.js depodan indirilen yapidan baslatildi (ctx.root = yapi klasoru)');
  ok(g.repo && g.repo.tree === s.tree && g.repo.commit === s.commit && g.version === '5.0.24' && g.source === 'bundled' && g.updater === c1.updater && g.bundledRoot === c1.bundledRoot, 'devir: yukleyicinin ctx alanlari (version/source/updater/bundledRoot) aynen korundu, ctx.repo eklendi');
  ok(c1.repoRoot === undefined, 'devir: orijinal ctx nesnesi degistirilmedi (kopya gecildi)');
  ok(R.readState(s.ud).boot.tries === 1, 'devir: acilis sayaci 1 (markGood gelene kadar)');
  // 2) zaten depodan calisiyorsa tekrar devretmez (sonsuz dongu yok)
  global.__got = null; try { APP.start(ctxOf({ repoRoot: '/x', repo: { tree: s.tree, commit: s.commit } })); } catch (e) { /* uygulamayla gelen govde sahte ortamda cokebilir */ } ok(global.__got === null, 'devir: ctx.repoRoot varsa tekrar devredilmez (dongu yok)');
  // 3) update.repo=false -> devretmez
  fs.writeFileSync(path.join(s.ud, 'statscan-app.config.json'), JSON.stringify({ update: { repo: false } })); global.__got = null; let threw = false; try { APP.start(ctxOf()); } catch (e) { threw = true; } ok(global.__got === null && threw, 'ayar: update.repo=false iken devredilmez, uygulamayla gelen yola dusulur');
  fs.writeFileSync(path.join(s.ud, 'statscan-app.config.json'), '{bozuk'); global.__got = null; APP.start(ctxOf()); ok(global.__got !== null, 'ayar: bozuk ayar dosyasi varsayilani (depodan) kullanir');
  // 4) yapi yok -> devretmez
  UD = fresh(); global.__got = null; threw = false; try { APP.start(ctxOf()); } catch (e) { threw = true; } ok(global.__got === null && threw, 'yapi yoksa: uygulamayla gelen yola dusulur');
  // 5) app.js yuklenirken patlayan yapi -> geri alinir, uygulamayla gelen yola dusulur
  s = await stage("'use strict'; throw new Error('boom-load');"); UD = s.ud; threw = false; try { APP.start(ctxOf()); } catch (e) { threw = true; }
  ok(threw && R.readState(s.ud).bad.includes(s.tree) && R.readState(s.ud).current === null && /yuklenemedi/.test(R.readState(s.ud).lastRollback.why), 'bozuk yapi (yuklenirken hata): kara listeye alindi, geri alindi, uygulamayla gelen yola dusuldu');
  // 6) start() icinde patlayan yapi -> geri alinir + yeniden baslatilir
  s = await stage("'use strict'; module.exports = { start() { throw new Error('boom-start'); } };"); UD = s.ud; calls.relaunch = calls.exit = 0; APP.start(ctxOf());
  ok(calls.relaunch === 1 && calls.exit === 1 && R.readState(s.ud).bad.includes(s.tree), 'bozuk yapi (start hatasi): geri alindi + uygulama yeniden baslatilir');
  Module._load = origLoad; fs.rmSync(tmp, { recursive: true, force: true }); console.log(bad ? '\nBAZI TESTLER BASARISIZ: ' + bad : '\nTAMAM'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error('TEST COKTU', e); process.exit(2); });
