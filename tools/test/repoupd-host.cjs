// Depodan dogrudan guncelleme (REPOMOD) testi: sahte GitHub (gercek git blob sha1'leri) + gercek dosya sistemi.
// `node tools/test/repoupd-host.cjs --live` ayrica GERCEK GitHub deposundan indirip yerel app/ ile bayt bayt karsilastirir (ag gerekir).
const fs = require('fs'); const os = require('os'); const path = require('path'); const crypto = require('crypto');
const { repoModule: R } = require('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-repo-')); let n = 0; const fresh = () => path.join(tmp, 'ud' + (++n));
const sha1 = (b) => crypto.createHash('sha1').update('blob ' + b.length + '\0').update(b).digest('hex');
const uid = (s) => crypto.createHash('sha1').update(s).digest('hex'); // yalniz benzersiz kimlik uretmek icin
const GOOD = { 'StatScan.html': '<html><script>var a=1;</script><script type="application/json">{"x":1}</script><script src="x.js"></script></html>', 'desktop/app.js': "'use strict'; module.exports = { start() {} };", 'desktop/host.js': "'use strict'; module.exports = {};", 'desktop/preload.js': "'use strict'; const x = 1;", 'dyn/statscan-dyn.js': "'use strict'; return;", 'desktop/assets/icon.png': Buffer.from([137, 80, 78, 71, 0, 1, 2]), 'dyn/README.md': '# x' };
const toBuf = (v) => (Buffer.isBuffer(v) ? v : Buffer.from(v));

// Sahte GitHub: depo durumu -> getJson/getBuf
function mkRepo(files) {
  const ents = Object.keys(files).sort().map((p) => { const b = toBuf(files[p]); return { path: p, mode: '100644', type: 'blob', sha: sha1(b), size: b.length }; });
  const appTree = uid('app:' + ents.map((e) => e.path + e.sha).join()); const rootT = uid('root:' + appTree); const commit = uid('commit:' + rootT);
  return { ents, appTree, rootT, commit, calls: [], raw: Object.fromEntries(Object.keys(files).map((p) => [p, toBuf(files[p])])) };
}
function netOf(repo, over) {
  over = over || {}; const R0 = '/repos/yigido213/StatScan';
  return {
    getJson: async (u) => { repo.calls.push(u); const p = u.replace('https://api.github.com', '');
      if (over.fail) throw new Error(over.fail);
      if (p === R0 + '/git/ref/heads/main') return { object: { sha: repo.commit } };
      if (p === R0 + '/git/commits/' + repo.commit) return { tree: { sha: repo.rootT }, message: 'Ilk satir\nikinci satir' };
      if (p === R0 + '/git/trees/' + repo.rootT) return { tree: [{ path: 'CLAUDE.md', type: 'blob', mode: '100644', sha: 'a'.repeat(40) }, { path: 'app', type: 'tree', mode: '040000', sha: repo.appTree }], truncated: false };
      if (p === R0 + '/git/trees/' + repo.appTree + '?recursive=1') { const t = repo.ents.map((e) => Object.assign({}, e)); return { tree: over.tree ? over.tree(t) : t, truncated: !!over.truncated }; }
      throw new Error('beklenmeyen: ' + p); },
    getBuf: async (u, max) => { repo.calls.push(u); const m = new RegExp('^https://raw\\.githubusercontent\\.com/yigido213/StatScan/' + repo.commit + '/app/(.+)$').exec(u); if (!m) throw new Error('beklenmeyen raw: ' + u);
      const rel = decodeURIComponent(m[1]); let b = repo.raw[rel]; if (!b) throw new Error('yok'); if (over.tamper === rel) b = Buffer.concat([b, Buffer.from('X')]); if (over.tamperSame === rel) { b = Buffer.from(b); b[0] = b[0] ^ 1; } if (b.length > max) throw new Error('buyuk'); return b; }
  };
}
const rej = async (p, re, m) => { try { await p; ok(false, m + ' (reddedilmedi)'); } catch (e) { ok(re.test(String(e.message)), m + ' -> ' + e.message); } };
const chk = (dataDir, net) => R.check(Object.assign({ dataDir }, net));
const bdirOf = (ud, tree) => path.join(ud, 'kovan-repo', 'builds', tree.slice(0, 12));

(async () => {
  // --- yardimcilar ---
  ok(R.sha1Blob(Buffer.from('hello\n')) === 'ce013625030ba8dba906f756967f9e9ca394464a', 'sha1Blob: git hash-object ile ayni (hello\\n)');
  const base = Object.keys(GOOD).map((p) => ({ path: p, type: 'blob', mode: '100644', sha: 'a'.repeat(40), size: 3 }));
  ok(R.validateTree(base.concat([{ path: 'desktop', type: 'tree', mode: '040000', sha: 'b'.repeat(40) }])).length === 7, 'validateTree: gecerli liste (agac girdileri atlanir)');
  const badTree = (extra, re, m) => { try { R.validateTree(base.concat([extra])); ok(false, m + ' (reddedilmedi)'); } catch (e) { ok(re.test(e.message) && e.message.indexOf(tmp) < 0, m + ' -> ' + e.message); } };
  const bl = (p, o) => Object.assign({ path: p, type: 'blob', mode: '100644', sha: 'a'.repeat(40), size: 1 }, o || {});
  badTree(bl('../x.js'), /yol/, 'yol gecisi (..) reddedilir'); badTree(bl('a\\b.js'), /yol/, 'ters bolu reddedilir'); badTree(bl('/etc/x.js'), /yol/, 'mutlak yol reddedilir'); badTree(bl('C:/x.js'), /yol/, 'surucu harfi reddedilir'); badTree(bl('.hidden.js'), /yol/, 'nokta ile baslayan ad reddedilir');
  badTree(bl('x.exe'), /izin verilmeyen/, '.exe reddedilir'); badTree(bl('l.js', { mode: '120000' }), /desteklenmeyen/, 'sembolik baglanti reddedilir'); badTree({ path: 'sub', type: 'commit', mode: '160000', sha: 'a'.repeat(40) }, /desteklenmeyen/, 'alt modul reddedilir');
  badTree(bl('big.js', { size: 9 * 1024 * 1024 }), /buyuk/, 'cok buyuk dosya reddedilir'); badTree(bl('STATSCAN.HTML'), /buyuk\/kucuk/, 'buyuk/kucuk harf cakismasi reddedilir');
  try { R.validateTree(base.filter((e) => e.path !== 'desktop/host.js')); ok(false, 'eksik gerekli dosya (reddedilmedi)'); } catch (e) { ok(/gerekli dosya eksik: desktop\/host\.js/.test(e.message), 'gerekli dosya eksikse reddedilir'); }
  try { R.validateTree(Array.from({ length: 80 }, (_, i) => bl('f' + i + '.js'))); ok(false, 'cok dosya (reddedilmedi)'); } catch (e) { ok(/buyuk|eksik/.test(e.message), 'cok fazla dosya reddedilir'); }
  const sx = (rel, s) => { try { R.syntaxCheck(rel, Buffer.from(s)); return true; } catch (e) { return false; } };
  ok(sx('a.js', 'return 1;') && !sx('a.js', 'var = ;') && sx('a.json', '{"a":1}') && !sx('a.json', '{a:}') && sx('a.html', '<script>var a=1</script>') && !sx('a.html', '<script>var = </script>') && sx('a.html', '<script type="module">import x from "y"</script>') && sx('a.html', '<script src="x"></script>'), 'syntaxCheck: js/json/html betik (module/src atlanir)');
  ok(sx('a.js', '#!/usr/bin/env node\nreturn 1;') && sx('a.js', '\uFEFF"use strict";') && !sx('a.js', '#!/x\nvar = ;'), 'syntaxCheck: shebang ve BOM kabul, ardindaki hata yine yakalanir');
  { let ran = false; global.__kovanRan = () => { ran = true; }; R.syntaxCheck('x.js', Buffer.from('global.__kovanRan();')); ok(!ran, 'syntaxCheck: kod CALISTIRILMAZ'); }

  // --- ilk kurulum ---
  let ud = fresh(); let repo = mkRepo(GOOD); let net = netOf(repo);
  ok(R.pickBoot({ dataDir: ud }) === null, 'pickBoot: kurulum yokken null (uygulamayla gelen calisir)');
  let r = await chk(ud, net); ok(r.status === 'staged' && r.commit === repo.commit && r.tree === repo.appTree && r.msg === 'Ilk satir', 'check: ilk kurulum hazirlandi, commit mesajinin ilk satiri geldi');
  ok(Object.keys(GOOD).every((p) => fs.readFileSync(path.join(bdirOf(ud, repo.appTree), p)).equals(toBuf(GOOD[p]))), 'check: tum dosyalar bayt bayt ayni yazildi');
  ok(!fs.readdirSync(path.join(ud, 'kovan-repo', 'builds')).some((x) => /^staging-/.test(x)), 'check: gecici staging klasoru kalmadi');
  ok(repo.calls.every((u) => /^https:\/\/(api\.github\.com|raw\.githubusercontent\.com)\//.test(u)) && repo.calls.some((u) => u.indexOf('/' + repo.commit + '/app/') > 0), "check: yalniz GitHub adresleri, dosyalar commit sha'sina sabit");
  repo.calls.length = 0; r = await chk(ud, net); ok(r.status === 'current' && repo.calls.length === 1, 'check: ayni commit -> current, yalniz 1 istek (' + repo.calls.length + ')');
  { const rp2 = Object.assign({}, repo, { commit: uid('baska-commit'), rootT: uid('baska-root'), calls: [] }); r = await chk(ud, netOf(rp2)); ok(r.status === 'current' && !rp2.calls.some((u) => /raw\./.test(u)), 'check: yalniz app/ disi degisti -> current, dosya indirilmedi'); }
  let b = R.pickBoot({ dataDir: ud }); ok(b && b.root === bdirOf(ud, repo.appTree) && b.info.tree === repo.appTree && b.info.commit === repo.commit, 'pickBoot: dogrulanmis yapi bulundu');
  R.markGood(ud, repo.appTree); ok(R.readState(ud).boot.tries === 0, 'markGood: sayac sifirlandi');

  // --- guncelleme: yeni surum + temizlik ---
  const V2 = Object.assign({}, GOOD, { 'desktop/host.js': "'use strict'; module.exports = { v: 2 };" }); const repo2 = mkRepo(V2); r = await chk(ud, netOf(repo2));
  ok(r.status === 'staged' && r.tree === repo2.appTree, 'check: yeni surum indirildi'); let stt = R.readState(ud); ok(stt.current.tree === repo2.appTree && stt.previous && stt.previous.tree === repo.appTree, 'durum: current=yeni, previous=eski');
  ok(fs.existsSync(bdirOf(ud, repo.appTree)) && fs.existsSync(bdirOf(ud, repo2.appTree)), 'yeni ve onceki yapi diskte');
  const repo3 = mkRepo(Object.assign({}, V2, { 'dyn/README.md': '# 3' })); await chk(ud, netOf(repo3)); ok(!fs.existsSync(bdirOf(ud, repo.appTree)) && fs.readdirSync(path.join(ud, 'kovan-repo', 'builds')).length === 2, 'temizlik: yalniz current + previous kalir');

  // --- geri alma ---
  b = R.pickBoot({ dataDir: ud }); ok(b && b.info.tree === repo3.appTree, 'pickBoot: 3. surum (acilis 1)'); b = R.pickBoot({ dataDir: ud }); ok(b && b.info.tree === repo3.appTree, 'pickBoot: 3. surum (acilis 2, markGood yok)');
  b = R.pickBoot({ dataDir: ud }); ok(b && b.info.tree === repo2.appTree, 'pickBoot: 2 basarisiz acilistan sonra ONCEKI surume donuldu'); stt = R.readState(ud); ok(stt.bad.includes(repo3.appTree) && stt.lastRollback && stt.lastRollback.tree === repo3.appTree && stt.previous === null, 'durum: bozuk surum kara listede, rollback kaydi var');
  r = await chk(ud, netOf(repo3)); ok(r.status === 'blocked', 'check: kara listedeki surum tekrar indirilmez (blocked)');
  r = await chk(ud, netOf(mkRepo(Object.assign({}, V2, { 'dyn/README.md': '# duzeltme' })))); ok(r.status === 'staged', 'check: duzeltilmis yeni surum gelince indirilir');
  ud = fresh(); repo = mkRepo(GOOD); await chk(ud, netOf(repo)); R.pickBoot({ dataDir: ud }); R.markGood(ud, repo.appTree); R.pickBoot({ dataDir: ud }); R.markGood(ud, repo.appTree); R.pickBoot({ dataDir: ud }); R.markGood(ud, repo.appTree); ok(R.pickBoot({ dataDir: ud }) !== null, 'markGood her seferinde sayaci sifirlar: saglikli surum asla geri alinmaz');

  // --- bozuk yapi / state ---
  ud = fresh(); repo = mkRepo(GOOD); await chk(ud, netOf(repo)); fs.appendFileSync(path.join(bdirOf(ud, repo.appTree), 'desktop', 'host.js'), '//x'); ok(R.pickBoot({ dataDir: ud }) === null && R.readState(ud).bad.includes(repo.appTree), 'pickBoot: diskte degistirilmis dosya -> kullanilmaz, geri alinir');
  ud = fresh(); repo = mkRepo(GOOD); await chk(ud, netOf(repo)); fs.rmSync(path.join(bdirOf(ud, repo.appTree), 'dyn', 'statscan-dyn.js')); ok(R.pickBoot({ dataDir: ud }) === null, 'pickBoot: eksik dosya -> null');
  ud = fresh(); fs.mkdirSync(path.join(ud, 'kovan-repo'), { recursive: true }); fs.writeFileSync(path.join(ud, 'kovan-repo', 'state.json'), '{bozuk'); ok(R.pickBoot({ dataDir: ud }) === null && R.status(ud).current === null, 'bozuk state.json -> null, cokme yok');
  ud = fresh(); fs.mkdirSync(path.join(ud, 'kovan-repo'), { recursive: true }); fs.writeFileSync(path.join(ud, 'kovan-repo', 'state.json'), JSON.stringify({ v: 1, current: { tree: 'x', commit: 'y', dir: '../../etc' } })); ok(R.pickBoot({ dataDir: ud }) === null, 'state.json icinde gecersiz dir (yol gecisi) yok sayilir');

  // --- saldiri / hata ---
  ud = fresh(); repo = mkRepo(GOOD);
  await rej(chk(ud, netOf(repo, { tamper: 'desktop/host.js' })), /eslesmedi: desktop\/host\.js/, 'boyutu degisen dosya reddedilir');
  await rej(chk(ud, netOf(repo, { tamperSame: 'desktop/app.js' })), /eslesmedi: desktop\/app\.js/, 'ayni boyutta degistirilmis dosya (sha1) reddedilir');
  ok(R.readState(ud).current === null && (!fs.existsSync(path.join(ud, 'kovan-repo', 'builds')) || fs.readdirSync(path.join(ud, 'kovan-repo', 'builds')).length === 0), 'reddedilince diske hicbir yapi yazilmaz');
  await rej(chk(ud, netOf(repo, { truncated: true })), /okunamadi/, 'kesik (truncated) agac reddedilir');
  await rej(chk(ud, netOf(repo, { tree: (t) => t.concat([bl('../evil.js')]) })), /yol/, 'agacta yol gecisi reddedilir');
  await rej(chk(ud, netOf(repo, { fail: 'GitHub istek siniri doldu; biraz sonra tekrar dene.' })), /istek siniri/, 'GitHub hata mesaji kullaniciya iletilir');
  await rej(chk(ud, netOf(mkRepo(Object.assign({}, GOOD, { 'desktop/host.js': 'var = ;' })))), /sozdizimi bozuk/, 'sozdizimi bozuk push INDIRILMEZ (kimsenin uygulamasi bozulmaz)'); ok(R.readState(ud).current === null, 'sozdizimi bozuk push: durum degismedi');
  await rej(chk(ud, netOf(mkRepo(Object.assign({}, GOOD, { 'StatScan.html': '<script>var = </script>' })))), /betik #1 sozdizimi/, 'StatScan.html icindeki bozuk betik reddedilir');
  await rej(chk(ud, netOf(mkRepo(Object.assign({}, GOOD, { 'x.exe': 'MZ' })))), /izin verilmeyen/, 'depoya .exe eklenirse reddedilir');

  // --- sifirlama ---
  ud = fresh(); repo = mkRepo(GOOD); await chk(ud, netOf(repo)); ok(R.status(ud).current.tree === repo.appTree, 'status: mevcut yapi'); ok(R.reset(ud) && R.pickBoot({ dataDir: ud }) === null && !fs.existsSync(path.join(ud, 'kovan-repo')), 'reset: yapilar silindi, pickBoot null');

  // --- kaynak taramasi ---
  { const src = fs.readFileSync(path.join(__dirname, '../../app/desktop/host.js'), 'utf8'); const m = /const REPOMOD = \(\(\) => \{[\s\S]*?\n\}\)\(\);/.exec(src); const body = m ? m[0] : '';
    ok(body.length > 1000 && !/child_process|(^|[^.\w])exec\(|execFile|spawn|\beval\(|new Function|\.runIn|shell\s*:/.test(body), 'kaynak: REPOMOD kabuk/exec/eval/betik calistirma icermez (vm yalniz derler; RegExp.exec serbest)');
    ok((body.match(/https:\/\/[a-z.]+/g) || []).every((u) => /^https:\/\/(api\.github\.com|raw\.githubusercontent\.com)$/.test(u)) && /HOSTS = new Set\(\['api\.github\.com', 'raw\.githubusercontent\.com'\]\)/.test(body), 'kaynak: yalniz api.github.com ve raw.githubusercontent.com');
    ok(/owner: 'yigido213', repo: 'StatScan', branch: 'main'/.test(body), 'kaynak: depo sabit (yigido213/StatScan, main)'); }

  // --- GERCEK GitHub (istege bagli) ---
  if (process.argv.includes('--live')) {
    const ud2 = fresh(); const t0 = Date.now(); const rr = await R.check({ dataDir: ud2 }); ok(rr.status === 'staged', 'CANLI: gercek depodan indirildi (' + rr.commit.slice(0, 7) + ', ' + (Date.now() - t0) + ' ms): ' + rr.msg);
    const dir = bdirOf(ud2, rr.tree); const meta = JSON.parse(fs.readFileSync(path.join(dir, '.kovan-build.json'), 'utf8')); const rels = Object.keys(meta.files);
    ok(rels.length >= 5 && rels.every((x) => R.sha1Blob(fs.readFileSync(path.join(dir, ...x.split('/')))) === meta.files[x].sha), 'CANLI: ' + rels.length + ' dosyanin hepsi diskte kendi git blob sha1 degeriyle eslesiyor');
    let gitTree = ''; try { gitTree = require('child_process').execFileSync('git', ['rev-parse', rr.commit + ':app'], { cwd: path.join(__dirname, '../..'), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch (e) { /* commit yerelde yok */ }
    if (gitTree) ok(gitTree === rr.tree, 'CANLI: REPOMOD agac kimligi git rev-parse <commit>:app ile AYNI (' + rr.tree.slice(0, 10) + ')'); else console.log('ATLA CANLI: commit yerelde yok (git fetch origin yap) — git agac karsilastirmasi atlandi');
    ok(R.pickBoot({ dataDir: ud2 }).info.tree === rr.tree, 'CANLI: pickBoot yeniden dogrulamadan gecti'); const again = await R.check({ dataDir: ud2 }); ok(again.status === 'current', 'CANLI: ikinci denetim current');
  }
  fs.rmSync(tmp, { recursive: true, force: true }); console.log(bad ? '\nBAZI TESTLER BASARISIZ: ' + bad : '\nTAMAM'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error('TEST COKTU', e); process.exit(2); });
