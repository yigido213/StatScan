'use strict';
// RAM Analizi host testi (MEMMOD + 102-memscan.js bulgu motoru). SAHTE vol (tools/test/mem/fake-vol.js) ile; gerçek Volatility ya da gerçek Windows dökümü KULLANILMAZ.
// Çalıştır: node tools/test/mem-host.cjs
const fs = require('fs'); const os = require('os'); const path = require('path'); const crypto = require('crypto');
const { createHost, memModule: M } = require(path.join(__dirname, '../../app/desktop/host.js'));
const engine = require(path.join(__dirname, '../../app/dyn/statscan-dyn.js')).loadEngine(path.join(__dirname, '../../app/StatScan.html'));
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-memtest-')); const bin = path.join(tmp, 'bin'); fs.mkdirSync(bin);
const FAKE = path.join(__dirname, 'mem/fake-vol.js'); const FIX = path.join(__dirname, 'mem/fixtures.json'); const LOG = path.join(tmp, 'argv.log');
const sh = (p, body) => { fs.writeFileSync(p, '#!/bin/sh\n' + body + '\n'); fs.chmodSync(p, 0o755); };
sh(path.join(bin, 'vol'), 'exec "' + process.execPath + '" "' + FAKE + '" "$@"');
const dump = path.join(tmp, 'sahte.raw'); fs.writeFileSync(dump, crypto.randomBytes(4096)); fs.utimesSync(dump, new Date(2020, 1, 1), new Date(2020, 1, 1));
const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex'); const dumpSha = sha(dump); const dumpMt = fs.statSync(dump).mtimeMs;
process.env.FAKE_FIX = FIX; process.env.FAKE_LOG = LOG;
const argvLog = () => { try { return fs.readFileSync(LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((a) => !a.includes('-h')); } catch (e) { return []; } }; /* -h: Volatility bulma yoklaması, analiz çağrısı değil */
let confirms = []; let confirmAns = false;
function mkHost(extra) { return createHost(Object.assign({ service: { closeAll() {} }, sys: false, compile: false, mem: Object.assign({ onlyDirs: [bin], engine, chooseDump: async () => dump, chooseVol: async () => path.join(bin, 'vol'), confirm: async (o) => { confirms.push(o); return confirmAns; } }, extra || {}) }, {})); }
const wait = async (H, id, ms) => { const t0 = Date.now(); for (;;) { const j = await H.handlers['mem:job'](null, id); if (j.state !== 'running' || Date.now() - t0 > (ms || 20000)) return j; await sleep(40); } };
const call = (H, ch, ...a) => H.handlers[ch](null, ...a);

(async () => {
  // ---------- saf yardımcılar ----------
  ok(M.parseJson('\n[\n {"a":1}\n]\n')[0].a === 1 && M.parseJson('garbage') === null && M.parseJson('\n{"x":2}')[0].x === 2, 'parseJson: baştaki boş satırı atlar, bozuk girdide null');
  ok(M.flat([{ a: 1, __children: [{ a: 2, __children: [{ a: 3 }] }] }]).map((r) => r.a + ':' + r.__depth).join() === '1:0,2:1,3:2', 'flat: __children ağacı düzleşir (derinlikli)');
  ok(M.classify('Unsatisfied requirement plugins.X.kernel.symbol_table_name\nA symbol table requirement was not fulfilled', true).code === 'symbols' && /çevrimdışı/.test(M.classify('A symbol table requirement\nUnable to validate the plugin requirements: symbol', true).message), 'classify: sembol hatası → net çevrimdışı mesajı');
  ok(M.classify('A translation layer requirement was not fulfilled', true).code === 'layer', 'classify: geçersiz döküm');
  ok(M.LAYERS.map((l) => l.id).join() === 'info,pslist,psscan,pstree,cmdline,dlllist,ldrmodules,malfind,netscan,svcscan,modules,driverscan,filescan,handles' && M.LAYERS.filter((l) => l.heavy).map((l) => l.id).join() === 'filescan,handles' && !M.DEFAULT_IDS.includes('filescan') && !M.DEFAULT_IDS.includes('handles'), 'katman listesi: 12 varsayılan + filescan/handles isteğe bağlı (ağır)');
  ok(M.LAYERS.every((l) => l.names.every((n) => /^windows\.[a-z.]+$/.test(n))), 'eklenti adları beyaz liste biçiminde (yalnızca windows.*)');
  const src = fs.readFileSync(path.join(__dirname, '../../app/desktop/host.js'), 'utf8'); const mem = src.slice(src.indexOf('const MEMMOD'), src.indexOf('function riskyList'));
  ok(!/shell:\s*true/.test(mem) && !/\bcp\.(exec|execSync|execFile|execFileSync)\(/.test(mem) && !/require\('child_process'\)\.exec/.test(mem) && /shell: false/.test(mem), 'MEMMOD: shell yok (spawn/spawnSync + shell:false + argüman dizisi)');

  // ---------- dosya doğrulama ----------
  const dd = (p) => M.validDump(p); const empty = path.join(tmp, 'bos.raw'); fs.writeFileSync(empty, ''); const txt = path.join(tmp, 'a.txt'); fs.writeFileSync(txt, 'x');
  ok(dd(dump).ok && dd(dump).size === 4096, 'validDump: geçerli .raw kabul');
  ok(dd('rel/x.raw').error && dd(tmp).error && dd(path.join(tmp, 'yok.raw')).error && dd(empty).error && dd(txt).error && dd(42).error, 'validDump: göreli yol / klasör / yok / boş / yanlış uzantı / tür reddedilir');
  for (const e of ['raw', 'mem', 'dmp', 'vmem', 'lime']) { const f = path.join(tmp, 'x.' + e.toUpperCase()); fs.writeFileSync(f, 'y'); if (!dd(f).ok) ok(false, 'uzantı ' + e); } ok(true, 'validDump: .raw .mem .dmp .vmem .lime (büyük harf dahil) kabul');

  // ---------- Volatility bulma ----------
  let r = M.findVol({ onlyDirs: [bin] }); ok(r.found && r.best.kind === 'path' && r.best.version === '2.28.2-fake', 'findVol: PATH’teki vol bulunur, sürüm okunur (' + (r.best && r.best.version) + ')');
  r = M.findVol({ onlyDirs: [] }); ok(!r.found && r.tried.length === 0, 'findVol: kurulu değilse found=false (yükleme yönergesi UI’da)');
  const notvol = path.join(tmp, 'notvol'); sh(notvol, 'echo hello'); r = M.findVol({ onlyDirs: [], userPath: notvol }); ok(!r.found && r.tried[0] && !r.tried[0].ok, 'findVol: Volatility olmayan dosya doğrulanamaz');
  r = M.findVol({ onlyDirs: [], userPath: path.join(bin, 'vol') }); ok(r.found && r.best.kind === 'user', 'findVol: kullanıcının seçtiği yol kullanılır');
  const bin2 = path.join(tmp, 'bin2'); fs.mkdirSync(bin2); sh(path.join(bin2, 'python3'), 'if [ "$1" = "-c" ]; then case "$2" in *volatility3*) shift 2; exec "' + process.execPath + '" "' + FAKE + '" "$@";; esac; fi; exit 3');
  r = M.findVol({ onlyDirs: [bin2] }); ok(r.found && r.best.kind === 'module' && r.best.pre[0] === '-c' && /volatility3\.cli/.test(r.best.pre[1]) && !/-m/.test(r.best.pre.join(' ')), 'findVol: Python modül yolu (-c "from volatility3.cli import main"; "-m volatility3" kullanılmaz)');

  // ---------- araçlar / dosya seçimi (arayüz yol GÖNDEREMEZ) ----------
  let H = mkHost(); let t = await call(H, 'mem:tools'); ok(t.found && t.version === '2.28.2-fake' && t.layers.length === 14 && t.install.length >= 3, 'mem:tools: sürüm + katmanlar + kurulum yönergesi');
  const Hno = mkHost({ onlyDirs: [] }); t = await call(Hno, 'mem:tools'); ok(!t.found && /pip install volatility3/.test(t.install.join(' ')), 'mem:tools: Volatility yoksa kurulum yönergesi (pip install volatility3)');
  let s = await call(Hno, 'mem:start', { layers: ['pslist'] }); ok(s.error && /seç/.test(s.message), 'start: dosya seçilmeden reddedilir');
  const c0 = await call(H, 'mem:chooseDump'); ok(c0.ok && c0.name === 'sahte.raw' && c0.size === 4096 && !('path' in c0), 'chooseDump: yalnız ad/boyut döner, YOL arayüze verilmez');
  s = await call(Hno, 'mem:chooseDump'); s = await call(Hno, 'mem:start', { layers: ['pslist'] }); ok(s.error && s.needVol && /Volatility 3 bulunamadı/.test(s.message), 'start: Volatility yoksa needVol + net mesaj');
  const bogus = path.join(tmp, 'baska.raw'); fs.writeFileSync(bogus, 'SECRET'); fs.mkdirSync(path.join(tmp, 'c'), { recursive: true });
  confirms = []; fs.writeFileSync(LOG, ''); s = await call(H, 'mem:start', { layers: ['pslist'], file: bogus, path: bogus, args: ['--evil'], plugin: 'windows.hashdump' }); const j0 = await wait(H, s.id);
  const a0 = argvLog(); ok(a0.length === 1 && a0[0].includes(dump) && !a0[0].includes(bogus) && !a0[0].includes('--evil') && a0[0][a0[0].length - 1] === 'windows.pslist', 'start: arayüzün yolu/argümanı/eklentisi YOK SAYILIR (-f yalnız host’un seçtiği dosya)');
  ok(a0[0].includes('--offline') && a0[0].includes('-r') && a0[0][a0[0].indexOf('-r') + 1] === 'json' && a0[0].includes('-q') && confirms.length === 0, 'start: varsayılan AĞ KAPALI (--offline), -r json, onay penceresi gerekmedi');
  for (const bad2 of [{ layers: [] }, { layers: ['pslist', 'pslist'] }, { layers: ['windows.hashdump'] }, { layers: ['../x'] }, { layers: [1] }, { layers: 'pslist' }, null, 5]) { const x = await call(H, 'mem:start', bad2); if (!(x && x.error)) ok(false, 'geçersiz katman isteği kabul edildi: ' + JSON.stringify(bad2)); } ok(true, 'start: geçersiz/yinelenen/bilinmeyen katman ve bozuk istekler reddedilir');
  await wait(H, s.id);

  // ---------- tam analiz (sahte vol + GERÇEK bulgu motoru) ----------
  H = mkHost(); await call(H, 'mem:chooseDump'); confirms = []; fs.writeFileSync(LOG, ''); s = await call(H, 'mem:start', {}); ok(s.id && s.network === false, 'start: varsayılan katmanlarla başladı, ağ kapalı');
  const busy = await call(H, 'mem:start', {}); ok(busy.error && /sürüyor/.test(busy.message), 'eşzamanlı tek iş: ikinci start reddedilir');
  let j = await wait(H, s.id); ok(j.state === 'done', 'iş tamamlandı (' + j.state + (j.error ? ': ' + j.error : '') + ')');
  const ids = argvLog().map((a) => a[a.length - 1]); ok(ids.length === 12 && !ids.includes('windows.filescan') && !ids.includes('windows.handles') && ids.every((x) => /^windows\.(malware\.)?[a-z]+$/.test(x)), 'varsayılan 12 katman çalıştı; filescan/handles çalışmadı (' + ids.length + ')');
  ok(argvLog().every((a) => a.includes('--offline')), 'her çağrıda --offline');
  const R = j.result; ok(R && R.scan && !R.partial && R.scan.coverage.filter((c) => c.state === 'ok').length === 12, 'sonuç: bulgu motoru çalıştı, 12 katman kapsandı');
  const sc = R.scan; ok(sc.score >= 60 && sc.level === 'high' && sc.score <= 100, 'genel puan 0-100 ve yüksek: ' + sc.score);
  const F = sc.findings; const has = (rule, pid) => F.some((f) => f.rule === rule && (pid === undefined || f.pid === pid));
  ok(has('hidden', 6666), 'bulgu: pslist↔psscan → gizli süreç (rootkitd.exe PID 6666)'); ok(has('terminated') && !F.some((f) => f.rule === 'hidden' && f.pid === 5000), 'bulgu: sonlanmış süreç (old.exe) gizli sayılmaz, bilgi olarak ayrı');
  ok(has('inject', 4100) && F.find((f) => f.rule === 'inject' && f.pid === 4100).pts >= 35, 'bulgu: malfind RWX + MZ başlığı → enjekte kod (PID 4100)'); const fpC = F.find((f) => f.rule === 'inject' && f.pid === 2000); ok(fpC && fpC.pts <= 10 && /JIT/.test(fpC.detail), 'bulgu: chrome RWX (MZ yok) düşük puan + JIT açıklaması (yanlış pozitif azaltma)');
  ok(has('unlink', 4100), 'bulgu: ldrmodules üç listede de eksik DLL → unlink'); ok(has('lookalike', 4100), 'bulgu: scvhost.exe sistem süreci adı taklidi'); ok(has('path') === false && has('baddir', 4100), 'bulgu: Temp klasöründen çalışma');
  ok(has('parent', 900), 'bulgu: svchost.exe ebeveyni services.exe değil (PID 900, PPID 1234 yok)'); ok(has('cmdline', 4200), 'bulgu: kodlu/gizli PowerShell komut satırı'); ok(has('shellnet', 4200), 'bulgu: PowerShell internete bağlantılı (4444)'); ok(!F.some((f) => f.pid === 2000 && f.rule === 'shellnet') && !F.some((f) => f.pid === 3100 && f.pts >= 15), 'yanlış alarm yok: chrome:443 ve notepad puan almadı');
  ok(has('service', 4100), 'bulgu: hizmet ikilisi Temp’te'); ok(F.every((f) => typeof f.fp === 'string' && f.fp.length > 20 || f.pts === 0), 'her puanlı bulgunun yanlış pozitif açıklaması var');
  const top = sc.procs[0]; ok(top.pid === 4100 && top.score >= 80 && top.why.length >= 4 && sc.procs.every((p) => p.score >= 0 && p.score <= 100), 'süreç puanları 0-100; en şüpheli PID 4100 gerekçeleriyle (' + top.score + ', ' + top.why.length + ' gerekçe)');
  ok(!/temiz|zararsız|güvenli/i.test(sc.headline) && sc.caveats.some((c) => /hüküm değildir|sınıflandırma/.test(c)), 'rapor “temiz” hükmü vermez; sınırlar açık');
  const rep = await call(H, 'mem:report', s.id, 'md'); ok(rep.ok && /\/ 100/.test(rep.text) && /yanlış pozitif/i.test(rep.text) && /GERÇEK bir Windows dökümünde.*denenmemiştir/.test(rep.text) && !/\btemiz\b/i.test(rep.text) && /Volatility: 2\.28\.2-fake/.test(rep.text) && /--offline/.test(JSON.stringify(R.meta)), 'Türkçe Markdown rapor: puan, yanlış pozitif notu, “Windows’ta denenmedi” notu, sürüm; ağ durumu meta’da');
  const rj = await call(H, 'mem:report', s.id, 'json'); let pj = null; try { pj = JSON.parse(rj.text); } catch (e) { /* bozuk */ } ok(pj && pj.result && pj.result.score === sc.score && pj.meta.name === 'sahte.raw', 'JSON rapor geçerli ve aynı puan');
  ok(sha(dump) === dumpSha && fs.statSync(dump).mtimeMs === dumpMt, 'DÖKÜM değişmedi (SHA-256 ve değiştirilme zamanı aynı); yalnız okundu');
  ok(fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('kovan-ram-')).length === 0, 'geçici çalışma klasörü temizlendi');

  // ---------- sayfalama / arama / sınır ----------
  H = mkHost(); await call(H, 'mem:chooseDump'); process.env.FAKE_MODE = 'big'; s = await call(H, 'mem:start', { layers: ['pslist', 'filescan'] }); j = await wait(H, s.id); delete process.env.FAKE_MODE; ok(j.state === 'done', 'filescan (isteğe bağlı, ağır) seçilince çalışır');
  let pg = await call(H, 'mem:rows', s.id, 'filescan', 0, 100000); ok(pg.total === 1200 && pg.rows.length === 200, 'sayfalama: istek 100000 olsa da sayfa en çok 200 satır (toplam 1200)');
  pg = await call(H, 'mem:rows', s.id, 'filescan', 1300, 100); ok(pg.rows.length === 100 && pg.offset === 1100 && pg.rows[99].Name.includes('file1199'), 'sayfalama: son sayfaya taşan offset düzeltilir');
  pg = await call(H, 'mem:rows', s.id, 'filescan', 0, 50, 'FILE77.'); ok(pg.total === 1 && /file77\.dll/.test(pg.rows[0].Name), 'arama: büyük/küçük harf duyarsız süzme');
  pg = await call(H, 'mem:rows', s.id, 'pslist', 0, 5); ok(pg.columns.includes('PID') && !pg.columns.includes('__depth') && pg.total === 13, 'pslist satırları ve sütunları');
  ok((await call(H, 'mem:rows', s.id, 'malfind', 0, 5)).error && (await call(H, 'mem:rows', s.id, 'windows.hashdump', 0, 5)).error && (await call(H, 'mem:rows', 'x', 'pslist', 0, 5)).error, 'rows: çalışmamış katman / beyaz liste dışı ad / bilinmeyen iş reddedilir');

  // ---------- AĞ onayı (sembol indirme) ----------
  process.env.FAKE_MODE = 'symbols'; H = mkHost(); await call(H, 'mem:chooseDump'); confirms = []; fs.writeFileSync(LOG, '');
  s = await call(H, 'mem:start', { layers: ['info', 'pslist'], symbols: 'offline' }); j = await wait(H, s.id); ok(j.state === 'failed' && j.errorCode === 'symbols' && /çevrimdışı/.test(j.error) && /indirilemedi/.test(j.error) && confirms.length === 0, 'çevrimdışı + sembol yok → net hata (“çevrimdışı önbellekte yok, indirilemedi”), onay sorulmadı');
  ok(j.steps.filter((x) => x.status === 'skip').length >= 1, 'döküm çözülemeyince kalan katmanlar atlanır (boşa beklenmez)');
  confirmAns = false; confirms = []; fs.writeFileSync(LOG, ''); s = await call(H, 'mem:start', { layers: ['info'], symbols: 'allow' }); ok(confirms.length === 1 && /msdl\.microsoft\.com/.test(confirms[0].message) && /GÖNDERİLMEZ/.test(confirms[0].message) && /Reddedersen ağ KULLANILMAZ/.test(confirms[0].message), 'onay penceresi neyin indirileceğini açıkça söyler (msdl.microsoft.com, içerik gönderilmez, ret = ağ yok)');
  ok(s.declined === true && s.network === false, 'ret → declined, ağ kapalı'); j = await wait(H, s.id); ok(argvLog().every((a) => a.includes('--offline')) && j.state === 'failed' && j.errorCode === 'symbols', 'ret → --offline ile devam; sembol yoksa net söylenir');
  confirmAns = true; confirms = []; fs.writeFileSync(LOG, ''); s = await call(H, 'mem:start', { layers: ['info', 'pslist'], symbols: 'allow' }); j = await wait(H, s.id); ok(confirms.length === 1 && s.network === true && argvLog().length === 2 && argvLog().every((a) => !a.includes('--offline')) && j.state === 'done' && j.network === true, 'onay → --offline OLMADAN çalışır; yalnız onaydan sonra');
  ok(JSON.stringify((await call(H, 'mem:job', s.id)).result.meta.network).includes('izinli'), 'rapor meta’sında ağ durumu “izinli”');
  const Hnc = mkHost({ confirm: undefined }); await call(Hnc, 'mem:chooseDump'); const x2 = await call(Hnc, 'mem:start', { layers: ['info'], symbols: 'allow' }); ok(x2.error && /Onay penceresi yok/.test(x2.message), 'onay penceresi yoksa ağ ASLA açılmaz (hata)'); delete process.env.FAKE_MODE; confirmAns = false;

  // ---------- geçersiz döküm, eski eklenti adları ----------
  process.env.FAKE_MODE = 'junk'; H = mkHost(); await call(H, 'mem:chooseDump'); s = await call(H, 'mem:start', { layers: ['pslist'] }); j = await wait(H, s.id); ok(j.state === 'failed' && j.errorCode === 'layer' && /tanınmadı/.test(j.error), 'geçersiz döküm → “Windows bellek dökümü olarak tanınmadı”'); delete process.env.FAKE_MODE;
  process.env.FAKE_MODE = 'oldnames'; H = mkHost(); await call(H, 'mem:chooseDump'); fs.writeFileSync(LOG, ''); s = await call(H, 'mem:start', { layers: ['malfind', 'ldrmodules'] }); j = await wait(H, s.id); const pl = argvLog().map((a) => a[a.length - 1]); ok(j.state === 'done' && pl.join() === 'windows.malware.ldrmodules,windows.ldrmodules,windows.malware.malfind,windows.malfind', 'eski Volatility: windows.malware.* yoksa windows.malfind/ldrmodules adına düşülür'); delete process.env.FAKE_MODE;

  // ---------- iptal ve zaman aşımı ----------
  process.env.FAKE_SLEEP_MS = '1500'; H = mkHost(); await call(H, 'mem:chooseDump'); s = await call(H, 'mem:start', {}); await sleep(400); ok((await call(H, 'mem:cancel', s.id)).ok, 'cancel: kabul edildi'); const t0 = Date.now(); j = await wait(H, s.id, 6000); ok(j.state === 'canceled' && Date.now() - t0 < 2500 && !j.result, 'iptal: süreç öldürüldü, iş “canceled”, sonuç yok (' + (Date.now() - t0) + ' ms)');
  ok(j.steps.some((x) => x.status === 'skip' && /İptal/.test(x.detail)), 'iptal: kalan adımlar “İptal edildi” işaretli'); const nx = await call(H, 'mem:start', { layers: ['info'] }); ok(nx.id, 'iptalden sonra yeni iş başlatılabilir'); await call(H, 'mem:cancel', nx.id); await wait(H, nx.id, 4000);
  process.env.FAKE_SLEEP_MS = '700'; H = mkHost({ msPerMin: 4000 }); await call(H, 'mem:chooseDump'); s = await call(H, 'mem:start', { timeoutMin: 1 }); j = await wait(H, s.id, 15000);
  ok(j.state === 'partial' && /Zaman aşımı/.test(j.error) && j.result && j.result.partial && j.result.timedOut, 'zaman aşımı: kısmi rapor (partial) + açıklama'); ok(j.steps.some((x) => x.status === 'ok') && j.steps.some((x) => x.status === 'skip'), 'zaman aşımı: biten katmanlar korunur, kalanlar atlandı');
  ok(j.result.scan && j.result.scan.notes.some((n) => /eksik/.test(n)) && j.result.scan.coverage.some((c) => c.state === 'missing'), 'kısmi raporda eksik katmanlar notu + kapsam'); delete process.env.FAKE_SLEEP_MS;
  const rp = await call(H, 'mem:report', s.id, 'md'); ok(/KISMİ/.test(rp.text), 'kısmi rapor başlığında “KISMİ” yazar');
  H = mkHost(); await call(H, 'mem:chooseDump'); s = await call(H, 'mem:start', { timeoutMin: 99999, layers: ['info'] }); ok((await call(H, 'mem:job', s.id)).timeoutMin === 120, 'zaman aşımı üst sınırı 120 dk’ya kısılır'); await wait(H, s.id); const s2 = await call(H, 'mem:start', { timeoutMin: -5, layers: ['info'] }); ok((await call(H, 'mem:job', s2.id)).timeoutMin === 1, 'zaman aşımı alt sınırı 1 dk'); await wait(H, s2.id);

  // ---------- engelli kurulum ----------
  const Hb = createHost({ service: { closeAll() {} }, sys: false, compile: false, mem: { onlyDirs: [bin], engine, chooseDump: async () => dump }, access: { dataDir: tmp, publicKey: '' } }); if (Hb.access) { ok(typeof Hb.handlers['mem:start'] === 'function', 'erişim modülüyle birlikte mem:* kanalları kayıtlı (engelli kurulumda reddedilir)'); }

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(bad ? '\n' + bad + ' BAŞARISIZ' : '\nHepsi geçti'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error('HATA', e); process.exit(2); });
