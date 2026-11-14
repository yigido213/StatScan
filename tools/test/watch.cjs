'use strict';
const fs = require('fs'), os = require('os'), path = require('path'); const { createWatcher } = require('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ssw-')); const dl = path.join(root, 'dl'); const out = path.join(root, 'StatScan-Cikti'); fs.mkdirSync(dl); fs.mkdirSync(out);
  const w = createWatcher({ excludeDir: out, maxBytes: 1000, tickMs: 50 });
  ok(w.validate(out) && w.validate(root), 'çıktı klasörü ve onu içeren klasör reddedilir'); ok(w.validate(path.parse(root).root), 'kök dizin reddedilir'); ok(w.validate(path.join(root, 'yok')), 'olmayan klasör reddedilir');
  fs.writeFileSync(path.join(dl, 'eski.exe'), 'old'); const r = w.setFolders([dl, out]); ok(r.folders.length === 1 && r.errors.length === 1, 'yalnızca geçerli klasör izlenir');
  await sleep(100); ok(w.take().item === null, 'eski dosyalar taranmaz');
  fs.writeFileSync(path.join(dl, 'a.crdownload'), 'x'); fs.writeFileSync(path.join(dl, 'a.exe'), 'MZ12'); await sleep(50);
  const early = []; const fd = fs.openSync(path.join(dl, 'b.exe'), 'w'); for (let i = 0; i < 5; i++) { fs.writeSync(fd, 'abc'); w._consider(dl, 'b.exe'); await sleep(40); w._tick(); const t = w.take(); if (t.item) early.push(t.item); } 
  await sleep(300); ok(!early.some((x) => x.name === 'b.exe'), 'yazılırken bekler'); const got = early; for (let i = 0; i < 5; i++) { const t = w.take(); if (t.item) got.push(t.item); }
  ok(got.some((x) => x.name === 'a.exe' && x.bytes && Buffer.from(x.bytes).toString() === 'MZ12'), 'tamamlanan dosya baytlarıyla verilir');
  ok(!got.some((x) => /crdownload/.test(x.name)), 'geçici uzantı yok sayılır');
  fs.closeSync(fd); fs.writeFileSync(path.join(dl, 'big.bin'), Buffer.alloc(2000)); await sleep(300); const bg = w.take().item; ok(bg && bg.tooBig && !bg.bytes, 'büyük dosya taranmaz, not düşer');
  fs.writeFileSync(path.join(out, 'x.exe'), 'MZ'); w._consider(out, 'x.exe'); await sleep(200); ok(w.take().item === null, 'çıktı klasörü dosyaları taranmaz');
  ok(fs.readFileSync(path.join(dl, 'a.exe'), 'utf8') === 'MZ12', 'orijinal dosya değişmedi'); ok(w.log().length > 0, 'günlük tutulur'); w.stop(); fs.rmSync(root, { recursive: true, force: true });

  /* ---- kalici gecmis + icerik (SHA-256) tekillestirme: ayni dosya tekrar taranmaz / bildirilmez ---- */
  {
    const crypto = require('crypto'); const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
    const r2 = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-')); const d2 = path.join(r2, 'dl'); fs.mkdirSync(d2); const hp = path.join(r2, 'ud', 'tarama-gecmisi.json');
    const mk = () => createWatcher({ tickMs: 30, maxBytes: 100000, historyPath: hp });
    const next = async (w, name, wait) => { w._consider(d2, name); await sleep(wait || 200); const t = w.take(); return t.item; };
    let w2 = mk(); w2.setFolders([d2]);
    const body = Buffer.from('MZ-dup-test-content'); fs.writeFileSync(path.join(d2, 'tool.exe'), body);
    const first = await next(w2, 'tool.exe'); ok(first && first.bytes && first.sha256 === sha(body) && !first.dup, 'ilk görülen dosya baytları + SHA-256 ile verilir');
    const row = w2.historyAdd({ src: 'watch', name: 'tool.exe', dir: d2, size: body.length, sha256: first.sha256, score: 12, verdict: 'Düşük risk', partial: false, mode: 'normal', alert: true, notified: true, top: ['a', 'b', 'c', 'd'] });
    ok(row && row.count === 1 && row.top.length === 3, 'tarama sonucu geçmişe yazılır (ilk 3 bulgu başlığı)');
    const t0 = new Date(); fs.utimesSync(path.join(d2, 'tool.exe'), new Date(t0.getTime() + 5000), new Date(t0.getTime() + 5000));
    const again = await next(w2, 'tool.exe'); ok(again && again.dup === true && !again.bytes && again.prev && again.prev.score === 12, 'mtime değişse de aynı içerik yeniden taranmaz (dup)');
    fs.copyFileSync(path.join(d2, 'tool.exe'), path.join(d2, 'tool (1).exe')); const ren = await next(w2, 'tool (1).exe'); ok(ren && ren.dup === true, 'aynı içerik başka adla gelse de yeniden taranmaz');
    let l = w2.historyList({}); ok(l.total === 1 && l.rows[0].count === 3 && l.rows[0].name === 'tool (1).exe', 'tek satır, görülme sayacı artar, son ad/klasör tutulur');
    fs.writeFileSync(path.join(d2, 'tool.exe'), Buffer.from('MZ-changed-content!!')); const chg = await next(w2, 'tool.exe'); ok(chg && chg.bytes && !chg.dup, 'içerik değişirse yeniden taranır');
    w2.flush(); ok(fs.existsSync(hp) && (fs.statSync(hp).mode & 0o077) === 0, 'geçmiş diske yazılır (yalnız sahibi okuyabilir)'); w2.stop();
    const w3 = mk(); w3.setFolders([d2]); const rb = await next(w3, 'tool (1).exe'); ok(rb && rb.dup === true, 'yeniden başlatma sonrası da aynı dosya tekrar taranmaz (kalıcı)'); l = w3.historyList({}); ok(l.total === 1 && l.rows[0].alert === true && l.rows[0].notified === true, 'yeniden yüklenen kayıt alanları korunur');
    /* sonucu olmayan (taranamadi/atlandi) kayit "taranmis" sayilmaz */
    w3.historyAdd({ src: 'watch', name: 'big.bin', size: 5, sha256: sha(Buffer.from('BIG-bin-x')), score: null, verdict: 'Atlandı' }); fs.writeFileSync(path.join(d2, 'big.bin'), 'BIG-bin-x'); const bb = await next(w3, 'big.bin'); ok(bb && bb.bytes && !bb.dup, 'skoru olmayan kayıt tekilleştirmeyi tetiklemez');
    /* gecmis listesi: arama, filtre, sayfalama, temizleme */
    for (let i = 0; i < 6; i++) w3.historyAdd({ src: i % 2 ? 'manual' : 'watch', name: 'f' + i + '.jar', size: i, sha256: sha(Buffer.from('h' + i)), score: i * 10, verdict: i === 5 ? 'Kritik' : 'Düşük risk', alert: i === 5 });
    l = w3.historyList({ limit: 4 }); ok(l.rows.length === 4 && l.matched === l.total && l.rows[0].name === 'f5.jar', 'en yeni üstte, sayfa sınırı uygulanır');
    ok(w3.historyList({ filter: 'alert' }).matched === 2 && w3.historyList({ filter: 'alert' }).rows.every((x) => x.alert) && w3.historyList({ filter: 'manual' }).rows.every((x) => x.src === 'manual') && w3.historyList({ filter: 'watch' }).rows.every((x) => x.src === 'watch'), 'uyarı / kaynak süzgeçleri');
    ok(w3.historyList({ q: 'F3.JAR' }).matched === 1 && w3.historyList({ q: sha(Buffer.from('h2')).slice(0, 10) }).matched === 1 && w3.historyList({ q: 'kritik' }).matched === 1, 'arama ad/SHA/karar üzerinde, büyük-küçük harfe duyarsız');
    ok(w3.historyList({ offset: 4, limit: 50 }).rows.length === w3.historyList({}).total - 4, 'offset ile sonraki sayfa');
    ok(w3.historyAdd({ src: 'x', name: 'z'.repeat(500), size: -3, sha256: 'bozuk', score: 999, verdict: 'v'.repeat(200), top: 'x' }).name.length === 200 && w3.historyList({ q: 'zzzz' }).rows[0].score === 100 && w3.historyList({ q: 'zzzz' }).rows[0].sha256 === '', 'alanlar temizlenir (uzunluk, skor 0-100, geçersiz SHA)');
    ok(w3.historyAdd(null) === null && w3.historyAdd('x') === null, 'geçersiz kayıt reddedilir');
    w3.historyClear(); ok(w3.historyList({}).total === 0 && JSON.parse(fs.readFileSync(hp, 'utf8')).rows.length === 0, 'temizleme listeyi ve dosyayı boşaltır');
    const tt = new Date(Date.now() + 9000); fs.utimesSync(path.join(d2, 'tool (1).exe'), tt, tt); const cl = await next(w3, 'tool (1).exe'); ok(cl && cl.bytes && !cl.dup, 'temizlemeden sonra (dosya yeniden görülünce) içerik yeniden taranır; hafıza da silinmiştir'); w3.stop();
    fs.writeFileSync(hp, '{bozuk json'); let w4 = null; try { w4 = mk(); } catch (e) { /* asagida */ } ok(w4 && w4.historyList({}).total === 0, 'bozuk geçmiş dosyası çökertmez, boş başlar'); w4 && w4.stop();
    const w5 = createWatcher({ tickMs: 30 }); w5.historyAdd({ src: 'manual', name: 'm.exe', size: 1, sha256: sha(Buffer.from('m')), score: 3, verdict: 'x' }); ok(w5.historyList({}).total === 1, 'historyPath yoksa yalnız bellekte tutulur (hata yok)');
    const cap = createWatcher({ historyMax: 5 }); for (let i = 0; i < 9; i++) cap.historyAdd({ src: 'manual', name: 'c' + i, size: i, sha256: sha(Buffer.from('c' + i)), score: 1, verdict: 'x' }); ok(cap.historyList({}).total === 5 && cap.historyList({}).rows[0].name === 'c8', 'geçmiş sınırı: en eski kayıtlar atılır');
    fs.rmSync(r2, { recursive: true, force: true });
  }
  /* ---- host kanallari: bildirim koruması + history:* ---- */
  {
    const { createHost } = require('../../app/desktop/host.js'); const r3 = fs.mkdtempSync(path.join(os.tmpdir(), 'ssn-')); const sent = []; let confirmAns = true;
    const host = createHost({ service: { closeAll() {}, status() { return {}; } }, notify: (t, b) => sent.push([t, b]), historyPath: path.join(r3, 'h.json'), confirm: async () => confirmAns, obfOutputRoot: path.join(r3, 'out') }); const H = host.handlers;
    await H['watch:notify'](null, 'StatScan: Şüpheli dosya', 'a.exe — skor 80/100'); const sup = await H['watch:notify'](null, 'StatScan: Şüpheli dosya', 'a.exe — skor 80/100'); await H['watch:notify'](null, 'StatScan: Şüpheli dosya', 'b.exe — skor 80/100');
    ok(sent.length === 2 && sup.suppressed === true, 'aynı metinli bildirim 10 dk içinde tekrar gösterilmez, farklı dosya gösterilir');
    ok((await H['history:add'](null, { src: 'manual', name: 'q.exe', size: 1, sha256: 'a'.repeat(64), score: 7, verdict: 'Düşük risk' })).ok === true && (await H['history:add'](null, null)).error === 'bad', 'history:add geçerliyi alır, geçersizi reddeder');
    ok((await H['history:list'](null, { filter: 'manual' })).rows.length === 1, 'history:list');
    confirmAns = false; ok((await H['history:clear'](null)).canceled === true && (await H['history:list'](null, {})).total === 1, 'onaylanmazsa geçmiş silinmez'); confirmAns = true; ok((await H['history:clear'](null)).ok === true && (await H['history:list'](null, {})).total === 0, 'onaylanırsa silinir');
    fs.rmSync(r3, { recursive: true, force: true });
  }
  console.log(bad ? 'BAŞARISIZ ' + bad : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
})();
