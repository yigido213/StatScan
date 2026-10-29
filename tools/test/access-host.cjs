'use strict';
/* Kovan: kurulum kimliği, imzalı engelli liste, sahip modu, Notlarım (ana süreç) — gerçek Ed25519, ağ yok (fetch enjekte) */
const fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto'), cp = require('child_process');
const { createHost, accessModule: A } = require('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'kacc-')); const kp = () => crypto.generateKeyPairSync('ed25519'); const pemPub = (k) => k.publicKey.export({ type: 'spki', format: 'pem' });
(async () => {
  const owner = kp(), other = kp(); const pubPem = pemPub(owner); const ID1 = 'ABCDEFGHIJKLMNOP'; const base = (dir, extra) => Object.assign({ dataDir: dir, publicKey: pubPem, machineId: () => 'machine-guid-1', downloadsDir: dir, allowPathUnlock: true }, extra || {});
  const mk = (dir, extra) => { const h = createHost({ service: { closeAll() {} }, downloadsDir: dir, compile: false, access: base(dir, extra) }); return h; };
  // --- kimlik ---
  const d1 = tmp(); const h1 = mk(d1); let s = await h1.handlers['access:status'](); ok(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$/.test(s.id) && !s.blocked && !s.owner, 'kimlik biçimi XXXX-XXXX-XXXX-XXXX, engelli değil, sahip değil: ' + s.id);
  const h1b = mk(tmp()); ok((await h1b.handlers['access:status']()).id === s.id, 'aynı makine kimliği → aynı kurulum kimliği (yeniden kurulum/veri silme kimliği değiştirmez)');
  ok((await mk(tmp(), { machineId: () => 'baska-makine' }).handlers['access:status']()).id !== s.id, 'farklı makine → farklı kimlik');
  ok(!s.id.replace(/-/g, '').includes('MACHINE'), 'kimlik GUID’i açık etmez (tuzlu özet)');
  const dr = tmp(); const r1 = (await mk(dr, { machineId: () => null }).handlers['access:status']()).id; ok(r1 === (await mk(dr, { machineId: () => null }).handlers['access:status']()).id && fs.existsSync(path.join(dr, 'install-id.json')), 'GUID yoksa rastgele kimlik üretilir ve saklanır, sonraki açılışta aynı');
  // --- imzalı liste ---
  const selfId = s.id.replace(/-/g, ''); const sign = (k, seq, ids, notice) => A.signBlocklist(k.privateKey, { seq, notice, entries: ids.map((id) => ({ id, note: 'x', added: '2026-10-29' })) });
  const net = { text: null, err: null }; const fetchText = async () => { if (net.err) throw new Error(net.err); return net.text; };
  const dB = tmp(); const hB = mk(dB, { fetchText }); net.text = sign(owner, 1, [ID1]); s = await hB.handlers['access:refresh'](); ok(!s.blocked && s.source === 'remote' && s.seq === 1 && s.count === 1, 'imzalı liste alınır, bu kimlik listede değil → engelli değil');
  net.text = sign(owner, 2, [ID1, selfId], 'Erişim kapatıldı'); s = await hB.handlers['access:refresh'](); ok(s.blocked === true && s.notice === 'Erişim kapatıldı' && s.seq === 2, 'kimlik listede → engelli + mesaj');
  const refused = await hB.handlers['compile:tools'] ? await hB.handlers['compile:tools']() : null; ok(refused === null || (refused && refused.error === 'blocked'), 'engelliyken ayrıcalıklı işlemler reddedilir (compile:tools yok → atlandı)');
  for (const k of ['dyn:status', 'watch:log', 'dyn:job']) { const r = await hB.handlers[k]({}, 'x'); ok(r && r.error === 'blocked', 'engelliyken ' + k + ' reddedilir'); }
  ok((await hB.handlers['app:info']()).version !== undefined && (await hB.handlers['access:status']()).blocked, 'ayarlar/uygulama bilgisi/erişim durumu açık kalır');
  net.err = 'ağ yok'; s = await hB.handlers['access:refresh'](); ok(s.blocked === true && /alınamadı/.test(s.error), 'ağ hatası: doğrulanmış önbellek uygulanmaya devam eder');
  const hB2 = mk(dB, { fetchText }); ok((await hB2.handlers['access:status']()).blocked === true, 'uygulama yeniden açılınca önbellekten engel sürer (çevrimdışı)');
  net.err = null; net.text = sign(owner, 3, [ID1]); s = await hB.handlers['access:refresh'](); ok(!s.blocked && s.seq === 3, 'yeni imzalı liste (kimlik çıkarıldı, seq artar) → engel kalkar');
  net.text = sign(owner, 2, [ID1, selfId]); s = await hB.handlers['access:refresh'](); ok(!s.blocked && /eski/.test(s.error), 'eski liste tekrar oynatma (geri sarma) reddedilir');
  net.text = sign(other, 9, [selfId]); s = await hB.handlers['access:refresh'](); ok(!s.blocked && /doğrulanamadı/.test(s.error), 'başka anahtarla imzalı liste yok sayılır');
  const good = sign(owner, 10, [selfId]); const parsed = JSON.parse(good); parsed.manifest = parsed.manifest.replace('"seq":10', '"seq":11'); net.text = JSON.stringify(parsed); s = await hB.handlers['access:refresh'](); ok(!s.blocked && /doğrulanamadı/.test(s.error), 'manifest kurcalanırsa imza bozulur → yok sayılır');
  net.text = '<html>404</html>'; s = await hB.handlers['access:refresh'](); ok(!s.blocked && /doğrulanamadı/.test(s.error), 'JSON olmayan yanıt yok sayılır (fail-open)');
  net.text = 'x'.repeat(600 * 1024); s = await hB.handlers['access:refresh'](); ok(!s.blocked && /doğrulanamadı/.test(s.error), 'aşırı büyük yanıt yok sayılır');
  const dC = tmp(); const hC = mk(dC, { fetchText: async () => { throw new Error('HTTP 404'); } }); s = await hC.handlers['access:refresh'](); ok(!s.blocked && s.source === 'none', 'liste hiç yoksa (404) kimse engellenmez');
  ok(A.trustedKey(undefined).export({ type: 'spki', format: 'pem' }) === A.EMBEDDED_PUBKEY && A.trustedKey('çöp') !== null, 'ctx.publicKey yok/okunamazsa gömülü güven anahtarı kullanılır');
  // --- liste biçimi ---
  const v = A.verifyBlocklist(sign(owner, 5, [ID1, ID1]), A.trustedKey(pubPem)); ok(v.ok && v.entries.length === 1, 'yinelenen kimlikler tekilleştirilir');
  ok(!A.verifyBlocklist(sign(owner, 5, [ID1]), A.trustedKey(pemPub(other))).ok, 'yanlış genel anahtarla doğrulama başarısız');
  let threw = false; try { A.signBlocklist(owner.privateKey, { seq: 1, entries: [{ id: 'KISA' }] }); } catch (e) { threw = true; } ok(threw, 'geçersiz kimlikle imzalama reddedilir');
  // --- sahip modu ---
  const dO = tmp(); const hO = mk(dO, { fetchText }); const H = hO.handlers; ok((await H['notes:list']()).error === 'access' && (await H['owner:bl:get']()).error === 'access', 'sahip değilken Notlarım/Yönetim işlemleri reddedilir');
  const wrongPem = path.join(dO, 'wrong.pem'); fs.writeFileSync(wrongPem, other.privateKey.export({ type: 'pkcs8', format: 'pem' })); let r = await H['owner:unlock']({}, wrongPem); ok(r.error === 'access' && /eşleşmiyor/.test(r.message), 'yanlış anahtar: sahip modu açılmaz');
  const junk = path.join(dO, 'junk.pem'); fs.writeFileSync(junk, 'hello'); r = await H['owner:unlock']({}, junk); ok(r.error === 'access', 'PEM olmayan dosya reddedilir');
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }); const rsaPem = path.join(dO, 'rsa.pem'); fs.writeFileSync(rsaPem, rsa.privateKey.export({ type: 'pkcs8', format: 'pem' })); r = await H['owner:unlock']({}, rsaPem); ok(r.error === 'access' && /Ed25519/.test(r.message), 'Ed25519 olmayan anahtar reddedilir');
  const okPem = path.join(dO, 'private.pem'); fs.writeFileSync(okPem, owner.privateKey.export({ type: 'pkcs8', format: 'pem' })); r = await H['owner:unlock']({}, okPem); ok(r.ok && r.owner && r.unlocked, 'doğru anahtar: sahip modu açıldı');
  ok(!fs.readdirSync(dO).some((n) => fs.readFileSync(path.join(dO, n)).toString().includes('PRIVATE KEY') && !['wrong.pem', 'junk.pem', 'rsa.pem', 'private.pem'].includes(n)), 'özel anahtar userData’ya kopyalanmaz/yazılmaz');
  const hO2 = mk(dO); ok((await hO2.handlers['access:status']()).owner === true && (await hO2.handlers['access:status']()).unlocked === false, 'yeniden açılışta sahip bayrağı kalır ama anahtar bellekte yok');
  ok((await hO2.handlers['owner:bl:publish']()).needKey === true, 'anahtar seçilmeden liste imzalanamaz');
  // --- engelli liste yönetimi ---
  ok((await H['owner:bl:add']({}, 'kısa', '')).error === 'access', 'geçersiz kimlik eklenemez'); ok(/kendi/i.test((await H['owner:bl:add']({}, selfId, '')).message), 'kendi kimliğini engelleyemez (kilitlenme koruması)');
  r = await H['owner:bl:add']({}, 'abcd-efgh-ijkl-mnop', 'Ahmet'); ok(r.ok && r.draft.entries.length === 1 && r.draft.entries[0].id === 'ABCD-EFGH-IJKL-MNOP', 'kimlik eklendi (küçük harf/tire normalize)'); ok((await H['owner:bl:add']({}, ID1, '')).error === 'access', 'aynı kimlik ikinci kez eklenemez');
  await H['owner:bl:add']({}, 'QRSTUVWXYZ234567', 'Veli'); r = await H['owner:bl:remove']({}, 'QRST-UVWX-YZ23-4567'); ok(r.ok && r.draft.entries.length === 1, 'kimlik çıkarıldı'); await H['owner:bl:notice']({}, 'Kovan erişimin kapatıldı');
  const pub1 = await H['owner:bl:publish'](); ok(pub1.ok && pub1.seq === 1 && pub1.count === 1 && fs.existsSync(pub1.file), 'imzalı blocklist.json üretildi (seq 1): ' + path.basename(path.dirname(pub1.file)));
  const chk = A.verifyBlocklist(fs.readFileSync(pub1.file, 'utf8'), A.trustedKey(pubPem)); ok(chk.ok && chk.entries[0].id === ID1 && chk.notice === 'Kovan erişimin kapatıldı' && !fs.readFileSync(pub1.file, 'utf8').includes('PRIVATE'), 'üretilen dosya uygulamanın doğrulamasından geçer, anahtar içermez');
  ok((await H['owner:bl:publish']()).seq === 2, 'her yayında seq artar');
  // uçtan uca: üretilen liste, listedeki kimlikli bir istemcide engeli uygular
  const victim = tmp(); const hv = createHost({ service: { closeAll() {} }, downloadsDir: victim, compile: false, access: base(victim, { machineId: () => 'victim-guid', fetchText: async () => fs.readFileSync(pub1.file, 'utf8') }) }); const vid = (await hv.handlers['access:status']()).id.replace(/-/g, '');
  const pubV = A.signBlocklist(owner.privateKey, { seq: 5, entries: [{ id: vid }] }); fs.writeFileSync(pub1.file, pubV); s = await hv.handlers['access:refresh'](); ok(s.blocked === true, 'üretilen/imzalı dosya hedef istemcide engeli uygular');
  r = await H['owner:lock'](); ok(r.unlocked === false && (await H['owner:bl:publish']()).needKey === true, 'kilidi kapatınca anahtar bellekten silinir');
  r = await H['owner:off'](); ok(!r.owner && (await H['notes:list']()).error === 'access', 'geliştirici modu kapatılınca sahip araçları kapanır');
  // CLI
  const cli = path.join(__dirname, '../make-blocklist.mjs'); const keyFile = path.join(dO, 'private.pem'); const root = path.resolve(__dirname, '../..'); const bl = path.join(root, 'blocklist.json'); const had = fs.existsSync(bl) ? fs.readFileSync(bl) : null;
  try { if (had) fs.unlinkSync(bl); const run = (...a) => cp.spawnSync('node', [cli, keyFile, ...a], { encoding: 'utf8' }); let o = run('add', 'ZZZZ-YYYY-XXXX-2222', 'test'); ok(o.status === 0 && fs.existsSync(bl), 'CLI: add → blocklist.json yazıldı'); o = run('list'); ok(/ZZZZ-YYYY-XXXX-2222/.test(o.stdout) && /seq 1/.test(o.stdout), 'CLI: list'); o = run('add', 'ZZZZ-YYYY-XXXX-2222'); ok(o.status !== 0, 'CLI: aynı kimlik ikinci kez eklenmez'); o = run('remove', 'ZZZZ-YYYY-XXXX-2222'); ok(o.status === 0 && /seq 2/.test(run('list').stdout), 'CLI: remove → seq artar'); const t = JSON.parse(fs.readFileSync(bl, 'utf8')); t.sig = Buffer.alloc(64).toString('base64'); fs.writeFileSync(bl, JSON.stringify(t)); o = run('add', 'AAAA-BBBB-CCCC-DDDD'); ok(o.status !== 0 && /doğrulanamadı/.test(o.stderr), 'CLI: bozuk mevcut liste üzerine yazılmaz'); }
  finally { try { fs.unlinkSync(bl); } catch (e) { /* yok */ } if (had) fs.writeFileSync(bl, had); }
  // --- Notlarım ---
  const dNt = tmp(); const hNt = mk(dNt); await hNt.handlers['owner:unlock']({}, okPem); const N = hNt.handlers; ok((await N['notes:list']()).notes.length === 0, 'Notlarım: başlangıçta boş');
  r = await N['notes:save']({}, { text: 'ilk fikir #oyun' }); ok(r.ok && r.note.id && r.note.created > 0, 'not oluşturuldu'); const nid = r.note.id; r = await N['notes:save']({}, { id: nid, text: 'ilk fikir #oyun — güncellendi', pinned: true }); ok(r.ok && r.note.pinned && /güncellendi/.test(r.note.text), 'not güncellendi + sabitlendi');
  ok((await N['notes:list']()).notes.length === 1 && fs.existsSync(path.join(dNt, 'notes.json.bak')), 'kalıcı (notes.json) + yedek (.bak)'); ok(fs.readFileSync(path.join(dNt, 'notes.json'), 'utf8').includes('güncellendi'), 'dosyada Türkçe karakterler korunur');
  ok((await mk(dNt).handlers['notes:list']()).notes.length === 1, 'yeniden açılışta notlar yerinde'); ok((await N['notes:save']({}, { text: 'x'.repeat(200001) })).error === 'access', 'aşırı uzun not reddedilir'); ok((await N['notes:save']({}, { id: '../x', text: 'a' })).error === 'access', 'geçersiz not kimliği reddedilir');
  await Promise.all([1, 2, 3, 4, 5].map((i) => N['notes:save']({}, { text: 'eşzamanlı ' + i }))); ok((await N['notes:list']()).notes.length === 6, 'eşzamanlı kayıtlar sıraya girer, hiçbiri kaybolmaz');
  r = await N['notes:delete']({}, nid); ok(r.ok && (await N['notes:list']()).notes.length === 5, 'not silindi'); r = await N['notes:restore']({}, r.note); ok(r.ok && (await N['notes:list']()).notes.length === 6, 'silme geri alındı (aynı kimlik/zaman damgası)');
  fs.writeFileSync(path.join(dNt, 'notes.json'), '{bozuk'); ok((await N['notes:list']()).notes.length === 0, 'bozuk notes.json çökertmez (boş liste; .bak diskte duruyor)'); ok(fs.existsSync(path.join(dNt, 'notes.json.bak')), 'yedek dosya silinmedi');
  await N['notes:save']({}, { text: 'dışa aktarılacak' }); r = await N['notes:export'](); ok(r.ok && /Kovan-Notlar/.test(r.file) && /dışa aktarılacak/.test(fs.readFileSync(r.file, 'utf8')), 'Markdown dışa aktarım');
  console.log(bad ? bad + ' HATA' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
