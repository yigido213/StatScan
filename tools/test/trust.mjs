// "Kendi dosyalarim" + java muafiyeti politikasi testleri: SAMPLES=<dizin> node tools/test/trust.mjs
import fs from 'node:fs'; import { loadEngine, scan } from './engine.mjs';
const E = loadEngine(); const S = process.env.SAMPLES; let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const jp = fs.readFileSync(S + '/pe_javainj.exe'); const ij = (r) => r.findings.find((f) => f.id === 'pe_inject');
// 1) politika yok: varsayilan (herkese) muafiyet
let r = await scan(E, 'client.exe', jp, 'deep'); ok(ij(r).exempt === true && r.trust === undefined, 'politika yok: varsayılan java muafiyeti geçerli, trust alanı yok');
// 2) kapali
r = await scan(E, 'client.exe', jp, 'deep', { policy: { javaExempt: 'off', trusted: [] } }); ok(!ij(r).exempt && ij(r).w > 0 && /muafiyeti bu dosya için kapalı/.test(ij(r).why), 'muafiyet kapalı: bulgu puanlandı ve nedeni yazıyor');
// 3) yalnizca isaretli dosyalar
const snap = E.trustSnapshot(await scan(E, 'client-1.0.exe', jp, 'deep'), { javaExempt: true, note: 'benim istemcim' });
ok(snap.sha256 && snap.key === 'client.exe' && Array.isArray(snap.ids), 'anlık görüntü: sha256, ad anahtarı (sürüm numarası ayıklandı) ve bulgu kimlikleri');
r = await scan(E, 'client-1.0.exe', jp, 'deep', { policy: { javaExempt: 'trusted', trusted: [snap] } }); ok(ij(r).exempt === true && r.trust && r.trust.status === 'exact', 'yalnızca işaretliler: işaretli (aynı hash) dosyada muafiyet var, trust=exact');
r = await scan(E, 'baska.exe', jp, 'deep', { policy: { javaExempt: 'trusted', trusted: [snap] } }); ok(r.trust && r.trust.status === 'exact', 'ad farklı olsa da aynı hash tanınır');
const jp2 = Buffer.concat([jp, Buffer.from('\0yeni surum\0')]);
r = await scan(E, 'client-1.1.exe', jp2, 'deep', { policy: { javaExempt: 'trusted', trusted: [snap] } }); ok(r.trust && r.trust.status === 'newversion' && ij(r).exempt === true, 'yeni sürüm (farklı hash, aynı ad ailesi): newversion ve muafiyet ad ailesiyle sürüyor');
r = await scan(E, 'other.exe', jp, 'deep', { policy: { javaExempt: 'trusted', trusted: [Object.assign({}, snap, { sha256: 'x'.repeat(64), key: 'zzz.exe' })] } }); ok(!ij(r).exempt && !r.trust, 'işaretli listede olmayan dosyada muafiyet YOK (yalnızca işaretliler modu)');
r = await scan(E, 'client-1.0.exe', jp, 'deep', { policy: { javaExempt: 'trusted', trusted: [Object.assign({}, snap, { javaExempt: false })] } }); ok(!ij(r).exempt, 'işaretli ama java muafiyeti verilmemiş: muafiyet yok');
// 4) surum farki: yeni davranis uyarisi
const pe = fs.readFileSync(S + '/pe_inject.exe'); const base = E.trustSnapshot(await scan(E, 'tool-1.0.exe', jp, 'deep'), {});
r = await scan(E, 'tool-2.0.exe', pe, 'deep', { policy: { trusted: [base] } }); ok(r.trust.status === 'newversion' && r.trust.alert && r.trust.newFindings.length > 0 && r.trust.delta > 0, 'yeni sürüme eklenen davranış uyarısı: +' + r.trust.newFindings.length + ' bulgu, skor ' + r.trust.scoreBefore + '→' + r.trust.scoreNow);
ok(r.findings.some((f) => f.id === 'pe_inject' && f.w > 0), 'işaretli ad ailesi bulguları GİZLEMEZ');
// 5) cok kisa/anlamsiz adlar ad ailesiyle eslesmez
const tiny = E.trustSnapshot(await scan(E, '1.2.exe', jp, 'deep'), {}); r = await scan(E, '3.4.exe', jp2, 'deep', { policy: { trusted: [tiny] } }); ok(!r.trust, 'sürüm numarasından ibaret ad: ad ailesi eşleşmesi yok (yalnızca hash)');
console.log(bad ? bad + ' TEST BAŞARISIZ' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
