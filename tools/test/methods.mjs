// 4.5 ek yontemler + mod farklari: SAMPLES=<dizin> node tools/test/methods.mjs
import fs from 'node:fs'; import { loadEngine, scan, ids, allIds } from './engine.mjs';
const E = loadEngine(); const S = process.env.SAMPLES; let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const rnd = (n, seed) => { const a = new Uint8Array(n); let x = seed >>> 0; for (let i = 0; i < n; i++) { x = (Math.imul(x, 1664525) + 1013904223) >>> 0; a[i] = x >>> 24; } return a; };
// --- CTPH ---
const A = rnd(60000, 1); const B = A.slice(); for (let i = 20000; i < 20300; i++) B[i] ^= 0x55; const C = rnd(60000, 99);
const hA = E.ctph(A), hB = E.ctph(B), hC = E.ctph(C);
ok(/^\d+:[A-Za-z0-9+\/]{1,64}:[A-Za-z0-9+\/]{0,32}$/.test(hA), 'CTPH biçimi blocksize:imza1:imza2 → ' + hA.slice(0, 30));
ok(E.ctph(A) === hA, 'CTPH deterministik'); ok(E.fuzzyCompare(hA, hA) === 100, 'aynı dosya %100');
ok(E.fuzzyCompare(hA, hB) >= 70, 'küçük değişiklik (300 bayt) yüksek benzerlik: %' + E.fuzzyCompare(hA, hB)); ok(E.fuzzyCompare(hA, hC) < 20, 'ilgisiz veri düşük benzerlik: %' + E.fuzzyCompare(hA, hC)); ok(E.ctph(new Uint8Array(100)) === null, '512 bayttan küçük girdi: hash yok (uydurma yok)');
// --- ad denetimi ---
const cf = (n) => E.confusableName(n);
ok(cf('p\u0430ypal.exe').mixed.length === 1, 'Latin+Kiril karışımı (раураl) yakalandı'); ok(cf('Игра.exe').mixed.length === 0 && cf('çalışma_şğü.exe').mixed.length === 0 && cf('readme.txt').invisible.length === 0, 'tek yazı sistemli (Kiril/Türkçe/Latin) ad yanlış alarm vermez');
ok(cf('rapor\u200b.exe').invisible.length === 1 && cf('a\u2066b.txt').invisible.length === 1, 'sıfır genişlik / yön karakteri yakalandı');
// --- PDB ---
const pe = fs.readFileSync(S + '/pe_chk.exe'); const p = 'C:\\Users\\ahmet\\source\\repos\\TokenStealer\\obj\\Release\\TokenStealer.pdb'; const rsds = new Uint8Array(24 + p.length + 1); rsds.set([0x52, 0x53, 0x44, 0x53]); rsds.set(Array.from({ length: 16 }, (_, i) => i + 1), 4); rsds[20] = 1; for (let i = 0; i < p.length; i++) rsds[24 + i] = p.charCodeAt(i);
const withPdb = new Uint8Array(pe.length + rsds.length + 8); withPdb.set(pe); withPdb.set(rsds, pe.length + 4);
ok(E.pdbPaths(withPdb).length === 1 && E.pdbPaths(pe).length === 0, 'PDB yolu bulundu; temiz örnekte yok'); ok(E.pdbPaths(new Uint8Array([0x52, 0x53, 0x44, 0x53, 1, 2, 3])).length === 0, 'kısa/bozuk RSDS yok sayıldı');
// --- modlar: gercekten farkli adimlar ---
const led = (r, id) => (r.analyses.find((a) => a.id === id) || {}).status;
const q = await scan(E, 'a.exe', withPdb, 'quick'), n = await scan(E, 'a.exe', withPdb, 'normal'), d = await scan(E, 'a.exe', withPdb, 'deep');
ok(led(q, 'pdb') === 'skipped' && led(n, 'pdb') === 'done' && led(d, 'pdb') === 'done', 'PDB: hızlı atlar, normal/derin çalışır');
ok(led(q, 'fuzzy') === 'skipped' && led(n, 'fuzzy') && led(d, 'fuzzy') === 'done', 'bulanık hash: hızlı atlar, derin çalışır (normal: ' + led(n, 'fuzzy') + ')');
ok(!ids(q).includes('pdb_path') && ids(n).includes('pdb_path') && ids(n).includes('pdb_susp') && ids(d).includes('pdb_susp'), 'pdb_path/pdb_susp bulguları yalnızca normal+derinde');
ok(led(q, 'confusable') === 'done', 'ad denetimi tüm modlarda'); ok(d.info.fuzzy && d.info.fuzzy.hash === E.ctph(withPdb), 'derin: info.fuzzy gerçekten hesaplandı');
const cfz = await scan(E, 'p\u0430ypal.exe', pe, 'quick'); ok(ids(cfz).includes('name_confusable'), 'tarama akışında name_confusable bulgusu');
// --- aile gruplama ---
const mk = async (nm, buf, mode = 'deep') => scan(E, nm, buf, mode);
const f1 = await mk('v1.bin', A), f2 = await mk('v2.bin', B), f3 = await mk('x.bin', C), f4 = await mk('copy.bin', A);
const g = E.familyGroups([f1, f2, f3, f4]); ok(g.length === 1 && g[0].members.length === 3 && !g[0].members.some((m) => m.name === 'x.bin'), 'aile grubu: v1, v2 ve birebir kopya birlikte; ilgisiz dosya dışarıda');
ok(g[0].links.some((l) => /birebir/.test(l.why)) && g[0].links.some((l) => /bulanık hash/.test(l.why)), 'gruplama nedenleri açıklanıyor');
ok(E.familyGroups([await mk('v1.bin', A, 'quick'), await mk('v2.bin', B, 'quick')]).length === 0, 'hızlı modda bulanık hash olmadığı için benzerlik uydurulmaz');
// --- yontem matrisi mod ayarlarindan ---
const M = E.methodMatrix(); const row = (id) => M.rows.find((r) => r.id === id);
ok(M.modes.length === 3 && M.rows.length >= 25, 'matris: 3 mod, ' + M.rows.length + ' yöntem');
ok(row('deobf').modes.quick.state === 'off' && row('deobf').modes.normal.state === 'off' && row('deobf').modes.deep.state === 'full', 'matris: deobf yalnızca derin');
ok(row('jar_flow').modes.quick.state === 'off' && row('jar_flow').modes.normal.state === 'full' && /derinliği: 2/.test(row('jar_flow').modes.deep.note), 'matris: bytecode akışı normal 1 / derin 2');
ok(row('rules').modes.quick.state === 'partial' && row('rules').modes.deep.state === 'full', 'matris: kural kataloğu hızlıda kısmi');
ok(['pdb', 'fuzzy', 'confusable'].every((i) => row(i).since === '4.5'), 'yeni yöntemler 4.5 olarak işaretli'); ok(M.never.length >= 5, 'yapılmayanlar listede');
// matris <-> gercek defter tutarliligi (PE, 3 mod)
const map = { pdb: 'pdb', fuzzy: 'fuzzy', confusable: 'confusable', pe_sig: 'sig' };
for (const [mid, lid] of Object.entries(map)) for (const [mode, r] of [['quick', q], ['normal', n], ['deep', d]]) { const st = led(r, lid); if (st === undefined) continue; const exp = row(mid).modes[mode].state; const okc = exp === 'off' ? st === 'skipped' : st === 'done' || st === 'partial' || st === 'na'; if (!okc) { ok(false, 'matris ≠ defter: ' + mid + ' ' + mode + ' matris=' + exp + ' defter=' + st); } }
console.log(bad ? bad + ' TEST BAŞARISIZ' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
