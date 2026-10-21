// Yanlis-pozitif regresyon seti: bilinen-temiz ornekler her modda dusuk skor almali ve yuksek/kritik bulgu uretmemeli.
// SAMPLES=<dizin> node tools/test/fp.mjs   (yeni bir yanlis alarm gorursen dosyayi tools/test/benign/ icine ekle)
import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url'; import { loadEngine, scan, allIds, walk } from './engine.mjs'; import { zipStore } from './zipw.mjs';
const E = loadEngine(); const S = process.env.SAMPLES; const here = path.dirname(fileURLToPath(import.meta.url)); let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const LIMIT = 20; const items = [];
for (const f of fs.readdirSync(path.join(here, 'benign'))) items.push([f, new Uint8Array(fs.readFileSync(path.join(here, 'benign', f)))]);
const enc = new TextEncoder(); const fm = fs.readFileSync(path.join(here, 'benign/fabric.mod.json'), 'utf8');
items.push(['ornek.jar', zipStore([['fabric.mod.json', fm], ['ornek.mixins.json', '{"required":true,"package":"ornek.mixin","mixins":[]}'], ['assets/ornek/lang/en_us.json', '{"item.ornek":"Item"}'], ['META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n']])]);
items.push(['belgeler.zip', zipStore([['rapor.txt', 'Yillik rapor ozeti\n'], ['liste.csv', 'a,b\n1,2\n'], ['resim/ornek.txt', 'x']])]);
if (S) for (const n of ['clean.rtf', 'ok.pdf', 'img_clean.png', 'elf_hello', 'macho_hello', 'pe_lib.dll', 'pe_chk.exe', 'pe_version.exe', 't.jar', 'T.class', 'pack/clean.asar', 'mc/mc_ok.jar', 'elf_static']) { const p = path.join(S, n); if (fs.existsSync(p)) items.push([n, new Uint8Array(fs.readFileSync(p))]); }
const SEVHI = new Set(['high', 'crit']); const rows = [];
for (const [n, u] of items) for (const m of ['quick', 'normal', 'deep']) { const r = await scan(E, path.basename(n), u, m); const hi = []; walk(r, (x) => x.findings.forEach((f) => { if (SEVHI.has(f.sev) && !f.exempt) hi.push(f.id); })); rows.push({ n, m, s: r.score, hi }); if (r.score > LIMIT || hi.length) ok(false, n + ' [' + m + '] skor ' + r.score + (hi.length ? ' yüksek/kritik: ' + hi.join(',') : '') + ' — yanlış pozitif'); }
const worst = rows.reduce((a, r) => (r.s > a.s ? r : a), { s: 0 });
ok(!rows.some((r) => r.s > LIMIT || r.hi.length), items.length + ' temiz örnek × 3 mod: skor ≤ ' + LIMIT + ' ve yüksek/kritik bulgu yok (en yüksek: ' + worst.n + ' ' + worst.m + ' ' + (worst.s || 0) + ')');
// duyarlilik: ayni motor bilinen kotu ornekleri hala yakaliyor (yanlis-pozitif ayari kor olmasin)
const must = [['pe_inject.exe', 50], ['macho_stealer', 60], ['macro.doc', 70], ['elf_revshell', 20]]; if (S) for (const [n, min] of must) { const p = path.join(S, n); if (!fs.existsSync(p)) continue; const r = await scan(E, n, new Uint8Array(fs.readFileSync(p)), 'normal'); ok(r.score >= min, 'duyarlılık: ' + n + ' skor ' + r.score + ' ≥ ' + min); }
console.log(bad ? bad + ' TEST BAŞARISIZ' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
