// Minecraft mod kontrolleri + java/javaw.exe muafiyeti: SAMPLES=<dizin> node tools/test/mc.mjs
import fs from 'node:fs'; import { loadEngine, scan } from './engine.mjs';
const E = loadEngine(); const S = process.env.SAMPLES; let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const ids = (r) => r.findings.map((f) => f.id);
const sj = async (n) => scan(E, n, fs.readFileSync(S + '/mc/' + n), 'deep');
let r = await sj('mc_ok.jar'); ok(!ids(r).some((i) => i.startsWith('mc_')), 'tutarlı mod: mc_* bulgusu yok');
r = await sj('mc_missing_ep.jar'); ok(ids(r).includes('mc_ep_missing'), 'eksik giriş sınıfı bulundu');
r = await sj('mc_nested.jar'); const n = r.findings.find((f) => f.id === 'mc_nested_undeclared'); ok(n && n.ev.some((e) => /hidden\.jar/.test(e)) && !n.ev.some((e) => /ok\.jar/.test(e)), 'bildirilmeyen gömülü jar (yalnızca hidden.jar)');
r = await sj('mc_mimic.jar'); ok(ids(r).includes('mc_mimic'), 'popüler mod adı + az sınıf: sahte mod şüphesi');
r = await sj('mc_plugin_missing.jar'); ok(ids(r).includes('mc_ep_missing'), 'plugin.yml ana sınıfı eksik');
// java/javaw.exe muafiyeti
const pe = fs.readFileSync(S + '/pe_inject.exe'); const base = await scan(E, 'p.exe', pe, 'deep'); const bi = base.findings.find((f) => f.id === 'pe_inject'); ok(bi && bi.w > 0 && !bi.javaTarget, 'taban (javaw yok): pe_inject puanlanıyor (' + (bi && bi.w) + ')');
const withJavaKeylog = await scan(E, 'p.exe', Buffer.concat([pe, Buffer.from('\0javaw.exe\0')]), 'deep'); ok(withJavaKeylog.findings.find((f) => f.id === 'pe_inject').w > 0, 'javaw.exe + keylogger kombinasyonu: muafiyet UYGULANMADI');
const jp = fs.readFileSync(S + '/pe_javainj.exe'); const jr = await scan(E, 'j.exe', jp, 'deep'); const ji = jr.findings.find((f) => f.id === 'pe_inject'); ok(ji && ji.w === 0 && ji.exempt && ji.sev === 'info', 'javaw.exe hedefli enjeksiyon, çalma belirtisi yok: puanlanmadı (skor ' + jr.score + ')');
const nojava = await scan(E, 'j.exe', Buffer.from(jp.toString('latin1').replace('javaw.exe', 'notepad.e'), 'latin1'), 'deep'); ok(nojava.findings.find((f) => f.id === 'pe_inject').w > 0, 'başka hedef süreç: muafiyet yok');
const withTheft = await scan(E, 'j.exe', Buffer.concat([jp, Buffer.from('\0https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789\0')]), 'deep'); const ti = withTheft.findings.find((f) => f.id === 'pe_inject'); ok(ti && ti.w > 0 && !ti.exempt, 'javaw.exe + webhook (çalma/sızdırma belirtisi): muafiyet UYGULANMADI');
const withTok = await scan(E, 'j.exe', Buffer.concat([jp, Buffer.from('\0launcher_accounts.json\0')]), 'deep'); ok(withTok.findings.find((f) => f.id === 'pe_inject').w > 0 || withTok.findings.some((f) => f.id === 'mc_launcher'), 'javaw.exe + Minecraft hesap dosyası göstergesi: bulgu korunuyor');
console.log(bad ? bad + ' TEST BAŞARISIZ' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
