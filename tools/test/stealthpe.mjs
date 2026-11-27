// Gizlenmiş bilgi çalıcı PE profili (src/engine/106-stealthpe.js): sentetik, ZARARSIZ PE'lerle sinyal ve yanlış-pozitif testi.
// Dosyalar yalnızca bayt kalıplarıdır (çalıştırılamaz, gerçek zararlı kodu içermez). Kullanım: node tools/test/stealthpe.mjs
import fs from 'node:fs';
import { loadEngine } from './engine.mjs';
const E = loadEngine(); let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const u32 = (n) => [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255];
const align = (n, a) => Math.ceil(n / a) * a;

/* Minimal PE32 üretici: .text + .idata (içe aktarma tablosu) */
function makePE(code, imports) {
  const FA = 0x200, SA = 0x1000, textRaw = align(code.length, FA), textVirt = align(code.length, SA), idVA = 0x1000 + textVirt;
  const dlls = Object.keys(imports); const descSize = (dlls.length + 1) * 20; let off = descSize; const layout = [];
  for (const d of dlls) { const ilt = off; off += (imports[d].length + 1) * 4; layout.push({ d, ilt }); }
  const names = []; for (const l of layout) { l.fn = []; for (const f of imports[d(l)]) { l.fn.push(off); off += 2 + f.length + 1; if (off & 1) off++; } l.nameOff = off; off += l.d.length + 1; }
  function d(l) { return l.d; }
  const idRaw = align(off, FA); const id = new Uint8Array(idRaw);
  layout.forEach((l, i) => {
    id.set([...u32(idVA + l.ilt), ...u32(0), ...u32(0), ...u32(idVA + l.nameOff), ...u32(idVA + l.ilt)], i * 20);
    imports[l.d].forEach((f, k) => { id.set(u32(idVA + l.fn[k]), l.ilt + k * 4); id.set([0, 0], l.fn[k]); for (let c = 0; c < f.length; c++) id[l.fn[k] + 2 + c] = f.charCodeAt(c); });
    for (let c = 0; c < l.d.length; c++) id[l.nameOff + c] = l.d.charCodeAt(c);
  });
  const hdr = new Uint8Array(0x200); const dv = new DataView(hdr.buffer);
  hdr[0] = 0x4d; hdr[1] = 0x5a; dv.setUint32(0x3c, 0x40, true);
  hdr.set([0x50, 0x45, 0, 0], 0x40); dv.setUint16(0x44, 0x14c, true); dv.setUint16(0x46, 2, true); dv.setUint32(0x48, 1778189591, true); dv.setUint16(0x54, 0xe0, true); dv.setUint16(0x56, 0x102, true);
  const oh = 0x58; dv.setUint16(oh, 0x10b, true); dv.setUint32(oh + 4, textRaw, true); dv.setUint32(oh + 16, 0x1000, true); dv.setUint32(oh + 20, 0x1000, true); dv.setUint32(oh + 28, 0x400000, true);
  dv.setUint32(oh + 32, SA, true); dv.setUint32(oh + 36, FA, true); dv.setUint16(oh + 40, 6, true); dv.setUint16(oh + 48, 6, true); dv.setUint32(oh + 56, idVA + align(idRaw, SA), true); dv.setUint32(oh + 60, 0x200, true); dv.setUint16(oh + 68, 2, true); dv.setUint32(oh + 92, 16, true);
  dv.setUint32(oh + 96 + 8, idVA, true); dv.setUint32(oh + 96 + 12, off, true);
  const sh = oh + 0xe0;
  hdr.set([0x2e, 0x74, 0x65, 0x78, 0x74], sh); dv.setUint32(sh + 8, code.length, true); dv.setUint32(sh + 12, 0x1000, true); dv.setUint32(sh + 16, textRaw, true); dv.setUint32(sh + 20, 0x200, true); dv.setUint32(sh + 36, 0x60000020, true);
  hdr.set([0x2e, 0x69, 0x64, 0x61, 0x74, 0x61], sh + 40); dv.setUint32(sh + 48, off, true); dv.setUint32(sh + 52, idVA, true); dv.setUint32(sh + 56, idRaw, true); dv.setUint32(sh + 60, 0x200 + textRaw, true); dv.setUint32(sh + 76, 0xc0000040, true);
  const out = new Uint8Array(0x200 + textRaw + idRaw); out.set(hdr, 0); out.set(code, 0x200); out.set(id, 0x200 + textRaw); return out;
}
/* Kod parçaları */
const FILL = [0x55, 0x8b, 0xec, 0x5d, 0xc3];                 /* push ebp; mov ebp,esp; pop ebp; ret (zararsız dolgu) */
const fill = (n) => { const a = []; while (a.length < n) a.push(...FILL); return a; };
const nops = (n) => new Array(n).fill(0x90);
/* MBA tarzı yığın dize çözme: 5 yığın dword'ü + bayt döngüsü (not/or/and + add cl + geri yaz) */
function mbaLoop(seed) {
  const c = [];
  for (let i = 0; i < 5; i++) c.push(0xc7, 0x44, 0x24, 0x10 + i * 4, ...u32((seed * 2654435761 + i * 40503) >>> 0));
  c.push(0x31, 0xc0);                                         /* xor eax,eax */
  c.push(0x0f, 0xb6, 0x4c, 0x04, 0x10);                       /* movzx ecx, byte [esp+eax+0x10] */
  c.push(0x89, 0xc2, 0xf7, 0xd2, 0x81, 0xca, ...u32(0xfffffff5)); /* mov edx,eax; not edx; or edx,imm32 */
  c.push(0x21, 0xca, 0x23, 0xd1);                             /* and edx,ecx; and edx,ecx */
  c.push(0x80, 0xc1, 0x85);                                   /* add cl,0x85 */
  c.push(0x88, 0x4c, 0x04, 0x10);                             /* mov [esp+eax+0x10], cl */
  c.push(0x40, 0x83, 0xf8, 0x14, 0x75, 0xe0);                 /* inc eax; cmp eax,0x14; jne */
  return c;
}
/* Mantık işlemi OLMAYAN bayt döngüsü (ör. toupper benzeri): MBA sayılmamalı */
function plainLoop() {
  return [0x31, 0xc0, 0x0f, 0xb6, 0x4c, 0x04, 0x10, 0x80, 0xc1, 0x20, 0x88, 0x4c, 0x04, 0x10, 0x40, 0x83, 0xf8, 0x14, 0x75, 0xf0];
}
const K32 = ['ExitProcess', 'GetCurrentProcessId', 'GetCurrentThreadId', 'GetDiskFreeSpaceW', 'CreateThread'];
const CAPS = { 'GDI32.dll': ['BitBlt', 'CreateCompatibleBitmap', 'CreateCompatibleDC'], 'USER32.dll': ['OpenClipboard', 'GetClipboardData', 'CloseClipboard'], 'ole32.dll': ['CoCreateInstance', 'CoSetProxyBlanket', 'CoInitializeSecurity'] };
const scan = async (u8) => { const r = await E.scanFile(new File([u8], 'sample.exe'), { mode: 'normal' }); r.ids = r.findings.map((f) => f.id); return r; };

/* 1) Tam profil: MBA + NOP + gizli API + ekran/pano/WMI → pe_stl_profile, yüksek risk */
let code = []; for (let i = 0; i < 40; i++) { code.push(...mbaLoop(i + 1)); code.push(...nops(10 + (i % 5)), 0x40); } for (let i = 0; i < 120; i++) code.push(...nops(9), 0x48); code.push(...fill(110000));
const full = await scan(makePE(new Uint8Array(code), { 'KERNEL32.dll': K32, ...CAPS }));
ok(['pe_stl_mba', 'pe_stl_nop', 'pe_stl_hidden', 'pe_stl_caps', 'pe_stl_profile'].every((x) => full.ids.includes(x)), 'tam profil: beş pe_stl_* bulgusu da çıktı (' + full.ids.filter((x) => /pe_stl/.test(x)).join(',') + ')');
ok(full.score >= 55 && full.score < 100, 'tam profil: skor Yüksek risk aralığında ama kesin 100 değil (' + full.score + ' ' + full.verdict + ')');
ok(full.findings.filter((f) => /^pe_stl_/.test(f.id)).every((f) => f.basis === 'heuristic'), 'pe_stl_* bulguları "heuristic" olarak işaretli (kanıt iddiası yok)');
ok(/aile tespiti değil/.test(full.findings.find((f) => f.id === 'pe_stl_profile').why), 'profil bulgusu aile tespiti iddia etmiyor, dürüstçe belirtiyor');
ok(full.info && full.info.stealth && full.info.stealth.mbaLoops >= 40, 'info.stealth sayaçları dolu (mbaLoops=' + (full.info.stealth && full.info.stealth.mbaLoops) + ')');

/* 2) Temiz: aynı importlar + dolgu, kalıp yok → hiçbir pe_stl_ bulgusu OLMAMALI (ağ importu + LoadLibrary yok ama kod 100 KB; caps tek başına) */
const benign = await scan(makePE(new Uint8Array(fill(120000)), { 'KERNEL32.dll': [...K32, 'LoadLibraryA', 'GetProcAddress'], ...CAPS, 'WS2_32.dll': ['socket', 'connect', 'send'] }));
ok(!benign.ids.some((x) => /^pe_stl_/.test(x)) && benign.score < 30, 'temiz (ağ + LoadLibrary var, kalıp yok): pe_stl_ yok, skor ' + benign.score);

/* 3) Yalnız NOP kızakları (LoadLibrary var): en çok zayıf pe_stl_nop, profil YOK, skor Şüpheli altı */
let c3 = []; for (let i = 0; i < 150; i++) c3.push(...nops(12), 0x48); c3.push(...fill(110000));
const onlyNop = await scan(makePE(new Uint8Array(c3), { 'KERNEL32.dll': [...K32, 'LoadLibraryA', 'GetProcAddress'] }));
ok(!onlyNop.ids.includes('pe_stl_profile') && onlyNop.score < 30, 'yalnız NOP kızakları: profil yok, skor ' + onlyNop.score + ' (' + onlyNop.verdict + ')');

/* 4) Mantık işlemi olmayan bayt döngüleri MBA sayılmaz (sade kod: toupper/ofset kaydırma) */
let c4 = []; for (let i = 0; i < 60; i++) c4.push(...plainLoop(), ...nops(2)); c4.push(...fill(20000));
const plain = await scan(makePE(new Uint8Array(c4), { 'KERNEL32.dll': [...K32, 'LoadLibraryA', 'GetProcAddress'] }));
ok(!plain.ids.includes('pe_stl_mba'), 'mantık işlemsiz bayt döngüleri MBA sayılmadı');

/* 5) Yalnız yetenek importları (3 grup, ağ yok) küçük kodla: caps çıkar ama profil çıkmaz */
const capsOnly = await scan(makePE(new Uint8Array(fill(8000)), { 'KERNEL32.dll': [...K32, 'LoadLibraryA'], ...CAPS }));
ok(!capsOnly.ids.includes('pe_stl_profile'), 'tek başına yetenek kombinasyonu profil üretmez (skor ' + capsOnly.score + ')');

/* 6) .NET ve bozuk girdi: modül hata fırlatmaz */
const junk = new Uint8Array(40000); junk[0] = 0x4d; junk[1] = 0x5a; let thrown = false; try { await scan(junk); } catch (e) { thrown = true; }
ok(!thrown, 'bozuk MZ dosyasında tarama hata vermiyor');

/* 7) Gerçek örnek (isteğe bağlı, depoda YOK): STEALTH_SAMPLE=<yol> ile yerelde denenir */
if (process.env.STEALTH_SAMPLE && fs.existsSync(process.env.STEALTH_SAMPLE)) { const r = await scan(new Uint8Array(fs.readFileSync(process.env.STEALTH_SAMPLE))); ok(r.ids.includes('pe_stl_profile'), 'gerçek örnek: pe_stl_profile çıktı (skor ' + r.score + ')'); } else console.log('SKIP gerçek örnek (STEALTH_SAMPLE yok; örnek depoya konmaz)');
console.log(bad ? bad + ' test başarısız' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
