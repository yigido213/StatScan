// 4.6 yerel kod analizi: ELF/PE yukleyici, islev kesfi, ana kod bulma (gcc/clang/lld-link gerekir; yoksa atlanir)
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { execFileSync, spawnSync } from 'node:child_process'; import { fileURLToPath } from 'node:url'; import { loadEngine } from './engine.mjs';
const E = loadEngine(); let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const has = (c) => spawnSync('which', [c]).status === 0; if (!has('gcc') || !has('objdump') || !has('nm')) { console.log('SKIP gcc/objdump/nm yok'); process.exit(0); }
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nat-')); const gen = path.join(path.dirname(fileURLToPath(import.meta.url)), 'gen');
const src = `#include <stdio.h>\n#include <string.h>\nstatic int helper(int x){ return x*3+1; }\nint check(const char*s){ if(strcmp(s,"secret")==0){ puts("access granted"); return helper(7);} puts("denied"); return 0; }\nint main(int argc,char**argv){ if(argc>1) return check(argv[1]); printf("usage: %s <pw>\\n",argv[0]); return 1; }\n`;
fs.writeFileSync(dir + '/m.c', src);
const build = (out, flags) => execFileSync('gcc', ['-O1', ...flags, '-o', dir + '/' + out, dir + '/m.c']);
build('pie', []); build('nopie', ['-no-pie']); build('strip', []); execFileSync('strip', [dir + '/strip']);
const load = (f) => new Uint8Array(fs.readFileSync(dir + '/' + f)); const nm = (f) => { const o = {}; for (const l of execFileSync('nm', ['-S', '--defined-only', dir + '/' + f]).toString().split('\n')) { const m = /^([0-9a-f]+) ([0-9a-f]+) [Tt] (\S+)$/.exec(l); if (m) o[m[3]] = { a: parseInt(m[1], 16), s: parseInt(m[2], 16) }; } return o; };
for (const f of ['pie', 'nopie']) {
  const r = E.nativeAnalyze(load(f)); const s = nm(f); ok(r.ok && r.format === 'elf', f + ': yüklendi'); ok(r.main.addr === s.main.a && r.main.level === 'kesin', f + ': main adresi nm ile aynı (' + r.main.addr.toString(16) + ', ' + r.main.level + ')');
  for (const n of ['main', 'check']) { const fn = r.funcs.find((x) => x.start === s[n].a); ok(fn && fn.size === s[n].s, f + ': ' + n + ' sınırı nm ile birebir (' + (fn ? fn.size : '?') + '/' + s[n].s + ')'); }
  const od = execFileSync('objdump', ['-d', '-M', 'intel', '--no-show-raw-insn', '--disassemble=check', dir + '/' + f]).toString().split('\n').map((l) => /^\s+([0-9a-f]+):\s+(.*)$/.exec(l)).filter(Boolean).map((m) => parseInt(m[1], 16) + ' ' + m[2].replace(/\s+/g, ' ').replace(/\s*#.*$/, '').replace(/\s*<.*>$/, '').trim());
  const mine = [...r.funcs.find((x) => x.start === s.check.a).insns.values()].sort((a, b) => a.addr - b.addr).map((i) => i.addr + ' ' + i.text); const norm = (a) => a.map((x) => x.replace(/ 0x([0-9a-f]+)$/, ' $1')); ok(JSON.stringify(norm(od)) === JSON.stringify(norm(mine)), f + ': check() komut listesi objdump ile birebir (' + mine.length + ' komut)');
  ok(/"access granted"/.test(r.allText) && /"secret"/.test(r.allText) && /puts/.test(r.mainText + r.allText), f + ': dize ve import adlandırması');
  ok(/DECOMPILE \(C kodu\) DEĞİLDİR/.test(r.mainText), f + ': başlıkta decompile değil uyarısı');
}
const ps = E.nativeAnalyze(load('strip')), pi = E.nativeAnalyze(load('pie')); ok(ps.ok && ps.main.addr === pi.main.addr && ps.main.level === 'kesin', 'soyulmuş PIE: main yine kesin bulundu (sembolsüz)'); ok(ps.funcs.some((x) => x.addr === ps.main.addr) && ps.notes.some((n) => /Sembol tablosu yok/.test(n)), 'soyulmuş: işlev eklendi, sembol yok notu');
// PE
if (has('clang') && has('lld-link') && has('llvm-dlltool')) {
  execFileSync('bash', [gen + '/build_native.sh', dir]);
  const c64 = E.nativeAnalyze(load('nat_crt64.exe')), c32 = E.nativeAnalyze(load('nat_crt32.exe')), b64 = E.nativeAnalyze(load('nat_bare64.exe'));
  ok(c64.ok && c64.arch === 'x86-64' && c64.main.level === 'sezgisel' && /hello from tiny exe/.test(c64.mainText) && /second message/.test(c64.mainText), 'PE x64: CRT’li örnekte ana kod bulundu (sezgisel) ve dizeleri gösterildi');
  ok(c32.ok && c32.arch === 'x86' && c32.main.level === 'sezgisel' && /hello from tiny exe/.test(c32.mainText), 'PE x86: ana kod bulundu (sezgisel), mutlak adresli dize çözüldü');
  ok(c64.main.evidence.some((e) => /kalıp eşleştirmesidir/.test(e)), 'PE: sezgisel sonucun kanıtı ve uyarısı yazıldı');
  ok(c64.funcs.some((f) => [...f.imports].some((i) => /KERNEL32\.dll!WriteFile/.test(i))) && /ExitProcess/.test(c64.allText), 'PE x64: IAT import adları çözüldü (rex.W jmp [rip] kuyruk çağrısı dahil)');
  ok(b64.ok && b64.main.level === 'giriş-noktası' && /bare entry/.test(b64.mainText), 'PE CRT’siz: giriş noktası ana kod olarak verildi, seviye dürüstçe "giriş-noktası"');
  // obf hatti
  const o = await E.obf(load('nat_crt64.exe'), 'x.exe', {}); ok(o.outputs.some((x) => /ana-kod\.asm$/.test(x.name)) && o.steps.some((s) => s.id === 'native' && s.status === 'done') && o.steps.some((s) => s.id === 'decompile' && s.status === 'unsupported'), 'obf: ana-kod/tum-kod/cagri-grafigi üretildi, C decompile "desteklenmiyor" kaldı');
}
// olumsuz/dayanıklılık
ok(!E.nativeAnalyze(new Uint8Array(100)).ok, 'PE/ELF olmayan dosya reddedildi');
const arm = load('pie').slice(); arm[18] = 0xb7; arm[19] = 0; const ra = E.nativeAnalyze(arm); ok(!ra.ok && /Mimari desteklenmiyor/.test(ra.reason), 'ARM ELF: desteklenmiyor diye dürüstçe reddedildi');
const ent = load('pie').slice(); ent[24] = 0x00; ent[25] = 0x00; ent[26] = 0; ent[27] = 0; const re = E.nativeAnalyze(ent); ok(!re.ok && /yürütülebilir/.test(re.reason), 'geçersiz giriş noktası: açıklamalı red');
let thr = 0, n = 0; const base = fs.existsSync(dir + '/nat_crt64.exe') ? load('nat_crt64.exe') : load('pie'); let seed = 12345; const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
for (let i = 0; i < 300; i++) { const m = base.slice(); for (let k = 0; k < 1 + (i % 12); k++) m[Math.floor(rnd() * Math.min(m.length, 1500))] = Math.floor(rnd() * 256); try { E.nativeAnalyze(m); n++; } catch (e) { thr++; if (thr < 3) console.log(e); } }
ok(thr === 0, 'bozulmuş 300 dosya: istisna yok (' + n + ')');
const big = E.nativeAnalyze(load('pie'), { lim: { insns: 20, funcs: 2 } }); ok(big.ok && big.limits.length > 0 && big.truncated, 'düşük sınırda "kısmi" işaretlendi (sessiz kesme yok)');
console.log(bad ? 'BAŞARISIZ ' + bad : 'TAMAM'); process.exit(bad ? 1 : 0);
