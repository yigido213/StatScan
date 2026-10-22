// x86/x64 disassembler'i objdump -M intel ile birebir karsilastirir (yalnizca gelistirme makinesi: gcc, clang, objdump gerekir).
// node tools/test/disasm-objdump.mjs [--verbose]
import { execFileSync, spawnSync } from 'node:child_process'; import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { fileURLToPath } from 'node:url'; import { loadEngine } from './engine.mjs';
const here = path.dirname(fileURLToPath(import.meta.url)); const gen = path.join(here, 'gen/disasm'); const verbose = process.argv.includes('--verbose');
const have = (c) => spawnSync('which', [c]).status === 0; if (!have('objdump') || !have('gcc')) { console.log('objdump/gcc yok: test atlandı'); process.exit(0); }
const E = loadEngine(); const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ssdis-')); const jobs = [];
const run = (cmd, args) => { const r = spawnSync(cmd, args, { encoding: 'utf8' }); if (r.status !== 0) { console.log('derleme başarısız:', cmd, args.join(' '), (r.stderr || '').slice(0, 200)); return false; } return true; };
for (const f of ['a', 'b']) for (const O of ['-O0', '-O1', '-O2', '-O3', '-Os']) {
  const o64 = path.join(tmp, `${f}${O}.gcc64`); if (run('gcc', [O, '-fno-pie', '-no-pie', path.join(gen, f + '.c'), '-o', o64, '-lm'])) jobs.push([o64, 64]);
  const p64 = path.join(tmp, `${f}${O}.pie64`); if (run('gcc', [O, path.join(gen, f + '.c'), '-o', p64, '-lm'])) jobs.push([p64, 64]);
  const o32 = path.join(tmp, `${f}${O}.gcc32.o`); if (run('gcc', ['-m32', '-ffreestanding', O, '-c', path.join(gen, f + '_fs.c'), '-o', o32])) jobs.push([o32, 32]);
  if (have('clang')) { const c64 = path.join(tmp, `${f}${O}.clang64`); if (run('clang', [O, path.join(gen, f + '.c'), '-o', c64, '-lm'])) jobs.push([c64, 64]); const c32 = path.join(tmp, `${f}${O}.clang32.o`); if (run('clang', ['-target', 'i686-linux-gnu', '-ffreestanding', O, '-c', path.join(gen, f + '_fs.c'), '-o', c32])) jobs.push([c32, 32]); }
}
const ex = process.argv.indexOf('--files'); if (ex > 0) for (const f of process.argv.slice(ex + 1)) jobs.push([f, 64]);
const norm = (s) => s.replace(/\s*<[^>]*>/g, '').replace(/\s*#.*$/, '').replace(/\s+/g, ' ').trim();
let total = 0, ok = 0, lenBad = 0, textBad = 0, nul = 0; const bad = new Map(); const nulls = new Map();
for (const [file, bits] of jobs) {
  const h = execFileSync('objdump', ['-h', file], { encoding: 'utf8' }); const secs = {}; for (const m of h.matchAll(/^\s*\d+\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)/gm)) secs[m[1]] = { size: parseInt(m[2], 16), vma: parseInt(m[3], 16), off: parseInt(m[5], 16) };
  const data = new Uint8Array(fs.readFileSync(file)); const d = execFileSync('objdump', ['-d', '-M', 'intel', '--insn-width=16', file], { encoding: 'utf8', maxBuffer: 1 << 28 }); let sec = null;
  for (const line of d.split('\n')) {
    const sm = /^Disassembly of section (\S+):/.exec(line); if (sm) { sec = secs[sm[1]]; continue; } if (!sec) continue;
    const m = /^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t?(.*)$/.exec(line); if (!m) continue; const addr = parseInt(m[1], 16); const blen = m[2].trim().split(' ').length; const txt = norm(m[3]); if (!txt || /^\(bad\)|^\.byte/.test(txt)) continue;
    const fo = sec.off + (addr - sec.vma); total++; const r = E.x86Decode(data, fo, bits === 64, addr);
    if (!r) { nul++; const k = txt.split(' ')[0] + ' [' + m[2].trim().split(' ').slice(0, 4).join(' ') + ']'; nulls.set(k, (nulls.get(k) || 0) + 1); continue; }
    if (r.len !== blen) { lenBad++; const k = 'UZUNLUK ' + txt + ' | benim: ' + r.text + ' len ' + r.len + '≠' + blen; bad.set(k, (bad.get(k) || 0) + 1); continue; }
    if (norm(r.text) !== txt) { textBad++; const k = 'METİN  ' + txt + '  |  benim: ' + r.text; bad.set(k, (bad.get(k) || 0) + 1); continue; } ok++;
  }
}
fs.rmSync(tmp, { recursive: true, force: true });
console.log(`${jobs.length} ikili, ${total} komut: ${ok} birebir eşleşti, ${textBad} metin farkı, ${lenBad} uzunluk farkı, ${nul} çözülemedi`);
const show = (m, t, n) => { const a = [...m].sort((x, y) => y[1] - x[1]).slice(0, n); if (a.length) { console.log(t); for (const [k, c] of a) console.log('  ' + c + '× ' + k); } };
show(bad, 'Farklar:', verbose ? 200 : 25); show(nulls, 'Çözülemeyenler (opcode):', verbose ? 200 : 25);
process.exit(textBad || lenBad ? 1 : 0);
