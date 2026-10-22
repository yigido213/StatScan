/* 4.6: yerel (native) x86/x64 kod — yukleyici, fonksiyon kesfi, cagri grafigi, ana kodu bulma. STATIK; kod CALISTIRILMAZ.
   Cikti TAHMIN DEGIL: komut listesi birebir disassembly'dir. Ana islev: ELF'te __libc_start_main argumani (kesin) veya sembol;
   PE'de CRT cagri deseni (sezgisel, kanitiyla) ya da "bulunamadi". Cozulemeyen/dolayli yollar acikca raporlanir. */
const NAT_LIM = { insns: 400000, funcs: 4000, listBytes: 6e6 };
const NAT_NORET = /^(exit|_exit|abort|__stack_chk_fail|__assert_fail|__cxa_throw|longjmp|_longjmp|quick_exit|ExitProcess|ExitThread|TerminateProcess_|RtlExitUserProcess|__fastfail|terminate|_Exit)(@plt)?$/;
function natHex(n, w) { let s = n.toString(16); while (s.length < (w || 0)) s = '0' + s; return s; }
function natU16(b, o) { return b[o] | (b[o + 1] << 8); }
function natU32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }
function natU64(b, o) { return natU32(b, o) + natU32(b, o + 4) * 4294967296; }
function natCStr(b, o, max) { let s = ''; for (let i = o; i < b.length && i < o + (max || 256) && b[i]; i++) s += String.fromCharCode(b[i]); return s; }

function natLoadPE(u8) {
  if (u8.length < 0x100 || u8[0] !== 0x4d || u8[1] !== 0x5a) return { err: 'MZ başlığı yok' };
  const pe = natU32(u8, 0x3c); if (pe + 0x108 > u8.length || natU32(u8, pe) !== 0x4550) return { err: 'PE imzası yok' };
  const machine = natU16(u8, pe + 4); if (machine !== 0x8664 && machine !== 0x14c) return { err: 'Mimari desteklenmiyor (makine 0x' + natHex(machine) + '); yalnızca x86 ve x64' };
  const nsec = natU16(u8, pe + 6), osz = natU16(u8, pe + 20), opt = pe + 24, magic = natU16(u8, opt);
  const is64 = magic === 0x20b; if (magic !== 0x20b && magic !== 0x10b) return { err: 'İsteğe bağlı başlık geçersiz' };
  if ((machine === 0x8664) !== is64) return { err: 'Makine ve başlık türü uyumsuz' };
  const base = is64 ? natU64(u8, opt + 24) : natU32(u8, opt + 28), entryRva = natU32(u8, opt + 16);
  const ddo = opt + (is64 ? 112 : 96), ndd = natU32(u8, opt + (is64 ? 108 : 92)); const dd = (i) => (i < ndd && ddo + i * 8 + 8 <= u8.length ? { rva: natU32(u8, ddo + i * 8), size: natU32(u8, ddo + i * 8 + 4) } : { rva: 0, size: 0 });
  if (dd(14).rva) return { err: '.NET (CLR) derlemesi: yerel kod değil; .NET yapı dökümü kullanılır' };
  const secs = []; const st = opt + osz;
  for (let i = 0; i < nsec && st + i * 40 + 40 <= u8.length; i++) {
    const o = st + i * 40; const vs = natU32(u8, o + 8), va = natU32(u8, o + 12), rs = natU32(u8, o + 16), rp = natU32(u8, o + 20), ch = natU32(u8, o + 36);
    const n = Math.min(vs || rs, rs, Math.max(0, u8.length - rp)); secs.push({ name: natCStr(u8, o, 8), va: base + va, rva: va, vsize: vs || rs, off: rp, n, exec: !!(ch & 0x20000000) || !!(ch & 0x20), write: !!(ch & 0x80000000) });
  }
  const r2o = (rva) => { for (const s of secs) if (rva >= s.rva && rva < s.rva + s.n) return s.off + (rva - s.rva); return -1; };
  const slots = new Map(), exports = new Map(), notes = []; const ps = is64 ? 8 : 4;
  const readImports = (rva, delay) => {
    if (!rva) return; let o = r2o(rva); if (o < 0) { notes.push('Import dizini okunamadı'); return; } const esz = delay ? 32 : 20;
    for (let k = 0; k < 2000 && o + esz <= u8.length; k++, o += esz) {
      let nameRva, ft, oft; if (delay) { nameRva = natU32(u8, o + 4); ft = natU32(u8, o + 12); oft = natU32(u8, o + 16); } else { oft = natU32(u8, o); nameRva = natU32(u8, o + 12); ft = natU32(u8, o + 16); }
      if (!nameRva && !ft) break; const no = r2o(nameRva); const dll = no >= 0 ? natCStr(u8, no, 64) : '?'; const src = r2o(oft || ft); if (src < 0) continue;
      for (let i = 0; i < 4000; i++) {
        const so = src + i * ps; if (so + ps > u8.length) break; const v = is64 ? natU64(u8, so) : natU32(u8, so); if (!v) break;
        let nm; if (is64 ? v >= 9223372036854775808 : v & 0x80000000) nm = '#' + (v % 65536); else { const ho = r2o(v); nm = ho >= 0 ? natCStr(u8, ho + 2, 128) : '?'; }
        slots.set(base + ft + i * ps, dll + '!' + nm + (delay ? ' (gecikmeli)' : ''));
      }
    }
  };
  try { readImports(dd(1).rva, false); readImports(dd(13).rva, true); } catch (e) { notes.push('Import okuma hatası'); }
  try {
    const e = dd(0); const eo = e.rva ? r2o(e.rva) : -1;
    if (eo >= 0) { const nf = natU32(u8, eo + 20), nn = natU32(u8, eo + 24), af = r2o(natU32(u8, eo + 28)), an = r2o(natU32(u8, eo + 32)), ao = r2o(natU32(u8, eo + 36)); if (af >= 0 && an >= 0 && ao >= 0) for (let i = 0; i < Math.min(nn, 5000); i++) { const nm = natCStr(u8, r2o(natU32(u8, an + i * 4)), 128); const idx = natU16(u8, ao + i * 2); if (idx >= nf) continue; const fr = natU32(u8, af + idx * 4); if (fr >= e.rva && fr < e.rva + e.size) continue; exports.set(base + fr, nm); } }
  } catch (e) { notes.push('Export okuma hatası'); }
  const pdata = []; if (is64) { const d = dd(3); const po = d.rva ? r2o(d.rva) : -1; if (po >= 0) for (let i = 0; i < Math.min(d.size / 12 | 0, 30000); i++) { const b0 = natU32(u8, po + i * 12), e0 = natU32(u8, po + i * 12 + 4); if (!b0 || e0 <= b0) continue; pdata.push({ a: base + b0, e: base + e0 }); } }
  return { fmt: 'pe', arch: is64 ? 'x86-64' : 'x86', is64, base, entry: base + entryRva, secs, slots, exports, syms: new Map(), pdata, notes };
}

function natLoadELF(u8) {
  if (u8.length < 64 || u8[0] !== 0x7f || u8[1] !== 0x45 || u8[2] !== 0x4c || u8[3] !== 0x46) return { err: 'ELF imzası yok' };
  if (u8[5] !== 1) return { err: 'Big-endian ELF desteklenmiyor' }; const is64 = u8[4] === 2; if (u8[4] !== 1 && !is64) return { err: 'ELF sınıfı geçersiz' };
  const mach = natU16(u8, 18); if (mach !== 62 && mach !== 3) return { err: 'Mimari desteklenmiyor (e_machine ' + mach + '); yalnızca x86 ve x86-64' };
  if ((mach === 62) !== is64) return { err: 'Sınıf ve makine uyumsuz' };
  const rd = (o) => (is64 ? natU64(u8, o) : natU32(u8, o)); const entry = is64 ? natU64(u8, 24) : natU32(u8, 24);
  const shoff = is64 ? natU64(u8, 40) : natU32(u8, 32), shentsz = is64 ? natU16(u8, 58) : natU16(u8, 46), shnum = is64 ? natU16(u8, 60) : natU16(u8, 48), shstr = is64 ? natU16(u8, 62) : natU16(u8, 50);
  const phoff = is64 ? natU64(u8, 32) : natU32(u8, 28), phentsz = is64 ? natU16(u8, 54) : natU16(u8, 42), phnum = is64 ? natU16(u8, 56) : natU16(u8, 44);
  const secs = [], notes = [], syms = new Map(), slots = new Map(), sizes = new Map(); const shs = [];
  if (shoff && shentsz >= 40 && shoff + shnum * shentsz <= u8.length) for (let i = 0; i < Math.min(shnum, 200); i++) {
    const o = shoff + i * shentsz; shs.push(is64 ? { nm: natU32(u8, o), type: natU32(u8, o + 4), flags: natU64(u8, o + 8), addr: natU64(u8, o + 16), off: natU64(u8, o + 24), size: natU64(u8, o + 32), link: natU32(u8, o + 40), entsz: natU64(u8, o + 56) } : { nm: natU32(u8, o), type: natU32(u8, o + 4), flags: natU32(u8, o + 8), addr: natU32(u8, o + 12), off: natU32(u8, o + 16), size: natU32(u8, o + 20), link: natU32(u8, o + 24), entsz: natU32(u8, o + 36) });
  }
  const strOf = (si, off) => (shs[si] && shs[si].off + off < u8.length ? natCStr(u8, shs[si].off + off, 256) : '');
  if (shs.length && shstr < shs.length) { for (const s of shs) { s.name = strOf(shstr, s.nm); if ((s.flags & 2) && s.type !== 8 && s.addr && s.off + s.size <= u8.length) secs.push({ name: s.name, va: s.addr, off: s.off, n: s.size, vsize: s.size, exec: !!(s.flags & 4), write: !!(s.flags & 1) }); } }
  if (!secs.length) { for (let i = 0; i < Math.min(phnum, 64); i++) { const o = phoff + i * phentsz; if (natU32(u8, o) !== 1) continue; const f = is64 ? { fl: natU32(u8, o + 4), off: natU64(u8, o + 8), va: natU64(u8, o + 16), fs: natU64(u8, o + 32) } : { fl: natU32(u8, o + 24), off: natU32(u8, o + 4), va: natU32(u8, o + 8), fs: natU32(u8, o + 16) }; if (f.off + f.fs <= u8.length) secs.push({ name: 'LOAD' + i, va: f.va, off: f.off, n: f.fs, vsize: f.fs, exec: !!(f.fl & 1), write: !!(f.fl & 2) }); } if (secs.length) notes.push('Bölüm tablosu yok/bozuk: program başlıkları (PT_LOAD) kullanıldı; sembol/PLT adları eksik olabilir.'); }
  if (!secs.length) return { err: 'Yüklenebilir bölüm bulunamadı' };
  const symtabs = {}; for (let si = 0; si < shs.length; si++) {
    const s = shs[si]; if (s.type !== 2 && s.type !== 11) continue; const esz = is64 ? 24 : 16; const list = []; const cnt = Math.min(Math.floor(s.size / esz), 60000);
    for (let i = 0; i < cnt; i++) { const o = s.off + i * esz; if (o + esz > u8.length) break; const nm = natU32(u8, o), info = u8[o + (is64 ? 4 : 12)], shndx = natU16(u8, o + (is64 ? 6 : 14)), val = is64 ? natU64(u8, o + 8) : natU32(u8, o + 4), sz = is64 ? natU64(u8, o + 16) : natU32(u8, o + 8); const name = strOf(s.link, nm); list.push({ name, type: info & 15, shndx, val, size: sz }); if ((info & 15) === 2 && shndx !== 0 && val && name) { if (!syms.has(val)) syms.set(val, name); sizes.set(val, sz); } }
    symtabs[si] = list;
  }
  for (const s of shs) {
    if (s.type !== 4 && s.type !== 9) continue; const esz = s.type === 4 ? (is64 ? 24 : 12) : (is64 ? 16 : 8); const list = symtabs[s.link]; if (!list) continue;
    for (let i = 0; i < Math.min(Math.floor(s.size / esz), 40000); i++) { const o = s.off + i * esz; if (o + esz > u8.length) break; const off = rd(o); let sym, typ; if (is64) { const inf = natU64(u8, o + 8); sym = Math.floor(inf / 4294967296); typ = inf % 4294967296; } else { const inf = natU32(u8, o + 4); sym = inf >>> 8; typ = inf & 255; } if ((typ === 7 || typ === 6) && list[sym] && list[sym].name) slots.set(off, list[sym].name); }
  }
  return { fmt: 'elf', arch: is64 ? 'x86-64' : 'x86', is64, base: 0, entry, secs, slots, exports: new Map(), syms, sizes, pdata: [], notes, symtabCount: Object.keys(symtabs).length };
}

function natStrAt(img, u8, va) {
  const s = img.secs.find((x) => va >= x.va && va < x.va + x.n); if (!s || s.exec) return null; const o = s.off + (va - s.va), end = Math.min(s.off + s.n, o + 96); if (o >= end) return null;
  let i = o, t = ''; while (i < end && u8[i] >= 0x20 && u8[i] < 0x7f || (i < end && (u8[i] === 9 || u8[i] === 10 || u8[i] === 13))) { t += u8[i] === 10 ? '\\n' : u8[i] === 13 ? '\\r' : u8[i] === 9 ? '\\t' : String.fromCharCode(u8[i]); i++; }
  if (t.length >= 4 && (i >= end || u8[i] === 0)) return '"' + t + (i >= end && u8[i] ? '…' : '') + '"';
  i = o; t = ''; while (i + 1 < end && u8[i + 1] === 0 && u8[i] >= 0x20 && u8[i] < 0x7f) { t += String.fromCharCode(u8[i]); i += 2; }
  if (t.length >= 4 && i + 1 < end + 1 && (i + 1 >= end || (u8[i] === 0 && u8[i + 1] === 0))) return 'L"' + t + '"'; return null;
}

function natDiscover(img, u8, extraSeeds, lim) {
  const is64 = img.is64; const secOf = (va) => { for (const s of img.secs) if (va >= s.va && va < s.va + s.n) return s; return null; };
  const dis = (va) => { const s = secOf(va); if (!s || !s.exec) return null; const off = s.off + (va - s.va), l = s.off + s.n; if (off >= l) return null; const I = x86Decode(u8, off, is64, va); if (!I || off + I.len > l) return null; I.addr = va; I.off = off; return I; };
  const funcs = new Map(), thunks = new Map(), queue = [], known = new Set(); let total = 0, truncated = false; const limits = [];
  const nameOf = (a) => { const f = funcs.get(a); if (f) return f.name; if (img.exports.has(a)) return img.exports.get(a); if (img.syms.has(a)) return img.syms.get(a); if (thunks.has(a)) return thunks.get(a); return null; };
  const addKnown = (a, nm, src) => { if (secOf(a) && secOf(a).exec) { known.add(a); if (nm && !img.syms.has(a) && !img.exports.has(a)) img.syms.set(a, nm); } };
  for (const [a, nm] of img.exports) addKnown(a, null); for (const [a] of img.syms) addKnown(a, null); for (const p of img.pdata) addKnown(p.a, null);
  const seed = (a, name, src) => {
    if (funcs.has(a) || thunks.has(a)) return true; const s = secOf(a); if (!s || !s.exec) return false;
    { const pn = img.syms.get(a); if (pn && /@plt$/.test(pn)) { thunks.set(a, pn.replace(/@plt$/, '') + ' (PLT)'); return true; } }
    const I = dis(a); if (I && I.kind === 'jmpi' && typeof I.ptr === 'number' && img.slots.has(I.ptr)) { thunks.set(a, img.slots.get(I.ptr)); return true; }
    if (funcs.size >= lim.funcs) { truncated = true; if (!limits.includes('fonksiyon')) limits.push('fonksiyon'); return false; }
    const f = { addr: a, name: name || img.exports.get(a) || img.syms.get(a) || 'sub_' + natHex(a), src: src || 'çağrı hedefi', insns: new Map(), leaders: new Set([a]), calls: new Map(), imports: new Set(), incomplete: [], indirect: 0, tails: new Set() };
    funcs.set(a, f); queue.push(f); return true;
  };
  const explore = (f) => {
    const stack = [f.addr], seen = f.insns;
    while (stack.length) {
      let a = stack.pop();
      for (;;) {
        if (seen.has(a)) break; if (a !== f.addr && known.has(a) && !f.leaders.has(a)) { f.tails.add(a); f.calls.set(a, 'tail'); break; }
        if (total >= lim.insns) { truncated = true; if (!limits.includes('komut')) limits.push('komut'); return; }
        const I = dis(a); if (!I) { const s = secOf(a); f.incomplete.push('0x' + natHex(a) + ': ' + (s && s.exec ? 'komut çözülemedi' : 'kod bölümü dışına/sonuna çıkıldı')); break; }
        seen.set(a, I); total++; const nx = a + I.len;
        if (I.kind === 'ret' || I.kind === 'int3' || I.kind === 'ud2' || I.kind === 'hlt') break;
        if (I.kind === 'jcc') { if (typeof I.target === 'number' && I.target >= 0) { f.leaders.add(I.target); f.leaders.add(nx); stack.push(I.target); } a = nx; continue; }
        if (I.kind === 'jmp') {
          const t = I.target; if (typeof t !== 'number' || t < 0) break; const th = dis(t);
          if (thunks.has(t) || (th && th.kind === 'jmpi' && typeof th.ptr === 'number' && img.slots.has(th.ptr)) || (known.has(t) && t !== f.addr && !f.leaders.has(t))) { seed(t); f.calls.set(t, 'tail'); break; }
          f.leaders.add(t); a = t; continue;
        }
        if (I.kind === 'call') {
          const t = I.target; let noret = false; if (typeof t === 'number' && t >= 0 && seed(t)) { f.calls.set(t, f.calls.get(t) || 'call'); const nm = nameOf(t); if (nm && NAT_NORET.test(nm)) noret = true; } if (noret) break; a = nx; continue;
        }
        if (I.kind === 'calli' || I.kind === 'jmpi') {
          const nm = typeof I.ptr === 'number' ? img.slots.get(I.ptr) : null; if (nm) { f.imports.add(nm); if (NAT_NORET.test(nm.split('!').pop())) break; } else f.indirect++;
          if (I.kind === 'jmpi') { if (!nm) f.incomplete.push('0x' + natHex(a) + ': dolaylı atlama (' + I.text + ') — hedefler çözülemedi (anahtar tablosu/işaretçi olabilir)'); break; } a = nx; continue;
        }
        a = nx;
      }
    }
  };
  for (const sd of extraSeeds) seed(sd.a, sd.name, sd.src);
  for (let i = 0; i < queue.length; i++) { explore(queue[i]); if (truncated && limits.includes('komut')) break; }
  for (const f of funcs.values()) { let mn = Infinity, mx = 0; for (const I of f.insns.values()) { if (I.addr < mn) mn = I.addr; if (I.addr + I.len > mx) mx = I.addr + I.len; } f.start = f.insns.size ? mn : f.addr; f.end = mx; f.size = f.insns.size ? mx - mn : 0; for (const I of f.insns.values()) if ((I.kind === 'calli' || I.kind === 'jmpi') && typeof I.ptr === 'number' && img.slots.has(I.ptr)) f.imports.add(img.slots.get(I.ptr)); }
  for (const f of funcs.values()) { for (const [t] of f.calls) { const th = thunks.get(t); if (th) f.imports.add(th); } }
  return { funcs, thunks, total, truncated, limits, dis, secOf, nameOf };
}

function natFindMain(img, d, u8) {
  const ev = []; const fn = (a) => { const f = d.funcs.get(a); return f ? f.name : 'sub_' + natHex(a); };
  const sym = [...img.syms].find(([, n]) => n === 'main');
  if (img.fmt === 'elf') {
    const entry = d.dis(img.entry); const lin = []; let a = img.entry; for (let i = 0; i < 60 && a; i++) { const I = d.dis(a); if (!I) break; lin.push(I); if (I.kind === 'call' || I.kind === 'calli') { const nm = I.kind === 'calli' ? (img.slots.get(I.ptr) || '') : (d.nameOf(I.target) || ''); if (/^__libc_start_main/.test(nm)) { let m = null, mi = null; for (let k = lin.length - 2; k >= 0; k--) { const J = lin[k]; if (img.is64) { const g = /^(lea|mov) (rdi|edi),(.*)$/.exec(J.text); if (g) { if (g[1] === 'lea' && typeof J.ptr === 'number') m = J.ptr; else if (g[1] === 'mov' && /^0x[0-9a-f]+$/.test(g[3])) m = parseInt(g[3], 16); mi = J; break; } if (/^(call|jmp)/.test(J.text)) break; } else { if (J.mnem === 'push') { const g = /^0x[0-9a-f]+$/.exec(J.ops); if (g) m = parseInt(J.ops, 16); mi = J; break; } } } if (m !== null && d.secOf(m)) return { addr: m, level: 'kesin', method: 'ELF giriş kodu: __libc_start_main’in ilk argümanı (main)', evidence: ['giriş noktası 0x' + natHex(img.entry) + ' → __libc_start_main çağrısı 0x' + natHex(I.addr), 'main adresi: 0x' + natHex(mi.addr) + ' `' + mi.text + '` (' + (img.is64 ? 'SysV x86-64: rdi' : 'cdecl: son push') + ')'].concat(sym && sym[0] === m ? ['sembol tablosu da aynı adresi main olarak veriyor'] : []) }; ev.push('__libc_start_main çağrısı bulundu ama main argümanı sabit adres olarak okunamadı (' + (mi ? mi.text : 'kurulum komutu yok') + ')'); break; } } if (I.kind === 'ret' || I.kind === 'jmp' || I.kind === 'jmpi') break; a += I.len; }
    if (sym) return { addr: sym[0], level: 'kesin', method: 'sembol tablosunda main', evidence: ev.concat(['.symtab/.dynsym: main = 0x' + natHex(sym[0])]) };
    if (!entry) ev.push('giriş noktası çözülemedi'); return { addr: null, level: 'bulunamadı', method: 'ELF', evidence: ev.concat(['main’i belirleyen sabit bir adres bulunamadı (soyulmuş/PIE-32 olabilir)']) };
  }
  if (sym) return { addr: sym[0], level: 'kesin', method: 'sembol', evidence: ['sembol: main'] };
  const ef = d.funcs.get(img.entry); if (!ef) return { addr: null, level: 'bulunamadı', method: 'PE', evidence: ['giriş noktası işlevi bulunamadı'] };
  const depth = new Map([[ef.addr, 0]]); const order = [ef]; for (let i = 0; i < order.length; i++) { const f = order[i]; const dp = depth.get(f.addr); if (dp >= 4) continue; for (const [t] of f.calls) { const g = d.funcs.get(t); if (g && !depth.has(t)) { depth.set(t, dp + 1); order.push(g); } } }
  const cands = [];
  for (const f of order) {
    const L = [...f.insns.values()].sort((x, y) => x.addr - y.addr);
    for (let i = 0; i < L.length; i++) {
      const C = L[i]; if (C.kind !== 'call' || typeof C.target !== 'number' || !d.funcs.has(C.target) || C.target === f.addr) continue;
      const nx = []; for (let k = i + 1; k < Math.min(L.length, i + 4); k++) { if (L[k].addr !== (k === i + 1 ? C.addr + C.len : L[k - 1].addr + L[k - 1].len)) break; nx.push(L[k]); }
      if (!nx.length) continue; const pv = []; for (let k = i - 1; k >= Math.max(0, i - 10); k--) { if (L[k].addr + L[k].len !== (k === i - 1 ? C.addr : L[k + 1].addr)) break; pv.push(L[k]); }
      const exitF = L.slice(i + 1, i + 9).some((N) => ((N.kind === 'calli' || N.kind === 'jmpi') && typeof N.ptr === 'number' && /exit/i.test(img.slots.get(N.ptr) || '')) || ((N.kind === 'call' || N.kind === 'jmp') && typeof N.target === 'number' && NAT_NORET.test(d.nameOf(N.target) || '')));
      if (img.is64) {
        const w = new Set(); for (const P of pv) { const dst = P.ops.split(',')[0]; if (/^(mov|lea|xor|sub|add)$/.test(P.mnem)) { if (/^(ecx|rcx)$/.test(dst)) w.add('c'); else if (/^(edx|rdx)$/.test(dst)) w.add('d'); else if (/^(r8d|r8)$/.test(dst)) w.add('r8'); } }
        const sv = nx.slice(0, 2).some((N) => /^mov (e[a-z]{2}|r\d+d),eax$/.test(N.text));
        if (w.size === 3 && sv) cands.push({ f, C, depth: depth.get(f.addr), score: 3, why: 'x64: rcx/rdx/r8 hazırlandı (argc, argv, envp) → çağrı → dönüş değeri eax saklandı' });
        else if (w.size >= 1 && sv && exitF) cands.push({ f, C, depth: depth.get(f.addr), score: 2, why: 'x64: argüman yazmacı hazırlandı → çağrı → dönüş değeri (eax) → exit/ExitProcess' + (w.size < 3 ? ' (derleyici kullanılmayan argc/argv/envp yüklemelerini atmış olabilir)' : '') });
      } else {
        let np = 0; for (const P of pv) { if (P.mnem === 'push') np++; else break; }
        const ad = nx[0] && /^add esp,0x([0-9a-f]+)$/.exec(nx[0].text);
        if (np >= 3 && ad && ad[1] === 'c' && nx.slice(1, 3).some((N) => /^mov [a-z]+,eax$/.test(N.text) || /^mov DWORD PTR .*,eax$/.test(N.text))) cands.push({ f, C, depth: depth.get(f.addr), score: 3, why: 'x86: 3 push (envp, argv, argc) → çağrı → add esp,0xc → dönüş değeri eax saklandı' });
        else if (np >= 1 && ad && exitF && L.slice(i + 1, i + 9).some((N) => /^push eax$/.test(N.text) || /^mov DWORD PTR \[esp\],eax$/.test(N.text))) cands.push({ f, C, depth: depth.get(f.addr), score: 2, why: 'x86: argüman push → çağrı → add esp → dönüş değeri (eax) → exit/ExitProcess' });
      }
    }
  }
  cands.sort((x, y) => y.score - x.score || x.depth - y.depth || x.C.addr - y.C.addr); const uniq = []; for (const c of cands) if (!uniq.some((u) => u.C.target === c.C.target)) uniq.push(c);
  if (uniq.length) { const c = uniq[0]; return { addr: c.C.target, level: 'sezgisel', method: 'CRT başlangıç deseni (' + (c.score === 3 ? 'argc/argv/envp ile çağrı' : 'çağrı → exit zinciri; zayıf kanıt') + ')', evidence: ['giriş noktası ' + fn(img.entry) + ' (0x' + natHex(img.entry) + ') → ' + fn(c.f.addr) + ' içinde 0x' + natHex(c.C.addr) + ' `' + c.C.text + '`', c.why, 'Bu bir kalıp eşleştirmesidir (derleyici CRT’si değişirse yanılabilir); komut listesi yine de birebirdir.'].concat(uniq.length > 1 ? ['diğer adaylar: ' + uniq.slice(1, 4).map((u) => '0x' + natHex(u.C.target)).join(', ')] : []) }; }
  const calls = [...ef.calls.keys()].filter((t) => d.funcs.has(t)).length;
  return { addr: img.entry, level: 'giriş-noktası', method: 'CRT deseni bulunamadı', evidence: ['giriş noktası işlevi doğrudan listelendi (' + ef.insns.size + ' komut, ' + calls + ' iç çağrı)', 'Bu program CRT’siz olabilir (giriş noktası = ana kod) ya da CRT deseni tanınmadı; ' + (calls ? 'iç çağrılar da aşağıda listelenir.' : 'iç çağrı yok.')] };
}

function natRender(img, u8, d, mainRes, funcList, opts) {
  const lines = []; const hexb = (I) => { let s = ''; for (let i = 0; i < Math.min(I.len, 10); i++) s += natHex(u8[I.off + i], 2) + ' '; return s.trim() + (I.len > 10 ? '…' : ''); };
  const nm = (a) => d.nameOf(a) || ('loc_' + natHex(a));
  const comment = (I) => {
    const c = [];
    if ((I.kind === 'call' || I.kind === 'jmp' || I.kind === 'jcc') && typeof I.target === 'number' && I.target >= 0) { const n = d.nameOf(I.target); if (n) c.push('→ ' + n); }
    if (typeof I.ptr === 'number') { const sl = img.slots.get(I.ptr); if (sl) c.push('IAT/GOT: ' + sl); else { const sa = natStrAt(img, u8, I.ptr); if (sa) c.push(sa); } }
    if (!img.is64 && /^(push|mov) /.test(I.text)) { const g = /(?:^|,| )(0x[0-9a-f]{5,8})$/.exec(I.text); if (g) { const v = parseInt(g[1], 16); const sl = img.slots.get(v); const sa = sl ? null : natStrAt(img, u8, v); if (sa) c.push(sa); } }
    return c.length ? '   ; ' + c.join(' · ') : '';
  };
  for (const f of funcList) {
    const L = [...f.insns.values()].sort((x, y) => x.addr - y.addr);
    lines.push('; ' + '─'.repeat(70)); lines.push('; ' + f.name + '  @ 0x' + natHex(f.start) + '  boyut ' + f.size + ' bayt, ' + L.length + ' komut' + (f.src ? '  [' + f.src + ']' : ''));
    const cl = [...f.calls.keys()].map((t) => (f.calls.get(t) === 'tail' ? 'tail:' : '') + (d.nameOf(t) || 'sub_' + natHex(t))); if (cl.length) lines.push('; çağırır: ' + cl.join(', ')); if (f.imports.size) lines.push('; import: ' + [...f.imports].join(', '));
    for (const w of f.incomplete) lines.push('; UYARI: ' + w);
    let prev = null;
    for (const I of L) {
      if (prev && prev.addr + prev.len !== I.addr) lines.push('        ; ··· (bitişik olmayan blok) ···');
      if (f.leaders.has(I.addr) && I.addr !== f.addr) lines.push('loc_' + natHex(I.addr) + ':');
      lines.push('  ' + natHex(I.addr, img.is64 ? 8 : 8) + ':  ' + hexb(I).padEnd(31) + I.text + comment(I)); prev = I;
    }
    lines.push('');
  }
  return lines.join('\n');
}

function natAnalyze(u8, opts) {
  opts = opts || {}; const lim = Object.assign({}, NAT_LIM, opts.lim || {}); const R = { ok: false, notes: [], limits: [] };
  const isPE = u8.length > 2 && u8[0] === 0x4d && u8[1] === 0x5a, isELF = u8.length > 4 && u8[0] === 0x7f && u8[1] === 0x45 && u8[2] === 0x4c && u8[3] === 0x46;
  if (!isPE && !isELF) { R.reason = 'PE/ELF değil'; return R; }
  let img; try { img = isPE ? natLoadPE(u8) : natLoadELF(u8); } catch (e) { R.reason = 'Başlık okunamadı: ' + String((e && e.message) || e).slice(0, 80); return R; }
  if (img.err) { R.reason = img.err; return R; }
  R.format = img.fmt; R.arch = img.arch; R.entry = img.entry; R.notes.push(...img.notes);
  const ent = img.secs.find((s) => img.entry >= s.va && img.entry < s.va + s.n); if (!ent || !ent.exec) { R.reason = 'Giriş noktası (0x' + natHex(img.entry) + ') yürütülebilir bir bölümde değil (paketli/özel yükleyici olabilir)'; R.partialInfo = true; return R; }
  if (img.fmt === 'elf') { const plts = img.secs.filter((s) => /^\.plt/.test(s.name) && s.exec); for (const s of plts) for (let o = 0; o + 16 <= s.n; o += 16) { let a = s.va + o, k = 0; while (k < 16) { const I = x86Decode(u8, s.off + o + k, img.is64, a + k); if (!I) break; if (I.kind === 'jmpi' && typeof I.ptr === 'number' && img.slots.has(I.ptr)) { img.syms.set(a, img.slots.get(I.ptr) + '@plt'); break; } if (I.kind !== 'other') break; k += I.len; } } }
  const seeds = [{ a: img.entry, name: img.exports.get(img.entry) || img.syms.get(img.entry) || (img.fmt === 'elf' ? '_start' : 'giriş_noktası'), src: 'giriş noktası' }];
  for (const [a, n] of img.exports) seeds.push({ a, name: n, src: 'export' }); for (const p of img.pdata) seeds.push({ a: p.a, src: '.pdata' });
  if (img.fmt === 'elf') for (const [a, n] of img.syms) if (!/@plt$/.test(n)) seeds.push({ a, name: n, src: 'sembol' });
  let d = natDiscover(img, u8, seeds, lim); R.disc = d; R.img = img;
  let mainRes = natFindMain(img, d, u8); if (mainRes.addr !== null && !d.funcs.has(mainRes.addr) && d.secOf(mainRes.addr) && d.secOf(mainRes.addr).exec) { seeds.push({ a: mainRes.addr, name: 'main', src: 'main (' + mainRes.level + ')' }); d = natDiscover(img, u8, seeds, lim); R.disc = d; }
  R.main = mainRes;
  if (mainRes.addr !== null && d.funcs.has(mainRes.addr)) { const f = d.funcs.get(mainRes.addr); if (f.addr !== img.entry || mainRes.level !== 'giriş-noktası') f.name = f.name.startsWith('sub_') || f.name === '_start' ? (mainRes.level === 'kesin' ? 'main' : 'main_adayı') : f.name; f.src = 'ANA KOD (' + mainRes.level + ')'; }
  else if (mainRes.addr !== null && d.secOf(mainRes.addr)) { mainRes.evidence.push('main adresi keşfedilen işlevler arasında yok (keşif sınırı?)'); mainRes.level = 'bulunamadı'; mainRes.addr = null; }
  R.funcs = [...d.funcs.values()].sort((a, b) => a.addr - b.addr); R.total = d.total; R.truncated = d.truncated; if (d.limits.length) R.limits.push('Keşif sınırı aşıldı (' + d.limits.join(', ') + '): sonuç kısmi.');
  const incompl = R.funcs.filter((f) => f.incomplete.length); if (incompl.length) R.notes.push(incompl.length + ' işlevde çözülemeyen komut/dolaylı atlama var (listede UYARI satırı olarak işaretli).');
  if (img.fmt === 'pe' && !img.pdata.length && img.is64) R.notes.push('.pdata yok: işlev sınırları yalnızca çağrı/atlama izlemesinden çıkarıldı.');
  if (img.fmt === 'elf' && ![...img.syms.values()].some((n) => !/@plt$/.test(n) && n !== 'main')) R.notes.push('Sembol tablosu yok (soyulmuş): işlev adları sub_XXXX olarak verildi.');
  const noDec = R.funcs.reduce((s, f) => s + f.incomplete.filter((x) => /çözülemedi/.test(x)).length, 0); R.undecoded = noDec;
  const mainF = mainRes.addr !== null ? d.funcs.get(mainRes.addr) : null; R.mainFunc = mainF || null;
  // ana kod listesi: ana islev + dogrudan ic cagrilari (1 seviye)
  const mainList = []; if (mainF) { mainList.push(mainF); for (const [t] of mainF.calls) { const g = d.funcs.get(t); if (g && g !== mainF && mainList.length < 12) mainList.push(g); } }
  const head = ['; StatScan 4.6 — yerel kod disassembly (STATİK; dosya çalıştırılmadı)', '; Biçim: ' + img.fmt.toUpperCase() + ' ' + img.arch + ' · giriş noktası 0x' + natHex(img.entry) + ' · ' + R.funcs.length + ' işlev, ' + d.total + ' komut', '; Ana kod: ' + (mainRes.addr !== null ? '0x' + natHex(mainRes.addr) + ' [' + mainRes.level + '] — ' + mainRes.method : 'BULUNAMADI — ' + mainRes.method), ...mainRes.evidence.map((e) => ';   · ' + e), '; Bu liste DECOMPILE (C kodu) DEĞİLDİR: her satır dosyadaki gerçek bayttan çözülmüş makine komutudur; yorumlar (;) yalnızca import/dize/hedef adlandırmasıdır.', ''];
  if (mainList.length) R.mainText = head.concat([natRender(img, u8, d, mainRes, mainList)]).join('\n'); else R.mainText = head.concat(['; Ana işlev belirlenemediği için bu dosyada ana kod listesi yok; tum-kod listesine bakın.']).join('\n');
  const all = []; let sz = 0; let cut = 0; for (const f of R.funcs) { const t = natRender(img, u8, d, mainRes, [f]); if (sz + t.length > lim.listBytes) { cut++; continue; } sz += t.length; all.push(t); } if (cut) R.limits.push(cut + ' işlev çıktı boyut sınırı nedeniyle tum-kod listesine yazılmadı.');
  R.allText = head.concat(all).join('\n');
  const cg = ['# Çağrı grafiği', '']; for (const f of R.funcs) { const c = [...f.calls.keys()].map((t) => (f.calls.get(t) === 'tail' ? 'tail:' : '') + (d.nameOf(t) || 'sub_' + natHex(t))); cg.push(f.name + ' (0x' + natHex(f.start) + ', ' + f.size + ' bayt, ' + f.insns.size + ' komut)' + (c.length ? '\n    → ' + c.join('\n    → ') : '') + (f.imports.size ? '\n    ⇒ import: ' + [...f.imports].join(', ') : '') + (f.indirect ? '\n    ? dolaylı çağrı: ' + f.indirect + ' (hedef statik çözülemedi)' : '')); }
  R.graphText = cg.join('\n');
  R.ok = true; return R;
}
