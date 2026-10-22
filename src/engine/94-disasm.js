/* 4.6: yerlesik x86/x64 disassembler (statik; kod CALISTIRILMAZ). Intel sozdizimi, objdump -M intel ile ayni bicim.
   Cozemedigi komutta TAHMIN ETMEZ: null doner, cagiran yol kesilir ve "cozulemedi" diye raporlanir.
   Desteklenmeyenler: VEX/EVEX (AVX), AVX-512, MMX, 0F38/0F3A uc baytli SSE, 16 bit adresleme, sistem/segment komutlari, x87'nin nadir formlari. */
const X_R64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'];
const X_R32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d'];
const X_R16 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w'];
const X_R8R = ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil', 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b'];
const X_R8L = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh'];
const X_CC = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g'];
const X_ALU = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp'];
const X_SHIFT = ['rol', 'ror', 'rcl', 'rcr', 'shl', 'shr', 'shl', 'sar'];
const X_KW = { 8: 'BYTE', 16: 'WORD', 32: 'DWORD', 64: 'QWORD', 80: 'TBYTE', 128: 'XMMWORD' };
const xHex = (n) => '0x' + n.toString(16);
function xImm(v, bits) {
  if (bits === 64) { let b = BigInt(v); if (b < 0n) b += 1n << 64n; return '0x' + b.toString(16); }
  if (bits === 8) return '0x' + (v & 0xff).toString(16); if (bits === 16) return '0x' + (v & 0xffff).toString(16); return '0x' + (v >>> 0).toString(16);
}
const xSgn = (d) => (d < 0 ? '-0x' + (-d).toString(16) : '+0x' + d.toString(16));
/* SSE: 0F opcode -> [yok, 66, F3, F2] mnemonic (null = yok); tur: 'x' xmm,xmm/m ; bellek boyutu ayri */
const X_SSE = {
  0x10: ['movups', 'movupd', 'movss', 'movsd'], 0x14: ['unpcklps', 'unpcklpd', null, null], 0x15: ['unpckhps', 'unpckhpd', null, null], 0x28: ['movaps', 'movapd', null, null], 0x2e: ['ucomiss', 'ucomisd', null, null], 0x2f: ['comiss', 'comisd', null, null],
  0x51: ['sqrtps', 'sqrtpd', 'sqrtss', 'sqrtsd'], 0x52: ['rsqrtps', null, 'rsqrtss', null], 0x53: ['rcpps', null, 'rcpss', null], 0x54: ['andps', 'andpd', null, null], 0x55: ['andnps', 'andnpd', null, null], 0x56: ['orps', 'orpd', null, null], 0x57: ['xorps', 'xorpd', null, null],
  0x58: ['addps', 'addpd', 'addss', 'addsd'], 0x59: ['mulps', 'mulpd', 'mulss', 'mulsd'], 0x5a: ['cvtps2pd', 'cvtpd2ps', 'cvtss2sd', 'cvtsd2ss'], 0x5b: ['cvtdq2ps', 'cvtps2dq', 'cvttps2dq', null], 0x5c: ['subps', 'subpd', 'subss', 'subsd'], 0x5d: ['minps', 'minpd', 'minss', 'minsd'], 0x5e: ['divps', 'divpd', 'divss', 'divsd'], 0x5f: ['maxps', 'maxpd', 'maxss', 'maxsd'],
  0xe6: [null, 'cvttpd2dq', 'cvtdq2pd', 'cvtpd2dq'], 0xc6: ['shufps', 'shufpd', null, null]
};
const X_PINT = { 0x60: 'punpcklbw', 0x61: 'punpcklwd', 0x62: 'punpckldq', 0x63: 'packsswb', 0x64: 'pcmpgtb', 0x65: 'pcmpgtw', 0x66: 'pcmpgtd', 0x67: 'packuswb', 0x68: 'punpckhbw', 0x69: 'punpckhwd', 0x6a: 'punpckhdq', 0x6b: 'packssdw', 0x6c: 'punpcklqdq', 0x6d: 'punpckhqdq', 0x74: 'pcmpeqb', 0x75: 'pcmpeqw', 0x76: 'pcmpeqd',
  0xd1: 'psrlw', 0xd2: 'psrld', 0xd3: 'psrlq', 0xd4: 'paddq', 0xd5: 'pmullw', 0xd8: 'psubusb', 0xd9: 'psubusw', 0xda: 'pminub', 0xdb: 'pand', 0xdc: 'paddusb', 0xdd: 'paddusw', 0xde: 'pmaxub', 0xdf: 'pandn', 0xe0: 'pavgb', 0xe1: 'psraw', 0xe2: 'psrad', 0xe3: 'pavgw', 0xe4: 'pmulhuw', 0xe5: 'pmulhw',
  0xe8: 'psubsb', 0xe9: 'psubsw', 0xea: 'pminsw', 0xeb: 'por', 0xec: 'paddsb', 0xed: 'paddsw', 0xee: 'pmaxsw', 0xef: 'pxor', 0xf1: 'psllw', 0xf2: 'pslld', 0xf3: 'psllq', 0xf4: 'pmuludq', 0xf5: 'pmaddwd', 0xf6: 'psadbw', 0xf8: 'psubb', 0xf9: 'psubw', 0xfa: 'psubd', 0xfb: 'psubq', 0xfc: 'paddb', 0xfd: 'paddw', 0xfe: 'paddd' };

function x86Decode(b, off, is64, ip, rx) {
  const n = b.length; const s0 = off; ip = ip || 0; const EOF = { eof: 1 }, BAD = { bad: 1 };
  const u8 = () => { if (off >= n) throw EOF; return b[off++]; };
  const i8 = () => { const v = u8(); return v > 127 ? v - 256 : v; };
  const u16 = () => { const a = u8(); return a | (u8() << 8); };
  const i32 = () => { const a = u8(), c = u8(), d = u8(), e = u8(); return (a | (c << 8) | (d << 16) | (e << 24)) | 0; };
  const u32 = () => i32() >>> 0;
  const bad = () => { throw BAD; };
  const hx = (t) => t < 0 ? BigInt.asUintN(64, BigInt(t)).toString(16) : t.toString(16);
  try {
    let o16 = 0, a32 = false, rep = 0, seg = '', lock = false, rex = 0;
    for (let i = 0; i < 14; i++) {
      const c = off < n ? b[off] : -1;
      if (c === 0x66) { o16++; off++; } else if (c === 0x67) { a32 = true; off++; } else if (c === 0xf2 || c === 0xf3) { rep = c; off++; } else if (c === 0xf0) { if (lock) bad(); lock = true; off++; }
      else if (c === 0x2e || c === 0x36 || c === 0x3e || c === 0x26 || c === 0x64 || c === 0x65) { if (seg) bad(); seg = { 0x2e: 'cs', 0x36: 'ss', 0x3e: 'ds', 0x26: 'es', 0x64: 'fs', 0x65: 'gs' }[c]; off++; }
      else if (false) { seg = 'cs'; off++; } else if (c === 0x36) { seg = 'ss'; off++; } else if (c === 0x3e) { seg = 'ds'; off++; } else if (c === 0x26) { seg = 'es'; off++; } else if (c === 0x64) { seg = 'fs'; off++; } else if (c === 0x65) { seg = 'gs'; off++; }
      else break;
    }
    if (is64 && off < n && b[off] >= 0x40 && b[off] <= 0x4f) { rex = b[off++]; if (rx !== undefined) rex = rx < 0 ? 0 : rx; }
    const W = !!(rex & 8); const osz = W ? 64 : (o16 ? 16 : 32); const mand = rep === 0xf3 ? 2 : rep === 0xf2 ? 3 : (o16 ? 1 : 0);
    let usedSeg = false, usedRep = false, usedLock = false, usedA32 = false, ripDisp = null, ptr = null, rexKeep = false;
    const REG = (nn, sz) => (sz === 8 ? (rex ? X_R8R[nn] : (nn < 8 ? X_R8L[nn] : bad())) : sz === 16 ? X_R16[nn] : sz === 32 ? X_R32[nn] : X_R64[nn]);
    const XMM = (nn) => 'xmm' + nn;
    function modrm() {
      const m = u8(); const mod = m >> 6; const r = { mod, reg: ((m >> 3) & 7) | ((rex & 4) << 1), rm: (m & 7) | ((rex & 1) << 3), isReg: mod === 3, mem: null }; if (mod === 3) return r;
      if (!is64 && a32) bad(); let base = -1, index = -1, scale = 1, disp = 0, hasDisp = false, rip = false, sibNoIdx = false; const rm = m & 7;
      if (rm === 4) { const sib = u8(); scale = 1 << (sib >> 6); const ix = (sib >> 3) & 7; index = (ix === 4 && !(rex & 2)) ? -1 : (ix | ((rex & 2) << 2)); if (index < 0) sibNoIdx = true; const bs = sib & 7; if (bs === 5 && mod === 0) { disp = i32(); hasDisp = true; } else base = bs | ((rex & 1) << 3); }
      else if (rm === 5 && mod === 0) { disp = i32(); hasDisp = true; if (is64) rip = true; } else base = rm | ((rex & 1) << 3);
      if (mod === 1) { disp = i8(); hasDisp = true; } else if (mod === 2) { disp = i32(); hasDisp = true; }
      r.mem = { base, index, scale, disp, hasDisp, rip, sibNoIdx }; return r;
    }
    let noSeg = false;
    function mstr(r, kw) {
      const m = r.mem; usedA32 = true; if (m.rip && a32) bad(); if (m.sibNoIdx && m.base < 0 && m.scale !== 1) bad(); const regs = is64 && !a32 ? X_R64 : X_R32; const sp = seg && !noSeg && (!is64 || seg === 'fs' || seg === 'gs') ? seg : ''; if (sp) usedSeg = true; let body;
      if (m.rip) { ripDisp = m.disp; body = '[rip' + (m.disp < 0 ? '+0x' + ((1n << 64n) + BigInt(m.disp)).toString(16) : '+0x' + m.disp.toString(16)) + ']'; if (sp) body = sp + ':' + body; }
      else if (m.base < 0 && m.index < 0) { const v = is64 ? (m.disp < 0 ? '0x' + ((1n << 64n) + BigInt(m.disp)).toString(16) : xHex(m.disp)) : xHex(m.disp >>> 0); body = (sp || 'ds') + ':' + v; ptr = m.disp >>> 0; }
      else { let t = ''; if (m.base >= 0) t += regs[m.base]; if (m.index >= 0) t += (t ? '+' : '') + regs[m.index] + '*' + m.scale; else if (m.sibNoIdx && ((m.base >= 0 && (m.base & 7) !== 4) || m.scale !== 1)) t += (t ? '+' : '') + (is64 && !a32 ? 'riz' : 'eiz') + '*' + m.scale; if (m.hasDisp) t += xSgn(m.disp); body = (sp ? sp + ':' : '') + '[' + t + ']'; }
      return (kw ? (X_KW[kw] || kw) + ' PTR ' : '') + body;
    }
    const RM = (r, sz) => (r.isReg ? REG(r.rm, sz) : mstr(r, sz));
    const RMX = (r, sz) => (r.isReg ? XMM(r.rm) : mstr(r, sz));
    let mnem = '', ops = '', kind = 'other', target = null; const set = (m, o) => { mnem = m; ops = o || ''; };
    const op = u8();
    const immOp = (sz) => (sz === 8 ? xImm(i8(), 8) : sz === 16 ? xImm(u16(), 16) : sz === 32 ? xImm(i32(), 32) : xImm(i32(), 64));
    if (op === 0x0f) {
      const o2 = u8();
      if (o2 >= 0x80 && o2 <= 0x8f) { const d = i32(); target = ip + (off - s0) + d; if (!is64) target >>>= 0; set('j' + X_CC[o2 & 15], hx(target)); kind = 'jcc'; }
      else if (o2 >= 0x90 && o2 <= 0x9f) { const r = modrm(); set('set' + X_CC[o2 & 15], RM(r, 8)); }
      else if (o2 >= 0x40 && o2 <= 0x4f) { const r = modrm(); set('cmov' + X_CC[o2 & 15], REG(r.reg, osz) + ',' + RM(r, osz)); }
      else if (o2 === 0x05) set('syscall'); else if (o2 === 0x0b) { set('ud2'); kind = 'ud2'; } else if (o2 === 0xa2) set('cpuid'); else if (o2 === 0x31) set('rdtsc');
      else if (o2 === 0x1e && rep === 0xf3 && off < n && (b[off] === 0xfa || b[off] === 0xfb)) { set(u8() === 0xfa ? 'endbr64' : 'endbr32'); usedRep = true; }
      else if (o2 === 0x1f || (o2 >= 0x19 && o2 <= 0x1d) || o2 === 0x1e) { if (o2 === 0x1a || o2 === 0x1b) bad(); noSeg = true; const r = modrm(); let pre = ''; if (seg === 'cs') { pre = 'cs '; usedSeg = true; } if (o16 > 1) pre = 'data16 '.repeat(o16 - 1) + pre; set(pre + 'nop', RM(r, osz)); }
      else if (o2 === 0xaf) { const r = modrm(); set('imul', REG(r.reg, osz) + ',' + RM(r, osz)); }
      else if (o2 === 0xb6 || o2 === 0xb7 || o2 === 0xbe || o2 === 0xbf) { const r = modrm(); const ss = (o2 & 1) ? 16 : 8; set((o2 < 0xb8 ? 'movzx' : 'movsx'), REG(r.reg, osz) + ',' + RM(r, ss)); }
      else if (o2 === 0xa3 || o2 === 0xab || o2 === 0xb3 || o2 === 0xbb) { const r = modrm(); set({ 0xa3: 'bt', 0xab: 'bts', 0xb3: 'btr', 0xbb: 'btc' }[o2], RM(r, osz) + ',' + REG(r.reg, osz)); }
      else if (o2 === 0xba) { const r = modrm(); const k = r.reg & 7; if (k < 4) bad(); set(['bt', 'bts', 'btr', 'btc'][k - 4], RM(r, osz) + ',' + xImm(u8(), 8)); }
      else if (o2 === 0xbc || o2 === 0xbd) { const r = modrm(); const t = rep === 0xf3; usedRep = t; set(t ? (o2 === 0xbc ? 'tzcnt' : 'lzcnt') : (o2 === 0xbc ? 'bsf' : 'bsr'), REG(r.reg, osz) + ',' + RM(r, osz)); }
      else if (o2 === 0xb8 && rep === 0xf3) { const r = modrm(); usedRep = true; set('popcnt', REG(r.reg, osz) + ',' + RM(r, osz)); }
      else if (o2 === 0xb0 || o2 === 0xb1) { const r = modrm(); const sz = o2 === 0xb0 ? 8 : osz; usedLock = true; set('cmpxchg', RM(r, sz) + ',' + REG(r.reg, sz)); }
      else if (o2 === 0xc0 || o2 === 0xc1) { const r = modrm(); const sz = o2 === 0xc0 ? 8 : osz; usedLock = true; set('xadd', RM(r, sz) + ',' + REG(r.reg, sz)); }
      else if (o2 === 0xa4 || o2 === 0xac) { const r = modrm(); set(o2 === 0xa4 ? 'shld' : 'shrd', RM(r, osz) + ',' + REG(r.reg, osz) + ',' + xImm(u8(), 8)); }
      else if (o2 === 0xa5 || o2 === 0xad) { const r = modrm(); set(o2 === 0xa5 ? 'shld' : 'shrd', RM(r, osz) + ',' + REG(r.reg, osz) + ',cl'); }
      else if (o2 >= 0xc8 && o2 <= 0xcf) set('bswap', REG((o2 & 7) | ((rex & 1) << 3), osz === 64 ? 64 : 32));
      else if (o2 === 0x18) { const r = modrm(); const k = r.reg & 7; if (k > 3 || r.isReg) bad(); set(['prefetchnta', 'prefetcht0', 'prefetcht1', 'prefetcht2'][k], mstr(r, 8)); }
      else if (o2 === 0xae) { const r = modrm(); if (r.isReg) { const k = r.reg & 7; if (k === 5) set('lfence'); else if (k === 6) set('mfence'); else if (k === 7) set('sfence'); else bad(); } else { const k = r.reg & 7; const nm = ['fxsave', 'fxrstor', 'ldmxcsr', 'stmxcsr', null, null, null, 'clflush'][k]; if (!nm) bad(); set(nm, mstr(r, k === 2 || k === 3 ? 32 : 8)); } }
      else if (o2 === 0x01 && off < n && b[off] === 0xd0) { off++; set('xgetbv'); }
      else if (o2 === 0x10 || o2 === 0x11) { const r = modrm(); const nm = X_SSE[0x10][mand]; if (!nm) bad(); usedRep = true; const sz = mand === 2 ? 32 : mand === 3 ? 64 : 128; const x = XMM(r.reg); const m = RMX(r, sz); set(nm, o2 === 0x10 ? x + ',' + m : m + ',' + x); }
      else if (o2 === 0x28 || o2 === 0x29) { const r = modrm(); if (mand > 1) bad(); const x = XMM(r.reg); const m = RMX(r, 128); set(mand ? 'movapd' : 'movaps', o2 === 0x28 ? x + ',' + m : m + ',' + x); }
      else if (o2 === 0x12 || o2 === 0x13 || o2 === 0x16 || o2 === 0x17) { const r = modrm(); if (mand > 1) bad(); const hi = o2 >= 0x16; let nm; if (r.isReg) { if (mand || o2 > 0x13 && o2 !== 0x16 || o2 === 0x13) bad(); nm = hi ? 'movlhps' : 'movhlps'; } else nm = (hi ? 'movh' : 'movl') + (mand ? 'pd' : 'ps'); const x = XMM(r.reg); const m = RMX(r, 64); set(nm, (o2 & 1) ? m + ',' + x : x + ',' + m); }
      else if (o2 === 0x2a) { if (mand < 2) bad(); const r = modrm(); usedRep = true; const sz = W ? 64 : 32; set(mand === 2 ? 'cvtsi2ss' : 'cvtsi2sd', XMM(r.reg) + ',' + RM(r, sz)); }
      else if (o2 === 0x2c || o2 === 0x2d) { if (mand < 2) bad(); const r = modrm(); usedRep = true; set((o2 === 0x2c ? 'cvtt' : 'cvt') + (mand === 2 ? 'ss2si' : 'sd2si'), REG(r.reg, W ? 64 : 32) + ',' + RMX(r, mand === 2 ? 32 : 64)); }
      else if (o2 === 0x2e || o2 === 0x2f) { if (mand > 1) bad(); const r = modrm(); set(X_SSE[o2][mand], XMM(r.reg) + ',' + RMX(r, mand ? 64 : 32)); }
      else if (o2 === 0x50) { const r = modrm(); if (!r.isReg || mand > 1) bad(); set(mand ? 'movmskpd' : 'movmskps', REG(r.reg, 32) + ',' + XMM(r.rm)); }
      else if (X_SSE[o2]) { const r = modrm(); const nm = X_SSE[o2][mand]; if (!nm) bad(); usedRep = true; const sc = mand === 2 || mand === 3; const sz = sc ? (mand === 2 ? 32 : 64) : 128; let extra = ''; if (o2 === 0xc6) extra = ',' + xImm(u8(), 8); const cvtSz = (o2 === 0x5a && mand === 0) || (o2 === 0xe6 && mand === 2) ? 64 : sz; set(nm, XMM(r.reg) + ',' + RMX(r, cvtSz) + extra); }
      else if (o2 === 0x6e) { if (mand !== 1) bad(); const r = modrm(); set(W ? 'movq' : 'movd', XMM(r.reg) + ',' + RM(r, W ? 64 : 32)); }
      else if (o2 === 0x7e) { const r = modrm(); if (mand === 2) { usedRep = true; set('movq', XMM(r.reg) + ',' + RMX(r, 64)); } else if (mand === 1) set(W ? 'movq' : 'movd', RM(r, W ? 64 : 32) + ',' + XMM(r.reg)); else bad(); }
      else if (o2 === 0xd6) { if (mand !== 1) bad(); const r = modrm(); set('movq', RMX(r, 64) + ',' + XMM(r.reg)); }
      else if (o2 === 0x6f || o2 === 0x7f) { if (mand !== 1 && mand !== 2) bad(); const r = modrm(); usedRep = true; const x = XMM(r.reg); const m = RMX(r, 128); set(mand === 1 ? 'movdqa' : 'movdqu', o2 === 0x6f ? x + ',' + m : m + ',' + x); }
      else if (o2 === 0x70) { if (mand < 1) bad(); const r = modrm(); usedRep = true; set(['', 'pshufd', 'pshufhw', 'pshuflw'][mand], XMM(r.reg) + ',' + RMX(r, 128) + ',' + xImm(u8(), 8)); }
      else if (o2 >= 0x71 && o2 <= 0x73) { if (mand !== 1) bad(); const r = modrm(); if (!r.isReg) bad(); const k = r.reg & 7; const nm = { 0x71: { 2: 'psrlw', 4: 'psraw', 6: 'psllw' }, 0x72: { 2: 'psrld', 4: 'psrad', 6: 'pslld' }, 0x73: { 2: 'psrlq', 3: 'psrldq', 6: 'psllq', 7: 'pslldq' } }[o2][k]; if (!nm) bad(); set(nm, XMM(r.rm) + ',' + xImm(u8(), 8)); }
      else if (o2 === 0xc5) { if (mand !== 1) bad(); const r = modrm(); if (!r.isReg) bad(); set('pextrw', REG(r.reg, 32) + ',' + XMM(r.rm) + ',' + xImm(u8(), 8)); }
      else if (o2 === 0xc4) { if (mand !== 1) bad(); const r = modrm(); set('pinsrw', XMM(r.reg) + ',' + (r.isReg ? REG(r.rm, 32) : mstr(r, 16)) + ',' + xImm(u8(), 8)); }
      else if (o2 === 0xc2) { const r = modrm(); usedRep = true; const sfx = ['ps', 'pd', 'ss', 'sd'][mand]; const a = XMM(r.reg) + ',' + RMX(r, mand === 2 ? 32 : mand === 3 ? 64 : 128); const k = u8(); const pn = ['eq', 'lt', 'le', 'unord', 'neq', 'nlt', 'nle', 'ord'][k]; if (pn) set('cmp' + pn + sfx, a); else set('cmp' + sfx, a + ',' + xImm(k, 8)); }
      else if (o2 === 0xd7) { if (mand !== 1) bad(); const r = modrm(); if (!r.isReg) bad(); set('pmovmskb', REG(r.reg, 32) + ',' + XMM(r.rm)); }
      else if (o2 === 0xe7) { if (mand !== 1) bad(); const r = modrm(); if (r.isReg) bad(); set('movntdq', mstr(r, 128) + ',' + XMM(r.reg)); }
      else if (o2 === 0xc3) { const r = modrm(); if (r.isReg) bad(); set('movnti', mstr(r, W ? 64 : 32) + ',' + REG(r.reg, W ? 64 : 32)); }
      else if (X_PINT[o2]) { if (mand !== 1) bad(); const r = modrm(); set(X_PINT[o2], XMM(r.reg) + ',' + RMX(r, 128)); }
      else bad();
    } else if (op < 0x40 && (op & 7) < 6) {
      const nm = X_ALU[op >> 3]; const f = op & 7; usedLock = true;
      if (f === 0 || f === 1) { const r = modrm(); const sz = f ? osz : 8; set(nm, RM(r, sz) + ',' + REG(r.reg, sz)); }
      else if (f === 2 || f === 3) { const r = modrm(); const sz = f === 3 ? osz : 8; set(nm, REG(r.reg, sz) + ',' + RM(r, sz)); }
      else if (f === 4) set(nm, 'al,' + xImm(u8(), 8)); else set(nm, REG(0, osz) + ',' + immOp(osz));
    } else if (!is64 && op >= 0x40 && op <= 0x4f) set(op < 0x48 ? 'inc' : 'dec', REG(op & 7, osz));
    else if (op >= 0x50 && op <= 0x5f) { const sz = is64 ? (o16 ? 16 : 64) : (o16 ? 16 : 32); set(op < 0x58 ? 'push' : 'pop', REG((op & 7) | ((rex & 1) << 3), sz)); }
    else if (is64 && op === 0x63) { const r = modrm(); set('movsxd', REG(r.reg, osz) + ',' + RM(r, 32)); }
    else if (op === 0x68) set('push', xImm(i32(), is64 ? 64 : 32)); else if (op === 0x6a) set('push', xImm(i8(), is64 ? 64 : 32));
    else if (op === 0x69 || op === 0x6b) { const r = modrm(); const a = RM(r, osz); set('imul', REG(r.reg, osz) + ',' + a + ',' + (op === 0x6b ? xImm(i8(), osz) : immOp(osz))); }
    else if (op >= 0x70 && op <= 0x7f) { const d = i8(); target = ip + (off - s0) + d; if (!is64) target >>>= 0; set('j' + X_CC[op & 15], hx(target)); kind = 'jcc'; }
    else if (op === 0x80 || op === 0x81 || op === 0x83) { const r = modrm(); const sz = op === 0x80 ? 8 : osz; const a = RM(r, sz); const imm = op === 0x81 ? immOp(osz) : xImm(i8(), sz); usedLock = true; set(X_ALU[r.reg & 7], a + ',' + imm); }
    else if (op === 0x84 || op === 0x85) { const r = modrm(); const sz = op === 0x84 ? 8 : osz; set('test', RM(r, sz) + ',' + REG(r.reg, sz)); }
    else if (op === 0x86 || op === 0x87) { const r = modrm(); const sz = op === 0x86 ? 8 : osz; usedLock = true; set('xchg', RM(r, sz) + ',' + REG(r.reg, sz)); }
    else if (op >= 0x88 && op <= 0x8b) { const r = modrm(); const sz = (op & 1) ? osz : 8; if (op < 0x8a) set('mov', RM(r, sz) + ',' + REG(r.reg, sz)); else set('mov', REG(r.reg, sz) + ',' + RM(r, sz)); }
    else if (op === 0x8d) { const r = modrm(); if (r.isReg) bad(); set('lea', REG(r.reg, osz) + ',' + mstr(r, 0)); }
    else if (op === 0x8f) { const r = modrm(); if ((r.reg & 7) !== 0) bad(); set('pop', RM(r, is64 ? 64 : 32)); }
    else if (op === 0x90) { if (rex & 1) set('xchg', REG(8, osz) + ',' + REG(0, osz)); else if (rep === 0xf3) { usedRep = true; set('pause'); } else if (o16) set('xchg', 'ax,ax'); else set('nop'); }
    else if (op >= 0x91 && op <= 0x97) set('xchg', REG((op & 7) | ((rex & 1) << 3), osz) + ',' + REG(0, osz));
    else if (op === 0x98) set(osz === 64 ? 'cdqe' : osz === 32 ? 'cwde' : 'cbw'); else if (op === 0x99) set(osz === 64 ? 'cqo' : osz === 32 ? 'cdq' : 'cwd');
    else if (op === 0x9c) set('pushf'); else if (op === 0x9d) set('popf'); else if (op === 0x9e) set('sahf'); else if (op === 0x9f) set('lahf');
    else if (op === 0xa8) set('test', 'al,' + xImm(u8(), 8)); else if (op === 0xa9) set('test', REG(0, osz) + ',' + immOp(osz));
    else if ((op >= 0xa4 && op <= 0xa7) || (op >= 0xaa && op <= 0xaf)) {
      usedA32 = true; const byte = !(op & 1); const sz = byte ? 8 : osz; const di = 'es:[' + (is64 ? (a32 ? 'edi' : 'rdi') : 'edi') + ']', si = 'ds:[' + (is64 ? (a32 ? 'esi' : 'rsi') : 'esi') + ']'; const K = X_KW[sz] + ' PTR '; const ac = REG(0, sz); const cmpLike = op === 0xa6 || op === 0xa7 || op === 0xae || op === 0xaf; let pre = '';
      if (rep) { usedRep = true; pre = rep === 0xf3 ? (cmpLike ? 'repz ' : 'rep ') : 'repnz '; }
      if (op <= 0xa5) set(pre + 'movs', K + di + ',' + K + si); else if (op <= 0xa7) set(pre + 'cmps', K + si + ',' + K + di); else if (op <= 0xab) set(pre + 'stos', K + di + ',' + ac); else if (op <= 0xad) set(pre + 'lods', ac + ',' + K + si); else set(pre + 'scas', ac + ',' + K + di);
    }
    else if (op >= 0xb0 && op <= 0xb7) set('mov', REG((op & 7) | ((rex & 1) << 3), 8) + ',' + xImm(u8(), 8));
    else if (op >= 0xb8 && op <= 0xbf) { const rg = (op & 7) | ((rex & 1) << 3); if (osz === 64) { const lo = u32(), hi = u32(); set('movabs', X_R64[rg] + ',0x' + ((BigInt(hi) << 32n) | BigInt(lo)).toString(16)); } else set('mov', REG(rg, osz) + ',' + (osz === 16 ? xImm(u16(), 16) : xImm(u32(), 32))); }
    else if (op === 0xc0 || op === 0xc1 || (op >= 0xd0 && op <= 0xd3)) { const r = modrm(); const sz = (op & 1) ? osz : 8; const a = RM(r, sz); const k = r.reg & 7; set(X_SHIFT[k], a + ',' + (op <= 0xc1 ? xImm(u8(), 8) : op <= 0xd1 ? '1' : 'cl')); }
    else if (op === 0xc2) { set('ret', xImm(u16(), 16)); kind = 'ret'; } else if (op === 0xc3) { set(rep === 0xf3 ? 'repz ret' : 'ret'); usedRep = rep === 0xf3; kind = 'ret'; }
    else if (op === 0xc6 || op === 0xc7) { const r = modrm(); if ((r.reg & 7) !== 0) bad(); const sz = op === 0xc6 ? 8 : osz; const a = RM(r, sz); set('mov', a + ',' + (sz === 8 ? xImm(u8(), 8) : immOp(sz))); }
    else if (op === 0xc9) set('leave'); else if (op === 0xcc) { set('int3'); kind = 'int3'; } else if (op === 0xcd) set('int', xImm(u8(), 8));
    else if (op === 0xe8) { const d = i32(); target = ip + (off - s0) + d; if (!is64) target >>>= 0; set('call', hx(target)); kind = 'call'; }
    else if (op === 0xe9) { const d = i32(); target = ip + (off - s0) + d; if (!is64) target >>>= 0; set('jmp', hx(target)); kind = 'jmp'; }
    else if (op === 0xeb) { const d = i8(); target = ip + (off - s0) + d; if (!is64) target >>>= 0; set('jmp', hx(target)); kind = 'jmp'; }
    else if (op >= 0xe0 && op <= 0xe3) { const d = i8(); target = ip + (off - s0) + d; if (!is64) target >>>= 0; set(['loopne', 'loope', 'loop', is64 ? 'jrcxz' : 'jecxz'][op - 0xe0], hx(target)); kind = 'jcc'; }
    else if (op === 0xf4) { set('hlt'); kind = 'hlt'; } else if (op === 0xf5) set('cmc'); else if (op === 0xf8) set('clc'); else if (op === 0xf9) set('stc'); else if (op === 0xfc) set('cld'); else if (op === 0xfd) set('std');
    else if (op === 0xf6 || op === 0xf7) { const r = modrm(); const sz = op === 0xf6 ? 8 : osz; const a = RM(r, sz); const k = r.reg & 7; usedLock = true; if (k < 2) set('test', a + ',' + (sz === 8 ? xImm(u8(), 8) : immOp(sz))); else set(['', '', 'not', 'neg', 'mul', 'imul', 'div', 'idiv'][k], a); }
    else if (op === 0xfe || op === 0xff) {
      const r = modrm(); const k = r.reg & 7; usedLock = true;
      if (k < 2) set(k ? 'dec' : 'inc', RM(r, op === 0xfe ? 8 : osz)); else if (op === 0xfe) bad();
      else if (k === 2 || k === 4) { if (o16) bad(); const sz = is64 ? 64 : 32; noSeg = seg === 'ds'; const a = RM(r, sz); const nt = seg === 'ds' ? 'notrack ' : ''; if (nt) usedSeg = true; if (!r.isReg) ptr = ptr !== null ? ptr : (r.mem.rip ? 'rip' : null); set((rex === 0x48 ? 'rex.W ' : '') + nt + (k === 2 ? 'call' : 'jmp'), a); if (rex === 0x48) rexKeep = true; kind = k === 2 ? 'calli' : 'jmpi'; }
      else if (k === 6) set('push', RM(r, is64 ? 64 : 32)); else bad();
    }
    else if (!is64 && op === 0x60) set('pusha'); else if (!is64 && op === 0x61) set('popa');
    else if (op >= 0xd8 && op <= 0xdf) { const x = x87(op); if (!x) bad(); set(x[0], x[1]); }
    else bad();
    function x87(opc) {
      const m = u8(); const mod = m >> 6, rg = (m >> 3) & 7, rm = m & 7; off--; const r = modrm(); const st = (i) => 'st(' + i + ')';
      if (mod !== 3) {
        const M = (kw) => mstr(r, kw);
        const T = { 0xd8: ['fadd', 'fmul', 'fcom', 'fcomp', 'fsub', 'fsubr', 'fdiv', 'fdivr'], 0xdc: ['fadd', 'fmul', 'fcom', 'fcomp', 'fsub', 'fsubr', 'fdiv', 'fdivr'] };
        if (opc === 0xd8 || opc === 0xdc) return [T[opc][rg], M(opc === 0xd8 ? 32 : 64)];
        if (opc === 0xd9) { const nm = ['fld', null, 'fst', 'fstp', 'fldenv', 'fldcw', 'fnstenv', 'fnstcw'][rg]; return nm ? [nm, M(rg === 0 || rg === 2 || rg === 3 ? 32 : (rg === 5 || rg === 7 ? 16 : ''))] : null; }
        if (opc === 0xdd) { const nm = ['fld', 'fisttp', 'fst', 'fstp', null, null, null, 'fnstsw'][rg]; return nm ? [nm, M(rg === 7 ? 16 : 64)] : null; }
        if (opc === 0xdb) { const nm = ['fild', 'fisttp', 'fist', 'fistp', null, 'fld', null, 'fstp'][rg]; return nm ? [nm, M(rg >= 5 ? 80 : 32)] : null; }
        if (opc === 0xdf) { const nm = ['fild', 'fisttp', 'fist', 'fistp', null, 'fild', null, 'fistp'][rg]; return nm ? [nm, M(rg === 5 || rg === 7 ? 64 : 16)] : null; }
        if (opc === 0xda || opc === 0xde) { const nm = ['fiadd', 'fimul', 'ficom', 'ficomp', 'fisub', 'fisubr', 'fidiv', 'fidivr'][rg]; return [nm, M(opc === 0xda ? 32 : 16)]; }
        return null;
      }
      if (opc === 0xd9) { if (rg === 0) return ['fld', st(rm)]; if (rg === 1) return ['fxch', st(rm)]; const t = { 0xe0: 'fchs', 0xe1: 'fabs', 0xe8: 'fld1', 0xee: 'fldz', 0xfa: 'fsqrt', 0xfc: 'frndint', 0xe5: 'fxam', 0xe4: 'ftst', 0xc9: null }[m]; return t ? [t, ''] : null; }
      if (opc === 0xdd) { if (rg === 3) return ['fstp', st(rm)]; if (rg === 2) return ['fst', st(rm)]; return null; }
      if (opc === 0xde) { const nm = { 0: 'faddp', 1: 'fmulp', 4: 'fsubrp', 5: 'fsubp', 6: 'fdivrp', 7: 'fdivp' }[rg]; if (m === 0xd9) return ['fcompp', '']; return nm ? [nm, st(rm) + ',st'] : null; }
      if (opc === 0xdf) { if (m === 0xe0) return ['fnstsw', 'ax']; if (rg === 5) return ['fucomip', 'st,' + st(rm)]; if (rg === 6) return ['fcomip', 'st,' + st(rm)]; return null; }
      if (opc === 0xdb) { if (rg === 5) return ['fucomi', 'st,' + st(rm)]; if (rg === 6) return ['fcomi', 'st,' + st(rm)]; return null; }
      if (opc === 0xd8) { const nm = ['fadd', 'fmul', 'fcom', 'fcomp', 'fsub', 'fsubr', 'fdiv', 'fdivr'][rg]; return [nm, rg === 2 || rg === 3 ? st(rm) : 'st,' + st(rm)]; }
      if (opc === 0xdc) { const nm = ['fadd', 'fmul', null, null, 'fsubr', 'fsub', 'fdivr', 'fdiv'][rg]; return nm ? [nm, st(rm) + ',st'] : null; }
      return null;
    }
    /* on ekler: kullanilmayan/uygunsuz oneklerde TAHMIN ETME */
    if (o16 && op !== 0x0f && ((op < 0x40 && !(op & 1) && (op & 7) < 6) || [0x80, 0x84, 0x86, 0x88, 0x8a, 0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xc0, 0xc6, 0xd0, 0xd2, 0xf6, 0xfe].includes(op) || (op >= 0xb0 && op <= 0xb7))) bad();
    if (o16 > 1 && op !== 0x0f) bad();
    if (o16 && op !== 0x0f && (op === 0xc2 || op === 0xcd || op === 0xf5 || op === 0x68 || op === 0x6a || (op >= 0xd8 && op <= 0xdf))) bad();
    if (o16 && op !== 0x0f && (op === 0x9e || op === 0x9f || (op >= 0xf8 && op <= 0xfd) || op === 0xc9 || op === 0x9c || op === 0x9d || op === 0xc3 || op === 0xcc || op === 0xf4 || (op >= 0xe0 && op <= 0xeb) || (op >= 0x70 && op <= 0x7f))) bad();
    if (rep === 0xf2 && ((op >= 0xe0 && op <= 0xe3) || (op >= 0x70 && op <= 0x7f))) bad();
    if (W && o16 && op !== 0x0f) { if (kind !== 'other') bad(); mnem = 'data16 '.repeat(o16) + mnem; }
    if (rep && !usedRep) { if (!(kind === 'call' || kind === 'jmp' || kind === 'ret' || kind === 'jcc' || kind === 'calli' || kind === 'jmpi') || rep !== 0xf2) bad(); mnem = 'bnd ' + mnem; }
    if (lock) { if (!usedLock || /^(set|mov|lea)/.test(mnem)) bad(); mnem = 'lock ' + mnem; }
    if (seg && !usedSeg) { bad(); }
    if (a32 && !usedA32) bad();
    const len = off - s0; if (len > 15) bad();
    if (rex && rx === undefined && !rexKeep) { const txt = mnem + (ops ? ' ' + ops : ''); const vs = [rex & ~8, rex & ~4, rex & ~2, rex & ~1, 0x40, 0x0]; for (const v of vs) { if (v === rex) continue; const o = x86Decode(b, s0, is64, ip, v === 0 ? -1 : v); if (o && o.len === len && o.text === txt) bad(); } }
    if (ripDisp !== null) ptr = ip + len + ripDisp;
    return { len, mnem, ops, text: mnem + (ops ? ' ' + ops : ''), kind, target, ptr: typeof ptr === 'number' ? ptr : null };
  } catch (e) { if (e === EOF || e === BAD) return null; throw e; }
}
