/* Kovan: cok dilli kaynak obfuscator (yalnizca METIN donusturur; hicbir sey calistirmaz/derlemez).
   101-srcscan.js'teki ayni sozlesmeye uyar: diller ve dosya turu srcLangOf ile belirlenir (bu dosya onu
   degistirmez, yalniz okur). Iki katman uretir:
     1) "temel": yorumlari kaldirir + bos/yalniz-bosluk satirlari siler + dize icermeyen satirlarda
        art arda bosluklari tek bosluga indirir. TUM dillerde (Java dahil) guvenlidir: hicbir token
        veya dize/karakter sabiti DEGISTIRILMEZ, yalnizca yorum ve anlamsiz bosluk kaldirilir.
     2) "isim karistirma" (yalnizca parantezli/suslu-parantez tabanli diller: C, C++, Java, C#, Go, Rust,
        Zig, Kotlin, D — Pascal ve Fortran'da YOK): bir tanimlayicinin DOSYA ICINDEKI TUM (nokta/ok/::'tan
        sonraki uye-erisimi HARIC) gorunumleri yalnizca fonksiyon/blok govdesi (tip govdesi veya dosya
        kapsami DEGIL) icinde ise, o ad baska hicbir yerde (alan adi, tur adi, ust duzey degisken/fonksiyon
        adi olarak) kullanilmiyorsa yeniden adlandirilir. Belirsiz/sinir durumlarda DEGISTIRMEZ (guvenlik
        her zaman obfuscation gucunden onceliklidir). Derleyici araciyla (101-srcscan.js, host.js COMPMOD)
        hicbir bag yoktur; bu dosya bagimsiz calisir. */

/* ---- 1) katman: yorum/bosluk sadelestirme icin dil basina 'cfg(keepStrings)' fonksiyonlari ----
   C/C++/Rust/C#/Kotlin/Pascal/Zig icin 101-srcscan.js'teki scCfg/scCfgRust/scCfgCs/scCfgKt/scCfgPas/scCfgZig
   zaten ayni amacla yazilmis ve ayni script kapsamina enjekte edilir (tools/inject.mjs); burada TEKRAR
   TANIMLANMAZ. Go/D/Java/Fortran(serbest bicim) icin kucuk, bagimsiz cfg'ler asagida. */
function sobCfgGo(keep) { return { keepStrings: keep, line: ['//'], block: [['/*', '*/', false]], quotes: [{ q: '"', esc: '\\' }, { q: '`', nl: true }, { q: "'", esc: '\\' }] }; }
function sobCfgD(keep) { return { keepStrings: keep, line: ['//'], block: [['/*', '*/', false], ['/+', '+/', true]], quotes: [{ q: '"', esc: '\\', nl: true }, { q: '`', nl: true }, { q: "'", esc: '\\' }], custom: (s, i) => { if (s[i] === 'r' && s[i + 1] === '"' && (i === 0 || !SC_IDC.test(s[i - 1]))) { const e = s.indexOf('"', i + 2); return { end: e < 0 ? s.length : e + 1, keep: true }; } return null; } }; }
function sobCfgJava(keep) {
  return { keepStrings: keep, line: ['//'], block: [['/*', '*/', false]], quotes: [{ q: '"', esc: '\\' }, { q: "'", esc: '\\' }],
    custom: (s, i) => { if (s[i] === '"' && s.startsWith('"""', i)) { let q = 3; while (s[i + q] === '"') q++; const close = '"'.repeat(q); const e = s.indexOf(close, i + q); return { end: e < 0 ? s.length : e + q, keep: true }; } return null; } };
}
function sobCfgForFree(keep) { return { keepStrings: keep, line: ['!'], quotes: [{ q: "'", dbl: true }, { q: '"', dbl: true }] }; }
const SOB_CFG = {
  c: (k) => scCfg(false, k), cpp: (k) => scCfg(true, k), rust: scCfgRust, csharp: scCfgCs, kotlin: scCfgKt,
  pascal: scCfgPas, zig: scCfgZig, go: sobCfgGo, d: sobCfgD, java: sobCfgJava
};
/* fixed-bicim Fortran (.f/.for/.f77/.ftn): kolon 1'de c, C veya yildiz isaretiyle baslayan tam satir yorum; genel katman uygulanmaz
   (kolon konumlari anlam tasir), yalnizca yorum satirlari ve bos satirlar silinir; hicbir karakter oynatilmaz. */
function sobStripFixedFortran(text) {
  const lines = String(text).replace(/\r\n?/g, '\n').split('\n'); const out = [];
  for (const ln of lines) { if (/^[cC*!]/.test(ln)) continue; if (!ln.trim()) continue; out.push(ln); }
  return out.join('\n');
}
/* ---- temel katman: yorum sil + bos satir sil + (dize icermeyen satirda) bosluk sadelestir.
   Donen: { text, removedComments, blankLinesRemoved, bytesBefore, bytesAfter } */
function sobStripBasic(text, lang) {
  const src = String(text).replace(/\r\n?/g, '\n'); const bytesBefore = new TextEncoder().encode(src).length;
  if (lang === 'fortran-fixed') { const out = sobStripFixedFortran(src); return { text: out, note: 'fixed-bicim Fortran: yalnizca tam-satir yorum (kolon 1: c/C/*/!) ve bos satirlar kaldirildi; kolon konumlarina dokunulmadi.', bytesBefore, bytesAfter: new TextEncoder().encode(out).length }; }
  const cfgFn = lang === 'fortran' ? sobCfgForFree : SOB_CFG[lang]; if (!cfgFn) return { text: src, note: 'Bu dil icin temel sadelestirme tanimli degil.', bytesBefore, bytesAfter: bytesBefore };
  const keep = scStrip(src, cfgFn(true)); const full = scStrip(src, cfgFn(false));
  const keepLines = keep.split('\n'), fullLines = full.split('\n'); const out = [];
  for (let i = 0; i < keepLines.length; i++) {
    const kl = keepLines[i] || ''; const fl = fullLines[i] !== undefined ? fullLines[i] : '';
    if (!kl.trim()) continue; /* bos ya da yalniz-yorum satiri: tamamen kaldir */
    if (kl === fl) out.push(kl.replace(/[ \t]{2,}/g, ' ').replace(/^[ \t]+|[ \t]+$/g, ''));
    else out.push(kl); /* satirda dize icerigi var: yalnizca yorumlar bosluga cevrildi, baska hicbir sey degistirilmedi */
  }
  const outText = out.join('\n'); return { text: outText, bytesBefore, bytesAfter: new TextEncoder().encode(outText).length };
}

/* ---- 2) katman: yerel degisken/parametre-govde-ici adlarini yeniden adlandirma (yalnizca suslu-parantez dilleri) ----
   Guvenlik kurali: bir ad YALNIZCA ve YALNIZCA dosyadaki TUM (uye-erisimi haric) gorunumleri
   "fonksiyon/blok govdesi" baglaminda ise yeniden adlandirilir. Tip govdesi (sinif/yapi alanlari),
   ad alani veya dosya-kapsaminda (parametre listeleri DAHIL — bunlar suslu parantezin disindadir)
   TEK bir gorunumu bile varsa o ad HIC degistirilmez. Boylelikle alan/degisken ad cakismasi,
   kisayol baslatma (`Point { x, y }` gibi) ve parametre adlari kendiliginden guvenli kalir. */
const SOB_KEYWORDS = {
  c: new Set('auto break case char const continue default do double else enum extern float for goto if inline int long register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while _Bool _Complex _Imaginary NULL true false'.split(' ')),
  cpp: new Set('alignas alignof and and_eq asm atomic_cancel atomic_commit atomic_noexcept auto bitand bitor bool break case catch char char8_t char16_t char32_t class compl concept const consteval constexpr constinit const_cast continue co_await co_return co_yield decltype default delete do double dynamic_cast else enum explicit export extern false float for friend goto if inline int long mutable namespace new noexcept not not_eq nullptr operator or or_eq private protected public register reinterpret_cast requires return short signed sizeof static static_assert static_cast struct switch template this thread_local throw true try typedef typeid typename union unsigned using virtual void volatile wchar_t while xor xor_eq override final NULL'.split(' ')),
  java: new Set('abstract assert boolean break byte case catch char class const continue default do double else enum extends final finally float for goto if implements import instanceof int interface long native new package private protected public return short static strictfp super switch synchronized this throw throws transient try void volatile while var record sealed permits yield true false null String'.split(' ')),
  csharp: new Set('abstract as base bool break byte case catch char checked class const continue decimal default delegate do double else enum event explicit extern false finally fixed float for foreach goto if implicit in int interface internal is lock long namespace new null object operator out override params private protected public readonly ref return sbyte sealed short sizeof stackalloc static string struct switch this throw true try typeof uint ulong unchecked unsafe ushort using virtual void volatile while var dynamic async await record init required'.split(' ')),
  go: new Set('break default func interface select case defer go map struct chan else goto package switch const fallthrough if range type continue for import return var true false nil iota byte rune string int int8 int16 int32 int64 uint uint8 uint16 uint32 uint64 float32 float64 error bool'.split(' ')),
  rust: new Set('as break const continue crate dyn else enum extern false fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait true type unsafe use where while async await dyn union i8 i16 i32 i64 i128 isize u8 u16 u32 u64 u128 usize f32 f64 bool char str String Some None Ok Err Vec Box'.split(' ')),
  kotlin: new Set('as break class continue do else false for fun if in interface is null object package return super this throw true try typealias typeof val var when while by catch constructor delegate dynamic field file finally get import init param property receiver set setparam where actual abstract annotation companion const crossinline data enum expect external final infix inline inner internal lateinit noinline open operator out override private protected public reified sealed suspend tailrec vararg Int String Boolean Double Float Long Short Byte Char Unit Any'.split(' ')),
  zig: new Set('align allowzero and anyframe anytype asm async await break callconv catch comptime const continue defer else enum errdefer error export extern fn for if inline noalias noinline nosuspend opaque or orelse packed pub resume return linksection struct suspend switch test threadlocal try union unreachable usingnamespace var volatile while bool void anyerror type i8 i16 i32 i64 i128 isize u8 u16 u32 u64 u128 usize f16 f32 f64 f128 true false null undefined noreturn'.split(' ')),
  d: new Set('abstract alias align asm assert auto body bool break byte case cast catch cdouble cent cfloat char class const continue creal dchar debug default delegate delete deprecated do double else enum export extern false final finally float for foreach foreach_reverse function goto idouble if ifloat immutable import in inout int interface invariant ireal is lazy long macro mixin module new nothrow null out override package pragma private protected public pure real ref return scope shared short static struct super switch synchronized template this throw true try typedef typeid typeof ubyte ucent uint ulong union unittest ushort version void volatile wchar while with __gshared size_t string'.split(' '))
};
/* Tip govdesi baslatan '{' anahtar sozcukleri: bu parantezin kendisi "tip" baglamidir (alanlar
   yeniden adlandirilmaz) ANCAK onun icinde YENIDEN bir fonksiyon govdesi ('<ad>(...) {') bulunursa
   o govde yine "func" sayilir (sinif icindeki metodlar normal sekilde islenir). */
const SOB_TYPE_RE = {
  c: /(?:^|[;{}]\s*)(?:typedef\s+)?(?:struct|union|enum)\b[^(){};]*$/,
  cpp: /(?:^|[;{}]\s*)(?:typedef\s+)?(?:class|struct|union|enum(?:\s+class)?|namespace)\b[^(){};]*$/,
  java: /(?:^|[;{}]\s*)[\w\s@.\[\],<>]*\b(?:class|interface|enum|record)\s+\w[^(){};]*$/,
  csharp: /(?:^|[;{}]\s*)[\w\s\[\],<>]*\b(?:class|struct|interface|enum|namespace|record)\b[^(){};]*$/,
  kotlin: /(?:^|[;{}]\s*)[\w\s]*\b(?:class|interface|object)\b[^(){};]*$/,
  go: /(?:^|[;{}]\s*)type\s+\w+\s+(?:struct|interface)\s*$/,
  rust: /(?:^|[;{}]\s*)(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:struct|enum|trait|mod|union)\b[^(){};]*$|(?:^|[;{}]\s*)impl\b[^{};]*$/,
  zig: /(?:^|[;{}]\s*)(?:pub\s+)?(?:const\s+\w+\s*=\s*)?(?:extern\s+)?(?:packed\s+)?(?:union|enum|struct)\s*(?:\([^()]*\))?\s*$/,
  d: /(?:^|[;{}]\s*)[\w\s]*\b(?:class|struct|union|interface|enum|module)\b[^(){};]*$/
};
/* Fonksiyon/blok govdesi baslatan '{': onceki (yorum/dize-bosaltilmis) kisim ')' ile bitiyorsa
   (olasi const/noexcept/override/throws/-> donus turu nitelikleriyle), ya da Zig'de 'fn ad(' iceriyorsa. */
function sobIsFuncHead(seg, lang) {
  if (/\)\s*(?:const|override|final|mut|sealed|async|noexcept(?:\s*\([^()]*\))?|throws\s+[\w.,\s<>\[\]]+|->\s*[\w:<>\[\],.&*?! ]+|where\s+[\w:,\s<>]+)*\s*$/.test(seg)) return true;
  if (lang === 'zig' && /\bfn\s+\w+\s*\([^()]*\)/.test(seg)) return true;
  if (lang === 'rust' && /\)\s*$/.test(seg)) return true;
  return false;
}
/* "Yalnizca func baglaminda gorunuyor" tek basina guvenli degildir: bir kutuphane/global sembolun
   (printf, std, System, fmt, bir paket adi...) bu DOSYADA hicbir ust-duzey bildirimi olmayabilir —
   o zaman da "disarida hic gorunmuyor" testini yanlislikla gecer. Bunun onune gecmek icin bir ad,
   yalnizca ACIKCA bir YEREL DEGISKEN BILDIRIMI kalibiyla eslesiyorsa aday olur (aksi halde dokunulmaz;
   bu, Go/Rust struct alani kisayolu gibi "Ad: deger" durumlarini da ayrica guvenli kilar). */
const SOB_DECL_RE = {
  c: [/(?:[{};]|^)\s*(?:const\s+|static\s+|volatile\s+|register\s+|unsigned\s+|signed\s+)*(?:struct\s+\w+|union\s+\w+|enum\s+\w+|[A-Za-z_]\w*)\s*[*\s]+([A-Za-z_]\w*)\s*(?:=[^=]|;|,|\[)/gd],
  cpp: [/(?:[{};]|^)\s*(?:const\s+|static\s+|volatile\s+|constexpr\s+)*(?:struct\s+\w+|[A-Za-z_]\w*(?:::\w+)*(?:\s*<[^<>;{}()]*>)?)\s*[*&\s]+([A-Za-z_]\w*)\s*(?:=[^=]|;|,|\{|\()/gd, /\bauto\s*&{0,2}\s*([A-Za-z_]\w*)\s*(?:=|:)/gd],
  java: [/(?:[{};]|^)\s*(?:final\s+)?(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:<[^<>;{}]*>)?(?:\[\])*)\s+([A-Za-z_]\w*)\s*(?:=[^=]|;|,|:)/gd, /\bvar\s+([A-Za-z_]\w*)\s*=/gd],
  csharp: [/(?:[{};]|^)\s*(?:var|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:<[^<>;{}]*>)?(?:\[\])*)\s+([A-Za-z_]\w*)\s*(?:=[^=]|;|,)/gd],
  go: [/\b([A-Za-z_]\w*)\s*:=/gd, /\bvar\s+([A-Za-z_]\w*)\b/gd],
  rust: [/\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\b/gd],
  zig: [/\b(?:const|var)\s+([A-Za-z_]\w*)\b/gd],
  kotlin: [/\b(?:val|var)\s+([A-Za-z_]\w*)\b/gd],
  d: [/(?:[{};]|^)\s*(?:const\s+|immutable\s+|scope\s+)*(?:[A-Za-z_]\w*)\s*[*[\]\s]+([A-Za-z_]\w*)\s*(?:=[^=]|;|,)/gd, /\bauto\s+([A-Za-z_]\w*)\s*=/gd]
};
const SC_IDC2 = /[\w$]/;
/* s[pos] bir tanimlayicinin ilk karakteridir; ondan hemen once (bosluk atlanarak) gelen "gercek" karakteri
   ve konumunu dondurur. Uye-erisimi testi ('.', '->', '::') bu konum uzerinden, ONDAN BIR ONCEKI karaktere
   bakilarak yapilir (araya bosluk girse bile dogru calismasi icin iki ayri "bosluk-atla" adimi gerekir). */
function sobPrevTok(s, pos) { let k = pos - 1; while (k >= 0 && /\s/.test(s[k])) k--; if (k < 0) return { c: '', k: -1 }; return { c: s[k], k }; }
function sobIsMemberAt(s, pos) { const a = sobPrevTok(s, pos); if (a.c === '.') return true; if (a.c === '>' || a.c === ':') { const b = sobPrevTok(s, a.k); if (a.c === '>' && b.c === '-') return true; if (a.c === ':' && b.c === ':') return true; } return false; }
function sobWord(name) { return new RegExp('(?<![.\\w$])(?<!->)(?<!::)\\b' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'g'); }
/* Dosyadaki gorunumleri brace-derinligi + baglam (func/type/top) etiketleriyle tarar. */
function sobScopeScan(clean, lang) {
  const n = clean.length; const stack = []; /* {kind:'func'|'type'|'top', depth} */ let depth = 0;
  const marks = new Array(n); /* her konum icin: 0 kapsam yigininin en-ici (current) 'kind' */
  const typeRe = SOB_TYPE_RE[lang];
  let cur = 'top'; marks.fill(0);
  const kindAt = []; /* paralel dizi: her karakter icin kapsam kind'i (func/type/top) */
  let lastBreak = 0; /* son ';' '{' '}' konumundan bu yana olan segment basi */
  for (let i = 0; i < n; i++) {
    const c = clean[i];
    if (c === ';') { lastBreak = i + 1; kindAt[i] = cur; continue; }
    if (c === '{') {
      const seg = clean.slice(lastBreak, i);
      let kind;
      if (typeRe && typeRe.test(seg)) kind = 'type';
      else if (sobIsFuncHead(seg, lang)) kind = 'func';
      else kind = cur; /* belirsiz: ebeveyn baglamini devral (if/for/while/switch/match/lambda/initializer govdeleri) */
      stack.push({ kind: cur, depth }); depth++; cur = kind; lastBreak = i + 1; kindAt[i] = cur; continue;
    }
    if (c === '}') { kindAt[i] = cur; const top = stack.pop(); if (top) { cur = top.kind; depth = top.depth; } lastBreak = i + 1; continue; }
    kindAt[i] = cur;
  }
  return kindAt;
}
/* text: tek dosya metni. lang: 101-srcscan.js srcLangOf() dilidir (c/cpp/java/csharp/go/rust/zig/kotlin/d).
   Donen: { text, renamed: [{from,to}], candidates, skipped } */
function sobRenameLocals(text, lang, opts) {
  const cfgFn = SOB_CFG[lang]; const KW = SOB_KEYWORDS[lang];
  if (!cfgFn || !KW || !SOB_TYPE_RE[lang]) return { text, renamed: [], skipped: true, reason: 'Bu dilde isim karıştırma desteklenmiyor.' };
  const src = String(text).replace(/\r\n?/g, '\n');
  const clean = scStrip(src, cfgFn(false)); /* yorum+dize+karakter sabiti bosaltilmis, uzunluk AYNI */
  const kindAt = sobScopeScan(clean, lang);
  const idRe = /[A-Za-z_$][A-Za-z0-9_$]*/g; let m;
  const info = new Map(); /* name -> { funcOnly: bool, anyOutside: bool, positions: number[] (func baglamindaki, uye-erisimi-olmayan) } */
  while ((m = idRe.exec(clean))) {
    const name = m[0]; const pos = m.index; if (KW.has(name)) continue;
    const isMember = sobIsMemberAt(clean, pos);
    let e = info.get(name); if (!e) { e = { anyOutside: false, positions: [] }; info.set(name, e); }
    const kind = kindAt[pos];
    if (kind !== 'func') { e.anyOutside = true; continue; } /* type/top baglaminda (uye-erisimi olsa da olmasa da) -> guvensiz, bu ad asla degistirilmez */
    if (isMember) continue; /* func icindeki uye-erisimi (x.name) -> gorunmez say, ad degismez ama baska bir yerde serbest kullanimi varsa yine aday olabilir */
    e.positions.push(pos);
  }
  const declared = new Set();
  for (const re of SOB_DECL_RE[lang] || []) { re.lastIndex = 0; let dm; while ((dm = re.exec(clean))) { if (!dm.indices || !dm.indices[1]) continue; const pos = dm.indices[1][0]; const name = dm[1]; if (KW.has(name) || kindAt[pos] !== 'func') continue; if (sobIsMemberAt(clean, pos)) continue; declared.add(name); } }
  const candidates = []; for (const [name, e] of info) { if (!e.anyOutside && e.positions.length && declared.has(name)) candidates.push(name); }
  /* yeni adlar: kisa, cakismasiz. Dosyadaki TUM taninimlayicilarla (adaylar dahil) cakismamali. */
  const used = new Set(); idRe.lastIndex = 0; while ((m = idRe.exec(clean))) used.add(m[0]);
  const rnd = () => Math.floor(Math.random() * 36 ** 4).toString(36).padStart(4, '0');
  const taken = new Set(used); const renamed = []; const nameMap = new Map();
  const prefix = (opts && opts.prefix) || '_k';
  for (const name of candidates) { let nn; let tries = 0; do { nn = prefix + rnd(); tries++; } while ((taken.has(nn) || KW.has(nn)) && tries < 50); if (taken.has(nn)) continue; taken.add(nn); nameMap.set(name, nn); renamed.push({ from: name, to: nn }); }
  if (!renamed.length) return { text: src, renamed: [], skipped: false, candidates: candidates.length };
  /* yeniden yazim: yalnizca 'clean' konumlarinda (yorum/dize DEGIL) ve uye-erisimi olmayan tam-sozcuk
     gorunumlerini degistir; orijinal metin (src) uzerinde, konum temelli, tek gecis. */
  let out = ''; let i = 0; const nL = src.length;
  while (i < nL) {
    const c = clean[i];
    if (/[A-Za-z_$]/.test(c)) {
      let j = i + 1; while (j < nL && SC_IDC2.test(clean[j])) j++;
      const word = clean.slice(i, j);
      if (nameMap.has(word) && kindAt[i] === 'func') {
        out += sobIsMemberAt(clean, i) ? src.slice(i, j) : nameMap.get(word);
      } else out += src.slice(i, j);
      i = j; continue;
    }
    out += src[i]; i++;
  }
  return { text: out, renamed, skipped: false, candidates: candidates.length };
}

const SOB_RENAME_LANGS = { c: 1, cpp: 1, java: 1, csharp: 1, go: 1, rust: 1, zig: 1, kotlin: 1, d: 1 };
const SOB_VERIFIED_LANGS = { c: 1, cpp: 1, java: 1, go: 1, rust: 1 }; /* bu oturumda gercek derleyiciyle (gcc/g++/javac/go/rustc) once-sonra derlenip CIKTISI karsilastirilarak dogrulandi */
/* Coklu dosya girdisi: files = [{name, text}]. opts: { basic: bool, rename: bool } (ikisi de varsayilan true) */
function srcObf(files, opts) {
  const o = Object.assign({ basic: true, rename: true }, opts || {});
  const out = { files: [], notes: [], langs: {} };
  for (const f of files) {
    const info = srcLangOf(f.name); const lang = info ? info.lang : null;
    const row = { name: f.name, lang, langName: lang ? srcLangName(lang) : null, supported: !!info, basicApplied: false, renamed: [], renameSupported: false, renameVerified: false, bytesBefore: 0, bytesAfter: 0, text: f.text };
    if (!info || info.kind !== 'source') { out.files.push(row); continue; }
    let text = f.text; const isFixedFortran = lang === 'fortran' && /\.(?:f|for|f77|ftn)$/i.test(f.name);
    if (o.basic) { const r = sobStripBasic(text, isFixedFortran ? 'fortran-fixed' : lang); text = r.text; row.basicApplied = true; row.bytesBefore = r.bytesBefore; row.bytesAfter = r.bytesAfter; if (r.note) row.note = r.note; }
    if (o.rename && SOB_RENAME_LANGS[lang]) {
      row.renameSupported = true; row.renameVerified = !!SOB_VERIFIED_LANGS[lang];
      const rr = sobRenameLocals(text, lang, {}); text = rr.text; row.renamed = rr.renamed; row.renameCandidates = rr.candidates || 0;
    }
    row.text = text; out.files.push(row);
  }
  return out;
}
function srcObfSupport() {
  const rows = []; for (const L of SRC_LANGS) rows.push({ id: L.id, name: L.name, basic: !!SOB_CFG[L.id] || L.id === 'fortran', rename: !!SOB_RENAME_LANGS[L.id], verified: !!SOB_VERIFIED_LANGS[L.id] });
  rows.unshift({ id: 'java', name: 'Java', basic: true, rename: true, verified: true });
  return rows;
}
