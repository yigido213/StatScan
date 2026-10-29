/* Kovan Derleyici: cok dilli kaynak cozumleyici (yalnizca METIN okur; hicbir sey calistirmaz/derlemez).
   Diller: C, C++, Rust, C#, Go, Zig, Kotlin, Pascal (FPC), Fortran, D. Java icin bkz. 100-javasrc.js.
   Cikarir: giris noktasi (main), GUI/konsol, yerel dosya basvurulari (#include "x.h", mod x;, uses x ...), dis bagimliliklar, olasi sorunlar.
   Regex tabanlidir: kesin derleme sonucu degil, on algilamadir. Derleme zamaninda kod calistiran diller (Nim, Haskell/TemplateHaskell vb.) bilerek YOK. */
const SRC_LANGS = [
  { id: 'c', name: 'C', exts: ['c'], aux: ['h'] },
  { id: 'cpp', name: 'C++', exts: ['cpp', 'cc', 'cxx', 'c++', 'cp'], aux: ['hpp', 'hh', 'hxx', 'h++', 'inl', 'ipp', 'tpp'] },
  { id: 'rust', name: 'Rust', exts: ['rs'] },
  { id: 'csharp', name: 'C#', exts: ['cs'] },
  { id: 'go', name: 'Go', exts: ['go'] },
  { id: 'zig', name: 'Zig', exts: ['zig'] },
  { id: 'kotlin', name: 'Kotlin', exts: ['kt'] },
  { id: 'pascal', name: 'Pascal', exts: ['pas', 'pp', 'lpr', 'dpr'] },
  { id: 'fortran', name: 'Fortran', exts: ['f90', 'f95', 'f03', 'f08', 'f18', 'f', 'for', 'f77', 'ftn'] },
  { id: 'd', name: 'D', exts: ['d'] }
];
const SRC_EXT = (() => { const m = Object.create(null); for (const L of SRC_LANGS) { for (const e of L.exts) m[e] = { lang: L.id, kind: 'source' }; for (const e of L.aux || []) m[e] = { lang: L.id, kind: 'header' }; } m.inc = { lang: '*', kind: 'aux' }; m.java = { lang: 'java', kind: 'source' }; return m; })();
const SRC_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9_.+-]{0,99}$/; const SRC_RESERVED = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;
function srcLangOf(fileName) { const m = /\.([A-Za-z0-9+]+)$/.exec(String(fileName || '')); return m ? SRC_EXT[m[1].toLowerCase()] || null : null; }
function srcLangName(id) { const L = SRC_LANGS.find((x) => x.id === id); return L ? L.name : id === 'java' ? 'Java' : id; }

/* ---- yorum/dize temizleyici: konumlar korunur (yeni satirlar kalir). keepStrings: yalniz yorumlar silinir, dizeler/direktifler kalir ---- */
function scStrip(src, cfg) {
  const n = src.length, o = src.split(''); let i = 0; const blank = (a, b) => { for (let k = a; k < b && k < n; k++) if (o[k] !== '\n' && o[k] !== '\r') o[k] = ' '; };
  while (i < n) {
    if (cfg.custom) { const r = cfg.custom(src, i); if (r && r.end > i) { if (!cfg.keepStrings || !r.keep) blank(i, r.end); i = r.end; continue; } }
    let done = false;
    for (const lc of cfg.line || []) if (src.startsWith(lc, i)) { let j = i; for (;;) { j = src.indexOf('\n', j); if (j < 0) { j = n; break; } if (cfg.lineCont && src[j - 1] === '\\') { j++; continue; } break; } blank(i, j); i = j; done = true; break; }
    if (done) continue;
    for (const [a, b, nest] of cfg.block || []) if (src.startsWith(a, i)) { let j = i + a.length, d = 1; while (j < n && d > 0) { if (nest && src.startsWith(a, j)) { d++; j += a.length; } else if (src.startsWith(b, j)) { d--; j += b.length; } else j++; } blank(i, j); i = j; done = true; break; }
    if (done) continue;
    const q = (cfg.quotes || []).find((x) => src[i] === x.q);
    if (q) { let j = i + 1; while (j < n) { const c = src[j]; if (q.esc && c === q.esc) { j += 2; continue; } if (c === q.q) { if (q.dbl && src[j + 1] === q.q) { j += 2; continue; } j++; break; } if (c === '\n' && !q.nl) break; j++; } j = Math.min(j, n); if (!cfg.keepStrings) blank(i + 1, Math.max(i + 1, j - 1)); i = j; continue; }
    i++;
  }
  return o.join('');
}
const SC_IDC = /[\w$]/;
/* C / C++ */
function scCfg(cpp, keep) {
  return { keepStrings: keep, line: ['//'], lineCont: true, block: [['/*', '*/', false]], quotes: [{ q: '"', esc: '\\' }],
    custom: (s, i) => {
      const c = s[i];
      if (c === "'") { if (i > 0 && /[0-9A-Fa-f]/.test(s[i - 1]) && /[0-9A-Fa-f]/.test(s[i + 1] || '') && /[0-9A-Za-z_.']/.test(s[i + 2] || ' ') && !/'/.test(s[i + 2] || '')) { let k = i - 1; while (k >= 0 && /[0-9A-Za-z_.']/.test(s[k])) k--; if (/[0-9.]/.test(s[k + 1] || '')) return { end: i + 1, keep: true }; } let j = i + 1; while (j < s.length && s[j] !== "'" && s[j] !== '\n') { if (s[j] === '\\') j++; j++; } return { end: Math.min(s.length, j + 1), keep: true }; }
      if (cpp && c === 'R' && s[i + 1] === '"' && (i === 0 || !SC_IDC.test(s[i - 1]) || /(?:u8|u|U|L)$/.test(s.slice(Math.max(0, i - 2), i)) && !SC_IDC.test(s[i - 3] || ' '))) { const m = /^R"([^()\\\s]{0,16})\(/.exec(s.slice(i, i + 24)); if (m) { const close = ')' + m[1] + '"'; const e = s.indexOf(close, i + m[0].length); return { end: e < 0 ? s.length : e + close.length, keep: true }; } }
      return null;
    } };
}
const SC_C_STD = new Set(('assert complex ctype errno fenv float inttypes iso646 limits locale math setjmp signal stdalign stdarg stdatomic stdbool stddef stdint stdio stdlib stdnoreturn string tgmath threads time uchar wchar wctype ' +
  'algorithm any array atomic barrier bit bitset charconv chrono codecvt compare complex concepts condition_variable coroutine deque exception execution expected filesystem flat_map flat_set format forward_list fstream functional future generator initializer_list iomanip ios iosfwd iostream istream iterator latch limits list locale map mdspan memory memory_resource mutex new numbers numeric optional ostream print queue random ranges ratio regex scoped_allocator semaphore set shared_mutex source_location span spanstream sstream stack stacktrace stdexcept stdfloat stop_token streambuf string string_view strstream syncstream system_error text_encoding thread tuple type_traits typeindex typeinfo unordered_map unordered_set utility valarray variant vector version ' +
  'cassert cctype cerrno cfenv cfloat cinttypes climits clocale cmath csetjmp csignal cstdalign cstdarg cstdbool cstddef cstdint cstdio cstdlib cstring ctgmath ctime cuchar cwchar cwctype').split(/\s+/));
const SC_C_SYS = /^(?:unistd|pthread|fcntl|dirent|dlfcn|poll|semaphore|termios|regex|glob|libgen|strings|syslog|utime|ftw|fnmatch|netdb|ifaddrs|grp|pwd|sched|spawn|wordexp|langinfo|iconv|inttypes|sys\/[\w/]+|arpa\/[\w/]+|netinet\/[\w/]+|net\/[\w/]+|linux\/[\w/]+|bits\/[\w+/.]+|windows|winsock2|ws2tcpip|windowsx|commctrl|shellapi|shlobj|tchar|conio|direct|io|process|intrin|immintrin|x86intrin|emmintrin|xmmintrin|wmmintrin|smmintrin|nmmintrin|avxintrin|malloc|memory|search|stdint|crtdbg|sdkddkver|winuser|wingdi|winbase|psapi|tlhelp32|wincrypt|bcrypt|iphlpapi|mswsock|mmsystem|mmeapi|dwmapi|uxtheme|versionhelpers|objbase|ole2|comdef|atlbase|_mingw|mingw|float|errno)(?:\.h)?$/;
const SC_WINLIB = { 'winsock2.h': 'ws2_32', 'ws2tcpip.h': 'ws2_32', 'mswsock.h': 'mswsock', 'commctrl.h': 'comctl32', 'shellapi.h': 'shell32', 'shlobj.h': 'shell32', 'mmsystem.h': 'winmm', 'mmeapi.h': 'winmm', 'iphlpapi.h': 'iphlpapi', 'bcrypt.h': 'bcrypt', 'wincrypt.h': 'crypt32', 'dwmapi.h': 'dwmapi', 'uxtheme.h': 'uxtheme', 'psapi.h': 'psapi', 'objbase.h': 'ole32', 'ole2.h': 'ole32', 'wininet.h': 'wininet' };
function scBraceNeutral(t, idx) { return /\bextern\s*$/.test(t.slice(Math.max(0, idx - 30), idx)); }
function scMatchParen(t, i) { let d = 0; for (let k = i; k < t.length; k++) { if (t[k] === '(') d++; else if (t[k] === ')') { d--; if (!d) return k; } } return -1; }
function scScanC(text, cpp) {
  const keep = scStrip(text, scCfg(cpp, true)), t = scStrip(text, scCfg(cpp, false)); const r = { entries: [], gui: false, local: [], localPath: [], external: [], libs: { m: false, pthread: false, win: [] }, problems: [], notes: [] };
  const incRe = /^[ \t]*#[ \t]*(?:include|import)[ \t]*(["<])([^">\n]+)[">]/gm; let m; const extSet = new Set();
  while ((m = incRe.exec(keep))) { const p = m[2].trim(); if (m[1] === '"') { if (/[\\/]/.test(p)) r.localPath.push(p); r.local.push(p.replace(/^.*[\\/]/, '')); } else { const base = p.replace(/^.*[\\/]/, ''); const name = p.replace(/\.h$/i, ''); if (p === 'math.h' || p === 'tgmath.h' || p === 'complex.h' || p === 'cmath' || p === 'ccomplex') r.libs.m = true; if (p === 'pthread.h' || p === 'semaphore.h' || p === 'thread' || p === 'future' || p === 'mutex' || p === 'condition_variable' || p === 'shared_mutex' || p === 'stop_token' || p === 'latch' || p === 'barrier') r.libs.pthread = true; if (SC_WINLIB[p.toLowerCase()] && !r.libs.win.includes(SC_WINLIB[p.toLowerCase()])) r.libs.win.push(SC_WINLIB[p.toLowerCase()]); if (!(SC_C_STD.has(name) || SC_C_STD.has(p) || SC_C_SYS.test(p) || SC_C_SYS.test(base))) extSet.add(p); } }
  r.external = [...extSet];
  const re = /(\{)|(\})|(?<![\w$.>:~])(main|wmain|_tmain|WinMain|wWinMain|_tWinMain|DllMain)\s*\(/g; let depth = 0; const stack = [];
  while ((m = re.exec(t))) {
    if (m[1]) { const neutral = scBraceNeutral(t, m.index); stack.push(neutral); if (!neutral) depth++; continue; }
    if (m[2]) { const neutral = stack.pop(); if (neutral === false) depth--; continue; }
    if (depth !== 0) continue; const open = m.index + m[0].length - 1; const close = scMatchParen(t, open); if (close < 0) continue; const after = t.slice(close + 1, close + 200).replace(/^\s*(?:(?:noexcept|throw)\s*(?:\([^)]*\))?\s*|->\s*[\w:<>*&\s]+?\s*|__attribute__\s*\(\([^)]*\)\)\s*)*/, ''); if (after[0] !== '{') continue;
    const segStart = Math.max(t.lastIndexOf(';', m.index), t.lastIndexOf('}', m.index), t.lastIndexOf('{', m.index), t.lastIndexOf('\n#', m.index)) + 1; const head = t.slice(segStart, m.index); if (/\bstatic\b/.test(head)) continue;
    const nm = m[3]; if (nm === 'DllMain') { r.notes.push('DllMain bulundu: bu bir DLL (kitaplık) kaynağı olabilir; bu araç yalnızca çalıştırılabilir (exe) üretir.'); continue; }
    r.entries.push({ name: nm, gui: /WinMain$/i.test(nm), ok: true });
  }
  if (r.entries.some((e) => e.gui)) r.gui = true; if (r.external.length) r.notes.push('Dış kitaplık başlığı: ' + r.external.slice(0, 6).join(', ') + (r.external.length > 6 ? '…' : '') + ' — kurulu değilse derleme/bağlama başarısız olur; araç kitaplık indirmez.');
  r.cppFeat = cpp ? (/\b(?:std::(?:format|print|println|expected|generator|flat_map|flat_set|mdspan|stacktrace)|import\s+std)\b|<(?:format|print|expected|generator|flat_map|flat_set|mdspan|stacktrace)>|\bstd::ranges::to\b|\bstd::views::(?:enumerate|zip|chunk|slide|join_with)\b/.test(keep) ? 23 : /<(?:ranges|concepts|span|coroutine|bit|compare|numbers|source_location|version|syncstream|stop_token|semaphore|latch|barrier)>|\bconcept\s+\w+|\brequires\b|\bco_(?:await|yield|return)\b|<=>|\bstd::(?:span|jthread|ranges::|views::)|\bconsteval\b|\bconstinit\b|\[\[(?:likely|unlikely)\]\]/.test(keep) ? 20 : 17) : (/\b(?:nullptr|constexpr|typeof|typeof_unqual|static_assert\s*\([^,)]*\))\b|#\s*embed\b|\b_BitInt\b|\bbool\s+\w+\s*=\s*(?:true|false)\b/.test(t) && !/\b_Static_assert\b/.test(t) ? 23 : 17);
  return r;
}
/* Rust */
function scCfgRust(keep) {
  return { keepStrings: keep, line: ['//'], block: [['/*', '*/', true]], quotes: [{ q: '"', esc: '\\', nl: true }],
    custom: (s, i) => {
      const c = s[i]; if (c === 'r' || c === 'b') { const m = /^(?:br|rb|r)(#*)"/.exec(s.slice(i, i + 24)); if (m && (i === 0 || !SC_IDC.test(s[i - 1]))) { const close = '"' + m[1]; const e = s.indexOf(close, i + m[0].length); return { end: e < 0 ? s.length : e + close.length, keep: true }; } }
      if (c === "'") { if (s[i + 1] === '\\') { let j = i + 2; while (j < s.length && s[j] !== "'" && s[j] !== '\n') j++; return { end: Math.min(s.length, j + 1), keep: true }; } const cp = s.codePointAt(i + 1); const w = cp > 0xffff ? 2 : 1; if (s[i + 1 + w] === "'" && s[i + 1] !== "'") return { end: i + w + 2, keep: true }; return { end: i + 1, keep: false }; }
      return null;
    } };
}
function scScanRust(text) {
  const keep = scStrip(text, scCfgRust(true)), t = scStrip(text, scCfgRust(false)); const r = { entries: [], gui: false, mods: [], inlineMods: [], external: [], problems: [], notes: [], nestedMods: [] };
  r.gui = /#!\[\s*windows_subsystem\s*=\s*"windows"\s*\]/.test(keep); const re = /(\{)|(\})|(?<![\w$])fn\s+main\s*(?:<[^>]*>)?\s*\(\s*\)|(?<![\w$])(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*(;|\{)?/g; let depth = 0, m;
  while ((m = re.exec(t))) {
    if (m[1]) depth++; else if (m[2]) depth--; else if (m[3] !== undefined) { if (m[4] === ';') { if (depth === 0) r.mods.push(m[3]); else r.nestedMods.push(m[3]); } else if (m[4] === '{') { r.inlineMods.push(m[3]); depth++; } } else if (depth === 0) { const head = t.slice(Math.max(0, m.index - 12), m.index); r.entries.push({ name: 'main', ok: true, async: /\basync\s+$/.test(head) }); }
  }
  const ext = new Set(), skip = new Set(['std', 'core', 'alloc', 'crate', 'self', 'super', 'proc_macro', 'test']); const ure = /(?<![\w$:])(?:use\s+(?:::)?|extern\s+crate\s+)([a-z_][a-z0-9_]*)\b/g; while ((m = ure.exec(t))) if (!skip.has(m[1])) ext.add(m[1]);
  const are = /#!?\[\s*([a-z_][a-z0-9_]*)\s*::/g; while ((m = are.exec(t))) if (!skip.has(m[1]) && !['rustfmt', 'clippy', 'rustc'].includes(m[1])) ext.add(m[1]);
  r.external = [...ext]; if (r.entries.some((e) => e.async)) r.notes.push('async fn main bulundu: bir async çalışma zamanı (ör. tokio) gerekir; araç crate indirmez.'); return r;
}
/* Go */
function scScanGo(text) {
  const keep = scStrip(text, { keepStrings: true, line: ['//'], block: [['/*', '*/', false]], quotes: [{ q: '"', esc: '\\' }, { q: '`', nl: true }, { q: "'", esc: '\\' }] }), t = scStrip(text, { line: ['//'], block: [['/*', '*/', false]], quotes: [{ q: '"', esc: '\\' }, { q: '`', nl: true }, { q: "'", esc: '\\' }] });
  const r = { entries: [], pkg: '', imports: [], external: [], localPkgs: [], cgo: false, embed: /\/\/go:embed\b/.test(text), tags: [], problems: [], notes: [] }; const pk = /(?:^|\n)[ \t]*package[ \t]+([A-Za-z_]\w*)/.exec(t); if (pk) r.pkg = pk[1];
  let m; const one = /(?:^|\n)[ \t]*import[ \t]+(?:[A-Za-z_.]\w*[ \t]+)?"([^"\n]+)"/g; while ((m = one.exec(keep))) r.imports.push(m[1]); const blk = /(?:^|\n)[ \t]*import[ \t]*\(([\s\S]*?)\)/g; while ((m = blk.exec(keep))) { const ln = /^[ \t]*(?:[A-Za-z_.]\w*[ \t]+)?"([^"\n]+)"/gm; let k; while ((k = ln.exec(m[1]))) r.imports.push(k[1]); }
  const STD = new Set('archive bufio bytes cmp compress container context crypto database debug embed encoding errors expvar flag fmt go hash html image index internal io iter log maps math mime net os path plugin reflect regexp runtime slices sort strconv strings structs sync syscall testing text time unicode unique unsafe weak'.split(' '));
  for (const p of r.imports) { const first = p.split('/')[0]; if (p === 'C') r.cgo = true; else if (first.includes('.')) r.external.push(p); else if (!STD.has(first)) r.localPkgs.push(p); }
  const re = /(\{)|(\})|(?<![\w$])func\s+main\s*\(\s*\)/g; let depth = 0; while ((m = re.exec(t))) { if (m[1]) depth++; else if (m[2]) depth--; else if (depth === 0) r.entries.push({ name: 'main', ok: true }); }
  const bt = /^\/\/go:build\s+(.+)$/m.exec(text); if (bt) r.tags.push(bt[1].trim()); return r;
}
/* Zig */
function scCfgZig(keep) { return { keepStrings: keep, line: ['//'], quotes: [{ q: '"', esc: '\\' }, { q: "'", esc: '\\' }], custom: (s, i) => { if (s[i] === '\\' && s[i + 1] === '\\') { const ls = s.lastIndexOf('\n', i - 1) + 1; if (/^[ \t]*$/.test(s.slice(ls, i))) { let j = s.indexOf('\n', i); if (j < 0) j = s.length; return { end: j, keep: true }; } } return null; } }; }
function scScanZig(text) {
  const keep = scStrip(text, scCfgZig(true)), t = scStrip(text, scCfgZig(false)); const r = { entries: [], imports: [], local: [], external: [], libc: /@cImport|@cInclude/.test(t), embed: /@embedFile\b/.test(t), problems: [], notes: [] }; let m;
  const re = /(\{)|(\})|(?<![\w$.@])pub\s+fn\s+main\s*\(/g; let depth = 0; while ((m = re.exec(t))) { if (m[1]) depth++; else if (m[2]) depth--; else if (depth === 0) r.entries.push({ name: 'main', ok: true }); }
  const ie = /@import\s*\(\s*"([^"\n]+)"\s*\)/g; while ((m = ie.exec(keep))) { const p = m[1]; if (['std', 'builtin', 'root', 'c', 'build_options'].includes(p)) continue; if (/\.zig$/.test(p)) { r.local.push(p.replace(/^.*[\\/]/, '')); if (/[\\/]/.test(p)) r.problems.push({ code: 'zig-path', msg: '@import("' + p + '"): alt klasör yolu desteklenmez; dosyaları aynı klasöre koy.' }); } else r.external.push(p); }
  return r;
}
/* D */
function scScanD(text) {
  const cfg = (k) => ({ keepStrings: k, line: ['//'], block: [['/*', '*/', false], ['/+', '+/', true]], quotes: [{ q: '"', esc: '\\', nl: true }, { q: '`', nl: true }, { q: "'", esc: '\\' }], custom: (s, i) => { if (s[i] === 'r' && s[i + 1] === '"' && (i === 0 || !SC_IDC.test(s[i - 1]))) { const e = s.indexOf('"', i + 2); return { end: e < 0 ? s.length : e + 1, keep: true }; } return null; } });
  const keep = scStrip(text, cfg(true)), t = scStrip(text, cfg(false)); const r = { entries: [], module: '', imports: [], external: [], problems: [], notes: [] }; let m; const md = /(?:^|\n)[ \t]*module[ \t]+([\w.]+)[ \t]*;/.exec(t); if (md) r.module = md[1];
  const re = /(\{)|(\})|(?<![\w$.])(?:void|int)\s+main\s*\(([^)]*)\)/g; let depth = 0; while ((m = re.exec(t))) { if (m[1]) depth++; else if (m[2]) depth--; else if (depth === 0) r.entries.push({ name: 'main', ok: true }); }
  const ie = /(?<![\w$.])import\s+([^;{}]+?)\s*;/g; while ((m = ie.exec(t))) for (const part of m[1].split(',')) { const p = part.split(':')[0].replace(/^[\w$]+\s*=\s*/, '').trim(); if (/^[\w.]+$/.test(p)) r.imports.push(p); }
  return r;
}
/* C# */
function scCfgCs(keep) {
  const skipInterp = (s, i, raw) => { /* $"..." / $@"..." icindeki {..} ifadeleri ozyinelemeli atlanir */ let j = i; while (j < s.length) { const c = s[j]; if (c === '{') { if (s[j + 1] === '{') { j += 2; continue; } let d = 1; j++; while (j < s.length && d > 0) { if (s[j] === '{') d++; else if (s[j] === '}') d--; else if (s[j] === '"') { j = scCsStr(s, j); continue; } j++; } continue; } if (c === '"') { if (raw && s[j + 1] === '"') { j += 2; continue; } return j + 1; } if (c === '\\' && !raw) { j += 2; continue; } if (c === '\n' && !raw) return j; j++; } return j; };
  function scCsStr(s, i) { /* normal dize */ let j = i + 1; while (j < s.length && s[j] !== '"' && s[j] !== '\n') { if (s[j] === '\\') j++; j++; } return Math.min(s.length, j + 1); }
  return { keepStrings: keep, line: ['//'], block: [['/*', '*/', false]], custom: (s, i) => {
    const c = s[i]; if (c === '"') { if (s.startsWith('"""', i)) { let q = 3; while (s[i + q] === '"') q++; const close = '"'.repeat(q); const e = s.indexOf(close, i + q); return { end: e < 0 ? s.length : e + q, keep: true }; } return { end: scCsStr(s, i), keep: true }; }
    if (c === '@' && s[i + 1] === '"') { let j = i + 2; while (j < s.length) { if (s[j] === '"') { if (s[j + 1] === '"') { j += 2; continue; } j++; break; } j++; } return { end: j, keep: true }; }
    if ((c === '$' || c === '@') && /^(?:\$@|@\$|\$)"/.test(s.slice(i, i + 3))) { const m = /^(\$@|@\$|\$)(#*)"/.exec(s.slice(i, i + 12)); const raw = m[1] !== '$'; if (m[2].length || s.startsWith('"""', i + m[1].length)) { let q = 3; while (s[i + m[1].length + q] === '"') q++; const close = '"'.repeat(q); const e = s.indexOf(close, i + m[1].length + q); return { end: e < 0 ? s.length : e + q, keep: true }; } return { end: skipInterp(s, i + m[0].length, raw), keep: true }; }
    if (c === "'") { let j = i + 1; while (j < s.length && s[j] !== "'" && s[j] !== '\n') { if (s[j] === '\\') j++; j++; } return { end: Math.min(s.length, j + 1), keep: true }; } return null; } };
}
function scCsTopLevel(t) {
  let depth = 0, buf = '', top = false, i = 0; const DECL = /^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|internal|static|sealed|abstract|partial|readonly|ref|unsafe|file|new)\s+)*(?:class|struct|interface|enum|record|delegate)\b/; const IGN = /^\s*(?:(?:global\s+)?using\s+(?!var\b|\()|namespace\b|extern\s+alias\b|\[\s*(?:assembly|module)\s*:)/;
  while (i < t.length) { const c = t[i]; if (depth === 0) { if (c === '{') { if (!(DECL.test(buf) || /^\s*namespace\b/.test(buf))) top = true; depth = 1; buf = ''; i++; continue; } if (c === ';') { if (buf.trim() && !DECL.test(buf) && !IGN.test(buf)) top = true; buf = ''; i++; continue; } if (c === '#') { const e = t.indexOf('\n', i); i = e < 0 ? t.length : e; continue; } buf += c; i++; continue; } if (c === '{') depth++; else if (c === '}') { depth--; if (depth === 0) buf = ''; } i++; }
  if (buf.trim() && !DECL.test(buf) && !IGN.test(buf) && !/^\s*namespace\b/.test(buf)) top = true; return top;
}
function scScanCs(text) {
  const t = scStrip(text, scCfgCs(false)); const r = { entries: [], top: false, namespaces: [], usings: [], external: [], gui: false, winforms: false, wpf: false, problems: [], notes: [] }; let m;
  const ure = /(?:^|\n)[ \t]*(?:global[ \t]+)?using[ \t]+(?:static[ \t]+)?(?:[A-Za-z_]\w*[ \t]*=[ \t]*)?([A-Za-z_][\w.]*)[ \t]*;/g; const nsre = /(?<![\w$.])namespace[ \t\r\n]+([A-Za-z_][\w.]*)/g; while ((m = nsre.exec(t))) r.namespaces.push(m[1]);
  const localRoots = new Set(r.namespaces.map((x) => x.split('.')[0])); const ext = new Set(); while ((m = ure.exec(t))) { r.usings.push(m[1]); const root = m[1].split('.')[0]; if (!['System', 'Microsoft', 'Windows'].includes(root) && !localRoots.has(root)) ext.add(root); } r.external = [...ext];
  r.winforms = /\bSystem\.(?:Windows\.Forms|Drawing)\b/.test(t); r.wpf = /\bSystem\.Windows(?!\.Forms)\b/.test(t) && !r.winforms; r.gui = r.winforms || r.wpf;
  const re = /(?<![.\w$@])namespace[ \t\r\n]+([A-Za-z_][\w.]*)[ \t\r\n]*(;|\{)?|(?<![.\w$@])(?:class|struct|interface|record(?:[ \t]+(?:class|struct))?)[ \t\r\n]+([A-Za-z_]\w*)|(\{)|(\})|(?:\bstatic[ \t\r\n]+(?:(?:async|unsafe)[ \t\r\n]+)*|\basync[ \t\r\n]+static[ \t\r\n]+)(?:void|int|Task(?:<int>)?|ValueTask(?:<int>)?)[ \t\r\n]+Main[ \t\r\n]*\(([^)]*)\)/g;
  const stack = []; let depth = 0, pend = null, fileNs = '';
  while ((m = re.exec(t))) {
    if (m[1] !== undefined) { if (m[2] === ';') fileNs = m[1]; else if (m[2] === '{') { stack.push({ kind: 'ns', name: m[1], depth: ++depth }); } else pend = { kind: 'ns', name: m[1] }; }
    else if (m[3] !== undefined) { if (!['where', 'new', 'struct', 'class'].includes(m[3])) pend = { kind: 'type', name: m[3] }; }
    else if (m[4]) { depth++; if (pend) { stack.push({ kind: pend.kind, name: pend.name, depth }); pend = null; } }
    else if (m[5]) { if (stack.length && stack[stack.length - 1].depth === depth) stack.pop(); depth--; pend = null; }
    else { const types = stack.filter((x) => x.kind === 'type'); if (!types.length) continue; const params = m[6]; const ok = /^\s*(?:string\s*\[\s*\]\s*\w+)?\s*$/.test(params); const ns = [fileNs, ...stack.filter((x) => x.kind === 'ns').map((x) => x.name)].filter(Boolean).join('.'); const binary = (ns ? ns + '.' : '') + types.map((x) => x.name).join('.'); r.entries.push({ name: binary, ok, gui: false, why: ok ? '' : 'Main parametresi string[] olmalı' }); }
  }
  r.top = scCsTopLevel(t); return r;
}
/* Kotlin */
function scCfgKt(keep) {
  const skipTpl = (s, i) => { let j = i, d = 1; while (j < s.length && d > 0) { const c = s[j]; if (c === '{') d++; else if (c === '}') d--; else if (c === '"') { j = ktStr(s, j); continue; } j++; } return j; };
  function ktStr(s, i) { if (s.startsWith('"""', i)) { const e = s.indexOf('"""', i + 3); if (e < 0) return s.length; let k = e + 3; while (s[k] === '"') k++; return k; } let j = i + 1; while (j < s.length && s[j] !== '"' && s[j] !== '\n') { if (s[j] === '\\') { j += 2; continue; } if (s[j] === '$' && s[j + 1] === '{') { j = skipTpl(s, j + 2); continue; } j++; } return Math.min(s.length, j + 1); }
  return { keepStrings: keep, line: ['//'], block: [['/*', '*/', true]], custom: (s, i) => { if (s[i] === '"') return { end: ktStr(s, i), keep: true }; if (s[i] === "'") { let j = i + 1; while (j < s.length && s[j] !== "'" && s[j] !== '\n') { if (s[j] === '\\') j++; j++; } return { end: Math.min(s.length, j + 1), keep: true }; } return null; } };
}
function scScanKt(text, fileName) {
  const keep = scStrip(text, scCfgKt(true)), t = scStrip(text, scCfgKt(false)); const r = { entries: [], pkg: '', imports: [], external: [], gui: false, problems: [], notes: [] }; let m;
  const pk = /(?:^|\n)[ \t]*package[ \t]+([\w.]+)/.exec(t); if (pk) r.pkg = pk[1]; const jn = /@file\s*:\s*JvmName\s*\(\s*"([A-Za-z_]\w*)"\s*\)/.exec(keep);
  const stem = String(fileName || 'Main').replace(/^.*[\\/]/, '').replace(/\.kt$/i, '').replace(/[^A-Za-z0-9_]/g, '_'); const fileCls = jn ? jn[1] : (stem.charAt(0).toUpperCase() + stem.slice(1)) + 'Kt'; const pre = r.pkg ? r.pkg + '.' : '';
  const ie = /(?:^|\n)[ \t]*import[ \t]+([\w.]+)/g; while ((m = ie.exec(t))) { r.imports.push(m[1]); const root = m[1].split('.')[0]; if (!['kotlin', 'java', 'javax', 'jdk'].includes(root)) r.external.push(m[1]); } if (r.imports.some((x) => /^(?:java\.awt|javax\.swing)/.test(x))) r.gui = true;
  const re = /(?<![\w$.@])(?:(companion)[ \t\r\n]+)?(object|class|interface)\b(?:[ \t\r\n]+([A-Za-z_]\w*))?|(\{)|(\})|(?<![\w$.])(?:suspend[ \t\r\n]+)?fun[ \t\r\n]+main[ \t\r\n]*\(([^)]*)\)/g; const stack = []; let depth = 0, pend = null;
  while ((m = re.exec(t))) {
    if (m[2]) { pend = { kind: m[2], companion: !!m[1], name: m[3] || '' }; }
    else if (m[4]) { depth++; if (pend) { stack.push({ depth, kind: pend.kind, companion: pend.companion, name: pend.name }); pend = null; } }
    else if (m[5]) { if (stack.length && stack[stack.length - 1].depth === depth) stack.pop(); depth--; pend = null; }
    else { const params = m[6].trim(); const okP = !params || /^(?:vararg\s+)?\w+\s*:\s*(?:Array\s*<\s*(?:out\s+)?String\s*>|String)\s*$/.test(params); if (depth === 0) r.entries.push({ name: pre + fileCls, ok: okP, why: okP ? '' : 'main parametresi Array<String> olmalı' });
      else { const head = t.slice(Math.max(0, m.index - 60), m.index); const top = stack[stack.length - 1]; if (/@JvmStatic\s*$/.test(head) && top && (top.kind === 'object' || top.companion)) { const owner = top.companion ? (stack[stack.length - 2] || {}).name : top.name; if (owner) r.entries.push({ name: pre + owner, ok: okP, why: okP ? '' : 'main parametresi Array<String> olmalı' }); } } }
  }
  return r;
}
/* Pascal (Free Pascal) */
function scCfgPas(keep) { return { keepStrings: keep, line: ['//'], quotes: [{ q: "'", dbl: true }], block: [], custom: (s, i) => { const c = s[i]; if (c === '{') { const e = s.indexOf('}', i + 1); const end = e < 0 ? s.length : e + 1; return { end, keep: s[i + 1] === '$' }; } if (c === '(' && s[i + 1] === '*') { const e = s.indexOf('*)', i + 2); const end = e < 0 ? s.length : e + 2; return { end, keep: s[i + 2] === '$' }; } return null; } }; }
function scScanPas(text) {
  const keep = scStrip(text, scCfgPas(true)), t = scStrip(text, scCfgPas(false)); const r = { entries: [], pkind: '', unit: '', uses: [], gui: false, problems: [], notes: [] }; let m;
  const hd = /^\s*(program|library|unit|package)\b[ \t]*([A-Za-z_][\w.]*)?/i.exec(t); if (hd) { r.pkind = hd[1].toLowerCase(); if (r.pkind === 'unit') r.unit = hd[2] || ''; if (r.pkind === 'program') r.entries.push({ name: hd[2] || 'program', ok: true }); }
  const ue = /\buses\b([^;]*);/gi; while ((m = ue.exec(t))) for (const part of m[1].split(',')) { const n = part.replace(/\bin\b[\s\S]*$/i, '').trim(); if (/^[A-Za-z_][\w.]*$/.test(n)) r.uses.push(n); }
  r.gui = /\{\$\s*APPTYPE\s+GUI\s*\}/i.test(keep); r.includes = []; const ie = /\{\$\s*(?:I|INCLUDE)\s+([^\s}]+)\s*\}/gi; while ((m = ie.exec(keep))) r.includes.push(m[1].replace(/^['"]|['"]$/g, '').replace(/^.*[\\/]/, '')); return r;
}
const SC_PAS_STD = new Set('system sysutils classes math strutils dateutils types typinfo variants character convutils fgl contnrs generics.collections generics.defaults crt dos objects strings getopts getopts2 cthreads cwstring ctypes unixtype unix baseunix windows messages syncobjs process pipes inifiles fileutil lazfileutils lazutf8 regexpr ucomplex matrix cmem heaptrc lineinfo rtlconsts ctypes sockets netdb fpjson jsonparser jsonscanner fpcunit testregistry base64 md5 sha1 crc zstream zipper hashes httpdefs fphttpclient opensslsockets strutils unicodedata widestrings'.split(' '));
/* Fortran */
function scScanFor(text, fileName) {
  const fixed = /\.(?:f|for|f77|ftn)$/i.test(fileName || ''); const lines = String(text).split('\n'); const out = lines.map((ln) => { if (fixed) { if (/^[cC*!]/.test(ln)) return ''; } let q = '', res = ''; for (let i = 0; i < ln.length; i++) { const c = ln[i]; if (q) { if (c === q) { if (ln[i + 1] === q) { res += '  '; i++; continue; } q = ''; res += c; } else res += ' '; continue; } if (c === "'" || c === '"') { q = c; res += c; continue; } if (c === '!') break; res += c; } return res; }); const t = out.join('\n');
  const r = { entries: [], modules: [], uses: [], includes: [], problems: [], notes: [] }; let m; const pr = /(?:^|\n)[ \t]*program[ \t]+([A-Za-z_]\w*)/gi; while ((m = pr.exec(t))) r.entries.push({ name: m[1], ok: true });
  const mo = /(?:^|\n)[ \t]*module[ \t]+(?!procedure\b)([A-Za-z_]\w*)/gi; while ((m = mo.exec(t))) r.modules.push(m[1].toLowerCase()); const INTR = new Set(['iso_fortran_env', 'iso_c_binding', 'ieee_arithmetic', 'ieee_exceptions', 'ieee_features', 'omp_lib', 'omp_lib_kinds', 'openacc']);
  const us = /(?:^|\n)[ \t]*use[ \t,]+(?:(?:intrinsic|non_intrinsic)[ \t]*::[ \t]*)?([A-Za-z_]\w*)/gi; while ((m = us.exec(t))) { const n = m[1].toLowerCase(); if (!INTR.has(n)) r.uses.push(n); }
  const inc = /(?:^|\n)[ \t]*include[ \t]+['"]([^'"\n]+)['"]/gi; while ((m = inc.exec(text))) r.includes.push(m[1].replace(/^.*[\\/]/, '')); if (/!\$omp\b/i.test(text)) r.notes.push('OpenMP yönergeleri bulundu (!$omp): derleme bayrağı olmadığı için paralel çalışmaz, yorum sayılır.'); return r;
}
/* ---- tek dosya ---- */
function srcScan(text, fileName) {
  const base = String(fileName || '').replace(/^.*[\\/]/, ''); const info = srcLangOf(base); const stem = base.replace(/\.[^.]+$/, ''); const src = String(text).replace(/\r\n?/g, '\n');
  const res = { file: base, stem, lang: info ? info.lang : null, kind: info ? info.kind : null, entries: [], gui: false, problems: [], notes: [], local: [], external: [] };
  if (!info || info.kind !== 'source') return res; let x;
  switch (info.lang) {
    case 'c': case 'cpp': x = scScanC(src, info.lang === 'cpp'); break; case 'rust': x = scScanRust(src); break; case 'go': x = scScanGo(src); break; case 'zig': x = scScanZig(src); break; case 'd': x = scScanD(src); break;
    case 'csharp': x = scScanCs(src); break; case 'kotlin': x = scScanKt(src, base); break; case 'pascal': x = scScanPas(src); break; case 'fortran': x = scScanFor(src, base); break; default: return res;
  }
  Object.assign(res, x, { file: base, stem, lang: info.lang, kind: info.kind }); res.problems = (x.problems || []).slice(); res.notes = (x.notes || []).slice(); return res;
}
/* ---- birden cok dosya: ortak plan. files: [{name, text}] ---- */
function srcPlan(files) {
  const out = { lang: null, langName: '', scans: [], candidates: [], problems: [], notes: [], gui: false, mainDefault: null, suggestName: 'app', order: [], std: null, libs: { m: false, pthread: false, win: [] }, mixedC: false, top: false, winforms: false, files: files.map((f) => f.name) };
  const P = (code, msg, file) => out.problems.push(file ? { code, msg, file } : { code, msg }); const names = files.map((f) => f.name); const lower = new Set(names.map((n) => n.toLowerCase()));
  if (lower.size !== names.length) P('dup-file', 'Büyük/küçük harf dışında aynı ada sahip iki dosya var.');
  for (const n of names) { if (!SRC_NAME_RE.test(n)) P('bad-name', '"' + n + '": dosya adı yalnızca harf, rakam, _ . - + içerebilir (boşluk ve Türkçe karakter yok); yeniden adlandır.'); else if (SRC_RESERVED.test(n.replace(/\..*$/, ''))) P('bad-name', '"' + n + '": Windows’ta ayrılmış bir ad.'); }
  const infos = files.map((f) => ({ f, info: srcLangOf(f.name) })); const bad = infos.filter((x) => !x.info || x.info.lang === 'java'); for (const x of bad) if (!x.info) P('bad-ext', '"' + x.f.name + '": desteklenmeyen dosya türü.');
  const srcLangs = new Set(infos.filter((x) => x.info && x.info.kind === 'source' && x.info.lang !== 'java').map((x) => x.info.lang)); const cLike = srcLangs.has('c') || srcLangs.has('cpp');
  if (cLike) { const others = [...srcLangs].filter((l) => l !== 'c' && l !== 'cpp'); if (others.length) P('multi-lang', 'Tek derlemede tek dil olabilir; C/C++ dışında başka dil de var: ' + others.map(srcLangName).join(', ') + '.'); out.lang = srcLangs.has('cpp') ? 'cpp' : 'c'; out.mixedC = srcLangs.has('c') && srcLangs.has('cpp'); }
  else if (srcLangs.size > 1) { P('multi-lang', 'Tek derlemede tek dil olabilir: ' + [...srcLangs].map(srcLangName).join(', ') + ' birlikte derlenemez.'); out.lang = [...srcLangs][0]; } else if (srcLangs.size === 1) out.lang = [...srcLangs][0];
  if (!out.lang) { P('no-source', 'Derlenecek bir kaynak dosyası yok' + (infos.some((x) => x.info && x.info.kind === 'header') ? ' (yalnızca başlık dosyaları var).' : '.')); return out; }
  out.langName = srcLangName(out.lang);
  for (const x of infos) { if (!x.info) continue; if (x.info.kind === 'aux') { if (!['pascal', 'fortran'].includes(out.lang)) P('bad-ext', '"' + x.f.name + '": .inc dosyası yalnızca Pascal/Fortran ile kullanılır.'); continue; } if (x.info.kind === 'header') { if (!(cLike && (x.info.lang === 'c' || x.info.lang === 'cpp'))) P('bad-ext', '"' + x.f.name + '": başlık dosyası bu dille birlikte kullanılamaz.'); continue; } if (x.info.lang !== out.lang && !(cLike && (x.info.lang === 'c' || x.info.lang === 'cpp'))) continue; }
  const scans = infos.filter((x) => x.info && x.info.kind === 'source' && x.info.lang !== 'java').map((x) => srcScan(x.f.text, x.f.name)); out.scans = scans;
  for (const s of scans) { for (const p of s.problems || []) out.problems.push(Object.assign({ file: s.file }, p)); if (s.gui) out.gui = true; for (const n of s.notes || []) out.notes.push(s.file + ': ' + n); }
  const have = new Set(names.map((n) => n.toLowerCase()));
  const L = out.lang; const withEntry = scans.filter((s) => s.entries && s.entries.length); const stemOf = (n) => String(n).replace(/\.[^.]+$/, '');
  if (L === 'c' || L === 'cpp') {
    for (const s of scans) { for (const lp of s.localPath || []) P('include-path', '#include "' + lp + '": alt klasör yolu desteklenmez; dosyaları aynı klasörde tut ve satırı #include "' + lp.replace(/^.*[\\/]/, '') + '" yap.', s.file); for (const inc of new Set(s.local || [])) if (!have.has(inc.toLowerCase())) P('missing-include', '#include "' + inc + '" bulunamadı: dosyayı da ekle.', s.file); else if (!names.includes(inc)) out.notes.push(s.file + ': #include "' + inc + '" büyük/küçük harfi dosya adıyla uyuşmuyor; Linux/macOS’ta derleme hata verir.'); for (const l of s.libs ? [s.libs] : []) { out.libs.m = out.libs.m || l.m; out.libs.pthread = out.libs.pthread || l.pthread; for (const w of l.win) if (!out.libs.win.includes(w)) out.libs.win.push(w); } }
    const f = scans.map((s) => s.cppFeat).filter((x) => x); out.std = L === 'cpp' ? 'c++' + Math.max(17, ...f) : 'c' + (f.includes(23) ? '23' : '17');
    for (const s of withEntry) for (const e of s.entries) out.candidates.push({ binary: e.name, file: s.file, cls: e.name, nested: false, gui: !!e.gui });
    if (out.candidates.length > 1) P('dup-main', 'Birden çok giriş noktası var (' + out.candidates.map((c) => c.file + ':' + c.binary).join(', ') + '); yalnızca biri olabilir.');
    out.mainDefault = out.candidates[0] ? out.candidates[0].binary : null; if (!out.candidates.length) P('no-main', 'Hiçbir dosyada çalıştırılabilir bir "int main(...)" (ya da WinMain) bulunamadı.');
    out.suggestName = out.candidates[0] ? stemOf(out.candidates[0].file) : stemOf(scans[0].file);
  } else if (L === 'rust') {
    const roots = scans.filter((s) => s.entries.length); for (const s of roots) out.candidates.push({ binary: s.file, file: s.file, cls: s.stem, nested: false }); roots.sort((a, b) => (b.file === 'main.rs') - (a.file === 'main.rs')); out.candidates.sort((a, b) => (b.file === 'main.rs') - (a.file === 'main.rs')); out.mainDefault = out.candidates[0] ? out.candidates[0].binary : null;
    if (!roots.length) P('no-main', 'Hiçbir dosyada "fn main()" bulunamadı' + (scans.some((s) => s.file === 'lib.rs') ? ' (lib.rs kitaplık; bu araç yalnızca çalıştırılabilir üretir).' : '.')); const root = roots[0];
    if (root) { for (const md of root.mods) if (!have.has(md.toLowerCase() + '.rs')) P('missing-mod', '"mod ' + md + ';" için ' + md + '.rs dosyası yok: ekle.', root.file); const rootMods = new Set(root.mods.map((x) => x.toLowerCase() + '.rs')); for (const s of scans) { if (s === root) continue; for (const nm of s.nestedMods || []) P('nested-mod', 'İç içe "mod ' + nm + ';" bildirimi klasör yapısı (' + s.stem + '/' + nm + '.rs) ister; bu araç tek klasörlü (düz) projeleri destekler.', s.file); for (const md of s.mods || []) P('nested-mod', '"mod ' + md + ';" klasör yapısı (' + s.stem + '/' + md + '.rs) ister; bu araç tek klasörlü (düz) projeleri destekler.', s.file); if (!rootMods.has(s.file.toLowerCase()) && s.entries.length === 0) out.notes.push(s.file + ': kök dosyadan "mod ' + s.stem + ';" ile çağrılmıyor; derlemeye katılmaz.'); } if (roots.length > 1) out.notes.push('Birden çok "fn main()" var; yalnızca seçilen kök dosya derlenir, diğerleri "mod" ile çağrılmıyorsa yok sayılır.'); const ext = new Set(); const localMods = new Set([...scans.flatMap((s) => s.mods), ...scans.flatMap((s) => s.inlineMods), ...scans.map((s) => s.stem.toLowerCase())]); for (const s of scans) for (const e of s.external) if (!localMods.has(e)) ext.add(e); if (ext.size) P('rust-ext', 'Dış crate kullanılıyor: ' + [...ext].slice(0, 8).join(', ') + '. Bu araç yalnızca standart kitaplıkla çalışır (rustc); crate indirmez ve cargo kullanmaz. Derleme büyük olasılıkla başarısız olur.'); }
    out.suggestName = root ? (root.stem === 'main' ? 'app' : root.stem) : 'app'; out.std = '2021';
  } else if (L === 'go') {
    const pk = new Set(scans.map((s) => s.pkg).filter(Boolean)); if (pk.size > 1) P('go-pkg', 'Dosyalar farklı paketlerde: ' + [...pk].join(', ') + '. Hepsi "package main" olmalı.'); else if (pk.size === 1 && !pk.has('main')) P('go-pkg', 'Paket adı "main" değil ("' + [...pk][0] + '"): çalıştırılabilir program için "package main" gerekir.');
    for (const s of withEntry) out.candidates.push({ binary: s.file, file: s.file, cls: 'main', nested: false }); if (out.candidates.length > 1) P('dup-main', 'Birden çok "func main()" var (' + out.candidates.map((c) => c.file).join(', ') + ').'); if (!out.candidates.length) P('no-main', 'Hiçbir dosyada "func main()" bulunamadı.'); out.mainDefault = out.candidates[0] ? out.candidates[0].binary : null;
    const ext = [...new Set(scans.flatMap((s) => s.external))]; if (ext.length) P('go-ext', 'Dış paket kullanılıyor: ' + ext.slice(0, 6).join(', ') + '. Araç modül indirmez (yalnızca standart kitaplık); derleme başarısız olur.'); const lp = [...new Set(scans.flatMap((s) => s.localPkgs))]; if (lp.length) P('go-local', 'Yerel paket içe aktarımı desteklenmez (tek paket): ' + lp.slice(0, 6).join(', ') + '.');
    if (scans.some((s) => s.cgo)) P('go-cgo', 'cgo (import "C") desteklenmez: C derleyicisi bağlantısı kapalıdır.'); if (scans.some((s) => s.embed)) P('go-embed', '//go:embed desteklenmez (gömülecek dosyalar alınmaz).'); for (const s of scans) for (const tg of s.tags || []) out.notes.push(s.file + ': //go:build ' + tg + ' — koşul bu sistemde sağlanmazsa dosya derlemeye girmez.');
    out.suggestName = out.candidates[0] ? stemOf(out.candidates[0].file) : stemOf(scans[0].file);
  } else if (L === 'zig') {
    const roots = scans.filter((s) => s.entries.length).sort((a, b) => (b.file === 'main.zig') - (a.file === 'main.zig')); for (const s of roots) out.candidates.push({ binary: s.file, file: s.file, cls: s.stem, nested: false }); out.mainDefault = out.candidates[0] ? out.candidates[0].binary : null; if (!roots.length) P('no-main', 'Hiçbir dosyada "pub fn main" bulunamadı.');
    for (const s of scans) { for (const lc of s.local || []) if (!have.has(lc.toLowerCase())) P('missing-import', '@import("' + lc + '") bulunamadı: dosyayı da ekle.', s.file); if (s.embed) P('zig-embed', '@embedFile desteklenmez (gömülecek dosyalar alınmaz).', s.file); if ((s.external || []).length) P('zig-ext', 'Paket içe aktarımı: ' + s.external.join(', ') + '; yalnızca std ve yerel .zig dosyaları desteklenir.', s.file); }
    out.suggestName = roots[0] ? (roots[0].stem === 'main' ? 'app' : roots[0].stem) : 'app';
  } else if (L === 'csharp') {
    const mains = []; for (const s of scans) for (const e of s.entries) mains.push({ binary: e.name, file: s.file, cls: e.name.split('.').pop(), nested: false, ok: e.ok, why: e.why }); const tops = scans.filter((s) => s.top); const okMains = mains.filter((m) => m.ok);
    for (const m of mains) if (!m.ok) P('main', m.binary + ': ' + m.why, m.file); if (tops.length > 1) P('top-multi', 'Üst düzey ifadeler yalnızca tek dosyada olabilir (' + tops.map((s) => s.file).join(', ') + ').'); if (tops.length && okMains.length) P('top-and-main', 'Hem Main metodu hem üst düzey ifadeler var; ikisi birlikte olamaz.');
    out.top = tops.length > 0; for (const m of okMains) out.candidates.push(m); if (!okMains.length && !tops.length) P('no-main', 'Hiçbir dosyada "static void Main" ya da üst düzey ifade (top-level statements) bulunamadı.');
    out.mainDefault = out.top ? '' : (okMains[0] ? okMains[0].binary : null); if (out.top) out.candidates.unshift({ binary: '', file: tops[0].file, cls: 'Program', nested: false, top: true }); out.needStartup = okMains.length > 1;
    const lr = new Set(scans.flatMap((s) => s.namespaces.map((n) => n.split('.')[0]))); const ext = new Set(); for (const s of scans) for (const e of s.external) if (!lr.has(e)) ext.add(e); if (ext.size) P('cs-ext', 'Dış kitaplık/NuGet paketi kullanılıyor: ' + [...ext].slice(0, 6).join(', ') + '. Araç NuGet paketi indirmez; derleme başarısız olur.'); out.winforms = scans.some((s) => s.winforms); if (scans.some((s) => s.wpf)) P('cs-wpf', 'WPF (System.Windows) algılandı: XAML dosyaları desteklenmez.'); if (out.winforms) out.notes.push('Windows Forms algılandı: çıktı yalnızca Windows’ta çalışır.');
    out.suggestName = out.top ? stemOf(tops[0].file) : okMains[0] ? okMains[0].binary.split('.').pop() : stemOf(scans[0].file);
  } else if (L === 'kotlin') {
    for (const s of scans) for (const e of s.entries) { if (!e.ok) P('main', e.name + ': ' + e.why, s.file); else out.candidates.push({ binary: e.name, file: s.file, cls: e.name.split('.').pop(), nested: false }); } out.candidates.sort((a, b) => (/Main(Kt)?$/.test(b.binary) - /Main(Kt)?$/.test(a.binary))); out.mainDefault = out.candidates[0] ? out.candidates[0].binary : null; if (!out.candidates.length) P('no-main', 'Hiçbir dosyada "fun main(...)" bulunamadı.');
    const pk = new Set(scans.map((s) => s.pkg).filter(Boolean)); const ext = new Set(); for (const s of scans) for (const e of s.external) { if (![...pk].some((p) => e === p || e.startsWith(p + '.'))) ext.add(e.split('.').slice(0, 2).join('.')); } if (ext.size) P('kt-ext', 'Dış kitaplık içe aktarımı: ' + [...ext].slice(0, 6).join(', ') + '. Yalnızca Kotlin standart kitaplığı ve JDK desteklenir; derleme başarısız olabilir.'); out.suggestName = out.candidates[0] ? out.candidates[0].cls.replace(/Kt$/, '') || 'app' : stemOf(scans[0].file);
  } else if (L === 'pascal') {
    const progs = scans.filter((s) => s.pkind === 'program'); for (const s of progs) out.candidates.push({ binary: s.file, file: s.file, cls: s.entries[0].name, nested: false }); out.mainDefault = out.candidates[0] ? out.candidates[0].binary : null; if (!progs.length) P('no-main', 'Hiçbir dosyada "program ...;" başlığı bulunamadı' + (scans.some((s) => s.pkind === 'library') ? ' (library: kitaplık, bu araç yalnızca exe üretir).' : '.')); if (progs.length > 1) P('dup-main', 'Birden çok "program" var (' + progs.map((s) => s.file).join(', ') + '); yalnızca biri olabilir.');
    const units = new Map(scans.filter((s) => s.pkind === 'unit').map((s) => [s.unit.toLowerCase(), s])); for (const s of scans.filter((x) => x.pkind === 'unit')) if (s.unit.toLowerCase() !== s.stem.toLowerCase()) P('unit-name', 'unit ' + s.unit + ' dosya adıyla (' + s.file + ') aynı olmalı; Free Pascal üniteyi dosya adından bulur.', s.file);
    for (const s of scans) { for (const u of s.uses || []) { const k = u.toLowerCase(); if (!units.has(k) && !SC_PAS_STD.has(k)) out.notes.push(s.file + ': "' + u + '" ünitesi bulunamadı (ne dosyalar arasında ne de bilinen standart ünitelerde); LCL/Delphi/üçüncü parti ünite ise derleme başarısız olur.'); } for (const inc of s.includes || []) if (!have.has(inc.toLowerCase())) P('missing-include', '{$I ' + inc + '} dosyası bulunamadı.', s.file); }
    const ord = []; const seen = new Set(); const visit = (s, stk) => { if (seen.has(s.file)) return; if (stk.includes(s.file)) { P('unit-cycle', 'Ünite döngüsü: ' + [...stk, s.file].join(' → ')); return; } for (const u of s.uses || []) { const d = units.get(u.toLowerCase()); if (d && d !== s) visit(d, [...stk, s.file]); } seen.add(s.file); ord.push(s.file); }; for (const s of scans.filter((x) => x.pkind === 'unit')) visit(s, []); for (const s of progs) visit(s, []); out.order = ord; out.suggestName = progs[0] ? stemOf(progs[0].file) : stemOf(scans[0].file);
  } else if (L === 'fortran') {
    const progs = []; for (const s of scans) for (const e of s.entries) progs.push({ binary: e.name, file: s.file, cls: e.name, nested: false }); out.candidates = progs; out.mainDefault = progs[0] ? progs[0].binary : null; if (!progs.length) P('no-main', 'Hiçbir dosyada "program ..." birimi bulunamadı.'); if (progs.length > 1) P('dup-main', 'Birden çok "program" var (' + progs.map((p) => p.file).join(', ') + '); yalnızca biri olabilir.');
    const mods = new Map(); for (const s of scans) for (const m of s.modules) mods.set(m, s); for (const s of scans) { for (const u of s.uses) if (!mods.has(u)) out.notes.push(s.file + ': "' + u + '" modülü bu dosyalarda tanımlı değil; sistem/üçüncü parti modülse bağlama başarısız olabilir.'); for (const inc of s.includes) if (!have.has(inc.toLowerCase())) P('missing-include', 'include "' + inc + '" dosyası bulunamadı.', s.file); }
    const ord = [], seen = new Set(); const visit = (s, stk) => { if (seen.has(s.file)) return; if (stk.includes(s.file)) { P('mod-cycle', 'Modül döngüsü: ' + [...stk, s.file].join(' → ')); return; } for (const u of s.uses) { const d = mods.get(u); if (d && d !== s) visit(d, [...stk, s.file]); } seen.add(s.file); ord.push(s.file); }; for (const s of scans) visit(s, []); out.order = ord; out.suggestName = progs[0] ? progs[0].binary : stemOf(scans[0].file);
  } else if (L === 'd') {
    for (const s of scans.filter((x) => x.entries.length)) out.candidates.push({ binary: s.file, file: s.file, cls: s.stem, nested: false }); out.mainDefault = out.candidates[0] ? out.candidates[0].binary : null; if (!out.candidates.length) P('no-main', 'Hiçbir dosyada "void main()" bulunamadı.'); if (out.candidates.length > 1) P('dup-main', 'Birden çok main var (' + out.candidates.map((c) => c.file).join(', ') + ').');
    const mods = new Set(scans.map((s) => s.module).filter(Boolean)); const ext = new Set(); for (const s of scans) for (const im of s.imports) { const root = im.split('.')[0]; if (!['std', 'core', 'etc', 'object', 'ldc', 'gcc', 'rt'].includes(root) && !mods.has(im) && ![...mods].some((m) => m.split('.')[0] === root)) ext.add(im); } if (ext.size) out.notes.push('Yerel olmayan modül içe aktarımları: ' + [...ext].slice(0, 6).join(', ') + ' — dub/üçüncü parti paketse derleme başarısız olur.'); out.suggestName = out.candidates[0] ? stemOf(out.candidates[0].file) : stemOf(scans[0].file);
  }
  out.suggestName = (String(out.suggestName).replace(/[^A-Za-z0-9_-]/g, '') || 'app').replace(/^[^A-Za-z]+/, '') || 'app'; return out;
}
