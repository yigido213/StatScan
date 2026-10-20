/* PyInstaller (CArchive/PYZ) ve Electron asar paketlerini STATIK olarak acar. Hicbir sey calistirilmaz/yorumlanmaz.
 * PyInstaller: icerik .pyc olarak cikarilir, dize/IOC/kural taramasindan gecer; kaynak koda DECOMPILE EDILMEZ (kurulu bir pycdc/uncompyle6 gerekir).
 * Sifreli PYZ (AES anahtarli) acilamaz. asar: .asar.unpacked klasorundeki dosyalar bu dosyada yoktur. */
const PYI_MAGIC = [0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e];
const PYI_STD = /^(?:__future__|_[a-z0-9_]*|abc|argparse|ast|asyncio|base64|bisect|calendar|cgi|codecs|collections|concurrent|configparser|contextlib|copy|csv|ctypes|dataclasses|datetime|decimal|difflib|dis|email|encodings|enum|errno|fnmatch|fractions|functools|gc|getpass|gettext|glob|gzip|hashlib|heapq|hmac|html|http|importlib|inspect|io|ipaddress|itertools|json|keyword|linecache|locale|logging|lzma|mimetypes|multiprocessing|netrc|nturl2path|numbers|opcode|operator|os|pathlib|pickle|pkgutil|platform|plistlib|posixpath|pprint|py_compile|queue|quopri|random|re|reprlib|runpy|sched|secrets|selectors|shlex|shutil|signal|site|smtplib|socket|socketserver|sre_[a-z]+|ssl|stat|statistics|string|stringprep|struct|subprocess|sysconfig|tarfile|tempfile|textwrap|threading|time|timeit|token|tokenize|traceback|tracemalloc|types|typing|unicodedata|unittest|urllib|uu|uuid|warnings|weakref|webbrowser|xml|zipfile|zipimport|zlib|pyimod\d+_[a-z]+|pkg_resources|setuptools|PyInstaller|pip|wheel|certifi|charset_normalizer|idna|urllib3|requests|six|packaging)(?:\.|$)/;
const PYI_BIN_SKIP = /^(?:python\d*\.dll|libpython|vcruntime|msvcp|ucrtbase|api-ms-win|libcrypto|libssl|libffi|zlib|_ssl|_ctypes|_socket|_hashlib|_bz2|_lzma|_decimal|_elementtree|_multiprocessing|_queue|_asyncio|_overlapped|select|unicodedata|pyexpat|VCRUNTIME|MSVCP|base_library)/i;
const PYC_MAGIC = { 36: [0x33, 0x0d, 0x0d, 0x0a], 37: [0x42, 0x0d, 0x0d, 0x0a], 38: [0x55, 0x0d, 0x0d, 0x0a], 39: [0x61, 0x0d, 0x0d, 0x0a], 310: [0x6f, 0x0d, 0x0d, 0x0a], 311: [0xa7, 0x0d, 0x0d, 0x0a], 312: [0xcb, 0x0d, 0x0d, 0x0a], 313: [0xf3, 0x0d, 0x0d, 0x0a] };
function pyiFind(u8) {
  if (!u8 || u8.length < 64) return null; const lo = Math.max(0, u8.length - 3e6);
  for (let i = u8.length - 24; i >= lo; i--) { if (u8[i] !== 0x4d) continue; let ok = true; for (let j = 1; j < 8; j++) if (u8[i + j] !== PYI_MAGIC[j]) { ok = false; break; } if (ok) return i; }
  return null;
}
function pyiParse(u8) {
  const ck = pyiFind(u8); if (ck == null) return null; const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  let ver21 = false, size = 24; if (ck + 88 <= u8.length) { const pl = ascii(u8, ck + 24, ck + 88); if (/^[\x20-\x7e\0]{3,64}$/.test(pl) && /py|lib|dll|so|\.\d/i.test(pl)) { ver21 = true; size = 88; } }
  const pkgLen = dv.getInt32(ck + 8), toc = dv.getInt32(ck + 12), tocLen = dv.getInt32(ck + 16), pyver = dv.getInt32(ck + 20);
  const pylib = ver21 ? ascii(u8, ck + 24, ck + 88).replace(/\0.*$/, '') : '';
  const tail = u8.length - ck - size; const start = u8.length - (pkgLen + tail); if (pkgLen <= 0 || start < 0 || toc < 0 || tocLen <= 0 || start + toc + tocLen > u8.length) return { bad: true, cookie: ck };
  const entries = []; let p = start + toc; const end = p + tocLen; let guard = 0;
  while (p + 18 <= end && guard++ < 20000) { const el = dv.getInt32(p); if (el < 18 || p + el > end + 1) break; const pos = dv.getUint32(p + 4), csz = dv.getUint32(p + 8), usz = dv.getUint32(p + 12), flag = u8[p + 16], type = String.fromCharCode(u8[p + 17]); let name = ''; for (let i = p + 18; i < p + el && u8[i]; i++) name += String.fromCharCode(u8[i]); entries.push({ name, type, flag, pos: start + pos, csz, usz }); p += el; }
  return { cookie: ck, start, pyver, pylib, entries, truncated: guard >= 20000 };
}
async function pyiData(u8, pk, e, cap) { if (e.pos < 0 || e.pos + e.csz > u8.length) throw new Error('girdi sınır dışı'); const raw = u8.subarray(e.pos, e.pos + e.csz); if (e.flag === 1) { const d = await inflateAny(raw, 'deflate', cap || 40e6); if (!d.length && e.usz > 0) throw new Error('zlib açılamadı'); return d; } return raw; }
/* marshal alt kumesi: yalnizca PYZ icindekileri okumak icin (kod nesnesi calistirilmaz/yorumlanmaz) */
function pyMarshalRead(u8, pos) {
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength); let p = pos; const refs = []; let nodes = 0; const END = {};
  const need = (n) => { if (p + n > u8.length) throw new Error('marshal: veri bitti'); };
  const str = (n, enc) => { need(n); const s = enc === 'u' ? td8.decode(u8.subarray(p, p + n)) : String.fromCharCode.apply(null, u8.subarray(p, p + n)); p += n; return s; };
  const rd = () => {
    if (++nodes > 300000) throw new Error('marshal: sınır'); need(1); let t = u8[p++]; const fl = t & 0x80; t &= 0x7f; const c = String.fromCharCode(t); let v;
    const reserve = () => (fl ? refs.push(undefined) - 1 : -1); const fin = (i, val) => { if (i >= 0) refs[i] = val; return val; };
    switch (c) {
      case 'N': v = null; break; case 'T': v = true; break; case 'F': v = false; break; case '0': return END; case '.': v = undefined; break;
      case 'i': need(4); v = dv.getInt32(p, true); p += 4; break;
      case 'I': need(8); v = Number(dv.getBigInt64(p, true)); p += 8; break;
      case 'g': need(8); v = dv.getFloat64(p, true); p += 8; break;
      case 'l': { need(4); const n = dv.getInt32(p, true); p += 4; const m = Math.abs(n); need(m * 2); let b = 0n; for (let i = m - 1; i >= 0; i--) b = (b << 15n) | BigInt(dv.getUint16(p + i * 2, true)); p += m * 2; v = Number(n < 0 ? -b : b); break; }
      case 's': { need(4); const n = dv.getUint32(p, true); p += 4; v = str(n, 's'); break; }
      case 't': case 'a': case 'A': case 'u': { need(4); const n = dv.getUint32(p, true); p += 4; v = str(n, c === 'u' ? 'u' : 's'); break; }
      case 'z': case 'Z': { need(1); const n = u8[p++]; v = str(n, 's'); break; }
      case 'r': { need(4); const i = dv.getUint32(p, true); p += 4; return refs[i]; }
      case '(': case '[': case '<': case '>': { need(4); const n = dv.getUint32(p, true); p += 4; if (n > 100000) throw new Error('marshal: büyük kapsayıcı'); const ri = reserve(); const a = []; for (let i = 0; i < n; i++) a.push(rd()); return fin(ri, a); }
      case ')': { need(1); const n = u8[p++]; const ri = reserve(); const a = []; for (let i = 0; i < n; i++) a.push(rd()); return fin(ri, a); }
      case '{': { const ri = reserve(); const m = new Map(); for (;;) { const k = rd(); if (k === END) break; const val = rd(); m.set(k, val); if (m.size > 100000) throw new Error('marshal: büyük sözlük'); } return fin(ri, m); }
      default: throw new Error('marshal: desteklenmeyen tür ' + c);
    }
    if (fl) refs.push(v); return v;
  };
  return rd();
}
async function pyzParse(u8, data) {
  if (data.length < 12 || ascii(data, 0, 3) !== 'PYZ') return null; const dv = new DataView(data.buffer, data.byteOffset, data.byteLength); const magic = Array.from(data.subarray(4, 8)); const tocOff = dv.getUint32(8);
  if (tocOff < 12 || tocOff >= data.length) return { magic, mods: [], bad: true };
  let toc; try { toc = pyMarshalRead(data, tocOff); } catch (e) { return { magic, mods: [], bad: true, err: String(e.message || e) }; }
  const items = toc instanceof Map ? [...toc] : (Array.isArray(toc) ? toc : []); const mods = [];
  for (const it of items) { const nm = Array.isArray(it) ? it[0] : null; const v = Array.isArray(it) ? it[1] : null; if (typeof nm !== 'string' || !Array.isArray(v) || v.length < 3) continue; mods.push({ name: nm, ispkg: v[0], pos: v[1], len: v[2] }); if (mods.length >= 20000) break; }
  return { magic, mods };
}
/* .pyc/marshal verisindeki dize sabitlerini (kisa ASCII 'z/Z', ASCII 'a/A', unicode 'u', bytes 's') tur baytlariyla karismadan toplar. Kod calistirilmaz. */
function pyConstText(u8) {
  const out = []; let tot = 0; const n = u8.length; const ok = (a, b) => { for (let k = a; k < b; k++) { const c = u8[k]; if (!((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13)) return false; } return true; };
  for (let i = 0; i + 2 < n && tot < 4e6; i++) {
    const t = u8[i] & 0x7f; let len = -1, st = 0;
    if (t === 0x7a || t === 0x5a) { len = u8[i + 1]; st = i + 2; }
    else if ((t === 0x61 || t === 0x41 || t === 0x75 || t === 0x73 || t === 0x74) && i + 5 <= n) { len = u8[i + 1] | (u8[i + 2] << 8) | (u8[i + 3] << 16) | (u8[i + 4] << 24); st = i + 5; }
    if (len < 4 || len > 65536 || st + len > n || !ok(st, st + len)) continue;
    out.push(String.fromCharCode.apply(null, u8.subarray(st, st + len))); tot += len; i = st + len - 1;
  }
  return out;
}
const pycWrap = (data, magic, pyver) => { const hdr = pyver && pyver < 37 ? 12 : 16; const o = new Uint8Array(hdr + data.length); o.set(magic.slice(0, 4), 0); o.set(data, hdr); return o; };
/* tum icerigi bellekte coz (sinirli). ret: { info, files:[{path, bytes, kind, lib}] } */
async function pyiExtract(u8, opts) {
  opts = opts || {}; const pk = pyiParse(u8); if (!pk) return null; if (pk.bad) return { info: { bad: true }, files: [], notes: ['PyInstaller çerezi bulundu ama içindekiler tablosu geçersiz/desteklenmiyor.'] };
  const files = [], notes = []; const maxMods = opts.maxMods || 4000, cap = opts.cap || 60e6; let total = 0; let encrypted = false; let libMods = 0, ownMods = 0;
  const py = pk.pyver >= 100 ? 'Python ' + Math.floor(pk.pyver / 100) + '.' + (pk.pyver % 100) : (pk.pyver >= 10 ? 'Python ' + Math.floor(pk.pyver / 10) + '.' + (pk.pyver % 10) : 'Python ?');
  const fallbackMagic = PYC_MAGIC[pk.pyver >= 100 ? pk.pyver : 0] || null;
  for (const e of pk.entries) {
    if (total > cap) { notes.push('Toplam açılmış veri sınırı aşıldı; kalan girdiler açılmadı.'); break; }
    let d = null; try { d = await pyiData(u8, pk, e, 30e6); } catch (er) { if (e.type === 'z' || e.type === 'Z') encrypted = true; notes.push(e.name + ': açılamadı (' + String(er.message || er).slice(0, 40) + ')'); continue; }
    total += d.length;
    if (e.type === 's') files.push({ path: 'scripts/' + e.name + '.pyc', bytes: pycWrap(d, fallbackMagic || [0, 0, 0, 0], pk.pyver), kind: 'script', lib: false, raw: d });
    else if (e.type === 'z' || e.type === 'Z') {
      const pz = await pyzParse(u8, d); if (!pz) { notes.push(e.name + ': PYZ başlığı tanınmadı'); continue; } if (pz.bad) { encrypted = true; notes.push(e.name + ': PYZ içindekiler tablosu okunamadı (şifreli olabilir)'); continue; }
      let nfail = 0; for (const m of pz.mods.slice(0, maxMods)) { let md = null; try { md = await inflateAny(d.subarray(m.pos, m.pos + m.len), 'deflate', 8e6); } catch (er) { nfail++; continue; } if (!md.length) { nfail++; continue; } const lib = PYI_STD.test(m.name); lib ? libMods++ : ownMods++; total += md.length; files.push({ path: 'pyz/' + m.name.replace(/\./g, '/') + (m.ispkg ? '/__init__' : '') + '.pyc', bytes: pycWrap(md, pz.magic, pk.pyver), kind: 'module', lib, raw: md, mod: m.name }); }
      if (pz.mods.length && nfail > pz.mods.length / 2) { encrypted = true; notes.push('PYZ modüllerinin çoğu açılamadı: arşiv şifreli (AES anahtarlı) olabilir.'); }
    } else if (e.type === 'm' || e.type === 'M') files.push({ path: 'modules/' + e.name + '.pyc', bytes: pycWrap(d, fallbackMagic || [0, 0, 0, 0], pk.pyver), kind: 'module', lib: PYI_STD.test(e.name), raw: d, mod: e.name });
    else if (e.type === 'b' || e.type === 'x' || e.type === 'd') files.push({ path: (e.type === 'b' ? 'binaries/' : 'data/') + e.name.replace(/\\/g, '/').replace(/^\/+/, ''), bytes: d, kind: e.type === 'b' ? 'binary' : 'data', lib: e.type === 'b' && PYI_BIN_SKIP.test(baseName(e.name)) });
  }
  return { info: { py, pyver: pk.pyver, pylib: pk.pylib, entries: pk.entries.length, scripts: files.filter((f) => f.kind === 'script').map((f) => f.path.replace(/^scripts\/|\.pyc$/g, '')), modules: files.filter((f) => f.kind === 'module').length, libMods, ownMods, encrypted, truncated: pk.truncated }, files, notes };
}
async function analyzePyInstaller(u8, name, st, depth) {
  const F = [], kids = []; const ex = await pyiExtract(u8, { cap: Math.min(st.cfg.maxTotal || 60e6, 80e6) }); if (!ex) return null; const info = ex.info;
  if (info.bad) return { findings: [mk('pyi_pack', 'info', 0, 'PyInstaller çerezi var ama içerik okunamadı', ex.notes[0], 'Dosyayı pyinstxtractor gibi bir araçla incele.', [], 'obf', { basis: 'fact' })], children: [], info: { pyinstaller: info } };
  const own = ex.files.filter((f) => (f.kind === 'script' || f.kind === 'module') && !f.lib); const names = ex.files.map((f) => f.path).join('\n');
  F.push(mk('pyi_pack', 'info', 1, 'PyInstaller ile paketlenmiş Python uygulaması', info.py + ' · ' + info.entries + ' girdi · ' + info.ownMods + ' özgün + ' + info.libMods + ' kütüphane modülü. İçerik .pyc olarak çıkarıldı ve taranıyor; hiçbir kod çalıştırılmadı. Kaynak koda DECOMPILE edilmedi.', 'Zararlı şüphesi varsa .pyc dosyalarını güvenli bir ortamda pycdc/uncompyle6 ile çöz.', ['giriş betikleri: ' + (info.scripts.slice(0, 6).join(', ') || '—')], 'obf', { basis: 'fact' }));
  if (/pytransform|pyarmor/i.test(names)) F.push(mk('pyi_pyarmor', 'med', 8, 'PyArmor ile korunmuş Python kodu', 'Paket içinde PyArmor çalışma zamanı (pytransform) var; kod şifreli olduğu için analizi sınırlıdır.', 'Statik inceleme yetersiz kalır; güvenli bir ortamda davranış analizi gerekir.', ['pytransform/pyarmor modülü'], 'obf', { basis: 'fact', mitre: ['T1027'] }));
  if (info.encrypted) F.push(mk('pyi_encrypted', 'low', 4, 'PyInstaller arşivi şifreli', 'PYZ içeriği açılamadı (AES anahtarlı paketleme olabilir). İçerik taranamadı.', 'İçeriği statik olarak değerlendiremedin; başka bir yöntemle incele.', ex.notes.slice(0, 3), 'obf', { basis: 'inference', mitre: ['T1027'] }));
  const MAXK = st.cfg.deepJar ? 160 : 60; let n = 0;
  for (const f of ex.files) {
    if (n >= MAXK || st.stop) { if (n >= MAXK) limitHit(st, 'pyi', 'PyInstaller içeriğinde çok girdi var; ilk ' + MAXK + ' özgün/ilgili girdi tarandı.'); break; }
    if (f.lib) continue; if (f.kind === 'binary' && f.bytes.length > 6e6) continue; if (f.kind === 'data' && f.bytes.length > 1e6) continue; if (depth + 1 > st.cfg.depth + 2) continue;
    n++; const isCode = f.kind === 'script' || f.kind === 'module'; const kr = await scanBuffer(isCode ? new TextEncoder().encode(pyConstText(f.raw).join('\n')) : f.bytes, name + ' › ' + f.path + (isCode ? ' [sabit dizeler]' : ''), st, depth + 1); kids.push(kr);
  }
  return { findings: F, children: kids, info: { pyinstaller: { py: info.py, scripts: info.scripts, own: info.ownMods, lib: info.libMods, encrypted: info.encrypted } }, extracted: ex };
}
/* ---- Electron asar ---- */
function isAsar(u8) { if (!u8 || u8.length < 24) return false; const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength); if (dv.getUint32(0, true) !== 4) return false; const jl = dv.getUint32(12, true); return jl > 2 && 16 + jl <= u8.length && ascii(u8, 16, 25) === '{"files":' && dv.getUint32(4, true) >= jl + 4; }
function asarParse(u8) {
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength); const hsz = dv.getUint32(4, true), jl = dv.getUint32(12, true); let j; try { j = JSON.parse(td8.decode(u8.subarray(16, 16 + jl))); } catch (e) { return null; }
  const base = 8 + hsz; const files = []; const walk = (node, prefix, depth) => { if (depth > 30 || files.length > 60000) return; for (const [k, v] of Object.entries(node.files || {})) { const pth = prefix ? prefix + '/' + k : k; if (v && v.files) walk(v, pth, depth + 1); else if (v) files.push({ path: pth, size: v.size >>> 0, offset: v.unpacked ? -1 : Number(v.offset || 0), unpacked: !!v.unpacked, link: !!v.link }); } };
  walk(j, '', 0); return { base, files };
}
async function analyzeAsar(u8, name, st, depth) {
  const F = [], kids = []; const a = asarParse(u8); if (!a) return { findings: [mk('asar_bad', 'info', 0, 'asar başlığı okunamadı', 'Electron asar başlığı bozuk veya desteklenmiyor.', 'Dosyayı elle incele.', [], 'obf', { basis: 'fact' })], children: [], info: { kind: 'Electron asar' } };
  const unp = a.files.filter((f) => f.unpacked).length; const info = { kind: 'Electron asar', asar: { files: a.files.length, unpacked: unp } };
  const pj = a.files.find((f) => f.path === 'package.json' && f.offset >= 0); let main = '';
  if (pj && a.base + pj.offset + pj.size <= u8.length) { try { const j = JSON.parse(td8.decode(u8.subarray(a.base + pj.offset, a.base + pj.offset + pj.size))); main = j.main || ''; info.asar.main = main; info.asar.pkg = j.name; } catch (e) { /* yoksay */ } }
  F.push(mk('asar_pack', 'info', 1, 'Electron uygulama paketi (asar)', a.files.length + ' dosya' + (main ? ' · ana dosya: ' + main : '') + '. İçerik statik olarak taranıyor; hiçbir kod çalıştırılmadı.' + (unp ? ' ' + unp + ' dosya .asar.unpacked klasöründe olduğu için bu dosyada yok.' : ''), 'Uygulamanın kaynağından emin değilsen çalıştırma.', [], 'obf', { basis: 'fact' }));
  const nodeMods = a.files.filter((f) => /\.node$/i.test(f.path) && f.offset >= 0); if (nodeMods.length) F.push(mk('asar_native', 'low', 4, 'Yerel eklenti (.node) içeriyor', 'asar içinde derlenmiş Node eklentileri var; JavaScript analizinin göremediği yerel kod çalıştırabilirler.', 'Eklentileri ayrıca tara.', nodeMods.slice(0, 5).map((f) => f.path), 'obf', { basis: 'fact' }));
  const MAXK = st.cfg.deepJar ? 400 : 120; let n = 0, bytes = 0;
  const cand = a.files.filter((f) => f.offset >= 0 && f.size > 0 && /\.(?:js|cjs|mjs|json|html|htm|node|ps1|bat|cmd|vbs|sh|py)$/i.test(f.path) && !/(^|\/)node_modules\//.test(f.path)).sort((x, y) => (x.path === main ? -1 : y.path === main ? 1 : 0));
  for (const f of cand) {
    if (n >= MAXK || st.stop) { if (n >= MAXK) limitHit(st, 'asar', 'asar içinde çok dosya var; ilk ' + MAXK + ' uygulama dosyası tarandı (node_modules hariç).'); break; }
    if (f.size > (/\.node$/i.test(f.path) ? 8e6 : 3e6) || a.base + f.offset + f.size > u8.length) continue; if (bytes + f.size > 60e6) { limitHit(st, 'asar', 'asar toplam okuma sınırı aşıldı.'); break; } bytes += f.size; n++;
    const kr = await scanBuffer(u8.slice(a.base + f.offset, a.base + f.offset + f.size), name + ' › ' + f.path, st, depth + 1); if (kr.score > 0 || f.path === main || (kr.info && kr.info.iocs)) kids.push(kr);
  }
  const nm = a.files.filter((f) => /(^|\/)node_modules\//.test(f.path)).length; if (nm) F.push(mk('asar_nm', 'info', 0, 'node_modules atlandı', nm + ' bağımlılık dosyası taranmadı (yalnızca uygulamanın kendi dosyaları incelenir).', 'Bağımlılıklar için npm audit gibi araçlar kullan.', [], 'obf', { basis: 'fact' }));
  return { findings: F, children: kids, info };
}
