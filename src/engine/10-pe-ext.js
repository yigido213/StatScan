/* ---------- v3.6: PE genisletmeleri (kaynak/surum/manifest, gecikmeli import, TLS, export yonlendirme, baslik tutarliligi, yetenek eslemesi) ---------- */
const RT_NAMES = { 1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU', 5: 'DIALOG', 6: 'STRING', 9: 'ACCELERATOR', 10: 'RCDATA', 11: 'MESSAGETABLE', 12: 'GROUP_CURSOR', 14: 'GROUP_ICON', 16: 'VERSION', 23: 'HTML', 24: 'MANIFEST' };
function peDirs(u8, p) {
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength); const oh = p.peOff + 24;
  const ddOff = oh + (p.is64 ? 112 : 96); const nd = dv.getUint32(oh + (p.is64 ? 108 : 92), true);
  const base = p.is64 ? Number(dv.getBigUint64(oh + 24, true)) : dv.getUint32(oh + 28, true);
  const sizeOfImage = dv.getUint32(oh + 56, true);
  const dd = (i) => (i < nd && ddOff + i * 8 + 8 <= u8.length ? { rva: dv.getUint32(ddOff + i * 8, true), size: dv.getUint32(ddOff + i * 8 + 4, true) } : { rva: 0, size: 0 });
  return { dv, base, sizeOfImage, dd, nd };
}
function peRva2Off(p, u8, rva) { for (const s of p.sections) { const sz = Math.max(s.vsize, s.rsize); if (rva >= s.va && rva < s.va + sz) { const o = rva - s.va + s.rptr; return o < u8.length ? o : -1; } } return -1; }
const rdU16z = (u8, o, max) => { let s = ''; for (let i = 0; i < (max || 256) && o + i * 2 + 1 < u8.length; i++) { const c = u8[o + i * 2] | (u8[o + i * 2 + 1] << 8); if (!c) break; s += String.fromCharCode(c); } return s; };
/* PE sağlama toplami (ImageHlp CheckSumMappedFile ile ayni) */
function peChecksum(u8, chkOff) {
  let sum = 0; const n = u8.length; const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  for (let i = 0; i + 1 < n; i += 2) { if (i === chkOff || i === chkOff + 2) continue; sum += dv.getUint16(i, true); if (sum > 0xffffffff) sum = (sum & 0xffffffff) + 1; }
  if (n & 1) { sum += u8[n - 1]; if (sum > 0xffffffff) sum = (sum & 0xffffffff) + 1; }
  sum = (sum & 0xffff) + (sum >>> 16); sum = (sum + (sum >>> 16)) & 0xffff; return (sum + n) >>> 0;
}
/* Kaynak dizini: 3 seviye (tur/ad/dil); en cok 3000 yaprak */
function peResources(u8, p, D) {
  const r = D.dd(2); if (!r.rva) return null; const base = peRva2Off(p, u8, r.rva); if (base < 0) return null;
  const out = []; let budget = 3000;
  const nameAt = (o) => { const q = base + (o & 0x7fffffff); if (q + 2 > u8.length) return '?'; return rdU16z(u8, q + 2, Math.min(60, u8[q] | (u8[q + 1] << 8))); };
  const walk = (dirOff, level, path) => {
    if (budget <= 0 || dirOff + 16 > u8.length) return;
    const n = (u8[dirOff + 12] | (u8[dirOff + 13] << 8)) + (u8[dirOff + 14] | (u8[dirOff + 15] << 8));
    for (let i = 0; i < Math.min(n, 512) && budget > 0; i++) {
      const e = dirOff + 16 + i * 8; if (e + 8 > u8.length) break;
      const nm = D.dv.getUint32(e, true), off = D.dv.getUint32(e + 4, true);
      const label = (nm & 0x80000000) ? nameAt(nm) : nm;
      if (off & 0x80000000) { if (level < 3) walk(base + (off & 0x7fffffff), level + 1, path.concat([label])); }
      else {
        const de = base + off; if (de + 16 > u8.length) continue; const rva = D.dv.getUint32(de, true), size = D.dv.getUint32(de + 4, true); const fo = peRva2Off(p, u8, rva);
        budget--; out.push({ type: path[0] != null ? path[0] : label, name: path[1] != null ? path[1] : label, lang: level >= 3 ? label : 0, off: fo, size });
      }
    }
  };
  walk(base, 1, []);
  return out;
}
/* VS_VERSIONINFO ayristirma */
function verNode(u8, o, lim, base) {
  if (o + 6 > lim) return null; const len = u8[o] | (u8[o + 1] << 8), vlen = u8[o + 2] | (u8[o + 3] << 8), type = u8[o + 4] | (u8[o + 5] << 8);
  if (len < 6 || o + len > lim) return null; let q = o + 6; let key = '';
  while (q + 1 < o + len) { const c = u8[q] | (u8[q + 1] << 8); q += 2; if (!c) break; key += String.fromCharCode(c); if (key.length > 64) break; }
  const al = (x) => base + (((x - base) + 3) & ~3); q = al(q);
  const node = { key, type, vlen, kids: [], val: '' }; const vbytes = type === 1 ? vlen * 2 : vlen;
  if (type === 1 && q + vbytes <= o + len) node.val = rdU16z(u8, q, vlen);
  q = al(q + vbytes);
  while (q + 6 <= o + len) { const k = verNode(u8, q, o + len, base); if (!k) break; node.kids.push(k.node); q = al(q + k.len); }
  return { node, len };
}
function peVersion(u8, res) {
  const v = res.find((r) => r.type === 16 && r.off >= 0 && r.size >= 40); if (!v) return null;
  const rn = verNode(u8, v.off, Math.min(u8.length, v.off + v.size), v.off); if (!rn || rn.node.key !== 'VS_VERSION_INFO') return null;
  const o = {}; for (const k of rn.node.kids) if (k.key === 'StringFileInfo') for (const t of k.kids) for (const s of t.kids) if (s.val) o[s.key] = s.val.slice(0, 120);
  return o;
}
function peManifest(u8, res) {
  const m = res.find((r) => r.type === 24 && r.off >= 0 && r.size > 20 && r.size < 200000); if (!m) return null;
  const t = td8.decode(u8.subarray(m.off, m.off + m.size)); const o = { len: m.size };
  let x = /requestedExecutionLevel[^>]*level\s*=\s*["']([A-Za-z]+)["']/i.exec(t); if (x) o.level = x[1];
  x = /uiAccess\s*=\s*["'](true|false)["']/i.exec(t); if (x) o.uiAccess = x[1] === 'true';
  o.autoElevate = /autoElevate[^<]*>\s*true/i.test(t); return o;
}
/* TLS geri cagirimlari */
function peTls(u8, p, D) {
  const t = D.dd(9); if (!t.rva) return []; const o = peRva2Off(p, u8, t.rva); if (o < 0) return [];
  const w = p.is64 ? 8 : 4; if (o + 4 * w > u8.length) return [];
  const cbVA = p.is64 ? Number(D.dv.getBigUint64(o + 3 * 8, true)) : D.dv.getUint32(o + 12, true); if (!cbVA) return [];
  let q = peRva2Off(p, u8, cbVA - D.base); const out = [];
  if (q < 0) return out;
  for (let i = 0; i < 16 && q + w <= u8.length; i++, q += w) { const a = p.is64 ? Number(D.dv.getBigUint64(q, true)) : D.dv.getUint32(q, true); if (!a) break; out.push(a - D.base); }
  return out;
}
/* Export yonlendirmeleri (forwarder) */
function peForwarders(u8, p, D) {
  const e = D.dd(0); if (!e.rva) return { n: 0, fw: [] }; const o = peRva2Off(p, u8, e.rva); if (o < 0 || o + 40 > u8.length) return { n: 0, fw: [] };
  const nf = Math.min(D.dv.getUint32(o + 20, true), 8000), af = peRva2Off(p, u8, D.dv.getUint32(o + 28, true)); const fw = [];
  if (af < 0) return { n: nf, fw };
  for (let i = 0; i < nf && af + i * 4 + 4 <= u8.length; i++) { const rva = D.dv.getUint32(af + i * 4, true); if (rva >= e.rva && rva < e.rva + e.size) { const fo = peRva2Off(p, u8, rva); if (fo >= 0) { let s = ''; for (let k = fo; k < u8.length && u8[k] && s.length < 120; k++) s += String.fromCharCode(u8[k]); fw.push(s); } } }
  return { n: nf, fw };
}
/* Gecikmeli import tablosu */
function peDelayImports(u8, p, D, out) {
  const d = D.dd(13); if (!d.rva) return 0; let o = peRva2Off(p, u8, d.rva); if (o < 0) return 0; let n = 0;
  for (let i = 0; i < 200 && o + 32 <= u8.length; i++, o += 32) {
    const attr = D.dv.getUint32(o, true), nameR = D.dv.getUint32(o + 4, true), intR = D.dv.getUint32(o + 16, true); if (!nameR) break;
    const rel = (attr & 1) === 0 ? (v) => v - D.base : (v) => v; // attr bit0: RVA mi VA mi (eski VA)
    const no = peRva2Off(p, u8, (attr & 1) ? nameR : rel(nameR)); if (no < 0) break; let dll = ''; for (let k = no; k < u8.length && u8[k] && dll.length < 100; k++) dll += String.fromCharCode(u8[k]); dll = dll.toLowerCase();
    let to = peRva2Off(p, u8, intR); const fns = []; const step = p.is64 ? 8 : 4;
    if (to >= 0) for (let k = 0; k < 2000 && to + step <= u8.length; k++, to += step) { const v = p.is64 ? Number(D.dv.getBigUint64(to, true)) : D.dv.getUint32(to, true); if (!v) break; if (v >= (p.is64 ? 2 ** 63 : 0x80000000)) { fns.push('#' + (v & 0xffff)); continue; } const no2 = peRva2Off(p, u8, v); if (no2 >= 0) { let s = ''; for (let q = no2 + 2; q < u8.length && u8[q] && s.length < 100; q++) s += String.fromCharCode(u8[q]); fns.push(s); } }
    out.set(dll, (out.get(dll) || []).concat(fns)); n += fns.length;
  }
  return n;
}
function overlayKind(u8, start, certOff, certSize) {
  let end = u8.length; if (certOff > start && certOff + certSize <= u8.length + 8) end = certOff; const len = end - start; if (len <= 0) return { kind: '', len: 0 };
  const h = u8.subarray(start, Math.min(end, start + 64)); const A = (s) => ascii(h, 0, s.length) === s;
  if (len >= 8 && h[4] === 0xef && h[5] === 0xbe && h[6] === 0xad && h[7] === 0xde && ascii(h, 8, 20) === 'NullsoftInst') return { kind: 'nsis', len, label: 'NSIS yükleyici verisi' };
  if (A('PK\x03\x04')) return { kind: 'zip', len, label: 'ZIP/SFX arşivi' };
  if (A('7z\xbc\xaf\x27\x1c')) return { kind: '7z', len, label: '7-Zip SFX arşivi' };
  if (A('Rar!')) return { kind: 'rar', len, label: 'RAR SFX arşivi' };
  if (A('MSCF')) return { kind: 'cab', len, label: 'CAB arşivi' };
  if (h[0] === 0x4d && h[1] === 0x5a) return { kind: 'pe', len, label: 'Eklenmiş başka bir PE' };
  if (A('zlb\x1a') || A('idska32\x1a')) return { kind: 'inno', len, label: 'Inno Setup verisi' };
  return { kind: 'data', len, label: 'Tanımsız ek veri' };
}
const SIDELOAD = new Set(['version', 'winmm', 'dwmapi', 'wtsapi32', 'cryptsp', 'cryptbase', 'uxtheme', 'dbghelp', 'dbgcore', 'd3d9', 'd3d11', 'dxgi', 'dinput8', 'xinput1_3', 'xinput1_4', 'winhttp', 'iphlpapi', 'msimg32', 'lpk', 'ntmarta', 'userenv', 'wlanapi', 'wow64log', 'apphelp', 'profapi', 'mscms', 'secur32', 'cabinet', 'hid', 'shfolder', 'edputil']);
const DRV_DLLS = /^(?:ntoskrnl|hal|ndis|fltmgr|wdfldr|ksecdd|cng)\.(?:exe|dll|sys)$/i;
/* Ana giris: analyzePE sonunda cagrilir. p.apis: kucuk harfli import adlari kumesi */
async function peExtra(u8, p, info, F, children, st, depth, name, apis, text) {
  const cfg = st.cfg; const L = []; const has = (n) => { n = n.toLowerCase(); return apis.has(n) || apis.has(n + 'a') || apis.has(n + 'w') || apis.has(n + 'exa') || apis.has(n + 'exw') || apis.has(n + 'ex'); };
  const any = (...a) => a.some(has); const loc = (o, n, l) => ({ o, n, l });
  let D; try { D = peDirs(u8, p); } catch (e) { return L; }
  const base = baseName(name); const bnl = base.replace(/\.[^.]*$/, '').toLowerCase();
  /* ---- baslik tutarliligi ---- */
  const chk = D.dv.getUint32(p.chkOff, true);
  if (chk && u8.length < 400e6) { const real = peChecksum(u8, p.chkOff); info.checksum = { header: chk, computed: real }; if (real !== chk) F.push(mk('pe_chk_bad', 'low', 3, 'PE sağlama toplamı dosyayla uyuşmuyor', 'Başlıktaki sağlama toplamı (0x' + chk.toString(16) + ') dosyadan hesaplanan değerden (0x' + real.toString(16) + ') farklı. Bağlayıcı sonrası yama/enfeksiyon, imza ekleme veya el ile düzenleme sonucu olabilir; birçok meşru dosyada da yoktur ya da hatalıdır.', 'Dosyayı resmi kaynaktan yeniden indirip hash’leri karşılaştır.', ['başlık 0x' + chk.toString(16) + ' ≠ hesaplanan 0x' + real.toString(16)], 'pe', { loc: [loc(p.chkOff, 4, 'CheckSum alanı')] })); }
  L.push(led('pe_chk', 'PE sağlama toplamı doğrulaması', chk ? 'done' : 'na', chk ? '' : 'başlıkta sağlama toplamı yok (0)'));
  const maxEnd = p.sections.reduce((a, s) => Math.max(a, s.va + Math.max(s.vsize, 0)), 0); if (D.sizeOfImage && maxEnd > D.sizeOfImage) F.push(mk('pe_sizeimg', 'low', 3, 'SizeOfImage bölümlerden küçük', 'Başlıktaki imaj boyutu bölümlerin sanal bitişinden küçük; Windows bu dosyayı yüklemez veya el ile bozulmuştur.', 'PE editörde başlığı incele.', ['SizeOfImage 0x' + D.sizeOfImage.toString(16) + ' < 0x' + maxEnd.toString(16)], 'pe'));
  const trunc = p.sections.filter((s) => s.rsize && s.rptr + s.rsize > u8.length + 0x200); if (trunc.length) F.push(mk('pe_trunc', 'low', 4, 'Bölümler dosya sonunu aşıyor', 'Bir veya daha fazla bölümün ham boyutu dosyanın bittiği yeri geçiyor (kesilmiş indirme ya da bilerek bozulmuş başlık).', 'Dosyanın eksiksiz indirilip indirilmediğini doğrula.', trunc.map((s) => s.name), 'pe'));
  const ov = []; const rs = p.sections.filter((s) => s.rsize).slice().sort((a, b) => a.rptr - b.rptr); for (let i = 1; i < rs.length; i++) if (rs[i].rptr < rs[i - 1].rptr + rs[i - 1].rsize) ov.push(rs[i - 1].name + ' ∩ ' + rs[i].name);
  if (ov.length) F.push(mk('pe_sec_overlap', 'low', 4, 'Üst üste binen bölüm verileri', 'Bölümlerin dosyadaki aralıkları çakışıyor; PE ayrıştırıcılarını şaşırtmak için kullanılan bir bozma tekniği olabilir.', 'PE editörde bölüm tablosunu incele.', ov, 'pe'));
  const badName = p.sections.filter((s) => /[^\x20-\x7e]/.test(s.name) || !s.name); if (badName.length) F.push(mk('pe_sec_name', 'low', 3, 'Bölüm adlarında yazdırılamayan/boş karakter', 'Normal derleyiciler okunabilir ASCII bölüm adı üretir.', 'Paketleyici/koruyucu izi olarak değerlendir.', badName.map((s) => JSON.stringify(s.name)), 'pe'));
  if (p.ep && D.dv.getUint32(p.peOff + 24 + 60, true) > p.ep) F.push(mk('pe_ep_hdr', 'med', 8, 'Giriş noktası başlık alanında', 'Program başlangıcı bölümlerin değil PE başlıklarının içinde; bilinçli bozulmuş/özel hazırlanmış PE belirtisi.', 'PE editörde giriş noktasını incele.', ['EP RVA 0x' + p.ep.toString(16)], 'pe', { loc: [loc(p.peOff + 24 + 16, 4, 'AddressOfEntryPoint')] }));
  if (p.ts && p.ts < 694224000) F.push(mk('pe_ts_old', 'info', 1, 'Derleme zamanı 1992’den önce', 'Tarih Windows NT öncesine denk geliyor; damga elle ayarlanmış olabilir (yeniden üretilebilir derlemelerde de görülür).', '—', [new Date(p.ts * 1000).toISOString().slice(0, 10)], 'pe'));
  /* ---- gecikmeli importlar ---- */
  const dly = new Map(); let nd = 0; try { nd = peDelayImports(u8, p, D, dly); } catch (e) { nd = 0; }
  if (nd) { info.delayImports = [...dly.keys()].slice(0, 20); for (const fns of dly.values()) for (const f of fns) apis.add(f.toLowerCase()); }
  L.push(led('pe_delay', 'Gecikmeli import tablosu', D.dd(13).rva ? 'done' : 'na', nd ? nd + ' işlev' : ''));
  /* ---- TLS ---- */
  let tls = []; try { tls = peTls(u8, p, D); } catch (e) { tls = []; }
  if (tls.length) { info.tlsCallbacks = tls.map((x) => '0x' + x.toString(16)); const odd = tls.filter((r) => { const s = p.sections.find((q) => r >= q.va && r < q.va + Math.max(q.vsize, q.rsize)); return !s || !(s.ch & 0x20000000); }); if (odd.length) F.push(mk('pe_tls_odd', 'med', 8, 'TLS geri çağırımı çalıştırılabilir olmayan/bilinmeyen bölgede', 'TLS geri çağırım adreslerinden en az biri çalıştırılabilir bir bölümün dışında. Giriş noktasından önce çalışan kod için bozuk veya gizlenmiş bir kurulum olabilir.', 'Hata ayıklayıcıda TLS geri çağırımlarına gir.', odd.map((x) => 'RVA 0x' + x.toString(16)), 'evade')); }
  L.push(led('pe_tls', 'TLS geri çağırımları', D.dd(9).rva ? 'done' : 'na', tls.length ? tls.length + ' geri çağırım' : ''));
  /* ---- export yonlendirme ve DLL yan yukleme ---- */
  let fw = { n: 0, fw: [] }; if (p.dll) { try { fw = peForwarders(u8, p, D); } catch (e) { fw = { n: 0, fw: [] }; } info.exportCount = fw.n; if (fw.fw.length) info.forwarders = fw.fw.slice(0, 6); }
  if (p.dll && SIDELOAD.has(bnl) && !p.signed) {
    const proxy = fw.fw.length >= 3 && fw.fw.length >= fw.n * 0.6;
    F.push(mk('pe_sideload', proxy ? 'high' : 'med', proxy ? 16 : 8, proxy ? 'Sistem DLL’ini taklit eden vekil (proxy) DLL' : 'Sistem DLL adını taşıyan imzasız DLL', 'Dosya adı “' + base + '” sık kötüye kullanılan (DLL yan yükleme / arama sırası ele geçirme) bir sistem DLL adı ve imzası yok' + (proxy ? '; ayrıca ' + fw.fw.length + ' export gerçek DLL’e yönlendiriliyor (proxy DLL kalıbı).' : '.') + ' Oyun/araç eklentileri (ör. grafik katmanları) de aynı adı meşru kullanır.', 'DLL’in hangi uygulamanın klasöründe durduğuna ve kaynağına bak; sistem klasöründeki gerçeğiyle karşılaştır.', ['ad: ' + base].concat(fw.fw.slice(0, 3)), 'evade', { basis: 'inference' }));
  }
  /* ---- kaynak dizini ---- */
  let res = null; try { res = peResources(u8, p, D); } catch (e) { res = null; }
  if (res) {
    const byType = {}; for (const r of res) { const k = typeof r.type === 'number' ? (RT_NAMES[r.type] || 'TYPE_' + r.type) : String(r.type); byType[k] = (byType[k] || 0) + 1; }
    info.resources = { count: res.length, types: byType, largest: res.slice().sort((a, b) => b.size - a.size).slice(0, 5).map((r) => ({ type: typeof r.type === 'number' ? (RT_NAMES[r.type] || r.type) : r.type, name: r.name, size: r.size, off: r.off })) };
    const ver = peVersion(u8, res); if (ver) {
      info.version = ver;
      const oname = (ver.OriginalFilename || '').replace(/\.[^.]*$/, '').toLowerCase();
      if (oname && bnl && oname !== bnl && !/^[0-9a-f]{8,}$/.test(bnl) && depth === 0) F.push(mk('pe_ver_rename', 'low', 4, 'Dosya adı sürüm bilgisindeki özgün adla uyuşmuyor', 'Sürüm bilgisi bu dosyanın aslında “' + ver.OriginalFilename + '” olduğunu söylüyor ama adı “' + base + '”. Yeniden adlandırılmış sistem araçları (LOLBin kopyaları) ve taklit dosyalar böyle görünür; meşru yeniden adlandırmalar da olur.', 'Dosyanın gerçekte hangi program olduğunu ve neden yeniden adlandırıldığını sor.', ['özgün ad: ' + ver.OriginalFilename, 'gerçek ad: ' + base], 'arch', { basis: 'fact' }));
      if (/microsoft|windows/i.test(ver.CompanyName || '') && !p.signed && depth === 0 && !/[\\/]windows[\\/]/i.test(name)) F.push(mk('pe_ver_ms_unsigned', 'low', 3, 'Microsoft adı iddia ediyor ama gömülü imzası yok', 'Üretici alanı “' + ver.CompanyName + '”. Windows’un kendi dosyaları katalog ile imzalıdır (gömülü imza taşımayabilir), bu yüzden bu tek başına bir kanıt değildir; ama üçüncü taraf bir klasörde bulunan, Microsoft adlı imzasız bir dosya taklit olabilir.', 'Windows’ta Özellikler → Dijital İmzalar veya sigcheck ile doğrula; dosyanın bulunduğu yola bak.', ['CompanyName: ' + ver.CompanyName], 'arch', { basis: 'inference' }));
    }
    L.push(led('pe_ver', 'Sürüm bilgisi (VERSIONINFO)', ver ? 'done' : 'na', ver ? '' : 'sürüm kaynağı yok'));
    const man = peManifest(u8, res); if (man) {
      info.manifest = man;
      if (man.autoElevate) F.push(mk('pe_man_autoelev', 'med', 6, 'Manifest autoElevate=true', 'Uygulama UAC isteği göstermeden yükselmeyi talep ediyor. Bu yalnızca Microsoft’un kendi imzalı sistem dosyaları için anlamlıdır; üçüncü taraf dosyada UAC atlatma düzeneklerinde görülür.', 'Dosya Windows sistem klasöründen değilse şüpheli say.', [], 'priv', { basis: 'fact' }));
      else if (man.uiAccess) F.push(mk('pe_man_uiaccess', 'low', 4, 'Manifest uiAccess=true', 'Uygulama diğer pencerelere girdi göndermek için ayrıcalık istiyor (erişilebilirlik araçları, bazı makro/uzaktan kontrol yazılımları).', 'Gerçekten bir erişilebilirlik aracı olup olmadığını kontrol et.', [], 'priv', { basis: 'fact' }));
      else if (/requireAdministrator/i.test(man.level || '')) F.push(mk('pe_man_admin', 'info', 1, 'Yönetici yetkisi istiyor (manifest)', 'Program her açılışta UAC ile yönetici yetkisi ister. Yükleyiciler ve sistem araçları için olağandır.', '—', ['level=' + man.level], 'priv', { basis: 'fact' }));
    }
    L.push(led('pe_manifest', 'Gömülü manifest', man ? 'done' : 'na', man ? '' : 'manifest kaynağı yok'));
    /* gomulu PE / yuksek entropili kaynak */
    let embN = 0;
    for (const r of res) {
      if (r.off < 0 || r.size < 1024) continue; const mz = u8[r.off] === 0x4d && u8[r.off + 1] === 0x5a && r.off + r.size <= u8.length; const tname = typeof r.type === 'number' ? (RT_NAMES[r.type] || 'TYPE_' + r.type) : r.type; const lbl = tname + '/' + r.name;
      if (mz && r.size > 400 && embN < 3) { const sub = u8.subarray(r.off, r.off + r.size); if (findAllMZ(sub, 0, 1).length) { embN++; F.push(mk('pe_res_pe', 'high', 16, 'Kaynak bölümünde gömülü çalıştırılabilir', 'Kaynak ' + lbl + ' bir PE başlığıyla başlıyor (' + r.size + ' bayt). Kurulum/yükleyici programları meşru olarak yük taşır; zararlılar da yükünü kaynaklarda saklar.', 'Gömülü dosya ayrıca taranıyor; sonucuna bak.', [lbl + ' @0x' + r.off.toString(16)], 'pe', { basis: 'fact', loc: [loc(r.off, Math.min(r.size, 512), 'kaynak ' + lbl)] })); if (depth < cfg.depth && cfg.parse) children.push(await scanBuffer(u8.slice(r.off, r.off + r.size), name + ' › kaynak ' + lbl, st, depth + 1)); else limitHit(st, 'depth', 'Derinlik sınırı nedeniyle kaynaktaki gömülü PE taranmadı.'); } }
      else if (!mz && r.size >= 32768 && (r.type === 10 || typeof r.type === 'string' || (typeof r.type === 'number' && r.type > 24))) { const e = entropy(u8, r.off, Math.min(u8.length, r.off + r.size)); if (e > 7.4) F.push(mk('pe_res_blob', 'med', 8, 'Yüksek entropili büyük kaynak (' + lbl + ')', 'Kaynak ' + Math.round(r.size / 1024) + ' KB ve entropisi ' + e.toFixed(2) + '; şifreli/sıkıştırılmış bir yük olabilir. Yazılım lisansları, medya ve sıkıştırılmış veriler de böyle görünür.', 'Kaynağı Resource Hacker ile çıkarıp türünü belirle.', ['entropi ' + e.toFixed(2) + ' @0x' + r.off.toString(16)], 'pe', { basis: 'heuristic', loc: [loc(r.off, Math.min(r.size, 512), 'kaynak ' + lbl)] })); }
    }
    L.push(led('pe_res', 'Kaynak dizini (resources)', 'done', res.length + ' kaynak'));
  } else L.push(led('pe_res', 'Kaynak dizini (resources)', D.dd(2).rva ? 'partial' : 'na', D.dd(2).rva ? 'dizin okunamadı' : 'kaynak yok'));
  /* ---- overlay siniflandirma ---- */
  if (p.overlay > 0) {
    const start = u8.length - p.overlay; const ok = overlayKind(u8, start, p.certOff, p.certSize); if (ok.len > 0) {
      info.overlayKind = ok.label; info.overlayStart = start; info.overlayLen = ok.len;
      if (ok.kind === 'zip' || ok.kind === '7z' || ok.kind === 'rar' || ok.kind === 'cab') {
        F.push(mk('pe_sfx', 'low', 4, 'Kendi kendini açan arşiv (' + ok.label + ')', 'Çalıştırılabilir dosyanın sonunda ' + ok.label + ' var; açıldığında içindekileri çalıştırabilir. Kurulum paketleri meşru kullanır; zararlılar da yükünü bu yolla paketler.', 'Arşiv içeriği taranıyor (desteklenen biçimlerde); açıp elle de incele.', ['ofset 0x' + start.toString(16) + ', ' + ok.len + ' bayt'], 'arch', { basis: 'fact', loc: [loc(start, Math.min(ok.len, 256), ok.label)] }));
        if (ok.kind === 'zip' && cfg.parse && depth < cfg.depth && ok.len < 400e6) children.push(await scanBuffer(u8.slice(start, start + ok.len), name + ' › SFX arşivi', st, depth + 1));
      } else if (ok.kind === 'nsis' || ok.kind === 'inno') F.push(mk('pe_installer', 'info', 0, ok.label, 'Dosya bir kurulum paketi (' + ok.kind.toUpperCase() + '). Paketin içi bu araçla açılmaz; yalnızca dış kabuk incelenir.', 'Gerekirse 7-Zip ile aç ve içindekileri ayrıca tara.', ['ofset 0x' + start.toString(16)], 'arch', { basis: 'fact' }));
    }
  }
  /* ---- surucu (kernel) ---- */
  const isDrv = p.subsystem === 1 || [...p.imports.keys()].some((d) => DRV_DLLS.test(d)); if (isDrv) {
    info.driver = true;
    if (any('MmMapIoSpace', 'MmMapIoSpaceEx', 'MmGetPhysicalAddress', 'ZwMapViewOfSection') && (/PhysicalMemory/i.test(text) || has('MmMapIoSpace'))) F.push(mk('pe_drv_phys', 'high', 14, 'Sürücü fiziksel belleğe erişim API’leri', 'Çekirdek sürücüsü fiziksel belleği eşleyen API’leri içe aktarıyor. Donanım/tanılama sürücüleri bunu meşru kullanır; savunmasız sürücülerin kötüye kullanımında (BYOVD) çekirdek belleğine yazmak için aynı yetenek kullanılır.', 'Sürücünün imzasını, bilinen savunmasız sürücü listeleriyle (LOLDrivers) karşılaştır.', cnt0(['MmMapIoSpace', 'MmMapIoSpaceEx', 'MmGetPhysicalAddress', 'ZwMapViewOfSection'], has), 'priv', { basis: 'inference' }));
    if (any('PsLookupProcessByProcessId') && any('ZwTerminateProcess', 'ZwOpenProcess')) F.push(mk('pe_drv_kill', 'high', 14, 'Sürücü süreç bulup sonlandırma API’leri', 'Çekirdekten rastgele süreç bulup sonlandırabilen API’ler bir arada. Güvenlik yazılımlarını susturan “EDR killer” sürücülerinde görülen kalıptır; bazı yönetim/koruma sürücüleri de kullanır.', 'Sürücünün kaynağını ve imzalayanını doğrula.', cnt0(['PsLookupProcessByProcessId', 'ZwTerminateProcess', 'ZwOpenProcess'], has), 'evade', { basis: 'inference' }));
    L.push(led('pe_drv', 'Sürücü (çekirdek) API incelemesi', 'done', 'yalnızca import tabanlı'));
  }
  /* ---- ek yetenek eslemeleri (import tabanli) ---- */
  if (has('OpenProcessToken') && any('DuplicateTokenEx', 'DuplicateToken') && any('ImpersonateLoggedOnUser', 'SetThreadToken', 'CreateProcessWithTokenW', 'CreateProcessAsUser')) F.push(mk('pe_token', 'med', 8, 'Token çalma/kopyalama API zinciri', 'Başka bir sürecin token’ını kopyalayıp başka bir kimlikle iş yapma API’leri birlikte. Yönetim araçları da kullanır.', 'Hangi sürecin token’ının alındığını dinamik analizle doğrula.', cnt0(['OpenProcessToken', 'DuplicateTokenEx', 'ImpersonateLoggedOnUser', 'CreateProcessWithTokenW', 'CreateProcessAsUser', 'SetThreadToken'], has), 'priv', { basis: 'inference' }));
  if (has('MiniDumpWriteDump') && /lsass/i.test(text)) F.push(mk('pe_lsass', 'crit', 28, 'LSASS bellek dökümü kalıbı', '“lsass” adı ve MiniDumpWriteDump birlikte: Windows kimlik bilgilerini bellekten döken araçların tipik birleşimi. Güvenlik/tanılama araçları da LSASS’a erişebilir.', 'Aracın kaynağını doğrula; çalıştırdıysan parolaları değiştir.', ['MiniDumpWriteDump + “lsass” metni'], 'cred', { basis: 'inference' }));
  else if (has('MiniDumpWriteDump')) F.push(mk('pe_minidump', 'low', 3, 'Bellek dökümü API’si (MiniDumpWriteDump)', 'Çökme raporlayıcılar ve hata ayıklayıcılar bu API’yi kullanır.', 'Başka bulgularla birlikte değerlendir.', [], 'cred', { basis: 'fact' }));
  if (any('LsaEnumerateLogonSessions', 'LsaRetrievePrivateData', 'SamEnumerateUsersInDomain', 'SamIConnect', 'CredEnumerate') ) F.push(mk('pe_credapi', 'med', 8, 'Kimlik bilgisi / LSA / SAM API’leri', 'Oturum, parola kasası veya hesap veritabanını sorgulayan API’ler içe aktarılmış. Parola yöneticileri ve yönetim araçları da kullanır.', 'API sonuçlarının nereye yazıldığına bak.', cnt0(['LsaEnumerateLogonSessions', 'LsaRetrievePrivateData', 'SamEnumerateUsersInDomain', 'CredEnumerate'], has), 'cred', { basis: 'inference' }));
  if (any('capCreateCaptureWindow', 'waveInOpen', 'waveInStart', 'mciSendString') && any('capCreateCaptureWindow', 'waveInOpen')) F.push(mk('pe_av_capture', 'med', 7, 'Kamera/mikrofon yakalama API’leri', 'Video veya ses yakalama API’leri içe aktarılmış. Görüntülü görüşme/kayıt yazılımları meşru kullanır; casus yazılımlar gizlice kullanır.', 'Yakalanan verinin kaydedilip gönderilmediğine bak.', cnt0(['capCreateCaptureWindow', 'waveInOpen', 'waveInStart'], has), 'spy', { basis: 'inference' }));
  if (any('NtAllocateVirtualMemory', 'NtWriteVirtualMemory', 'NtMapViewOfSection') && any('NtCreateThreadEx', 'NtQueueApcThread', 'RtlCreateUserThread', 'NtResumeThread') && !has('WriteProcessMemory')) F.push(mk('pe_inject_native', 'high', 22, 'Yerel (Nt*) API ile enjeksiyon zinciri', 'Bellek ayırma/yazma ve iş parçacığı/APC başlatma işlemleri doğrudan ntdll API’leriyle (Win32 katmanını atlayarak) içe aktarılmış. İzleme yazılımlarını atlatmak için tercih edilen biçimdir.', 'Hedef süreçleri ve yazılan veriyi dinamik analizle doğrula.', cnt0(['NtAllocateVirtualMemory', 'NtWriteVirtualMemory', 'NtMapViewOfSection', 'NtCreateThreadEx', 'NtQueueApcThread', 'RtlCreateUserThread'], has), 'inject', { basis: 'inference' }));
  if (any('InternetOpenUrl', 'InternetReadFile', 'WinHttpReadData', 'HttpSendRequest') && any('CreateFile') && any('WriteFile') && any('CreateProcess', 'ShellExecute', 'WinExec') && !has('URLDownloadToFile')) F.push(mk('pe_dl_chain', 'med', 12, 'İndir–yaz–çalıştır API zinciri', 'Ağdan veri okuma, dosyaya yazma ve süreç başlatma API’leri aynı dosyada. Güncelleme/kurulum programları meşru olarak yapar; indirici zararlıların temel kalıbıdır.', 'İndirilen adresi ve çalıştırılan dosyayı izole ortamda gözlemle.', cnt0(['InternetReadFile', 'WinHttpReadData', 'CreateFile', 'WriteFile', 'CreateProcess', 'ShellExecute'], has), 'dl', { basis: 'inference' }));
  if (any('NtLoadDriver', 'ZwLoadDriver') || (has('CreateService') && /SERVICE_KERNEL_DRIVER|\\\\Registry\\\\Machine\\\\System\\\\CurrentControlSet\\\\Services/i.test(text))) F.push(mk('pe_drv_load', 'med', 10, 'Sürücü yükleme girişimi', 'Çekirdek sürücüsü yükleme API’si veya ilgili kayıt yolu var. Savunmasız sürücü getirme (BYOVD) saldırılarının ilk adımıdır; sürücü kurulum araçları da yapar.', 'Hangi sürücü dosyasının yüklendiğini bul ve imzasını doğrula.', cnt0(['NtLoadDriver', 'ZwLoadDriver', 'CreateService'], has), 'priv', { basis: 'inference' }));
  if (/\\\\\.\\(?:PhysicalDrive\d|PHYSICALDRIVE\d|\\?HarddiskVolume\d)/.test(text) && any('WriteFile', 'DeviceIoControl')) F.push(mk('pe_rawdisk', 'high', 14, 'Ham diske yazma kalıbı', '“\\\\.\\PhysicalDriveN” yolu ve yazma API’si birlikte: disk yedekleme/imaj araçları ve önyükleyici (MBR) silen zararlılar bu yolu kullanır.', 'Disk araçlarıyla ilgisi yoksa çalıştırma.', ['\\\\.\\PhysicalDrive…'], 'evade', { basis: 'inference' }));
  if (any('NtRaiseHardError') && any('RtlAdjustPrivilege')) F.push(mk('pe_bsod', 'high', 12, 'Mavi ekran (BSOD) tetikleme API’leri', 'NtRaiseHardError ve RtlAdjustPrivilege birlikte: sistemi çökertmek için kullanılan kalıp.', 'Çalıştırma.', cnt0(['NtRaiseHardError', 'RtlAdjustPrivilege'], has), 'evade', { basis: 'inference' }));
  L.push(led('pe_caps', 'Import tabanlı yetenek eşleme', 'done', 'yalnızca import/metin; çağrı akışı izlenmez'));
  return L;
}
function cnt0(list, has) { return list.filter(has); }
