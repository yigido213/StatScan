/* 4.5: ek analiz yontemleri (PDB yolu, homoglif/gorunmez karakterli adlar, bulanik hash) + yontem katalogu + aile gruplama.
   Hepsi statik: dosya calistirilmaz, ag kullanilmaz. Yontem katalogu (METHODS) mod ayarlarindan (MODES) hesaplanir; elle yazilmis tablo degildir. */

/* ---------- ad denetimi: karisik yazi sistemi (homoglif) ve gorunmez/yon kontrol karakterleri ---------- */
const INVIS_CP = [[0x200b, 0x200f], [0x2028, 0x2029], [0x202a, 0x202d], [0x2060, 0x2064], [0x2066, 0x2069], [0xfeff, 0xfeff], [0xad, 0xad], [0x180e, 0x180e]];
const INVIS_RE = new RegExp('[' + INVIS_CP.map(([a, b]) => String.fromCharCode(a) + (b > a ? '-' + String.fromCharCode(b) : '')).join('') + ']');
function scriptOf(ch) {
  const c = ch.codePointAt(0);
  if ((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0xc0 && c <= 0x24f)) return 'Latin';
  if (c >= 0x400 && c <= 0x52f) return 'Kiril'; if (c >= 0x370 && c <= 0x3ff) return 'Yunan'; if (c >= 0x530 && c <= 0x58f) return 'Ermeni';
  if (c >= 0xff21 && c <= 0xff5a) return 'Tam genişlik'; return '';
}
function confusableName(name) {
  const base = String(name || '').split(/[\\/]/).pop(); const out = { invisible: [], mixed: [] };
  const m = base.match(new RegExp(INVIS_RE.source, 'g')); if (m) out.invisible = [...new Set(m.map((x) => 'U+' + x.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')))];
  for (const tok of base.split(/[^\p{L}\p{N}]+/u)) {
    if (tok.length < 2) continue; const sc = new Set(); for (const ch of tok) { const s = scriptOf(ch); if (s) sc.add(s); }
    if (sc.has('Latin') && (sc.has('Kiril') || sc.has('Yunan') || sc.has('Ermeni') || sc.has('Tam genişlik'))) out.mixed.push(tok.slice(0, 40) + ' (' + [...sc].join('+') + ')');
  }
  return out;
}

/* ---------- PE hata ayiklama bilgisi: CodeView (RSDS) PDB yolu ---------- */
const PDB_SUSP = /stealer|grabber|keylog|crypter|ransom|botnet|clipper|hvnc|\brat\b|\bfud\b|infostealer|cookie.?steal|token.?grab|\bdropper\b/i;
function pdbPaths(u8) {
  const out = []; const lim = Math.min(u8.length, 64e6);
  for (let i = 0; i + 28 < lim && out.length < 4; i++) {
    if (u8[i] !== 0x52 || u8[i + 1] !== 0x53 || u8[i + 2] !== 0x44 || u8[i + 3] !== 0x53) continue;
    let j = i + 24, s = ''; while (j < lim && u8[j] && s.length < 260) { const b = u8[j]; if (b < 32 || b > 126) { s = ''; break; } s += String.fromCharCode(b); j++; }
    if (s.length >= 5 && /\.pdb$/i.test(s) && u8[j] === 0) out.push({ off: i, path: s, guid: Array.from(u8.subarray(i + 4, i + 20)).map((x) => x.toString(16).padStart(2, '0')).join(''), age: u8[i + 20] | (u8[i + 21] << 8) });
  }
  return out;
}

/* ---------- bulanik hash (CTPH; ssdeep ailesi algoritma, birebir ssdeep uyumlulugu iddia edilmez) ---------- */
const SS_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function ctphRun(u8, bs) {
  let h1 = 0, h2 = 0, h3 = 0, n = 0; const win = new Uint8Array(7); let a = 0x28021967, b = 0x28021967; let s1 = '', s2 = ''; let any = false;
  for (let i = 0; i < u8.length; i++) {
    const c = u8[i]; h2 = (h2 - h1 + 7 * c) >>> 0; h1 = (h1 + c - win[n % 7]) >>> 0; win[n % 7] = c; n++; h3 = ((h3 << 5) ^ c) >>> 0; const r = (h1 + h2 + h3) >>> 0;
    a = (Math.imul(a, 0x01000193) ^ c) >>> 0; b = (Math.imul(b, 0x01000193) ^ c) >>> 0; any = true;
    if (r % bs === bs - 1) { if (s1.length < 63) { s1 += SS_B64[a & 63]; a = 0x28021967; } if (r % (bs * 2) === bs * 2 - 1) { if (s2.length < 31) { s2 += SS_B64[b & 63]; b = 0x28021967; } } }
  }
  if (any && (h1 + h2 + h3) >>> 0 !== 0) { s1 += SS_B64[a & 63]; s2 += SS_B64[b & 63]; }
  return { s1, s2 };
}
function ctph(u8) {
  if (!u8 || u8.length < 512) return null; let bs = 3; while (bs * 64 < u8.length) bs *= 2;
  let r = ctphRun(u8, bs); while (bs > 3 && r.s1.length < 32) { bs = Math.floor(bs / 2); r = ctphRun(u8, bs); }
  return bs + ':' + r.s1 + ':' + r.s2;
}
const ssNorm = (s) => s.replace(/(.)\1{3,}/g, '$1$1$1');
function ssEdit(a, b) { const la = a.length, lb = b.length; let prev = new Array(lb + 1); for (let j = 0; j <= lb; j++) prev[j] = j; for (let i = 1; i <= la; i++) { const cur = [i]; for (let j = 1; j <= lb; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 2)); prev = cur; } return prev[lb]; }
function ssScore(a, b, bs) {
  a = ssNorm(a); b = ssNorm(b); if (a.length < 7 || b.length < 7) return 0; const g = new Set(); for (let i = 0; i + 7 <= a.length; i++) g.add(a.slice(i, i + 7)); let common = false; for (let i = 0; i + 7 <= b.length && !common; i++) if (g.has(b.slice(i, i + 7))) common = true; if (!common) return 0;
  let sc = Math.floor((ssEdit(a, b) * 64) / (a.length + b.length)); sc = 100 - Math.floor((100 * sc) / 64); if (sc < 0) sc = 0; if (bs < 45) sc = Math.min(sc, Math.floor(bs / 3) * Math.min(a.length, b.length)); return Math.min(100, sc);
}
function fuzzyCompare(x, y) {
  const p = (h) => { const m = /^(\d+):([^:]*):([^:]*)$/.exec(h || ''); return m ? { bs: +m[1], s1: m[2], s2: m[3] } : null; }; const A = p(x), B = p(y); if (!A || !B) return 0; if (x === y) return 100;
  if (A.bs === B.bs) return Math.max(ssScore(A.s1, B.s1, A.bs), ssScore(A.s2, B.s2, A.bs * 2));
  if (A.bs === B.bs * 2) return ssScore(A.s1, B.s2, A.bs); if (B.bs === A.bs * 2) return ssScore(A.s2, B.s1, B.bs); return 0;
}
/* arsiv (jar/zip) icin ham bayt bulanik hash'i anlamsizdir (sikistirilmis); bunun yerine girdi adi+boyut dokumu uzerinden hesaplanir */
function zipStructText(u8) { try { const z = readZip(u8); const es = (z && (z.entries || z)) || []; const L = []; for (const e of es) { if (e && e.name && !/\/$/.test(e.name)) L.push(e.name + '|' + Math.round((e.size || 0) / 64)); } L.sort(); return L.length >= 4 ? L.join('\n') : ''; } catch (e) { return ''; } }

/* ---------- evrensel ek yontemler: her scanBuffer'da, kapsam mod ayarindan gelir ---------- */
function extraMethods(u8, kind, name, st, depth, info) {
  const cfg = st.cfg; const F = []; const L = []; const base = baseName(name);
  const cn = confusableName(base);
  if (cn.mixed.length) F.push(mk('name_confusable', 'med', 10, 'Karışık yazı sistemli (homoglif) ad', 'Ad aynı sözcükte Latin harfleriyle Kiril/Yunan/Ermeni/tam genişlik harfleri karıştırıyor; görünüşte tanıdık bir adı taklit etmek için kullanılan bir sahtekarlık tekniğidir.', 'Adı elle yazarak orijinaliyle karşılaştır; kaynağından emin değilsen açma.', cn.mixed.slice(0, 4), 'arch'));
  if (cn.invisible.length) F.push(mk('name_invisible', 'med', 12, 'Görünmez/yön kontrol karakterli ad', 'Ad görünmeyen karakterler (sıfır genişlik, yön kontrol vb.) içeriyor; uzantıyı veya adı gizlemek için kullanılabilir.', 'Gerçek adı bir hex görüntüleyiciyle incele.', cn.invisible.slice(0, 6), 'arch'));
  L.push(led('confusable', 'Ad denetimi: homoglif (karışık yazı sistemi) ve görünmez karakter', 'done', cn.mixed.length || cn.invisible.length ? 'bulgu var' : ''));
  if (kind === 'pe' && depth < 6) {
    if (cfg.parse) {
      const pd = pdbPaths(u8); if (pd.length) { info.pdb = pd.map((x) => x.path); const user = pd.map((x) => /[\\/](?:Users|home)[\\/]([^\\/]+)[\\/]/i.exec(x.path)).find(Boolean);
        F.push(mk('pdb_path', 'info', 0, 'PDB (hata ayıklama) yolu: ' + pd[0].path.slice(0, 90), 'Derleyicinin gömdüğü PDB yolu, derleme ortamını ve proje adını ele verir' + (user ? ' (kullanıcı adı “' + user[1] + '” görünüyor)' : '') + '. Tek başına zararlılık kanıtı değildir; aynı ailenin diğer örnekleriyle eşleştirmede işe yarar.', 'Yolu proje adıyla karşılaştır; başka örneklerde aynı yol varsa aynı kaynaktan geliyor olabilir.', pd.map((x) => x.path.slice(0, 160) + ' · GUID ' + x.guid.slice(0, 8) + '… · yaş ' + x.age), 'pe'));
        const sp = pd.find((x) => PDB_SUSP.test(x.path)); if (sp) F.push(mk('pdb_susp', 'low', 8, 'PDB yolunda zararlı yazılım proje adı kalıbı', 'Derleme yolunda stealer/keylogger/crypter/ransom/botnet gibi bir proje adı geçiyor; bazı zararlılar geliştirici yolunu kaldırmayı unutur. Güvenlik araştırması/eğitim projeleri de bu adları taşıyabilir.', 'Dosyanın kaynağını ve amacını doğrula.', [sp.path.slice(0, 160)], 'pe')); }
      L.push(led('pdb', 'PE hata ayıklama bilgisi (CodeView/PDB yolu)', 'done', pd.length ? pd.length + ' yol bulundu' : 'PDB yolu bulunamadı (kaldırılmış olabilir)'));
    } else L.push(led('pdb', 'PE hata ayıklama bilgisi (CodeView/PDB yolu)', 'skipped', 'Hızlı modda yapılmaz'));
  }
  if (depth === 0 && info) {
    const cap = cfg.deepJar ? 128e6 : (cfg.parse ? 32e6 : 0);
    if (!cap) L.push(led('fuzzy', 'Bulanık hash (CTPH) ve aile benzerliği', 'skipped', 'Hızlı modda yapılmaz'));
    else {
      let basis = 'bayt', data = u8; if (kind === 'zip') { const t = zipStructText(u8); if (t) { data = new TextEncoder().encode(t); basis = 'arşiv yapısı'; } else data = null; } else if (kind === 'text' || kind === 'script') basis = 'bayt';
      if (!data) L.push(led('fuzzy', 'Bulanık hash (CTPH) ve aile benzerliği', 'na', 'Arşiv girdi listesi çok kısa'));
      else if (u8.length > cap) L.push(led('fuzzy', 'Bulanık hash (CTPH) ve aile benzerliği', 'skipped', 'Dosya ' + fmtN(u8.length) + ' > ' + fmtN(cap) + ' (bu modun sınırı)'));
      else { const hsh = ctph(data); if (hsh) { info.fuzzy = { hash: hsh, basis }; L.push(led('fuzzy', 'Bulanık hash (CTPH) ve aile benzerliği', 'done', hsh.length > 40 ? hsh.slice(0, 40) + '… (' + basis + ')' : hsh + ' (' + basis + ')')); } else L.push(led('fuzzy', 'Bulanık hash (CTPH) ve aile benzerliği', 'na', 'Girdi çok küçük (512 bayttan az)')); }
    }
  }
  return { findings: F, analyses: L };
}

/* ---------- toplu tarama: aile / varyant gruplama ---------- */
function familyGroups(results, minScore) {
  minScore = minScore || 55; const items = []; for (const r of results || []) { if (!r || !r.sha256) continue; items.push({ r, fz: r.info && r.info.fuzzy ? r.info.fuzzy : null, imp: r.info && r.info.imphash ? r.info.imphash : null }); }
  const par = items.map((_, i) => i); const find = (i) => { while (par[i] !== i) { par[i] = par[par[i]]; i = par[i]; } return i; }; const links = [];
  for (let i = 0; i < items.length; i++) for (let j = i + 1; j < items.length; j++) {
    const a = items[i], b = items[j]; let why = null, sc = 0;
    if (a.r.sha256 === b.r.sha256) { why = 'aynı SHA-256 (birebir kopya)'; sc = 100; }
    else if (a.fz && b.fz && a.fz.basis === b.fz.basis) { sc = fuzzyCompare(a.fz.hash, b.fz.hash); if (sc >= minScore) why = 'bulanık hash benzerliği %' + sc + ' (' + a.fz.basis + ')'; }
    if (!why && a.imp && b.imp && a.imp === b.imp) { why = 'aynı imphash (aynı import kümesi)'; sc = 60; }
    if (why) { links.push({ a: a.r.name, b: b.r.name, why, score: sc }); par[find(i)] = find(j); }
  }
  const groups = new Map(); items.forEach((it, i) => { const k = find(i); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(it.r); });
  return [...groups.values()].filter((g) => g.length > 1).map((g) => { const names = new Set(g.map((x) => x.name)); return { members: g.map((x) => ({ name: x.name, score: x.score, verdict: x.verdict, sha256: x.sha256 })), links: links.filter((l) => names.has(l.a) && names.has(l.b)), maxScore: Math.max(...g.map((x) => x.score || 0)), minScore: Math.min(...g.map((x) => x.score || 0)) }; }).sort((x, y) => y.members.length - x.members.length);
}

/* ---------- yontem katalogu: hangi yontem hangi dosya turunde, hangi modda, ne kadar ---------- */
const MS = { full: 'Tam', partial: 'Kısmi', off: 'Yok' };
const mb = (n) => (n >= 1e6 ? Math.round(n / 1e6) + ' MB' : Math.round(n / 1e3) + ' KB');
const METHODS = [
  { id: 'type', since: 'önceki', label: 'Dosya türü tespiti (imza/magic, başlık doğrulama)', kinds: 'Tüm dosyalar', on: () => ['full', 'Uzantıya değil içeriğe bakılır; uzantı–içerik uyumsuzluğu ayrıca bulgudur'] },
  { id: 'hash', since: 'önceki', label: 'SHA-256, SHA-1 özetleri (ve imphash için MD5)', kinds: 'Tüm dosyalar', on: () => ['full', 'Tarayıcı SHA-256’yı desteklemezse not düşülür'] },
  { id: 'entropy', since: 'önceki', label: 'Entropi (dosya ve PE bölümü başına)', kinds: 'Tüm dosyalar; bölüm bazlı: PE', on: () => ['full', 'Yüksek entropi tek başına zararlılık kanıtı değildir'] },
  { id: 'names', since: 'önceki', label: 'Ad sahtekarlığı: RTLO, çift uzantı, riskli uzantı, içerik–uzantı uyumsuzluğu', kinds: 'Tüm dosyalar ve arşiv girdileri', on: () => ['full', ''] },
  { id: 'confusable', since: '4.5', label: 'Ad denetimi: homoglif (karışık yazı sistemi) ve görünmez karakter', kinds: 'Tüm dosyalar ve arşiv girdileri', on: () => ['full', 'Latin+Kiril/Yunan/Ermeni karışımı, sıfır genişlik/yön kontrol karakterleri'] },
  { id: 'strings', since: 'önceki', label: 'Dize çıkarma (ASCII + UTF-16LE)', kinds: 'PE, ELF, Mach-O, bilinmeyen ikili, jar sınıfları', on: (c) => [c.strCap >= 3e7 ? 'full' : 'partial', 'Üst sınır: ' + mb(c.strCap) + ' dize metni; büyük dosyada sonrası taranmaz'] },
  { id: 'rules', since: 'önceki', label: 'Dize/regex kural kataloğu (+ kullanıcı kural paketi)', kinds: 'Tüm türler (metin, betik, ikili, jar)', on: (c) => c.ids ? ['partial', 'Yalnızca yüksek riskli alt küme (' + c.ids.size + ' kural kimliği)'] : ['full', 'Tüm katalog'] },
  { id: 'sigs', since: 'önceki', label: 'Bayt imzaları (YARA-lite: shellcode, Cobalt Strike, syscall, kripto sabitleri)', kinds: 'PE, ELF, ikili, arşiv, metin', on: (c) => c.parse ? ['full', 'İlk ' + (c.deepJar ? '160' : '48') + ' MB'] : ['partial', 'İlk 4 MB'] },
  { id: 'pe_struct', since: 'önceki', label: 'PE yapısı: başlık, bölüm, import/export/TLS/overlay, paketleyici, API kombinasyonları, manifest', kinds: 'PE (exe, dll, sys)', on: () => ['full', 'Tüm modlarda çalışır'] },
  { id: 'pe_sig', since: 'önceki', label: 'Authenticode: gömülü özet ↔ dosya özeti tutarlılığı', kinds: 'İmzalı PE', on: (c) => c.parse ? ['full', 'Sertifika zinciri/iptal/zaman damgası doğrulanmaz'] : ['off', 'Hızlı modda yapılmaz'] },
  { id: 'pe_deep', since: 'önceki', label: 'PE ileri: imphash, Rich header, rsrc blob, gömülü PE, bindirme (overlay) PE', kinds: 'PE', on: (c) => c.deepJar ? ['full', ''] : ['partial', 'Yalnızca overlay içi MZ aranır; imphash/Rich/rsrc yalnızca Derin'] },
  { id: 'pdb', since: '4.5', label: 'PE hata ayıklama bilgisi: CodeView/PDB yolu, derleyici ortamı sızıntısı', kinds: 'PE', on: (c) => c.parse ? ['full', 'Yol bulgu olarak gösterilir; proje adı kalıbı hafif puanlanır'] : ['off', 'Hızlı modda yapılmaz'] },
  { id: 'dotnet', since: 'önceki', label: '.NET meta veri: P/Invoke, gömülü kaynak PE, gizleme adları, Costura', kinds: '.NET PE', on: () => ['full', 'Tüm modlarda çalışır'] },
  { id: 'elf_macho', since: 'önceki', label: 'ELF / Mach-O yapı ve davranış göstergeleri', kinds: 'ELF, Mach-O, fat', on: () => ['full', ''] },
  { id: 'jar_raw', since: 'önceki', label: 'Jar/class: ham bayt üzerinde yüksek riskli kalıplar', kinds: 'JAR, class', on: () => ['full', ''] },
  { id: 'jar_const', since: 'önceki', label: 'Java class sabit havuzu, API çağrıları, manifest, mod/eklenti meta verisi, Minecraft mod kontrolleri', kinds: 'JAR, class', on: (c) => c.parse ? ['full', ''] : ['off', 'Hızlı modda yapılmaz'] },
  { id: 'jar_flow', since: 'önceki', label: 'Java bytecode: metot içi/çağrı zinciri birlikteliği', kinds: 'JAR, class', on: (c) => c.flowDepth ? ['full', 'Çağrı zinciri derinliği: ' + c.flowDepth + ' (gerçek taint izlenmez)'] : ['off', 'Hızlı modda yapılmaz'] },
  { id: 'jar_deep', since: 'önceki', label: 'Jar: gizli class, yüksek entropili blob, class sürümü anomalisi, mixin/oturum', kinds: 'JAR', on: (c) => c.deepJar ? ['full', ''] : ['off', 'Yalnızca Derin'] },
  { id: 'archive', since: 'önceki', label: 'Arşiv: girdi listesi, zip-slip, zip bombası, şifreli girdi, gizli MZ, iç içe tarama', kinds: 'ZIP, jar, tar, gz, RAR/7z/CAB (kabuk), asar', on: (c) => ['full', 'İç içe derinlik: ' + c.depth + (c.parse ? '' : ' (yalnızca 1. seviye girdi listesi)')] },
  { id: 'doc', since: 'önceki', label: 'Belge: Office (VBA/XLM/DDE/uzak şablon), OLE, RTF, PDF, OneNote, LNK, HTA', kinds: 'DOC/XLS/PPT, OOXML, RTF, PDF, OneNote, LNK', on: () => ['full', ''] },
  { id: 'deobf', since: 'önceki', label: 'Katman çözme: Base64/hex/PowerShell -enc/gzip → yeniden tarama', kinds: 'Metin, betik, jar, ikili', on: (c) => c.deobf ? ['full', ''] : ['off', 'Yalnızca Derin'] },
  { id: 'xor', since: 'önceki', label: 'Tek baytlık XOR ile gizlenmiş PE arama', kinds: 'Bilinmeyen ikili, jar girdileri, PE', on: (c) => c.xor ? ['full', ''] : ['off', 'Yalnızca Derin'] },
  { id: 'ioc', since: 'önceki', label: 'IOC çıkarımı (URL/IP; Derin: e-posta, kayıt defteri, yol, cüzdan, webhook, Telegram, onion)', kinds: 'Tüm metin/dize içerikleri', on: (c) => c.ioc >= 2 ? ['full', ''] : c.ioc ? ['partial', 'Yalnızca URL/IP'] : ['off', 'Hızlı modda yapılmaz'] },
  { id: 'pack', since: 'önceki', label: 'PyInstaller (CArchive/PYZ) ve Electron asar açma', kinds: 'PE/ELF içinde PyInstaller, .asar', on: (c) => c.parse ? ['full', 'AES şifreli PYZ açılamaz (kısmi bildirilir)'] : ['off', 'Hızlı modda yapılmaz'] },
  { id: 'fuzzy', since: '4.5', label: 'Bulanık hash (CTPH) ve aile/varyant benzerliği (toplu taramada gruplama)', kinds: 'Üst düzey her dosya (arşivde: girdi listesi yapısı)', on: (c) => c.deepJar ? ['full', 'Dosya ≤ 128 MB'] : c.parse ? ['partial', 'Dosya ≤ 32 MB'] : ['off', 'Hızlı modda yapılmaz'] },
  { id: 'trust', since: 'önceki', label: 'Kendi dosyalarım: SHA-256/ad ailesi eşleşmesi ve yeni davranış farkı', kinds: 'Tüm dosyalar', on: () => ['full', 'İşaretlediğin dosyalar varsa'] },
  { id: 'decomp', since: 'önceki+4.5', label: 'İsteğe bağlı harici decompiler: ILSpy, CFR, Procyon, jadx, IDA, Ghidra, pycdc/decompyle3/uncompyle6', kinds: 'Masaüstü uygulaması; obfuscation panelinden, onayla', on: () => ['partial', 'Tarama akışının dışında, isteğe bağlı; araç kullanıcının kendi kurulumudur'] }
];
const METHOD_NEVER = [
  'Dosya çalıştırma, emülasyon, sandbox (isteğe bağlı Windows Sandbox ayrı bir özelliktir)',
  'Ağ üzerinden itibar/hash sorgusu, çoklu AV motoru (hiçbir içerik dışarı gönderilmez)',
  'Dijital imza GEÇERLİLİĞİ (sertifika zinciri, iptal, zaman damgası, imza matematiği)',
  'Gerçek veri akışı (taint) analizi ve sembolik yürütme',
  'Şifreli/özel algoritmalı yükler, çok baytlı XOR, çalışma anında açılan katmanlar'
];
function methodMatrix() {
  const ids = Object.keys(MODES); return { modes: ids.map((i) => ({ id: i, label: MODES[i].label })), rows: METHODS.map((m) => ({ id: m.id, label: m.label, kinds: m.kinds, since: m.since, modes: ids.reduce((o, i) => { const r = m.on(MODES[i]); o[i] = { state: r[0], label: MS[r[0]], note: r[1] || '' }; return o; }, {}) })), never: METHOD_NEVER };
}
