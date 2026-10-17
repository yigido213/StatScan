/* ---------- v3.6: bayt imzasi (YARA-lite) motoru ve gomulu dosya avcisi (carving) ----------
   Imzalar, herkese acik arastirma/YARA kurallarinda belgelenmis bayt kaliplaridir; KESIN HUKUM DEGIL, tespit ipucudur.
   YAPILMAYANLAR: tam YARA dili (kosullar, modul, regex-bayt karisimi); yalnizca joker (??) destekli sabit bayt dizileri. */
const hx = (s) => s.trim().split(/\s+/).map((t) => (t === '??' ? -1 : parseInt(t, 16)));
const BYTE_SIGS = [
  { id: 'sig_msf_stub', title: 'Metasploit/Meterpreter shellcode başlangıç kalıbı', why: 'Dosyada Metasploit “block_api” hash çözücü shellcode’unun başlangıç baytları bulundu (FC E8 .. 60 89 E5 … PEB okuma). Bu kalıp bilinen sızma/RAT yükleyicilerinde bildirilmiştir; shellcode test dosyalarında da bulunur.', act: 'Dosyayı çalıştırma; bulunan ofseti hex görünümünde incele.', w: 30, sev: 'crit', cat: 'inject', mitre: ['T1059'], kinds: ['pe', 'bin', 'elf'], pats: ['FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30', 'FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30', 'FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51 56 48 31 D2'] },
  { id: 'sig_cs_config', title: 'Cobalt Strike beacon yapılandırma bloğu şablonu (tek baytlık XOR)', why: 'Herkese açık tespit çalışmalarında belgelenen, varsayılan Cobalt Strike beacon yapılandırmasının (0x2E veya 0x69 ile XOR’lanmış TLV başlığı) bayt şablonu bulundu. Şablon çok özgüldür ama özelleştirilmiş beacon’lar farklı anahtar kullanır; araştırma/red-team örnekleri de aynı izi taşır.', act: 'Yapılandırmayı çıkarıp C2 adresini araştır (SentinelOne CobaltStrikeParser gibi araçlar); dosyayı çalıştırma.', w: 35, sev: 'crit', cat: 'exfil', mitre: ['T1071.001'], kinds: ['pe', 'bin', 'elf'], pats: ['2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E 2D', '69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 6A', '00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 03'] },
  { id: 'sig_syscall', title: 'Doğrudan sistem çağrısı (syscall) kalıpları', why: 'ntdll dışındaki bir dosyada “mov r10,rcx; mov eax,<no>; syscall” saplamaları bulundu. Doğrudan syscall, kullanıcı alanı API kancalarını (EDR/AV izleme) atlatmak için kullanılır; bazı koruma/anti-hile yazılımları ve Go/Rust çalışma zamanları da bunu yapar.', act: 'Hangi sistem çağrılarının kullanıldığını (eax değerleri) belirle; dinamik analizle gözlemle.', w: 14, sev: 'high', cat: 'evade', mitre: ['T1106'], kinds: ['pe'], minCount: 2, pats: ['4C 8B D1 B8 ?? ?? 00 00 0F 05'], skipNames: /ntdll|win32u/i },
  { id: 'sig_reflective', title: 'ReflectiveLoader dışa aktarımı/dizesi', why: '“ReflectiveLoader” adı, kendini belleğe yükleyen DLL’lerin (Metasploit, Cobalt Strike, Stephen Fewer tekniği) standart dışa aktarım adıdır. Meşru yazılımlarda nadirdir.', act: 'DLL’i yüklemeden izole ortamda incele.', w: 22, sev: 'high', cat: 'inject', mitre: ['T1620'], kinds: ['pe', 'bin'], str: /\bReflectiveLoader(?:@\d+)?\b/ },
  { id: 'sig_eicar', title: 'EICAR antivirüs test dizisi', why: 'Dosya, antivirüs yazılımlarını denemek için hazırlanmış standart EICAR test dizisini içeriyor. Bu bir ZARARLI DEĞİLDİR; yalnızca tarayıcıların çalıştığını görmek içindir.', act: 'Test amaçlıysa sorun yok; beklenmiyorsa kaynağını sor.', w: 10, sev: 'low', cat: '', mitre: [], kinds: ['pe', 'bin', 'text', 'zip'], str: /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/, fp: 'EICAR test dosyası bilerek tarayıcıları tetikler; gerçek bir zararlı değildir.' }
];
const CRYPTO_SIGS = [
  ['AES', '63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76'], ['SHA-256', '98 2F 8A 42 91 44 37 71'], ['MD5', '78 A4 6A D7 56 B7 C7 E8'], ['ChaCha20/Salsa20', '65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B'],
  ['CRC32 tablosu', '00 00 00 00 96 30 07 77 2C 61 0E EE'], ['TEA/XTEA (δ)', 'B9 79 37 9E'], ['SHA-1', '01 23 45 67 89 AB CD EF FE DC BA 98'], ['Blowfish (π)', '88 6A 3F 24 D3 08 A3 85']
];
function compileSigs(list) { // { name, bytes[] } diziler -> ilk iki bayta gore dizin
  const idx = new Map(); const all = [];
  for (const s of list) for (const ps of (s.pats || (s.hex ? [s.hex] : []))) { const b = hx(ps); if (b.length < 4 || b[0] < 0 || b[1] < 0) continue; const e = { s, b }; all.push(e); const k = b[0] | (b[1] << 8); (idx.get(k) || idx.set(k, []).get(k)).push(e); }
  return { idx, all };
}
const SIG_C = compileSigs(BYTE_SIGS), CRYPTO_C = compileSigs(CRYPTO_SIGS.map(([n, h]) => ({ name: n, hex: h })));
function sigSearch(u8, comp, cap, maxHits) {
  const hits = new Map(); const n = Math.min(u8.length, cap); const idx = comp.idx; const pre = new Uint8Array(65536); for (const k of idx.keys()) pre[k] = 1;
  for (let i = 0; i + 4 <= n; i++) {
    if (!pre[u8[i] | (u8[i + 1] << 8)]) continue; const list = idx.get(u8[i] | (u8[i + 1] << 8));
    for (const e of list) { const b = e.b; if (i + b.length > u8.length) continue; let ok = true; for (let k = 2; k < b.length; k++) if (b[k] >= 0 && u8[i + k] !== b[k]) { ok = false; break; } if (ok) { const key = e.s.id || e.s.name; let h = hits.get(key); if (!h) hits.set(key, h = { s: e.s, offs: [], n: 0 }); h.n++; if (h.offs.length < 4) h.offs.push(i); } }
  }
  return hits;
}
async function sigScan(u8, kind, name, st, text) {
  const cfg = st.cfg; const F = []; const L = []; const cap = cfg.parse ? (cfg.deepJar ? 160e6 : 48e6) : 4e6; const base = baseName(name);
  await pace(st, 'Bayt imzaları', null);
  const hits = sigSearch(u8, SIG_C, cap, 8);
  for (const s of BYTE_SIGS) {
    if (!s.kinds.includes(kind)) continue; if (s.skipNames && s.skipNames.test(base)) continue; let ev = [], loc = [], n = 0;
    if (s.str) { const m = s.str.exec(text || ''); if (m) { n = 1; ev = [clip(m[0], 80)]; } }
    else { const h = hits.get(s.id); if (h) { n = h.n; ev = h.offs.map((o) => 'ofset 0x' + o.toString(16)); loc = h.offs.map((o) => ({ o, n: 24, l: s.id })); } }
    if (!n || (s.minCount && n < s.minCount)) continue;
    F.push(mk(s.id, s.sev, s.w, s.title, s.why, s.act, ev.concat(n > 1 ? [n + ' eşleşme'] : []), s.cat, { basis: 'inference', mitre: s.mitre || [], loc, fp: s.fp }));
  }
  const cs = []; for (const h of sigSearch(u8, CRYPTO_C, cap, 4).values()) cs.push(h.s.name);
  if (cs.length && (kind === 'pe' || kind === 'elf' || kind === 'macho')) F.push(mk('sig_crypto', 'info', 0, 'Gömülü kripto sabitleri: ' + cs.join(', '), 'Dosya şu algoritmaların standart sabit tablolarını içeriyor: ' + cs.join(', ') + '. Bu bir davranış değil, yalnızca ipucudur: kripto kitaplıkları, sıkıştırma ve birçok meşru program aynı sabitleri taşır; fidye yazılımı/stealer analizinde şifreleme rutinini bulmaya yarar.', 'Şifreleme rutinini decompiler’da bu sabitlere çapraz başvuruyla bul.', cs, 'pe', { basis: 'fact' }));
  const exts = text ? (text.match(/\.(?:docx?|xlsx?|pptx?|pdf|jpe?g|png|sql|mdb|psd|bak|zip|rar|txt|csv|odt|wallet|kdbx)\b/gi) || []) : []; const dx = new Set(exts.map((x) => x.toLowerCase()));
  if ((kind === 'pe' || kind === 'elf') && dx.size >= 10 && cs.some((c) => /AES|ChaCha/.test(c)) && /(?:encrypt|decrypt|\.locked|\.enc\b|ransom|readme|recover|restore)/i.test(text)) F.push(mk('sig_ransom_ext', 'high', 18, 'Dosya uzantısı listesi + kripto sabitleri + şifreleme dizeleri (fidye yazılımı kalıbı)', 'Dosya çok sayıda belge/veritabanı/yedek uzantısı (' + dx.size + ' farklı) ile AES/ChaCha sabitlerini ve “encrypt/decrypt/ransom” benzeri dizeleri birlikte içeriyor. Fidye yazılımlarının hedef uzantı listesi tipik olarak böyledir; yedekleme/şifreleme araçları da benzerdir.', 'Çalıştırma. Uzantı listesini ve fidye notu metnini izole ortamda incele.', [...dx].slice(0, 8).concat(cs.slice(0, 2)), 'ransom', { basis: 'inference', mitre: ['T1486'] }));
  L.push(led('sigs', 'Bayt imzaları (YARA-lite: shellcode, Cobalt Strike, syscall, kripto sabitleri)', cfg.parse ? (u8.length > cap ? 'partial' : 'done') : 'partial', u8.length > cap ? 'ilk ' + fmtN(cap) + ' tarandı' : (cfg.parse ? '' : 'Hızlı mod: ilk 4 MB')));
  return { findings: F, analyses: L };
}
/* ---- gomulu dosya avcisi ---- */
const CARVE = [
  ['pe', (u8, i) => { if (u8[i] !== 0x4d || u8[i + 1] !== 0x5a) return 0; const l = u8[i + 0x3c] | (u8[i + 0x3d] << 8) | (u8[i + 0x3e] << 16); return (l > 0 && l < 0x1000 && i + l + 4 < u8.length && u8[i + l] === 0x50 && u8[i + l + 1] === 0x45 && u8[i + l + 2] === 0 && u8[i + l + 3] === 0) ? 1 : 0; }, 'PE (EXE/DLL)'],
  ['zip', (u8, i) => (u8[i] === 0x50 && u8[i + 1] === 0x4b && u8[i + 2] === 3 && u8[i + 3] === 4 && u8[i + 4] <= 63 && [0, 8, 9, 12, 14, 93, 95, 98].includes(u8[i + 8]) && u8[i + 9] === 0) ? 1 : 0, 'ZIP/JAR/APK'],
  ['rar', (u8, i) => (u8[i] === 0x52 && u8[i + 1] === 0x61 && u8[i + 2] === 0x72 && u8[i + 3] === 0x21 && u8[i + 4] === 0x1a && u8[i + 5] === 7 && (u8[i + 6] === 0 || u8[i + 6] === 1)) ? 1 : 0, 'RAR'],
  ['7z', (u8, i) => (u8[i] === 0x37 && u8[i + 1] === 0x7a && u8[i + 2] === 0xbc && u8[i + 3] === 0xaf && u8[i + 4] === 0x27 && u8[i + 5] === 0x1c) ? 1 : 0, '7-Zip'],
  ['elf', (u8, i) => (u8[i] === 0x7f && u8[i + 1] === 0x45 && u8[i + 2] === 0x4c && u8[i + 3] === 0x46 && (u8[i + 4] === 1 || u8[i + 4] === 2) && (u8[i + 5] === 1 || u8[i + 5] === 2)) ? 1 : 0, 'ELF'],
  ['ole', (u8, i) => (u8[i] === 0xd0 && u8[i + 1] === 0xcf && u8[i + 2] === 0x11 && u8[i + 3] === 0xe0 && u8[i + 4] === 0xa1 && u8[i + 5] === 0xb1 && u8[i + 6] === 0x1a && u8[i + 7] === 0xe1) ? 1 : 0, 'OLE (eski Office/MSI)'],
  ['pdf', (u8, i) => (u8[i] === 0x25 && u8[i + 1] === 0x50 && u8[i + 2] === 0x44 && u8[i + 3] === 0x46 && u8[i + 4] === 0x2d && u8[i + 5] === 0x31) ? 1 : 0, 'PDF'],
  ['rtf', (u8, i) => (u8[i] === 0x7b && u8[i + 1] === 0x5c && u8[i + 2] === 0x72 && u8[i + 3] === 0x74 && u8[i + 4] === 0x66 && u8[i + 5] === 0x31) ? 1 : 0, 'RTF'],
  ['class', (u8, i) => (u8[i] === 0xca && u8[i + 1] === 0xfe && u8[i + 2] === 0xba && u8[i + 3] === 0xbe && u8[i + 4] === 0 && u8[i + 5] === 0 && u8[i + 6] === 0 && u8[i + 7] >= 45 && u8[i + 7] < 100) ? 1 : 0, 'Java class'],
  ['gz', (u8, i) => (u8[i] === 0x1f && u8[i + 1] === 0x8b && u8[i + 2] === 8 && u8[i + 3] < 32 && (u8[i + 9] <= 13 || u8[i + 9] === 255) && u8[i + 8] <= 4) ? 1 : 0, 'gzip']
];
/* from'dan itibaren, kind'e gore gomulu dosya imzalarini arar; [{kind,label,off}] */
function carve(u8, from, opts) {
  opts = opts || {}; const out = []; const skip = opts.skip || new Set(); const n = Math.min(u8.length, opts.cap || 200e6); const maxn = opts.max || 12;
  const first = new Set([0x4d, 0x50, 0x52, 0x37, 0x7f, 0xd0, 0x25, 0x7b, 0xca, 0x1f]);
  for (let i = from; i + 16 < n && out.length < maxn; i++) {
    if (!first.has(u8[i])) continue;
    for (const [k, fn, label] of CARVE) { if (skip.has(k)) continue; if (fn(u8, i)) { out.push({ kind: k, label, off: i }); if (k === 'pe') i += 0x200; else i += 8; break; } }
  }
  return out;
}
const CARVE_SCAN = new Set(['pe', 'zip', 'rar', '7z', 'elf', 'ole', 'pdf', 'class', 'gz', 'rtf']);
/* bulunan gomulu dosyalari bulgu + alt tarama olarak ekler */
async function carveAndScan(u8, from, ctx) {
  const { st, F, kids, name, depth, cfg, id, title, skipKinds, cap } = ctx; const found = carve(u8, from, { skip: skipKinds, cap: cap || 200e6, max: 10 }); if (!found.length) return 0;
  const byKind = {}; for (const f of found) (byKind[f.label] = byKind[f.label] || []).push(f.off);
  const dir = found.filter((f) => CARVE_SCAN.has(f.kind));
  F.push(mk(id || 'carved', dir.some((f) => f.kind === 'pe' || f.kind === 'elf') ? 'high' : 'med', dir.some((f) => f.kind === 'pe' || f.kind === 'elf') ? 14 : 8, title || 'Dosya içinde gömülü başka dosyalar', 'Beklenmedik konumda başka dosya biçimlerinin başlıkları bulundu: ' + Object.entries(byKind).map(([k, v]) => k + ' ×' + v.length).join(', ') + '. Kurulum paketleri ve belge biçimleri meşru olarak dosya taşır; ancak veriye/görüntüye/belgeye eklenmiş çalıştırılabilir bir yük de bu şekilde saklanır. Başlık eşleşmesi içeriğin gerçekten geçerli olduğunu kanıtlamaz.', 'Gömülü dosyalar ayrıca taranıyor; sonuçlarına ve hex görünümündeki ofsetlere bak.', found.slice(0, 6).map((f) => f.label + ' @0x' + f.off.toString(16)), 'pe', { basis: 'fact', mitre: ['T1027.009'], loc: found.slice(0, 6).map((f) => ({ o: f.off, n: 32, l: f.label })) }));
  let k = 0; for (const f of found) { if (k >= 4) break; if (!['pe', 'zip', 'elf', 'ole', 'pdf', 'rtf', 'class', 'gz'].includes(f.kind)) continue; if (depth + 1 > cfg.depth || !cfg.parse) { limitHit(st, 'depth', 'Derinlik/mod sınırı nedeniyle gömülü ' + f.label + ' taranmadı.'); break; } const end = f.kind === 'class' || f.kind === 'gz' ? Math.min(u8.length, f.off + 8e6) : u8.length; kids.push(await scanBuffer(u8.slice(f.off, end), name + ' › gömülü ' + f.label + ' @0x' + f.off.toString(16), st, depth + 1)); k++; }
  return found.length;
}
/* resim dosyalari: bitisten sonra eklenmis veri ve cok bicimli (polyglot) dosyalar */
function imageEnd(u8) {
  const n = u8.length;
  if (n > 8 && u8[0] === 0x89 && u8[1] === 0x50 && u8[2] === 0x4e && u8[3] === 0x47) { let p = 8; while (p + 12 <= n) { const len = ((u8[p] << 24) | (u8[p + 1] << 16) | (u8[p + 2] << 8) | u8[p + 3]) >>> 0; const t = ascii(u8, p + 4, p + 8); if (len > n) return { kind: 'PNG', end: n, bad: true }; p += 12 + len; if (t === 'IEND') return { kind: 'PNG', end: p }; } return { kind: 'PNG', end: n, bad: true }; }
  if (n > 4 && u8[0] === 0xff && u8[1] === 0xd8) { let p = 2; while (p + 4 <= n) { if (u8[p] !== 0xff) { p++; continue; } const m = u8[p + 1]; if (m === 0xd9) return { kind: 'JPEG', end: p + 2 }; if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7) || m === 0xff) { p += (m === 0xff ? 1 : 2); continue; } if (m === 0xda) { /* tarama verisi: sonraki gercek isaretciyi ara */ p += 2 + ((u8[p + 2] << 8) | u8[p + 3]); while (p + 2 <= n && !(u8[p] === 0xff && u8[p + 1] !== 0 && !(u8[p + 1] >= 0xd0 && u8[p + 1] <= 0xd7))) p++; continue; } p += 2 + ((u8[p + 2] << 8) | u8[p + 3]); } return { kind: 'JPEG', end: n, bad: true }; }
  if (n > 10 && ascii(u8, 0, 3) === 'GIF') { for (let p = n - 1; p > 10; p--) if (u8[p] === 0x3b) return { kind: 'GIF', end: p + 1 }; }
  return null;
}
function isImage(u8) { return (u8.length > 8 && u8[0] === 0x89 && u8[1] === 0x50 && u8[2] === 0x4e && u8[3] === 0x47 && u8[4] === 0x0d) || (u8.length > 4 && u8[0] === 0xff && u8[1] === 0xd8 && u8[2] === 0xff) || (u8.length > 6 && ascii(u8, 0, 6).startsWith('GIF8')); }
async function analyzeImage(u8, name, st, depth) {
  const cfg = st.cfg; const F = []; const kids = []; const L = []; const e = imageEnd(u8); const info = { kind: 'Görüntü' };
  if (!e) { return { findings: F, info, children: kids, analyses: [led('img', 'Görüntü yapısı', 'partial', 'bitiş işaretçisi bulunamadı')] }; }
  info.kind = 'Görüntü (' + e.kind + ')'; const trail = u8.length - e.end; info.trailer = trail;
  L.push(led('img', 'Görüntü yapısı ve eklenmiş veri denetimi', 'done', e.kind));
  if (e.bad) F.push(mk('img_bad', 'low', 3, 'Görüntü yapısı bozuk/kesik', e.kind + ' parça zinciri bitiş işaretine ulaşmadan bitiyor.', 'Görüntü açıcıyla dene.', [], 'pe', { basis: 'fact' }));
  else if (trail > 32) {
    const ent = entropy(u8, e.end, u8.length); const tail = u8.subarray(e.end, Math.min(u8.length, e.end + 4)); const sigs = carve(u8, e.end, { max: 6 });
    F.push(mk('img_trailer', sigs.length ? 'high' : 'med', sigs.length ? 16 : 6, 'Görüntü bitişinden sonra eklenmiş ' + trail + ' bayt veri', e.kind + ' dosyası kendi bitiş işaretinden sonra ek veri taşıyor' + (sigs.length ? ' ve bu verinin başında/içinde ' + sigs.map((s) => s.label).join(', ') + ' başlığı var' : '') + ' (entropi ' + ent.toFixed(2) + '). Görüntü açıcılar bu kısmı yok sayar; bu yüzden zararsız görünen bir resme eklenmiş yük (dropper) olarak kullanılabilir. Bazı kameralar/araçlar da küçük meta veri ekler.', 'Eklenen kısmı çıkarıp türünü belirle; gömülü dosyalar ayrıca taranıyor.', ['ofset 0x' + e.end.toString(16) + ', ' + trail + ' bayt'].concat(sigs.map((s) => s.label + ' @0x' + s.off.toString(16))), 'pe', { basis: 'fact', mitre: ['T1027.009'], loc: [{ o: e.end, n: Math.min(trail, 256), l: 'eklenen veri' }] }));
    for (const s of sigs.slice(0, 3)) { if (depth + 1 > cfg.depth || !cfg.parse) { limitHit(st, 'depth', 'Derinlik/mod sınırı nedeniyle görüntüye eklenen dosya taranmadı.'); break; } kids.push(await scanBuffer(u8.slice(s.off), name + ' › görüntüye eklenmiş ' + s.label + ' @0x' + s.off.toString(16), st, depth + 1)); }
  }
  /* zip merkezi dizin sonu: gorsel + arsiv (polyglot) */
  const tailZone = u8.subarray(Math.max(0, u8.length - 65600)); for (let i = tailZone.length - 22; i >= 0; i--) if (tailZone[i] === 0x50 && tailZone[i + 1] === 0x4b && tailZone[i + 2] === 5 && tailZone[i + 3] === 6) { if (!F.some((f) => f.id === 'img_trailer')) F.push(mk('img_zip_polyglot', 'med', 10, 'Görüntü aynı zamanda ZIP arşivi olabilir (polyglot)', 'Dosyanın sonunda ZIP “merkezi dizin sonu” kaydı var; resim açıcılar ve arşiv yöneticileri aynı dosyayı farklı yorumlar (GIFAR tipi hile).', 'Dosyayı bir arşiv yöneticisiyle listele (açmadan).', [], 'arch', { basis: 'fact' })); break; }
  return { findings: F, info, children: kids, analyses: L };
}
