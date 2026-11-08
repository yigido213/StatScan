/* Guvenlik araclari motoru: Imza ve Sertifika Denetcisi (sigAudit) + Paketleyici/Obfuscation Dedektoru (packAudit).
 * Dosya CALISTIRILMAZ, ag istegi YAPILMAZ. IOC Cikarici mevcut collectIocTree/iocExport'u kullanir (90-ioc.js).
 * IMZA: PKCS#7 icindeki sertifikalar ayristirilir; imza matematigi ve zincir baglantilari dosya ici verilerle
 * (WebCrypto, yalnizca RSA) denetlenir. YAPILMAYANLAR: Windows kok sertifika deposuna guven, iptal (CRL/OCSP sorgusu),
 * bilinen sizdirilmis/kotuye kullanilmis sertifika listesi, ECDSA imza dogrulamasi. Iptal adresleri yalnizca LISTELENIR.
 * PAKET: bolum adi/entropi/giris noktasi/import ve bilinen koruyucu dizeleri sezgiseldir; "paketli" = zararli DEGIL. */
function sdr(b, p, end) {
  if (p + 2 > end) return null; const tag = b[p]; let l = b[p + 1], q = p + 2;
  if (l & 0x80) { const n = l & 0x7f; if (n === 0 || n > 4 || q + n > end) return null; l = 0; for (let i = 0; i < n; i++) l = l * 256 + b[q + i]; q += n; }
  if (q + l > end) return null; return { tag, h: p, s: q, e: q + l };
}
function sdk(b, n) { const out = []; if (!n) return out; let p = n.s; while (p < n.e && out.length < 400) { const k = sdr(b, p, n.e); if (!k) break; out.push(k); p = k.e; } return out; }
const sraw = (b, n) => b.subarray(n.h, n.e);
const SIG_RDN = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'S', '2.5.4.5': 'SERIAL', '1.2.840.113549.1.9.1': 'E' };
function sigName(b, n) {
  const map = {}; if (!n) return { map, str: '', key: '' };
  for (const rdn of sdk(b, n)) for (const atv of sdk(b, rdn)) { const k = sdk(b, atv); const key = SIG_RDN[derOid(b, k[0])]; if (key && k[1] && map[key] === undefined) map[key] = derStr(b, k[1]).slice(0, 120); }
  return { map, str: ['CN', 'O', 'OU', 'L', 'S', 'C'].filter((k) => map[k]).map((k) => k + '=' + map[k]).join(', '), key: hex(sraw(b, n)) };
}
function sigTimeMs(b, n) {
  if (!n) return null; const t = ascii(b, n.s, n.e); let m;
  if (n.tag === 0x17 && (m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?/.exec(t))) return Date.UTC(+m[1] < 50 ? 2000 + +m[1] : 1900 + +m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
  if (n.tag === 0x18 && (m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?/.exec(t))) return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
  return null;
}
const sigDay = (ms) => (ms == null ? '' : new Date(ms).toISOString().slice(0, 10));
const SIG_ALG_NAME = { '1.2.840.113549.1.1.2': 'MD2withRSA', '1.2.840.113549.1.1.4': 'MD5withRSA', '1.2.840.113549.1.1.5': 'SHA1withRSA', '1.2.840.113549.1.1.11': 'SHA256withRSA', '1.2.840.113549.1.1.12': 'SHA384withRSA', '1.2.840.113549.1.1.13': 'SHA512withRSA', '1.2.840.113549.1.1.10': 'RSASSA-PSS', '1.2.840.10045.4.1': 'SHA1withECDSA', '1.2.840.10045.4.3.2': 'SHA256withECDSA', '1.2.840.10045.4.3.3': 'SHA384withECDSA', '1.2.840.10045.4.3.4': 'SHA512withECDSA' };
const SIG_EC = { '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521' };
const SIG_HASH_OF = (alg) => (/^SHA1/.test(alg) ? 'SHA-1' : /^SHA256/.test(alg) ? 'SHA-256' : /^SHA384/.test(alg) ? 'SHA-384' : /^SHA512/.test(alg) ? 'SHA-512' : '');
function sigUris(b, n, out, depth) {
  if (!n || depth > 8) return; if (n.tag === 0x86) { out.push(ascii(b, n.s, n.e).slice(0, 200)); return; }
  if (n.tag & 0x20) for (const k of sdk(b, n)) sigUris(b, k, out, depth + 1);
}
function sigCert(b, n) {
  const k = sdk(b, n); const tbs = k[0]; const tk = sdk(b, tbs); const i = tk[0] && tk[0].tag === 0xa0 ? 1 : 0;
  const c = { tbs: sraw(b, tbs), serial: hex(b.subarray(tk[i].s, tk[i].e)).replace(/^(?:00)+(?=.)/, ''), sigOid: derOid(b, sdk(b, k[1])[0]), eku: [], crl: [], ocsp: [], caIssuers: [], ca: false, ku: null };
  c.sigAlg = SIG_ALG_NAME[c.sigOid] || c.sigOid; c.sigBits = b.subarray(k[2].s + 1, k[2].e);
  const iss = sigName(b, tk[i + 2]); const sub = sigName(b, tk[i + 4]); c.issuer = iss; c.subject = sub; c.issKey = iss.key; c.subjKey = sub.key;
  const v = sdk(b, tk[i + 3]); c.from = sigTimeMs(b, v[0]); c.to = sigTimeMs(b, v[1]);
  const spki = tk[i + 5]; c.spki = sraw(b, spki); const sk = sdk(b, spki); const ak = sdk(b, sk[0]); c.keyOid = derOid(b, ak[0]);
  if (c.keyOid === '1.2.840.113549.1.1.1') {
    c.keyAlg = 'RSA'; try { const bs = b.subarray(sk[1].s + 1, sk[1].e); const rk = sdr(bs, 0, bs.length); const mk = sdk(bs, rk)[0]; let o = mk.s; while (o < mk.e - 1 && bs[o] === 0) o++; c.keyBits = (mk.e - o - 1) * 8 + (32 - Math.clz32(bs[o])); } catch (e) { c.keyBits = 0; }
  } else if (c.keyOid === '1.2.840.10045.2.1') { c.keyAlg = 'EC'; c.curve = SIG_EC[derOid(b, ak[1])] || derOid(b, ak[1]); } else c.keyAlg = c.keyOid;
  for (const x of tk.slice(i + 6)) if (x.tag === 0xa3) for (const ext of sdk(b, sdk(b, x)[0])) {
    const ek = sdk(b, ext); const oid = derOid(b, ek[0]); const val = ek[ek.length - 1]; const inner = val && sdr(b, val.s, val.e); if (!inner) continue;
    if (oid === '2.5.29.19') { const kk = sdk(b, inner); c.ca = !!(kk[0] && kk[0].tag === 1 && b[kk[0].s] !== 0); }
    else if (oid === '2.5.29.15') { const f = b[inner.s + 1] || 0; c.ku = { sig: !!(f & 0x80), certSign: !!(f & 0x04), crlSign: !!(f & 0x02) }; }
    else if (oid === '2.5.29.37') c.eku = sdk(b, inner).map((o) => derOid(b, o));
    else if (oid === '2.5.29.31') sigUris(b, inner, c.crl, 0);
    else if (oid === '1.3.6.1.5.5.7.1.1') for (const ad of sdk(b, inner)) { const q = sdk(b, ad); const m = derOid(b, q[0]); const u = []; sigUris(b, q[1], u, 0); if (u[0]) (m === '1.3.6.1.5.5.7.48.1' ? c.ocsp : c.caIssuers).push(u[0]); }
  }
  c.codeSign = !c.eku.length || c.eku.includes('1.3.6.1.5.5.7.3.3') || c.eku.includes('1.3.6.1.4.1.311.2.1.22') || c.eku.includes('1.3.6.1.4.1.311.2.1.21');
  c.timestampOnly = c.eku.length > 0 && c.eku.includes('1.3.6.1.5.5.7.3.8') && !c.codeSign;
  c.self = c.issKey === c.subjKey; return c;
}
function sigFindGt(b, n, depth) {
  if (!n || depth > 14) return null; if (n.tag === 0x18) return sigTimeMs(b, n);
  if (n.tag === 0x04) { const x = sdr(b, n.s, n.e); return x && x.e === n.e ? sigFindGt(b, x, depth + 1) : null; }
  if (n.tag & 0x20) for (const k of sdk(b, n)) { const r = sigFindGt(b, k, depth + 1); if (r != null) return r; }
  return null;
}
function sigSigner(b, si) {
  const k = sdk(b, si); const o = { digestOid: '', auth: null }; const ias = sdk(b, k[1]);
  o.issuerKey = hex(sraw(b, ias[0])); o.serial = hex(b.subarray(ias[1].s, ias[1].e)).replace(/^(?:00)+(?=.)/, ''); o.digestOid = derOid(b, sdk(b, k[2])[0]);
  let j = 3; if (k[j] && k[j].tag === 0xa0) { o.auth = k[j]; j++; }
  o.sigOid = derOid(b, sdk(b, k[j])[0]); o.sig = b.subarray(k[j + 1].s, k[j + 1].e); j += 2; const un = k[j] && k[j].tag === 0xa1 ? k[j] : null;
  for (const a of sdk(b, o.auth)) { const ak = sdk(b, a); const oid = derOid(b, ak[0]); const val = sdk(b, ak[1])[0]; if (!val) continue; if (oid === '1.2.840.113549.1.9.4') o.msgDigest = hex(b.subarray(val.s, val.e)); else if (oid === '1.2.840.113549.1.9.5') o.signingTime = sigTimeMs(b, val); }
  for (const a of sdk(b, un)) {
    const ak = sdk(b, a); const oid = derOid(b, ak[0]); const val = sdk(b, ak[1])[0]; if (!val) continue;
    if (oid === '1.2.840.113549.1.9.6') { try { const ck = sdk(b, val); let jj = 3; if (ck[jj] && ck[jj].tag === 0xa0) for (const at of sdk(b, ck[jj])) { const q = sdk(b, at); if (derOid(b, q[0]) === '1.2.840.113549.1.9.5') { const t = sigTimeMs(b, sdk(b, q[1])[0]); if (t != null) o.ts = { ms: t, kind: 'counter' }; } } } catch (e) { /* yoksay */ } }
    else if (oid === '1.3.6.1.4.1.311.3.3.1' && !o.ts) { const t = sigFindGt(b, val, 0); if (t != null) o.ts = { ms: t, kind: 'rfc3161' }; }
  }
  return o;
}
async function sigVerifyRsa(spki, hashName, sig, data) {
  try {
    if (!hashName) return { ok: null, why: 'Özet algoritması WebCrypto’da yok (MD5/bilinmeyen)' };
    if (!(globalThis.crypto && crypto.subtle)) return { ok: null, why: 'Bu ortamda WebCrypto yok' };
    const key = await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: hashName }, false, ['verify']);
    return { ok: await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, data) };
  } catch (e) { return { ok: null, why: String(e && e.message || e).slice(0, 120) }; }
}
/* ---- yayinci taklidi ---- */
const SIG_BRANDS = ['Microsoft', 'Google', 'Adobe', 'Intel', 'NVIDIA', 'Advanced Micro Devices', 'Oracle', 'Mozilla', 'Valve', 'Discord', 'Riot Games', 'Epic Games', 'Apple', 'Amazon', 'Realtek', 'Logitech', 'Razer', 'Zoom Video Communications', 'Dropbox', 'Cloudflare', 'Docker', 'JetBrains', 'Brave Software', 'Opera Software', 'Spotify', 'Telegram', 'Blizzard Entertainment', 'Electronic Arts', 'Ubisoft', 'Mojang', 'VMware', 'Cisco Systems', 'Dell', 'Lenovo', 'ASUSTeK Computer', 'Samsung Electronics', 'Kaspersky', 'Avast Software', 'ESET', 'Malwarebytes', 'NortonLifeLock', 'McAfee', 'Python Software Foundation', 'GitHub', 'Slack Technologies', 'Notion Labs', 'OBS Project', 'Steam', 'Canonical', 'Red Hat', 'Qualcomm', 'Broadcom', 'Synaptics', 'Corsair', 'SteelSeries', 'MSI', 'Gigabyte'];
const SIG_LEGAL = /\b(?:inc|llc|ltd|limited|corp|corporation|co|company|gmbh|ag|sa|srl|sro|spol|as|ab|oy|plc|bv|nv|kg|lp|fz|pty|usa|incorporated|services|software|technologies|technology|systems|group|international|holdings|publisher|windows)\b/g;
function sigNorm(s) { return String(s || '').normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[.,'"’()&\-_]/g, ' ').replace(SIG_LEGAL, ' ').replace(/\s+/g, ''); }
const SIG_CONF = { '0': 'o', '1': 'l', '3': 'e', '5': 's', '$': 's', '@': 'a', '|': 'l', 'i': 'l', 'і': 'l', 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'ѕ': 's', 'ј': 'l', 'ο': 'o', 'ν': 'v', 'ι': 'l', 'α': 'a' };
function sigSkel(s) { return sigNorm(s).replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/[^a-z0-9]/g, (ch) => SIG_CONF[ch] || ch).replace(/[01i3$5@|]/g, (ch) => SIG_CONF[ch] || ch); }
function sigLev(a, b) { const m = a.length, n = b.length; if (Math.abs(m - n) > 3) return 9; let prev = Array.from({ length: n + 1 }, (_, j) => j); for (let i = 1; i <= m; i++) { const cur = [i]; for (let j = 1; j <= n; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); prev = cur; } return prev[n]; }
/* name: imzalayan O/CN; dondurur { kind: 'exact'|'homoglyph'|'typo'|'contains'|null, brand } */
function sigBrandMatch(name) {
  const n = sigNorm(name); if (n.length < 3) return { kind: null };
  const sk = sigSkel(name);
  for (const br of SIG_BRANDS) {
    const bn = sigNorm(br); if (bn.length < 4) continue; const bs = sigSkel(br);
    if (n === bn) return { kind: 'exact', brand: br };
    if (sk === bs) return { kind: 'homoglyph', brand: br };
    if (bn.length >= 6 && sigLev(n, bn) <= (bn.length >= 10 ? 2 : 1)) return { kind: 'typo', brand: br };
  }
  for (const br of SIG_BRANDS) { const bn = sigNorm(br); if (bn.length >= 5 && n.includes(bn) && n !== bn) return { kind: 'contains', brand: br }; }
  return { kind: null };
}
/* ---- ana: Imza ve Sertifika Denetcisi ---- */
async function sigAudit(u8, name, opts) {
  opts = opts || {}; const now = opts.now || Date.now(); const out = { name, kind: 'none', findings: [], certs: [], chain: [], signer: null, ts: null, limits: [] };
  const F = (id, sev, title, why, act) => out.findings.push({ id, sev, title, why: why || '', act: act || '' });
  let p = null; try { p = parsePE(u8); } catch (e) { p = null; }
  if (!p) { out.kind = 'notpe'; return out; }
  const ver = opts.ver || null; out.company = ver && ver.CompanyName ? String(ver.CompanyName).slice(0, 80) : '';
  const claim = out.company ? sigBrandMatch(out.company) : { kind: null };
  if (!p.signed || !p.certOff || !p.certSize) {
    out.kind = 'unsigned';
    F('sig_none', 'info', 'Dosyada dijital imza yok', 'İmzasız olmak tek başına kötü değildir (küçük geliştiricilerin ve kişisel araçların çoğu imzasızdır). Ama büyük bir yayıncı adını taşıyan imzasız dosya şüphelidir.', 'Dosyayı resmi kaynaktan indirdiğini doğrula.');
    if (claim.kind === 'exact' || claim.kind === 'contains') F('sig_unsigned_claim', 'med', '“' + claim.brand + '” adını taşıyor ama imzasız', 'Sürüm bilgisindeki üretici alanı “' + out.company + '”, oysa ' + claim.brand + ' dosyaları imzalı gelir. Sahte olabilir (ya da elle yazılmış sürüm bilgisi).', 'Yayıncının resmi sitesinden indirip SHA-256’yı karşılaştır.');
    out.verdict = { level: 'none', text: 'İmza yok.' }; return out;
  }
  let blob = null; try {
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength); let q = p.certOff; const endC = Math.min(u8.length, p.certOff + p.certSize); let nb = 0;
    while (q + 8 <= endC && nb < 8) { const len = dv.getUint32(q, true), type = dv.getUint16(q + 6, true); if (len < 8 || q + len > endC) break; nb++; if (type === 2 && !blob) blob = u8.subarray(q + 8, q + len); q += (len + 7) & ~7; }
    out.entries = nb;
  } catch (e) { blob = null; }
  if (!blob) { out.kind = 'broken'; F('sig_broken', 'med', 'İmza bloğu okunamadı', 'Sertifika tablosu var ama içindeki PKCS#7 yapısı bulunamadı ya da bozuk.', 'Dosyayı Windows’ta Özellikler → Dijital İmzalar ile kontrol et.'); out.verdict = { level: 'warn', text: 'İmza bloğu bozuk.' }; return out; }
  let sd, sk, content, certNodes = [], signerNode = null;
  try {
    const ci = sdr(blob, 0, blob.length); const ck = sdk(blob, ci); if (derOid(blob, ck[0]) !== '1.2.840.113549.1.7.2') throw new Error('signedData değil');
    sd = sdk(blob, ck[1])[0]; sk = sdk(blob, sd); content = sk[2];
    for (const x of sk.slice(3)) { if (x.tag === 0xa0) certNodes = sdk(blob, x); else if (x.tag === 0x31) signerNode = x; }
  } catch (e) { out.kind = 'broken'; F('sig_broken', 'med', 'İmza yapısı ayrıştırılamadı', String(e && e.message || e).slice(0, 120), 'Dosyayı Windows’ta doğrula.'); out.verdict = { level: 'warn', text: 'İmza yapısı ayrıştırılamadı.' }; return out; }
  const certs = []; for (const cn of certNodes) { try { certs.push(sigCert(blob, cn)); } catch (e) { out.limits.push('Bir sertifika ayrıştırılamadı'); } }
  let sg = null; try { const si = sdk(blob, signerNode)[0]; if (si) sg = sigSigner(blob, si); } catch (e) { out.limits.push('İmzalayan bilgisi (SignerInfo) ayrıştırılamadı'); }
  let leaf = sg ? certs.find((c) => c.serial === sg.serial && c.issKey === sg.issuerKey) : null;
  if (!leaf) leaf = certs.find((c) => !c.timestampOnly && !certs.some((o) => o !== c && o.issKey === c.subjKey)) || certs[0];
  if (!leaf) { out.kind = 'broken'; F('sig_nocert', 'med', 'İmzada sertifika yok', 'Bu imza içinde hiç sertifika bulunamadı; imzalayan kim olduğu dosyadan anlaşılamaz.', 'Windows’ta doğrula.'); out.verdict = { level: 'warn', text: 'İmzada sertifika yok.' }; return out; }
  /* zincir (yalniz ad eslesmesi; kok sertifika dosyada olmayabilir) */
  const chain = [leaf]; for (let n = 0; n < 8; n++) { const cur = chain[chain.length - 1]; if (cur.self) break; const nx = certs.find((o) => o !== cur && o.subjKey === cur.issKey && !chain.includes(o)); if (!nx) break; chain.push(nx); }
  out.kind = 'signed'; out.chain = chain.map((c) => ({ subject: c.subject.str, issuer: c.issuer.str, from: sigDay(c.from), to: sigDay(c.to), serial: c.serial, keyAlg: c.keyAlg, keyBits: c.keyBits || 0, curve: c.curve || '', sigAlg: c.sigAlg, ca: c.ca, self: c.self }));
  out.certs = certs.map((c) => ({ subject: c.subject.str, issuer: c.issuer.str, from: sigDay(c.from), to: sigDay(c.to), serial: c.serial, ts: c.timestampOnly }));
  const last = chain[chain.length - 1]; out.rootInFile = !!last.self; out.chainComplete = out.rootInFile;
  out.signer = { subject: leaf.subject.str, o: leaf.subject.map.O || '', cn: leaf.subject.map.CN || '', country: leaf.subject.map.C || '', issuer: leaf.issuer.str, issuerCn: leaf.issuer.map.CN || leaf.issuer.map.O || '', serial: leaf.serial, from: sigDay(leaf.from), to: sigDay(leaf.to), sigAlg: leaf.sigAlg, keyAlg: leaf.keyAlg, keyBits: leaf.keyBits || 0, curve: leaf.curve || '', ca: leaf.ca, eku: leaf.eku, crl: leaf.crl.slice(0, 4), ocsp: leaf.ocsp.slice(0, 4), self: leaf.self };
  /* 1) gomulu ozet ↔ dosya ozeti (mevcut denetim) */
  let pes = null; try { pes = await peSignature(u8, p, { skips: new Map() }); } catch (e) { pes = null; }
  if (pes) { out.digest = { alg: pes.alg || '', match: pes.match == null ? null : pes.match, embedded: pes.embedded || '', computed: pes.computed || '', note: pes.note || pes.err || '' }; }
  if (pes && pes.match === true) F('sig_digest_ok', 'ok', 'Dosya imzalandığı günkü haliyle (özet tutarlı)', 'İmzadaki Authenticode özeti dosyadan hesaplanan özetle aynı: imzadan sonra değiştirilmemiş.', '');
  else if (pes && pes.match === false) F('sig_digest_bad', 'high', 'İmza özeti dosyayla UYUŞMUYOR', 'Dosya imzalandıktan sonra değiştirilmiş (virüs bulaşması, yama ya da bozuk indirme). Windows bu imzayı geçersiz sayar.', 'Dosyayı resmi kaynaktan yeniden indir; SHA-256’yı karşılaştır.');
  else F('sig_digest_na', 'info', 'Gömülü özet karşılaştırılamadı', (pes && (pes.note || pes.err)) || 'Bilinmeyen neden', '');
  /* 2) imza matematigi (yalniz RSA, dosya ici sertifika ile) */
  out.math = { ok: null, why: '' };
  try {
    if (!sg || !sg.auth) { out.math.why = 'İmzalı öznitelikler (authenticatedAttributes) yok'; }
    else {
      const hashName = SIG_ALGS[sg.digestOid] || ''; const seq = sdk(blob, sdk(blob, content)[1])[0];
      const cHash = hashName && seq ? await digest(hashName, blob.subarray(seq.s, seq.e)) : null;
      if (cHash && sg.msgDigest) { out.msgDigestOk = cHash === sg.msgDigest; if (!out.msgDigestOk) F('sig_msgdigest', 'high', 'İmzalı özet, imzalanan içerikle UYUŞMUYOR', 'SignerInfo içindeki messageDigest, SpcIndirectDataContent’in özetinden farklı: imza yapısı kurcalanmış olabilir.', 'Dosyayı güvenme; resmi kaynaktan yeniden indir.'); }
      if (leaf.keyAlg !== 'RSA') out.math.why = 'İmzalayan anahtar ' + (leaf.keyAlg === 'EC' ? 'ECDSA' : leaf.keyAlg) + ': bu araç yalnızca RSA imzalarını doğrular';
      else {
        const data = Uint8Array.from(sraw(blob, sg.auth)); data[0] = 0x31;
        const r = await sigVerifyRsa(leaf.spki, hashName, sg.sig, data); out.math = { ok: r.ok, why: r.why || '' };
      }
    }
  } catch (e) { out.math = { ok: null, why: String(e && e.message || e).slice(0, 100) }; }
  if (out.math.ok === true) F('sig_math_ok', 'ok', 'İmza matematiği doğru', 'İmza, dosyadaki imzalayan sertifikanın açık anahtarıyla doğrulandı (RSA). Bu, kimliğe güvenmek DEĞİL; yalnızca imzanın bu sertifikayla atıldığını gösterir.', '');
  else if (out.math.ok === false) F('sig_math_bad', 'high', 'İmza matematiği GEÇERSİZ', 'İmza değeri, sertifikanın açık anahtarıyla doğrulanamadı: imza sahte ya da bozulmuş.', 'Dosyaya güvenme.');
  else F('sig_math_na', 'info', 'İmza matematiği doğrulanamadı', out.math.why || 'Neden belirsiz', '');
  /* 3) zincir baglantilari (dosya icinde bulunanlar) */
  out.links = [];
  for (let i = 0; i + 1 < chain.length; i++) { const c = chain[i], up = chain[i + 1]; const r = up.keyAlg === 'RSA' ? await sigVerifyRsa(up.spki, SIG_HASH_OF(c.sigAlg), c.sigBits, c.tbs) : { ok: null, why: 'ECDSA' }; out.links.push({ from: c.subject.map.CN || c.subject.map.O || '?', to: up.subject.map.CN || up.subject.map.O || '?', ok: r.ok }); }
  if (out.links.some((l) => l.ok === false)) F('sig_chain_bad', 'high', 'Zincir bağlantısı doğrulanamadı', 'Bir sertifika, bir üstündeki sertifikanın anahtarıyla imzalanmamış görünüyor: zincir sahte ya da bozuk olabilir.', 'Dosyaya güvenme.');
  else if (chain.length > 1 && out.links.every((l) => l.ok === true)) F('sig_chain_ok', 'ok', 'Dosyadaki sertifika zinciri kendi içinde tutarlı', 'Dosyadaki ' + chain.length + ' sertifikanın her biri bir üstündekinin anahtarıyla imzalanmış. Kök sertifikanın Windows’ta güvenilir olup olmadığı BU ARAÇTA denetlenmez.', '');
  if (!out.rootInFile && !leaf.self) F('sig_root_absent', 'info', 'Kök sertifika dosyada yok', 'Bu normaldir: Windows kök sertifikayı kendi deposundan bulur. Bu araç o depoya erişmediği için kökün güvenilir olup olmadığını söyleyemez.', 'Windows’ta Özellikler → Dijital İmzalar → Ayrıntılar ile doğrula.');
  /* 4) zaman damgasi + sureler */
  out.ts = sg && sg.ts ? { day: sigDay(sg.ts.ms), kind: sg.ts.kind } : null; const signTime = sg && sg.signingTime != null ? sg.signingTime : null; if (signTime != null) out.signingTime = sigDay(signTime);
  const at = out.ts ? sg.ts.ms : null;
  if (leaf.to != null && leaf.to < now) {
    if (at != null && at >= (leaf.from || 0) && at <= leaf.to) F('sig_expired_ts', 'info', 'Sertifikanın süresi dolmuş ama imza zaman damgalı', 'İmza, sertifika geçerliyken atılmış (zaman damgası ' + sigDay(at) + '). Windows bunu kabul eder.', '');
    else F('sig_expired', at != null ? 'high' : 'med', 'İmzalayan sertifikanın süresi dolmuş (' + sigDay(leaf.to) + ')', at != null ? 'Zaman damgası sertifika geçerlilik aralığının dışında.' : 'Zaman damgası olmadığı için imza, bugünün tarihiyle geçersiz sayılır.', 'Yayıncının güncel imzalı sürümünü kullan.');
  }
  if (leaf.from != null && leaf.from > now) F('sig_notyet', 'high', 'Sertifika henüz geçerli değil (' + sigDay(leaf.from) + ')', 'Sertifikanın başlangıç tarihi gelecekte: saat/tarih hilesi ya da sahte sertifika olabilir.', 'Dosyaya güvenme.');
  if (at != null && leaf.from != null && at < leaf.from - 86400e3) F('sig_ts_before', 'high', 'Zaman damgası sertifikadan ÖNCE', 'İmza, sertifika üretilmeden önceki bir tarihle damgalanmış: tutarsız.', 'Dosyaya güvenme.');
  if (!out.ts) F('sig_nots', 'low', 'Zaman damgası yok', 'Zaman damgalı olmayan imza, sertifika süresi dolunca (ya da iptal edilince) geçersiz olur. Güvenilir yayıncılar genelde zaman damgası kullanır.', '');
  /* 5) algoritma/anahtar/amac */
  if (/^(?:MD2|MD5|SHA1)/.test(leaf.sigAlg) || sg && (sg.digestOid === '1.3.14.3.2.26' || sg.digestOid === '1.2.840.113549.2.5')) F('sig_weak_hash', 'med', 'Zayıf özet algoritması (SHA-1/MD5)', 'SHA-1 ve MD5 ile imzalar artık güvenli sayılmaz; yeni imzalı yazılımlarda görülmemeli. Eski (2016 öncesi) dosyalarda normaldir.', '');
  if (leaf.keyAlg === 'RSA' && leaf.keyBits && leaf.keyBits < 2048) F('sig_weak_key', 'med', 'Kısa RSA anahtarı (' + leaf.keyBits + ' bit)', '2048 bitin altındaki anahtarlar kırılabilir sayılır.', '');
  if (!leaf.codeSign) F('sig_eku', 'high', 'Sertifika kod imzalama amaçlı değil', 'Sertifikanın kullanım amacı (EKU) kod imzalamayı içermiyor; başka bir amaç için alınmış sertifikayla imzalanmış.', 'Dosyaya güvenme.');
  if (leaf.ca) F('sig_ca_leaf', 'high', 'İmzalayan bir sertifika otoritesi (CA) sertifikası', 'Normalde kod imzalayan sertifika CA olmaz; CA sertifikasıyla doğrudan imzalama olağan dışı.', 'Dosyaya güvenme.');
  if (leaf.self) F('sig_self', 'med', 'Kendinden imzalı sertifika', 'Sertifikayı veren ile sahibi aynı: herkes kendi adına böyle bir sertifika üretebilir; kimliği hiçbir otorite onaylamamış.', 'Yayıncıya başka yoldan güven.');
  if (/\b(?:test|testing|do[_ ]not[_ ]trust|dummy|sample|demo|localhost|untrusted)\b/i.test((leaf.subject.map.CN || '') + ' ' + (leaf.subject.map.O || ''))) F('sig_test', 'med', 'Test/deneme sertifikası gibi görünüyor', 'Sertifika adında test/deneme ifadesi var: geliştirme imzası canlıda kullanılıyor ya da sahte olabilir.', '');
  /* 6) yayinci taklidi */
  const nm = leaf.subject.map.O || leaf.subject.map.CN || ''; const bm = sigBrandMatch(nm); out.brand = bm;
  const cf = typeof confusableName === 'function' ? confusableName(nm) : { invisible: [], mixed: [] };
  if (cf.mixed.length || cf.invisible.length) F('sig_pub_script', 'high', 'Yayıncı adında karışık alfabe / görünmez karakter', 'İmzalayan adı farklı alfabelerden karakter karıştırıyor ya da görünmez karakter içeriyor: görsel taklit (homoglif) işareti. ' + cf.mixed.concat(cf.invisible).slice(0, 3).join(', '), 'Dosyaya güvenme.');
  if (bm.kind === 'homoglyph') F('sig_pub_fake', 'high', 'Yayıncı adı “' + bm.brand + '” adının görsel taklidi', 'İmzalayan “' + nm + '”, “' + bm.brand + '” ile harf benzerliği (0/o, 1/l, rn/m …) üzerinden karıştırılabiliyor.', 'Dosyaya güvenme; gerçek yayıncının sitesinden indir.');
  else if (bm.kind === 'typo') F('sig_pub_typo', 'high', 'Yayıncı adı “' + bm.brand + '” adına çok benziyor', 'İmzalayan “' + nm + '” ile “' + bm.brand + '” arasında 1-2 harflik fark var: yazım taklidi (typosquatting) olabilir.', 'Gerçek yayıncının sitesinden indir.');
  else if (bm.kind === 'contains') F('sig_pub_contains', 'low', 'Yayıncı adı “' + bm.brand + '” markasını içeriyor ama aynı değil', 'İmzalayan “' + nm + '”. Bu, bağlı bir kuruluş olabilir ya da marka adını yanlış kullanan biri.', 'İmzalayanın gerçekten ilgili şirket olduğunu doğrula.');
  else if (bm.kind === 'exact') {
    if (leaf.self) F('sig_pub_selfclaim', 'high', '“' + bm.brand + '” adını taşıyan KENDİNDEN İMZALI sertifika', 'Büyük yayıncıların sertifikaları bir otoriteden gelir; kendinden imzalı olmaları imza sahteciliğidir.', 'Dosyaya güvenme.');
    else if (bm.brand === 'Microsoft' && !/microsoft/i.test(leaf.issuer.str)) F('sig_pub_msissuer', 'med', '“Microsoft” adlı ama veren Microsoft değil', 'Windows dosyalarını imzalayan Microsoft sertifikaları Microsoft’un kendi otoritelerinden gelir. Üçüncü taraf otorite Microsoft adı taşıyan sertifika vermez (vermemelidir).', 'Dosyaya güvenme.');
    else F('sig_pub_known', 'info', 'Tanınan yayıncı adı: ' + bm.brand, 'İmzalayan adı bilinen bir markayla aynı. Kök otoriteye güven doğrulanmadığı için bu bir onay değildir.', '');
  }
  if (claim.kind === 'exact' || claim.kind === 'contains') { const cb = claim.brand; if (!sigNorm(nm).includes(sigNorm(cb))) F('sig_claim_mismatch', 'med', 'Dosya “' + cb + '” gibi görünüyor ama imzalayan farklı', 'Sürüm bilgisinde üretici “' + out.company + '”, imzalayan ise “' + nm + '”.', 'Dosyanın kaynağını doğrula.'); }
  /* 7) iptal */
  const urls = leaf.crl.concat(leaf.ocsp); if (urls.length) F('sig_revoc', 'info', 'İptal durumu SORGULANMADI', 'Bu araç ağa bağlanmaz. Sertifikanın iptal edilip edilmediğini şu adreslerden Windows ya da başka bir araçla kontrol edebilirsin: ' + urls.slice(0, 3).join(' · '), 'Windows imza penceresi iptali kendisi denetler.');
  else F('sig_revoc', 'info', 'İptal durumu denetlenmedi', 'Sertifikada iptal adresi (CRL/OCSP) yok ya da okunamadı; bu araç zaten ağa bağlanmaz.', '');
  const sev = { high: 3, med: 2, low: 1, info: 0, ok: 0 }; const top = out.findings.reduce((m, f) => Math.max(m, sev[f.sev] || 0), 0);
  out.verdict = top >= 3 ? { level: 'bad', text: 'Ciddi sorun var.' } : top === 2 ? { level: 'warn', text: 'Dikkat edilmesi gereken noktalar var.' } : { level: 'ok', text: 'Dosya içi denetimlerde sorun görülmedi (güven zinciri ve iptal doğrulanmadı).' };
  return out;
}
/* ---- Paketleyici / Obfuscation Dedektoru ---- */
const PK_STD_SEC = /^(?:\.text|\.data|\.rdata|\.rsrc|\.reloc|\.idata|\.edata|\.pdata|\.xdata|\.bss|\.tls|\.crt|\.didat|\.gfids|\.giats|\.00cfg|\.debug|\.textbss|\.code|\.sdata|\.itext|\.bindat|\.ndata|CODE|DATA|BSS|\.init|\.fini|_RDATA|\.CRT|\.orpc)$/i;
const PK_SIGS = [
  { id: 'upx', name: 'UPX', cat: 'packer', needles: ['UPX!'], hint: 'UPX geri açılabilir: dosyanın KOPYASINDA `upx -d` ile (çalıştırmadan) aç, sonra yeniden tara.' },
  { id: 'mpress', name: 'MPRESS', cat: 'packer', needles: ['MPRESS1', 'MPRESS2'], hint: 'Özel açıcılar var; en güvenlisi izole bir sanal makinede dinamik açmak.' },
  { id: 'aspack', name: 'ASPack', cat: 'packer', needles: ['ASPack', 'ASPACK'], hint: 'Bilinen açıcılar var; bellekte açılmış hali dökülerek incelenir.' },
  { id: 'pecompact', name: 'PECompact', cat: 'packer', needles: ['PECompact2', 'PEC2TO', 'PEC2MO'], hint: 'Bellekte açılmış hali dökülerek incelenir.' },
  { id: 'petite', name: 'Petite', cat: 'packer', needles: ['.petite'], hint: '' },
  { id: 'nspack', name: 'NsPack', cat: 'packer', needles: ['.nsp0', '.nsp1', '.nsp2'], hint: '' },
  { id: 'themida', name: 'Themida / WinLicense', cat: 'protector', needles: ['Themida', 'WinLicense', 'SecureEngine'], hint: 'Sanallaştırma koruyucusu: genel bir otomatik açıcı yok; dinamik analiz ve uzman araçlar gerekir.' },
  { id: 'vmprotect', name: 'VMProtect', cat: 'protector', needles: ['VMProtect', '.vmp0', '.vmp1'], hint: 'Kodu sanal makineye çevirir; genel bir açıcı yok.' },
  { id: 'enigma', name: 'Enigma Protector', cat: 'protector', needles: ['Enigma protector', 'The Enigma Protector', 'ENIGMA'], hint: 'Bilinen açıcı betikleri var; yine de dinamik analiz önerilir.' },
  { id: 'obsidium', name: 'Obsidium', cat: 'protector', needles: ['Obsidium'], hint: '' },
  { id: 'armadillo', name: 'Armadillo', cat: 'protector', needles: ['Silicon Realms', 'ARMADILLO'], hint: '' },
  { id: 'asprotect', name: 'ASProtect', cat: 'protector', needles: ['ASProtect'], hint: '' },
  { id: 'confuserex', name: 'ConfuserEx', cat: 'dotnet', needles: ['ConfuserEx', 'Confused by', 'ConfusedByAttribute'], hint: 'de4dot / ConfuserEx açıcılarıyla kısmen geri alınır (çalıştırmadan).' },
  { id: 'eazfuscator', name: 'Eazfuscator.NET', cat: 'dotnet', needles: ['Eazfuscator'], hint: 'de4dot ile kısmen geri alınır.' },
  { id: 'reactor', name: '.NET Reactor', cat: 'dotnet', needles: ['.NET Reactor', 'NETReactor', 'Eziriz'], hint: 'NETReactorSlayer / de4dot varyantları vardır.' },
  { id: 'smartassembly', name: 'SmartAssembly', cat: 'dotnet', needles: ['SmartAssembly', 'PoweredByAttribute'], hint: 'de4dot desteği vardır.' },
  { id: 'dotfuscator', name: 'Dotfuscator', cat: 'dotnet', needles: ['DotfuscatorAttribute', 'Dotfuscator'], hint: '' },
  { id: 'agile', name: 'Agile.NET / CliSecure', cat: 'dotnet', needles: ['CliSecure', 'Agile.NET', 'SecureTeam'], hint: '' },
  { id: 'babel', name: 'Babel Obfuscator', cat: 'dotnet', needles: ['BabelObfuscatorAttribute', 'Babel Obfuscator'], hint: '' },
  { id: 'ilprotector', name: 'ILProtector', cat: 'dotnet', needles: ['ILProtector'], hint: '' },
  { id: 'dnguard', name: 'DNGuard', cat: 'dotnet', needles: ['DNGuard'], hint: '' },
  { id: 'cryptoobf', name: 'Crypto Obfuscator', cat: 'dotnet', needles: ['CryptoObfuscator', 'Crypto Obfuscator'], hint: '' },
  { id: 'pyarmor', name: 'PyArmor', cat: 'script', needles: ['pyarmor', 'PYARMOR', '__pyarmor__'], hint: 'Python betiğini şifreler; açmak için çalışma zamanı gerekir.' },
  { id: 'pyinstaller', name: 'PyInstaller', cat: 'bundle', needles: ['MEI\x0c\x0b\x0a\x0b\x0e'], hint: 'Python paketi: içindeki .pyc dosyaları çıkarılabilir (StatScan bunu zaten yapar).' },
  { id: 'nuitka', name: 'Nuitka', cat: 'bundle', needles: ['Nuitka', 'nuitka'], hint: 'Python’u C’ye derler; kaynak geri alınamaz, davranış analizi gerekir.' },
  { id: 'autoit', name: 'AutoIt (derlenmiş betik)', cat: 'bundle', needles: ['AU3!EA06', 'AU3!EA05', 'AutoIt v3'], hint: 'AutoIt betiği çıkarılabilir (Exe2Aut vb.). Zararlılar sık kullanır.' },
  { id: 'nsis', name: 'NSIS yükleyici', cat: 'installer', needles: ['Nullsoft Install System'], hint: 'Kurulum paketi; 7-Zip ile içi açılabilir.' },
  { id: 'inno', name: 'Inno Setup yükleyici', cat: 'installer', needles: ['Inno Setup Setup Data'], hint: 'Kurulum paketi; innoextract ile içi açılabilir.' }
];
const PK_CAT = { packer: 'Paketleyici (sıkıştırıcı)', protector: 'Koruyucu / sanallaştırıcı', dotnet: '.NET obfuscator', script: 'Betik koruyucu', bundle: 'Betik/uygulama paketi', installer: 'Kurulum paketi (zararsız olabilir)' };
const PK_JAR = [
  { name: 'Allatori', re: /ALLATORI|Allatori/ }, { name: 'Zelix KlassMaster (ZKM)', re: /ZKM|Zelix/ }, { name: 'Stringer', re: /Stringer|stringer/ }, { name: 'DashO', re: /DashO|PreEmptive/ }, { name: 'Skidfuscator', re: /Skidfuscator|skidfuscator/ },
  { name: 'Radon', re: /Radon obfuscator|radon\.obf/i }, { name: 'Paramorphism', re: /Paramorphism|paramorphism/ }, { name: 'superblaubeere27', re: /superblaubeere/i }, { name: 'BozarCrypt / Bozar', re: /Bozar/ }, { name: 'JNIC', re: /JNIC|jnic/ },
  { name: 'Caesium', re: /Caesium|caesium/ }, { name: 'Binscure', re: /Binscure/ }, { name: 'Branchlock', re: /Branchlock/i }, { name: 'ProGuard', re: /proguard|ProGuard/ }, { name: 'yGuard', re: /yGuard/ }, { name: 'Sandmark', re: /Sandmark/ }
];
function pkHay(u8) { const cap = 64e6; const td = new TextDecoder('latin1'); if (u8.length <= cap) return td.decode(u8); return td.decode(u8.subarray(0, cap / 2)) + '\n' + td.decode(u8.subarray(u8.length - cap / 2)); }
async function packAudit(u8, name, opts) {
  opts = opts || {}; const out = { name, kind: 'other', size: u8.length, evidence: [], sections: [], tools: [], notes: [], level: 'none', score: 0 };
  const add = (id, w, title, why, kind) => { out.evidence.push({ id, w, title, why, kind: kind || 'heuristic' }); out.score += w; };
  let p = null; if (u8.length > 64 && u8[0] === 0x4d && u8[1] === 0x5a) { try { p = parsePE(u8); } catch (e) { p = null; } }
  const isZip = u8.length > 4 && u8[0] === 0x50 && u8[1] === 0x4b && (u8[2] === 3 || u8[2] === 5);
  if (p) {
    out.kind = p.clr ? 'dotnet' : 'pe'; out.is64 = p.is64; out.overlay = p.overlay; out.importCount = [...p.imports.values()].reduce((a, v) => a + v.length, 0); out.entropy = +entropy(u8).toFixed(2);
    out.sections = p.sections.map((s) => ({ n: s.name, vsize: s.vsize, rsize: s.rsize, ent: +s.ent.toFixed(2), x: !!(s.ch & 0x20000000), w: !!(s.ch & 0x80000000), std: PK_STD_SEC.test(s.name), packer: (typeof PACKER_SEC !== 'undefined' ? PACKER_SEC.find(([re]) => re.test(s.name)) : null) }));
    const epSec = p.ep ? p.sections.find((s) => p.ep >= s.va && p.ep < s.va + Math.max(s.vsize, s.rsize)) : null; out.ep = epSec ? epSec.name : (p.ep ? '(bölüm dışı)' : '—'); out.epIndex = epSec ? p.sections.indexOf(epSec) : -1;
    const secSeen = new Set(); for (const s of out.sections) if (s.packer && !secSeen.has(s.packer[1])) { secSeen.add(s.packer[1]); add('sec_' + s.packer[1], 45, s.packer[1] + ' bölüm adı (' + out.sections.filter((x) => x.packer && x.packer[1] === s.packer[1]).map((x) => x.n).join(', ') + ')', 'Bölüm adı bu paketleyici/koruyucuya özgü.', 'fact'); }
    const hiX = out.sections.filter((s) => s.x && s.ent >= 7.2 && s.rsize > 4096); if (hiX.length) add('ent_x', 22, 'Yüksek entropili çalıştırılabilir bölüm', hiX.map((s) => s.n + ' (' + s.ent + ')').join(', ') + ' — kod sıkıştırılmış/şifrelenmiş gibi.');
    const hiAll = out.sections.filter((s) => !s.x && s.ent >= 7.4 && s.rsize > 65536); if (hiAll.length && !hiX.length) add('ent_d', 8, 'Yüksek entropili veri bölümü', hiAll.map((s) => s.n + ' (' + s.ent + ')').join(', ') + ' — gömülü sıkıştırılmış/şifreli veri (kaynak, kurulum verisi olabilir).');
    const rwx = out.sections.filter((s) => s.x && s.w); if (rwx.length) add('rwx', 10, 'Hem yazılabilir hem çalıştırılabilir bölüm', rwx.map((s) => s.n).join(', ') + ' — kendini açan kod bu izni ister.');
    const virt = out.sections.filter((s) => s.rsize < 512 && s.vsize > 0x10000); if (virt.length) add('virt', 16, 'Diskte boş, bellekte büyük bölüm', virt.map((s) => s.n + ' (' + Math.round(s.vsize / 1024) + ' KB sanal)').join(', ') + ' — paketleyici bellekte açılacağı alanı ayırmış.');
    if (!p.clr && p.sections.length) { if (!epSec && p.ep) add('ep_out', 14, 'Giriş noktası bölümlerin dışında', 'Program başlangıcı normal bölümlerin dışında.'); else if (epSec && out.epIndex === p.sections.length - 1 && p.sections.length > 2) add('ep_last', 12, 'Giriş noktası SON bölümde', 'Program son bölümde başlıyor (paketleyici kalıbı).'); else if (epSec && !/^(?:\.text|CODE|\.code|\.itext)$/i.test(epSec.name) && out.epIndex > 0) add('ep_odd', 8, 'Giriş noktası olağandışı bölümde (' + epSec.name + ')', 'Normalde .text/CODE gibi bir kod bölümünde olur.'); }
    const nstd = out.sections.filter((s) => !s.std && !s.packer); if (nstd.length >= 2 || (nstd.length && out.sections.length <= 4)) add('nonstd', 6, 'Standart olmayan bölüm adları', nstd.map((s) => s.n).join(', ') + ' — yalnızca ipucu (derleyiciye göre değişir).');
    const APIS = new Set(); for (const fns of p.imports.values()) for (const f of fns) APIS.add(f.toLowerCase());
    if (!p.clr && out.importCount > 0 && out.importCount <= 12 && APIS.has('getprocaddress') && (APIS.has('loadlibrarya') || APIS.has('loadlibraryw')) && u8.length > 30000) add('imp_stub', 20, 'Klasik paketleyici import kalıbı', 'Yalnızca ' + out.importCount + ' import ve LoadLibrary+GetProcAddress var: gerçek API\'ler çalışma anında çözülüyor olabilir.');
    else if (!p.clr && out.importCount > 0 && out.importCount <= 6 && u8.length > 30000) add('imp_few', 14, 'Çok az import', out.importCount + ' import: API\'ler gizlenmiş olabilir.');
    else if (!p.clr && out.importCount === 0 && !p.dll && u8.length > 20000) add('imp_none', 14, 'Import tablosu yok', 'Çalıştırılabilir dosya import tablosu taşımıyor.');
    if (out.overlay > 4096 && out.overlay / u8.length > 0.3) out.notes.push('Dosyanın %' + Math.round(100 * out.overlay / u8.length) + '’i bölümlerin dışında (overlay): yükleyici/kurulum paketi ya da gömülü veri olabilir.');
  } else if (isZip) {
    out.kind = 'zip';
    try {
      const ents = readZip(u8).filter((e) => !e.dir); const cls = ents.filter((e) => /\.class$/i.test(e.name)); out.classCount = cls.length; out.entryCount = ents.length;
      if (cls.length) {
        const simple = cls.map((e) => e.name.replace(/\.class$/i, '').split('/').pop().split('$')[0]); const short = simple.filter((s) => s.length <= 2).length; const conf = simple.filter((s) => /^[Il1O0_]{4,}$/.test(s)).length; const nonAscii = cls.filter((e) => /[^\x20-\x7e]/.test(e.name)).length;
        out.nameStats = { total: cls.length, shortPct: Math.round(100 * short / cls.length), confusablePct: Math.round(100 * conf / cls.length), nonAscii };
        if (cls.length >= 8 && short / cls.length >= 0.5) add('jar_short', 28, 'Sınıf adlarının çoğu 1-2 harf (%' + out.nameStats.shortPct + ')', 'ProGuard/Allatori gibi araçların ad karıştırma izi. Küçültülmüş (minified) meşru jar’larda da görülür.');
        if (conf >= 3) add('jar_conf', 30, 'I/l/1/O/0 karışımı sınıf adları (%' + out.nameStats.confusablePct + ')', 'Okunması bilerek zorlaştırılmış adlar (ör. IIIlIlIl).');
        if (nonAscii) add('jar_nonascii', 18, 'ASCII dışı / görünmez karakterli sınıf adları (' + nonAscii + ')', 'Ad karıştırmanın agresif türü; bazı araçlar sınıf/paket adlarında Unicode kullanır.');
        let scanned = 0, totalBytes = 0, notClass = 0, hi = 0; const hay = []; const tools = new Map();
        for (const e of cls.slice(0, 600)) { if (totalBytes > 24e6) break; let d; try { d = await readEntry(u8, e, 4e6); } catch (x) { continue; } scanned++; totalBytes += d.length; if (!(d[0] === 0xca && d[1] === 0xfe && d[2] === 0xba && d[3] === 0xbe)) { notClass++; continue; } if (d.length > 4000 && entropy(d) >= 7.2) hi++; if (hay.length < 80) hay.push(new TextDecoder('latin1').decode(d.subarray(0, 60000))); }
        const H = hay.join('\n'); for (const t of PK_JAR) if (t.re.test(H)) tools.set(t.name, 1);
        for (const e of ents) if (/^META-INF\/(?:MANIFEST\.MF)$/i.test(e.name)) { try { const mf = new TextDecoder('latin1').decode(await readEntry(u8, e, 2e5)); for (const t of PK_JAR) if (t.re.test(mf)) tools.set(t.name, 1); const ob = /^(?:Obfuscated-By|Protected-By):\s*(.+)$/im.exec(mf); if (ob) tools.set(ob[1].trim().slice(0, 40), 1); } catch (x) { /* yoksay */ } }
        out.jarScanned = scanned; if (notClass) add('jar_notclass', 38, scanned && notClass === scanned ? 'Hiçbir .class dosyası gerçek sınıf değil' : notClass + ' .class dosyası 0xCAFEBABE ile başlamıyor', '.class uzantılı ama bayt kodu olmayan (şifreli/sıkıştırılmış) dosyalar: özel sınıf yükleyicisiyle açılan paketleyici işareti.');
        if (hi >= 3) add('jar_ent', 20, hi + ' sınıfta yüksek entropi', 'Bayt kodunda normalde görülmeyen rastgelelik: şifreli dizeler/gövdeler olabilir.');
        for (const t of tools.keys()) { out.tools.push({ name: t, cat: 'java', evidence: 'dize/manifest ipucu' }); add('jar_' + t, 36, t + ' izi', 'Sınıf içeriğinde/manifestte bu araca özgü dize bulundu (ipucu; kesin kanıt değil).', 'fact'); }
      }
      const nested = ents.filter((e) => /\.(?:jar|exe|dll|bin|dat)$/i.test(e.name) && e.size > 20000); if (nested.length) out.notes.push('İçinde iç içe çalıştırılabilir/ikili dosya var: ' + nested.slice(0, 4).map((e) => e.name).join(', ') + '.');
    } catch (e) { out.notes.push('Arşiv ayrıştırılamadı: ' + String(e && e.message || e).slice(0, 80)); }
  }
  /* bilinen koruyucu/paketleyici dizeleri (PE, .NET ve genel ikili) */
  if (p || !isZip) {
    const hay = pkHay(u8); const seen = new Set();
    for (const sg of PK_SIGS) { const hit = sg.needles.find((nd) => hay.indexOf(nd) >= 0); if (!hit) continue; if (seen.has(sg.id)) continue; seen.add(sg.id); const secHit = p && out.sections.some((s) => s.packer && s.packer[1].toLowerCase().includes(sg.name.split(' ')[0].toLowerCase())); const strong = sg.id === 'upx' ? (hay.indexOf('UPX0') >= 0 || hay.indexOf('UPX1') >= 0) : true; out.tools.push({ id: sg.id, name: sg.name, cat: sg.cat, evidence: secHit ? 'bölüm adı + dize' : 'dize', hint: sg.hint }); if (sg.cat === 'installer') continue; if (!secHit) add('str_' + sg.id, strong ? 30 : 14, sg.name + ' izi (' + PK_CAT[sg.cat] + ')', 'Dosyada “' + hit.replace(/[\x00-\x1f]/g, '·') + '” dizesi bulundu' + (strong ? '' : ' (tek başına zayıf ipucu; belgeler/ürün adı olarak da geçebilir)') + '.', strong ? 'fact' : 'heuristic'); }
    for (const s of (p ? out.sections : [])) if (s.packer && !out.tools.some((t) => t.name.toLowerCase().includes(s.packer[1].toLowerCase().split(/[\/ ]/)[0]))) { const sg = PK_SIGS.find((x) => x.name.toLowerCase().includes(s.packer[1].toLowerCase().split(/[\/ ]/)[0])); out.tools.push({ id: sg && sg.id, name: s.packer[1], cat: sg ? sg.cat : 'packer', evidence: 'bölüm adı', hint: sg ? sg.hint : '' }); }
  }
  out.score = Math.min(100, out.score);
  const fact = out.evidence.some((e) => e.kind === 'fact' && e.w >= 30); out.level = out.score >= 45 && (fact || out.score >= 60) ? 'confirmed' : out.score >= 30 ? 'likely' : out.score >= 12 ? 'possible' : 'none';
  if (out.level === 'none' && out.tools.some((t) => t.cat === 'installer')) out.notes.push('Kurulum paketi algılandı; paket içindeki dosyaları ayrıca tara.');
  return out;
}
