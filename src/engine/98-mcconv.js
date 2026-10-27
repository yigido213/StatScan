/* Beta 0.0.1: Minecraft Java kaynak paketi (resource pack) surum donusturucu. Statik; dosyalar yalnizca okunur, cikti YENI bir zip'tir.
   Yapilanlar: pack.mcmeta format alanlari, vanilla doku yeniden adlandirmalari (96-mcdata.js: gercek vanilla dosyalarindan icerik/ad eslesmesiyle uretildi),
   model/font JSON icindeki doku basvurulari, 1.21.4+ icin yalnizca guvenli durumlarda models/item "overrides" -> items/ tanimi.
   YAPILMAYANLAR (raporda acikca yazilir): yeniden tasarlanan dokular (GUI sprite bolme vb.), shader/OptiFine/overlay icerigi, yeni surumde olmayan ozellikler. */
const MC_VERS = [['1.8.9', '1.6.1 – 1.8.9', 1], ['1.9', '1.9 – 1.10.2', 2], ['1.11', '1.11 – 1.12.2', 3], ['1.13', '1.13 – 1.14.4', 4], ['1.15', '1.15 – 1.16.1', 5], ['1.16.2', '1.16.2 – 1.16.5', 6], ['1.17', '1.17 – 1.17.1', 7], ['1.18', '1.18 – 1.18.2', 8], ['1.19', '1.19 – 1.19.2', 9], ['1.19.3', '1.19.3', 12], ['1.19.4', '1.19.4', 13], ['1.20', '1.20 – 1.20.1', 15], ['1.20.2', '1.20.2', 18], ['1.20.3', '1.20.3 – 1.20.4', 22], ['1.20.5', '1.20.5 – 1.20.6', 32], ['1.21', '1.21 – 1.21.1', 34], ['1.21.2', '1.21.2 – 1.21.3', 42], ['1.21.4', '1.21.4', 46], ['1.21.5', '1.21.5', 55], ['1.21.6', '1.21.6', 63], ['1.21.7', '1.21.7 – 1.21.8', 64], ['1.21.9', '1.21.9 – 1.21.10', 69], ['1.21.11', '1.21.11', 75], ['26.1', '26.1 – 26.1.2', 84], ['26.2', '26.2', 88], ['26.3', '26.3', 97]].map(([key, label, fmt]) => ({ key, label, fmt }));
const MC_FMT_NEW = 69; /* min_format/max_format donemi (1.21.9+) */
const mcVer = (k) => MC_VERS.find((v) => v.key === k) || null;
const MC_STEP_CACHE = {};
function mcParseLines(s) { const m = new Map(); if (s) for (const l of s.split('\n')) { const i = l.indexOf('>'); if (i > 0) m.set(l.slice(0, i), l.slice(i + 1)); } return m; }
function mcStep(i, level) {
  const k = MC_STEP_ORDER[i] + '>' + MC_STEP_ORDER[i + 1]; const key = k + '|' + level; if (MC_STEP_CACHE[key]) return MC_STEP_CACHE[key]; const d = MC_STEPS[k]; const fwd = new Map(), cls = new Map();
  for (const [c, str] of [['s', d.s], ['n', d.n], ['m', d.m]]) { if (level === 'strict' && c !== 's') continue; for (const [a, b] of mcParseLines(str)) { fwd.set(a, b); cls.set(a, c); } }
  const gone = new Set(d.g ? d.g.split('\n') : []); return (MC_STEP_CACHE[key] = { key: k, fwd, cls, gone, from: MC_STEP_ORDER[i], to: MC_STEP_ORDER[i + 1] });
}
function mcChain(srcKey, dstKey, level) {
  const i = MC_STEP_ORDER.indexOf(srcKey), j = MC_STEP_ORDER.indexOf(dstKey); if (i < 0 || j < 0) throw new Error('Bilinmeyen sürüm'); const steps = [];
  if (i < j) for (let k = i; k < j; k++) steps.push(Object.assign({ dir: 'up' }, mcStep(k, level)));
  else if (i > j) for (let k = i - 1; k >= j; k--) { const s = mcStep(k, level); const rev = new Map(); for (const [a, b] of s.fwd) rev.set(b, a); steps.push({ dir: 'down', key: s.key, fwd: rev, cls: s.cls, revCls: true, gone: new Set(), from: s.to, to: s.from, orig: s }); }
  return { dir: i < j ? 'up' : i > j ? 'down' : 'same', steps };
}
const MC_RANK = { s: 3, n: 2, m: 1 };
function mcMapRel(chain, rel) {
  let cur = rel, cls = null, gone = null;
  for (const st of chain.steps) {
    const nx = st.fwd.get(cur);
    if (nx !== undefined) { let c; if (st.revCls) c = st.orig.cls.get(nx); else c = st.cls.get(cur); if (!cls || MC_RANK[c] < MC_RANK[cls]) cls = c; cur = nx; }
    else if (st.gone.has(cur)) { gone = st.to; break; }
  }
  return { rel: cur, cls: cur === rel ? null : cls, gone };
}
/* ---- pack.mcmeta ---- */
function mcFmtMajor(v) { return Array.isArray(v) ? +v[0] : (typeof v === 'number' ? v : null); }
function mcReadMeta(meta) {
  const p = meta && meta.pack; if (!p || typeof p !== 'object') return { fmt: null, why: 'pack.mcmeta içinde "pack" nesnesi yok' };
  let fmt = null, how = '';
  if (typeof p.pack_format === 'number') { fmt = p.pack_format; how = 'pack_format'; }
  else if (p.min_format != null && mcFmtMajor(p.min_format) != null) { fmt = mcFmtMajor(p.min_format); how = 'min_format'; }
  else if (p.supported_formats != null) { const sf = p.supported_formats; fmt = typeof sf === 'number' ? sf : Array.isArray(sf) ? +sf[0] : (sf && typeof sf === 'object' ? sf.min_inclusive : null); how = 'supported_formats'; }
  if (typeof fmt !== 'number' || !isFinite(fmt)) return { fmt: null, why: 'pack_format okunamadı' };
  return { fmt, how, hasSupported: p.supported_formats != null, hasMinMax: p.min_format != null || p.max_format != null };
}
function mcGuessSource(fmt) { const exact = MC_VERS.filter((v) => v.fmt === fmt); if (exact.length) return { key: exact[0].key, exact: true }; const lower = MC_VERS.filter((v) => v.fmt < fmt); return { key: (lower.length ? lower[lower.length - 1] : MC_VERS[0]).key, exact: false }; }
function mcApplyMeta(meta, dst) {
  const m = JSON.parse(JSON.stringify(meta)); const p = m.pack; const notes = []; const before = JSON.stringify({ pack_format: p.pack_format, supported_formats: p.supported_formats, min_format: p.min_format, max_format: p.max_format });
  delete p.supported_formats; delete p.min_format; delete p.max_format;
  const ordered = {}; ordered.pack_format = dst.fmt; if (dst.fmt >= MC_FMT_NEW) { ordered.min_format = dst.fmt; ordered.max_format = dst.fmt; }
  for (const k of Object.keys(p)) if (!(k in ordered)) ordered[k] = p[k]; m.pack = ordered;
  if (JSON.stringify({ pack_format: p.pack_format, supported_formats: meta.pack.supported_formats, min_format: meta.pack.min_format, max_format: meta.pack.max_format }) !== JSON.stringify({ pack_format: ordered.pack_format, min_format: ordered.min_format, max_format: ordered.max_format })) notes.push('pack_format ' + (meta.pack.pack_format !== undefined ? meta.pack.pack_format : '—') + ' → ' + dst.fmt + (dst.fmt >= MC_FMT_NEW ? ' (+ min_format/max_format = ' + dst.fmt + ')' : ''));
  if (meta.pack.supported_formats !== undefined) notes.push('supported_formats kaldırıldı (hedef tek sürümdür)'); if (meta.pack.min_format !== undefined || meta.pack.max_format !== undefined) { if (dst.fmt < MC_FMT_NEW) notes.push('min_format/max_format kaldırıldı (bu alanlar 1.21.9 öncesinde bilinmez)'); }
  return { meta: m, notes, before };
}
/* ---- yol sinifi ---- */
const MC_TEX_PREFIX = 'assets/minecraft/textures/';
function mcClassify(name) {
  if (name.startsWith(MC_TEX_PREFIX)) { const r = name.slice(MC_TEX_PREFIX.length); if (r.endsWith('.png.mcmeta')) return { k: 'tex', rel: r.slice(0, -11), suf: '.png.mcmeta' }; if (r.endsWith('.png')) return { k: 'tex', rel: r.slice(0, -4), suf: '.png' }; return { k: 'other' }; }
  let m = /^assets\/([^/]+)\/models\/.+\.json$/.exec(name); if (m) return { k: 'model', ns: m[1] };
  if (/^assets\/minecraft\/font\/.+\.json$/.test(name)) return { k: 'font' };
  if (/^assets\/minecraft\/atlases\/.+\.json$/.test(name)) return { k: 'atlas' };
  if (/^assets\/minecraft\/optifine\//.test(name) || /^assets\/minecraft\/mcpatcher\//.test(name)) return { k: 'optifine' };
  if (/^assets\/minecraft\/shaders\//.test(name)) return { k: 'shader' };
  return { k: 'other' };
}
function mcRefMap(chain, ref) { /* ref: "blocks/dirt" veya "minecraft:blocks/dirt" (uzantisiz) -> yeni ref ya da null */
  if (typeof ref !== 'string' || ref.startsWith('#')) return null; let ns = 'minecraft', p = ref; const c = ref.indexOf(':'); if (c >= 0) { ns = ref.slice(0, c); p = ref.slice(c + 1); } if (ns !== 'minecraft') return null;
  const r = mcMapRel(chain, p); if (r.rel === p) return null; return (c >= 0 ? 'minecraft:' : '') + r.rel;
}
function mcRewriteModel(chain, obj) { let n = 0; const t = obj && obj.textures; if (t && typeof t === 'object') for (const k of Object.keys(t)) { const nv = mcRefMap(chain, t[k]); if (nv) { t[k] = nv; n++; } } return n; }
function mcRewriteFont(chain, obj) { let n = 0; const ps = obj && Array.isArray(obj.providers) ? obj.providers : []; for (const p of ps) if (p && typeof p.file === 'string' && /\.png$/.test(p.file)) { const nv = mcRefMap(chain, p.file.slice(0, -4)); if (nv) { p.file = nv + '.png'; n++; } } return n; }
function mcItemDefs(zipNames, files, dstKey, report) { /* models/item overrides -> items/ ; yalniz guvenli durumlar */ }

async function mcDetectPack(u8) {
  const zip = mzRead(u8); let root = ''; let mc = zip.entries.find((e) => e.name === 'pack.mcmeta');
  if (!mc) { const c = zip.entries.filter((e) => /^[^/]+\/pack\.mcmeta$/.test(e.name)); if (c.length === 1) { mc = c[0]; root = mc.name.slice(0, mc.name.indexOf('/') + 1); } }
  if (!mc) return { ok: false, reason: 'pack.mcmeta bulunamadı: bu bir Minecraft kaynak paketi (resource pack) değil.', zip };
  let meta; try { meta = JSON.parse(new TextDecoder('utf-8').decode(await mzData(zip, mc, 1e6)).replace(/^﻿/, '')); } catch (e) { return { ok: false, reason: 'pack.mcmeta okunamadı/geçersiz JSON: ' + String(e && e.message || e).slice(0, 80), zip }; }
  const info = mcReadMeta(meta); if (info.fmt == null) return { ok: false, reason: 'pack.mcmeta: ' + info.why, zip };
  const g = mcGuessSource(info.fmt); const desc = meta.pack && meta.pack.description; return { ok: true, zip, root, mc, meta, fmt: info.fmt, how: info.how, guess: g.key, exact: g.exact, description: typeof desc === 'string' ? desc : (desc ? JSON.stringify(desc).slice(0, 120) : ''), entries: zip.entries.length };
}
/* opts: { src, dst, level:'normal'|'strict', onProgress } */
async function mcConvertPack(u8, opts) {
  const level = opts.level === 'strict' ? 'strict' : 'normal'; const det = await mcDetectPack(u8); if (!det.ok) return { ok: false, reason: det.reason };
  const src = mcVer(opts.src || det.guess), dst = mcVer(opts.dst); if (!src || !dst) return { ok: false, reason: 'Kaynak/hedef sürüm geçersiz.' };
  const rep = { src: src.key, dst: dst.key, srcLabel: src.label, dstLabel: dst.label, srcFmt: src.fmt, dstFmt: dst.fmt, level, dir: null, renamed: [], renameCount: { s: 0, n: 0, m: 0 }, conflicts: [], gone: [], refs: [], refCount: 0, skipped: { dirs: 0, nested: !!det.root, backslash: 0 }, flags: { atlas: 0, optifine: 0, shader: 0, overlay: [] }, meta: [], items: { converted: [], skipped: [] }, warnings: [], errors: [], counts: { total: det.entries, copied: 0, changed: 0, dropped: 0 } };
  const chain = mcChain(src.key, dst.key, level); rep.dir = chain.dir; const zip = det.zip; const entries = zip.entries; const prog = opts.onProgress || (() => {});
  if (chain.dir === 'down') rep.warnings.push('Eski sürüme dönüştürme: yeni sürümde eklenen özellikler/dokular eski sürümde yoktur; yalnızca geri yönlü yeniden adlandırmalar ve pack.mcmeta uygulanır. Kayıpsız bir dönüşüm değildir.');
  if (src.fmt === dst.fmt && chain.dir === 'same') rep.warnings.push('Kaynak ve hedef aynı pack_format; yalnızca pack.mcmeta normalleştirildi.');
  if (!det.exact) rep.warnings.push('pack_format ' + det.fmt + ' bilinen sürüm tablosunda yok; kaynak olarak "' + src.label + '" varsayıldı. Doğru değilse kaynak sürümü elle seçin.');
  const pre = det.root; const norm = (n) => { let x = n.replace(/\\/g, '/'); if (x !== n) rep.skipped.backslash++; if (pre) { if (!x.startsWith(pre)) return null; x = x.slice(pre.length); } return x; };
  const entryList = []; const names = new Set();
  for (const e of entries) { if (e.isDir) { rep.skipped.dirs++; continue; } const nn = norm(e.name); if (nn === null) { rep.counts.dropped++; rep.warnings.push('Kök klasör dışında kalan girdi atıldı: ' + e.name); continue; } if (nn.split('/').some((s) => s === '..') || nn.startsWith('/')) { rep.counts.dropped++; rep.warnings.push('Güvensiz yol atıldı: ' + e.name); continue; } entryList.push({ e, orig: nn, out: nn, data: null, cls: mcClassify(nn) }); names.add(nn); }
  if (pre) rep.warnings.push('Paket "' + pre + '" klasörünün içindeydi; Minecraft bunu tanımaz. Çıktıda içerik kök dizine alındı.');
  if (rep.skipped.backslash) rep.warnings.push(rep.skipped.backslash + ' girdinin yol ayırıcısı "\\" idi; "/" olarak düzeltildi.');
  // overlay'ler
  const meta0 = det.meta; if (meta0.overlays && Array.isArray(meta0.overlays.entries)) for (const o of meta0.overlays.entries) if (o && typeof o.directory === 'string') { const n = entryList.filter((x) => x.orig.startsWith(o.directory + '/')).length; rep.flags.overlay.push(o.directory + ' (' + n + ' dosya)'); }
  if (rep.flags.overlay.length) rep.warnings.push('Overlay klasörleri dönüştürülmedi (içerikleri olduğu gibi kopyalandı): ' + rep.flags.overlay.join(', ') + '. Overlay\'lerin kendi min/max_format aralıkları hedef sürümü kapsamıyorsa elle güncelleyin.');
  // 1) doku yeniden adlandirma
  const finalSet = new Set(entryList.map((x) => x.out)); const moved = new Map(); let i = 0;
  if (chain.dir !== 'same') for (const x of entryList) {
    if (x.cls.k === 'tex') {
      const r = mcMapRel(chain, x.cls.rel);
      if (r.gone && !opts.noGone) rep.gone.push({ path: x.orig, stepTo: r.gone });
      if (r.rel !== x.cls.rel) { const nn = MC_TEX_PREFIX + r.rel + x.cls.suf; if (finalSet.has(nn) || moved.has(nn)) { rep.conflicts.push({ from: x.orig, to: nn, why: 'hedef yolda zaten bir dosya var; atlandı' }); continue; } moved.set(nn, x); finalSet.delete(x.out); finalSet.add(nn); x.out = nn; x.renamed = r.cls; if (x.cls.suf === '.png') rep.renameCount[r.cls]++; rep.renamed.push({ from: x.orig, to: nn, cls: r.cls }); }
    } else if (x.cls.k === 'atlas') rep.flags.atlas++; else if (x.cls.k === 'optifine') rep.flags.optifine++; else if (x.cls.k === 'shader') rep.flags.shader++;
    if (++i % 400 === 0) { prog(i / entryList.length * 0.4); await new Promise((r) => setTimeout(r, 0)); }
  }
  // 2) JSON basvuru yazimi (model, font)
  if (chain.dir !== 'same') { let k = 0; for (const x of entryList) { if (x.cls.k !== 'model' && x.cls.k !== 'font') continue; if (x.e.usize > 4e6) { rep.warnings.push('Büyük JSON atlandı (başvurular denetlenmedi): ' + x.orig); continue; } let obj; try { obj = JSON.parse(new TextDecoder('utf-8').decode(await mzData(zip, x.e, 4e6)).replace(/^﻿/, '')); } catch (er) { rep.warnings.push('JSON okunamadı, başvurular güncellenmedi: ' + x.orig); continue; } const n = x.cls.k === 'model' ? mcRewriteModel(chain, obj) : mcRewriteFont(chain, obj); if (n) { x.data = new TextEncoder().encode(JSON.stringify(obj, null, 2)); rep.refCount += n; rep.refs.push({ file: x.orig, n }); } if (++k % 100 === 0) { prog(0.4 + 0.2 * (k / entryList.length)); await new Promise((r) => setTimeout(r, 0)); } } }
  // 3) 1.21.4+ item tanimlari
  const newFiles = [];
  if (chain.dir === 'up' && src.fmt < 46 && dst.fmt >= 46) {
    const ik = MC_ITEMS_COMPLEX[dst.key] !== undefined ? dst.key : null; const complex = new Set((ik ? MC_ITEMS_COMPLEX[ik] : '').split(' ').filter(Boolean));
    for (const x of entryList) { const m = /^assets\/([^/]+)\/models\/item\/([^/]+)\.json$/.exec(x.orig); if (!m) continue; let obj; try { obj = JSON.parse(new TextDecoder('utf-8').decode(x.data || await mzData(zip, x.e, 4e6)).replace(/^﻿/, '')); } catch (er) { continue; } if (!Array.isArray(obj.overrides) || !obj.overrides.length) continue;
      const ns = m[1], nm = m[2]; const skip = (why) => rep.items.skipped.push({ item: ns + ':' + nm, why });
      if (ns !== 'minecraft') { skip('özel ad alanı (yalnızca minecraft: dönüştürülür)'); continue; } if (complex.has(nm)) { skip('vanilla tanımı karmaşık (renk/özel mantık içeriyor); elle yazılmalı'); continue; }
      const target = 'assets/minecraft/items/' + nm + '.json'; if (finalSet.has(target)) { skip('items/' + nm + '.json zaten pakette var'); continue; }
      const ents = []; let bad = null; for (const o of obj.overrides) { const keys = o && o.predicate ? Object.keys(o.predicate) : []; if (!o || typeof o.model !== 'string' || keys.length !== 1 || keys[0] !== 'custom_model_data' || typeof o.predicate.custom_model_data !== 'number') { bad = 'yalnızca custom_model_data koşulu desteklenir (' + (keys.join(',') || 'koşul yok') + ')'; break; } ents.push([o.predicate.custom_model_data, o.model]); }
      if (bad) { skip(bad); continue; } let sorted = true; for (let q = 1; q < ents.length; q++) if (ents[q][0] < ents[q - 1][0]) sorted = false; if (!sorted) { skip('override sırası eşik değerine göre artan değil (anlam değişirdi)'); continue; }
      const byT = new Map(); for (const [t, mo] of ents) byT.set(t, mo); const mid = (s) => { const mm = mcRefMap(chain, s.replace(/^minecraft:/, '')); return /^[a-z0-9_.-]+:/.test(s) ? s : 'minecraft:' + s; };
      const def = { model: { type: 'minecraft:range_dispatch', property: 'minecraft:custom_model_data', fallback: { type: 'minecraft:model', model: 'minecraft:item/' + nm }, entries: [...byT.entries()].sort((a, b) => a[0] - b[0]).map(([t, mo]) => ({ threshold: t, model: { type: 'minecraft:model', model: mid(mo) } })) } };
      newFiles.push({ name: target, data: new TextEncoder().encode(JSON.stringify(def, null, 2)) }); finalSet.add(target); rep.items.converted.push(ns + ':' + nm + ' (' + byT.size + ' model)'); }
    if (!ik) rep.warnings.push('Hedef sürüm için item tanım verisi yok; models/item "overrides" dönüştürülmedi.');
    else if (rep.items.skipped.length || rep.items.converted.length) rep.warnings.push('1.21.4 ile "models/item" içindeki overrides artık kullanılmaz; yalnızca aşağıda "dönüştürüldü" denen öğeler için items/ tanımı üretildi, diğerleri elle yazılmalıdır.');
  } else if (chain.dir === 'down' && src.fmt >= 46 && dst.fmt < 46 && entryList.some((x) => /^assets\/[^/]+\/items\/[^/]+\.json$/.test(x.orig))) rep.warnings.push('Pakette items/ (öğe tanımı) dosyaları var; 1.21.4 öncesinde bu klasör yoktur ve yok sayılır. custom_model_data için models/item "overrides" elle yazılmalıdır.');
  // 4) pack.mcmeta
  const am = mcApplyMeta(det.meta, dst); rep.meta = am.notes; const metaBytes = new TextEncoder().encode(JSON.stringify(am.meta, null, 2));
  // 5) yaz
  prog(0.7); const items = []; let ch = 0;
  for (const x of entryList) {
    if (x.orig === 'pack.mcmeta') { items.push({ name: 'pack.mcmeta', data: metaBytes }); rep.counts.changed++; continue; }
    if (x.data) { items.push({ name: x.out, data: x.data, time: x.e.time, date: x.e.date }); rep.counts.changed++; }
    else if (x.out !== x.e.name && x.out !== x.orig || pre || x.orig !== x.e.name) { items.push({ name: x.out, copy: { zip, entry: x.e }, time: x.e.time, date: x.e.date }); if (x.out !== x.orig) rep.counts.changed++; else rep.counts.copied++; }
    else { items.push({ name: x.out, nameBytes: x.e.nameBytes, utf8: x.e.utf8, copy: { zip, entry: x.e }, time: x.e.time, date: x.e.date }); rep.counts.copied++; }
  }
  for (const f of newFiles) { items.push(f); rep.counts.changed++; }
  const seen = new Set(); for (const it of items) { if (seen.has(it.name)) return { ok: false, reason: 'İç hata: çıktıda yinelenen yol (' + it.name + '); dönüştürme iptal edildi, dosya değiştirilmedi.' }; seen.add(it.name); }
  const out = await mzWrite(items); prog(1);
  const stats = { files: items.length };
  return { ok: true, out, report: rep, stats, name: (opts.name || 'pack.zip').replace(/\.zip$/i, '') + '-' + dst.key + '.zip' };
}
function mcReportText(r, srcName) {
  const L = []; const cl = { s: 'kanıtlı (içerik eşleşmesi)', n: 'ad kuralı', m: 'ad eşleşmesi' };
  L.push('# Kaynak paketi dönüştürme raporu', '', 'Dosya: ' + srcName, 'Yön: ' + r.srcLabel + ' (pack_format ' + r.srcFmt + ') → ' + r.dstLabel + ' (pack_format ' + r.dstFmt + ') · ' + (r.dir === 'up' ? 'yeni sürüme' : r.dir === 'down' ? 'eski sürüme' : 'aynı biçim') + ' · eşleştirme: ' + (r.level === 'strict' ? 'yalnızca kanıtlı' : 'kanıtlı + ad kuralları'), '');
  L.push('## Özet', '- Girdi: ' + r.counts.total + ' · değişmeden kopyalanan: ' + r.counts.copied + ' · değişen/yeniden adlandırılan/eklenen: ' + r.counts.changed + ' · atılan: ' + r.counts.dropped + (r.skipped.dirs ? ' · klasör girdisi (gereksiz) atıldı: ' + r.skipped.dirs : ''), '- Yeniden adlandırılan doku: ' + r.renamed.filter((x) => !/\.mcmeta$/.test(x.to)).length + ' (kanıtlı ' + r.renameCount.s + ', ad kuralı ' + r.renameCount.n + ', ad eşleşmesi ' + r.renameCount.m + ')', '- Model/font içinde güncellenen doku başvurusu: ' + r.refCount + (r.refs.length ? ' (' + r.refs.length + ' dosya)' : ''), '');
  L.push('## pack.mcmeta', ...(r.meta.length ? r.meta.map((x) => '- ' + x) : ['- Değişiklik gerekmedi.']), '');
  if (r.renamed.length) { L.push('## Yeniden adlandırmalar (' + r.renamed.length + ')'); for (const x of r.renamed.slice(0, 400)) L.push('- `' + x.from.replace(MC_TEX_PREFIX, '') + '` → `' + x.to.replace(MC_TEX_PREFIX, '') + '` — ' + cl[x.cls]); if (r.renamed.length > 400) L.push('- … ve ' + (r.renamed.length - 400) + ' tane daha'); L.push(''); }
  if (r.conflicts.length) { L.push('## Çakışmalar (atlandı)'); for (const c of r.conflicts) L.push('- `' + c.from + '` → `' + c.to + '`: ' + c.why); L.push(''); }
  if (r.gone.length) { L.push('## Hedef sürümde vanilla karşılığı olmayan veya yeniden tasarlanan dokular (' + r.gone.length + ')', 'Bu dosyalar paketten SİLİNMEDİ ve dönüştürülemedi; hedef sürümde büyük olasılıkla kullanılmaz ya da yapısı değişti (ör. GUI dokularının sprite\'lara bölünmesi). Elle uyarlanması gerekir.'); for (const g of r.gone.slice(0, 300)) L.push('- `' + g.path.replace(MC_TEX_PREFIX, '') + '` (' + g.stepTo + ' sürümünde yok)'); if (r.gone.length > 300) L.push('- … ve ' + (r.gone.length - 300) + ' tane daha'); L.push(''); }
  if (r.items.converted.length || r.items.skipped.length) { L.push('## 1.21.4 öğe tanımları (items/)'); for (const c of r.items.converted) L.push('- dönüştürüldü: ' + c); for (const s of r.items.skipped) L.push('- atlandı: ' + s.item + ' — ' + s.why); L.push(''); }
  const fl = []; if (r.flags.atlas) fl.push(r.flags.atlas + ' atlas JSON dosyası (kontrol edilmedi)'); if (r.flags.optifine) fl.push(r.flags.optifine + ' OptiFine/MCPatcher dosyası (dönüştürülmedi)'); if (r.flags.shader) fl.push(r.flags.shader + ' shader dosyası (dönüştürülmedi)'); if (fl.length) L.push('## Kapsam dışı bırakılanlar', ...fl.map((x) => '- ' + x), '');
  if (r.warnings.length) L.push('## Uyarılar', ...r.warnings.map((x) => '- ' + x), '');
  L.push('## Sınırlar', '- Dokuların YENİ SÜRÜMDE yeniden çizilmiş/bölünmüş olması durumu otomatik çözülmez; yalnızca dosya adı/yolu eşleşenler taşınır.', '- Eşleştirme tablosu gerçek vanilla dosyalarının sürümler arası karşılaştırmasından üretildi; kanıtlı sınıf içerik özetinin birebir aynı olduğu durumdur.', '- pack.mcmeta biçimi (1.21.9+ min_format/max_format) yayımlanmış kaynaklara göre yazıldı; gerçek oyunda sürüm uyarısı çıkarsa pack.mcmeta\'yı elle ayarlayın.', '- Orijinal dosya değiştirilmedi.');
  return L.join('\n');
}
