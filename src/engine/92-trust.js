/* "Kendi dosyalarim": kullanicinin isaretledigi dosyalar (sha256 + ad ailesi), surum farki ve java muafiyeti politikasi.
 * Isaretli olmak bulgulari GIZLEMEZ; yalnizca "bu senin dosyan" bilgisini ve surumler arasi farki gosterir. */
function trustNameKey(name) {
  const b = baseName(name || '').toLowerCase(); const ext = extOf(b); const stem = b.replace(/\.[^.]*$/, '');
  const k = stem.replace(/\d+(?:[._+-][0-9a-z]+)*/g, '').replace(/[\s._+()\[\]-]+/g, ' ').trim(); return k + '.' + ext;
}
function trustFlatIds(res) {
  const m = new Map(); const walk = (r, d) => { if (d > 12) return; for (const f of r.findings || []) if (f.w > 0 && !m.has(f.id)) m.set(f.id, { id: f.id, title: f.title, sev: f.sev, w: f.w, where: r.name }); for (const c of r.children || []) walk(c, d + 1); }; walk(res, 0); return m;
}
function trustSnapshot(res, extra) {
  const ids = [...trustFlatIds(res).keys()]; return Object.assign({ sha256: res.sha256, name: baseName(res.name), key: trustNameKey(res.name), size: res.size, score: res.score, ids, addedAt: new Date().toISOString(), note: '', javaExempt: false }, extra || {});
}
const trustPub = (e) => ({ name: e.name, note: e.note || '', addedAt: e.addedAt, score: e.score, javaExempt: !!e.javaExempt, sha256: e.sha256 });
function trustEvaluate(res, policy) {
  const list = (policy && policy.trusted) || []; if (!list.length || !res || !res.sha256) return null;
  const exact = list.find((e) => e.sha256 && e.sha256 === res.sha256); if (exact) return { status: 'exact', entry: trustPub(exact) };
  const key = trustNameKey(res.name); if (key.length <= 4) return null; const nv = list.find((e) => e.key === key); if (!nv) return null;
  const cur = trustFlatIds(res); const had = new Set(nv.ids || []); const fresh = [...cur.values()].filter((c) => !had.has(c.id)); const gone = (nv.ids || []).filter((id) => !cur.has(id));
  const delta = res.score - (nv.score || 0);
  return { status: 'newversion', entry: trustPub(nv), newFindings: fresh.slice(0, 20), goneIds: gone.slice(0, 20), scoreBefore: nv.score || 0, scoreNow: res.score, delta, alert: fresh.length > 0 || delta >= 10 };
}
function javaAllowed(policy, ident) {
  const mode = (policy && policy.javaExempt) || 'all'; if (mode === 'all') return true; if (mode === 'off') return false;
  const list = (policy && policy.trusted) || []; const key = ident && ident.name ? trustNameKey(ident.name) : '';
  return list.some((e) => e.javaExempt && ((ident && e.sha256 && e.sha256 === ident.sha256) || (key.length > 4 && e.key === key)));
}
