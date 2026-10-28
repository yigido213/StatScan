/* Kovan Derleyici: .java kaynak cozumleyici (yalnizca METIN okur; hicbir sey calistirmaz/derlemez).
   Cikarir: package, ust duzey siniflar, public static void main bulunan sinif (ic ice siniflar dahil), GUI/konsol, olasi sorunlar. Regex tabanlidir: kesin derleme sonucu degil, on algilamadir. */
function jvStrip(src) { /* yorumlari, dizeleri, metin bloklarini ve karakter sabitlerini bosluga cevirir; konumlar korunur */
  const o = src.split(''); const n = src.length; let i = 0;
  const blank = (a, b) => { for (let k = a; k < b; k++) if (o[k] !== '\n') o[k] = ' '; };
  while (i < n) {
    const c = src[i], d = src[i + 1];
    if (c === '/' && d === '/') { let j = i; while (j < n && src[j] !== '\n') j++; blank(i, j); i = j; }
    else if (c === '/' && d === '*') { let j = src.indexOf('*/', i + 2); j = j < 0 ? n : j + 2; blank(i, j); i = j; }
    else if (c === '"' && src.startsWith('"""', i)) { let j = i + 3; while (j < n && !(src.startsWith('"""', j) && src[j - 1] !== '\\')) j++; j = Math.min(n, j + 3); blank(i, j); i = j; }
    else if (c === '"') { let j = i + 1; while (j < n && src[j] !== '"' && src[j] !== '\n') { if (src[j] === '\\') j++; j++; } j = Math.min(n, j + 1); blank(i, j); i = j; }
    else if (c === "'") { let j = i + 1; while (j < n && src[j] !== "'" && src[j] !== '\n') { if (src[j] === '\\') j++; j++; } j = Math.min(n, j + 1); blank(i, j); i = j; }
    else i++;
  }
  return o.join('');
}
function javaScan(text, fileName) {
  const base = String(fileName || '').replace(/^.*[\\/]/, ''); const stem = base.replace(/\.java$/i, ''); const t = jvStrip(String(text).replace(/\r\n?/g, '\n'));
  const res = { file: base, stem, package: '', classes: [], publicTypes: [], mains: [], gui: false, javafx: false, problems: [], notes: [] };
  const pk = /(?:^|\n)\s*package\s+([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*;/.exec(t); if (pk) res.package = pk[1].replace(/\s+/g, '');
  const re = /(?<![.\w$@])(class|interface|enum|record)\s+([A-Za-z_$][\w$]*)|([{}])|\bvoid\s+main\s*\(\s*(?:final\s+)?String\s*(?:\[\s*\]\s*[A-Za-z_$][\w$]*|\.\.\.\s*[A-Za-z_$][\w$]*|[A-Za-z_$][\w$]*\s*\[\s*\])\s*\)/g;
  const stack = []; let depth = 0, pending = null, m; const tops = new Set();
  while ((m = re.exec(t))) {
    if (m[1]) { pending = { name: m[2], kind: m[1], idx: m.index }; }
    else if (m[3] === '{') { depth++; if (pending) { stack.push({ name: pending.name, depth, top: stack.length === 0 }); if (stack.length === 1) { tops.add(pending.name); const head = t.slice(Math.max(0, t.lastIndexOf('\n', pending.idx - 1) + 1), pending.idx); if (/\bpublic\b/.test(head) || /\bpublic\b[^;{}]*$/.test(t.slice(Math.max(0, pending.idx - 120), pending.idx))) res.publicTypes.push(pending.name); } pending = null; } }
    else if (m[3] === '}') { if (stack.length && stack[stack.length - 1].depth === depth) stack.pop(); depth--; }
    else { /* main */
      const encl = stack.length ? stack[stack.length - 1] : null; if (!encl) continue;
      const segStart = Math.max(t.lastIndexOf(';', m.index), t.lastIndexOf('{', m.index), t.lastIndexOf('}', m.index)) + 1; const head = t.slice(segStart, m.index);
      const isStatic = /\bstatic\b/.test(head), isPublic = /\bpublic\b/.test(head);
      const chain = stack.map((x) => x.name); const binary = (res.package ? res.package + '.' : '') + chain.join('$');
      res.mains.push({ cls: chain[chain.length - 1], binary, top: chain[0], nested: chain.length > 1, ok: isStatic && isPublic, why: !isStatic ? 'main static değil' : !isPublic ? 'main public değil' : '' });
    }
  }
  res.classes = [...tops];
  for (const p of res.publicTypes) if (p !== stem) res.problems.push({ code: 'public-name', cls: p, msg: 'public tür "' + p + '" dosya adıyla ("' + stem + '.java") aynı olmalı; javac bu dosyayı reddeder.' });
  if (/\bimport\s+javafx\.|\bjavafx\.(application|scene|stage)\b/.test(t)) { res.javafx = true; res.problems.push({ code: 'javafx', msg: 'JavaFX algılandı: JDK içinde JavaFX yoktur; derleme başarısız olabilir ya da JavaFX SDK gerekir.' }); }
  if (/\b(javax\.swing|java\.awt|org\.eclipse\.swt)\b/.test(t) || res.javafx) res.gui = true;
  if (/\bvoid\s+main\s*\(\s*\)/.test(t) && !res.mains.some((x) => x.ok)) res.notes.push('Parametresiz main() (Java 21+ önizleme özelliği) desteklenmez; "public static void main(String[] args)" kullanın.');
  if (!res.mains.length && !/\bvoid\s+main\s*\(\s*\)/.test(t)) res.notes.push('Bu dosyada "public static void main(String[] args)" yok.');
  for (const x of res.mains) if (!x.ok) res.problems.push({ code: 'main', cls: x.cls, msg: x.cls + ': ' + x.why + ' (klasik başlatıcı public static void main ister).' });
  return res;
}
/* Birden cok dosya: ortak ozet. files: [{name, text}] */
function javaPlan(files) {
  const scans = files.map((f) => javaScan(f.text, f.name)); const out = { scans, candidates: [], problems: [], gui: false, mainDefault: null, multiPackage: false };
  for (const s of scans) { if (s.gui) out.gui = true; for (const p of s.problems) out.problems.push(Object.assign({ file: s.file }, p)); for (const x of s.mains) if (x.ok) out.candidates.push({ binary: x.binary, file: s.file, cls: x.cls, nested: x.nested }); }
  const seen = new Set(); for (const s of scans) for (const c of s.classes) { const k = (s.package ? s.package + '.' : '') + c; if (seen.has(k)) out.problems.push({ file: s.file, code: 'dup-class', msg: 'Aynı sınıf iki dosyada: ' + k }); seen.add(k); }
  out.candidates.sort((a, b) => (/^(.*\.)?Main$/.test(b.binary) - /^(.*\.)?Main$/.test(a.binary)) || (a.nested - b.nested));
  out.mainDefault = out.candidates[0] ? out.candidates[0].binary : null;
  if (!out.candidates.length) out.problems.push({ code: 'no-main', msg: 'Hiçbir dosyada çalıştırılabilir "public static void main(String[] args)" bulunamadı.' });
  const base = out.candidates[0] ? out.candidates[0].cls : (scans[0] ? scans[0].stem : 'app'); out.suggestName = (base.replace(/[^A-Za-z0-9_-]/g, '') || 'app').replace(/^[^A-Za-z]+/, '') || 'app';
  return out;
}
