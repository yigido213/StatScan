/* ---------- v3.6: otomatik obfuscation analizi + (kaynak kodu icin) guvenli statik deobfuscation + yapi dokumu ----------
   TUM ISLEMLER STATIKTIR: dosya hicbir zaman calistirilmaz, eval/Function kullanilmaz, ag baglantisi kurulmaz.
   Deobfuscation yalnizca metin donusumleridir (kacis cozme, sabit katlama, base64/zlib katmani acma, Dean Edwards p,a,c,k,e,d acici).
   YAPILMAYANLAR: kod calistirmayi gerektiren cozumler (obfuscator.io dize dizisi + dondurme, RC4/AES dize sifreleri, sanallastirma, kontrol akisi duzlestirme),
   gercek decompile (yalniz yerlesik yapi dokumu; gercek decompile icin harici arac gerekir ve masaustu kabugunda onayla calisir). */
const OBF_LIM = { srcMax: 24e6, binMax: 200e6, layers: 4, outMax: 40e6, entries: 400, entryCap: 8e6, jarBudget: 160e6 };
const obfTick = () => new Promise((r) => setTimeout(r, 0));
const OBF_TOOLS = { dotnet: ['ilspycmd'], jar: ['cfr', 'procyon', 'jadx'], 'java-class': ['cfr', 'procyon'], apk: ['jadx'], pe: ['ida', 'ghidra'], elf: ['ida', 'ghidra'], macho: ['ida', 'ghidra'] };
function obfCheck(ctx) { if (ctx.signal && ctx.signal.aborted) { const e = new Error('iptal'); e.cancelled = true; throw e; } }
const obfStep = (ctx, id, label, status, note) => { const s = { id, label, status, note: note || '' }; ctx.steps.push(s); return s; };
const obfProg = (ctx, pct, label) => { try { if (ctx.onProgress) ctx.onProgress(Math.max(0, Math.min(100, Math.round(pct))), label); } catch (e) {} };
function noisyOr(list) { let p = 1; for (const c of list) p *= 1 - Math.min(97, c) / 100; return Math.round((1 - p) * 100); }
const lvl = (c) => (c >= 70 ? 'yüksek' : c >= 40 ? 'orta' : 'düşük');

/* ----- tur tespiti ----- */
const OBF_TEXT_EXT = { js: 'js', mjs: 'js', cjs: 'js', jse: 'js', ps1: 'ps', psm1: 'ps', psd1: 'ps', vbs: 'vbs', vbe: 'vbs', vba: 'vbs', bas: 'vbs', bat: 'bat', cmd: 'bat', py: 'py', pyw: 'py', sh: 'sh' };
const OBF_LABEL = { js: 'JavaScript', ps: 'PowerShell', vbs: 'VBScript/VBA', bat: 'Toplu iş (batch)', py: 'Python', sh: 'Kabuk betiği', dotnet: '.NET assembly', pe: 'Yerel PE (EXE/DLL)', 'java-class': 'Java .class', jar: 'Java arşivi (JAR/WAR)', apk: 'Android APK', elf: 'ELF', macho: 'Mach-O', asar: 'Electron asar paketi', document: 'Belge', archive: 'Arşiv', unknown: 'Belirsiz' };
function obfKind(u8, name) {
  const ext = extOf(name); const s = sniff(u8, name); const ev = [];
  if (s !== 'pe' && s !== 'zip' && isAsar(u8)) return { id: 'asar', conf: 97, basis: 'asar başlığı (Electron)', src: false };
  if (s === 'pe') { let clr = false; try { const p = parsePE(u8); clr = !!(p && p.clr); } catch (e) {} return { id: clr ? 'dotnet' : 'pe', conf: 98, basis: 'MZ/PE başlığı' + (clr ? ' + CLR üstbilgisi' : ''), src: false }; }
  if (s === 'class') return { id: 'java-class', conf: 98, basis: 'CAFEBABE', src: false };
  if (s === 'elf' || s === 'macho' || s === 'macho-fat') return { id: s === 'elf' ? 'elf' : 'macho', conf: 98, basis: s + ' başlığı', src: false };
  if (s === 'zip') { try { const en = readZip(u8); const nm = en.map((e) => e.name); if (nm.some((n) => /(^|\/)classes\d*\.dex$/.test(n)) && nm.includes('AndroidManifest.xml')) return { id: 'apk', conf: 97, basis: 'classes.dex + AndroidManifest.xml', src: false }; const nc = nm.filter((n) => n.endsWith('.class')).length; if (nc) return { id: 'jar', conf: 95, basis: nc + ' .class girdisi', src: false, count: nc }; } catch (e) {} return { id: 'archive', conf: 90, basis: 'ZIP', src: false }; }
  if (['pdf', 'ole', 'rtf', 'lnk', 'image', 'onenote', 'gz', 'tar', 'rar', '7z', 'xz', 'cab'].includes(s)) return { id: (['pdf', 'ole', 'rtf', 'lnk', 'onenote'].includes(s) ? 'document' : 'archive'), conf: 90, basis: s, src: false, sub: s };
  if (OBF_TEXT_EXT[ext]) return { id: OBF_TEXT_EXT[ext], conf: 90, basis: 'uzantı .' + ext, src: true };
  if (s === 'text' || s === 'bin') {
    const t = decodeText(u8.subarray(0, Math.min(u8.length, 200000))); if (printableRatio(u8.subarray(0, 4000)) < 0.9) return { id: 'unknown', conf: 0, basis: 'ikili/metin ayırt edilemedi', src: false };
    const sc = { js: 0, ps: 0, vbs: 0, bat: 0, py: 0, sh: 0 };
    if (/\b(?:function\s*\w*\s*\(|var\s+\w+\s*=|const\s+\w+\s*=|=>|require\(|document\.|window\.)/.test(t)) sc.js += 2; if (/_0x[0-9a-f]{3,6}\b/.test(t)) sc.js += 3;
    if (/\$\w+\s*=|\bparam\s*\(|\b(?:Get|Set|New|Invoke|Write)-[A-Z]\w+|\biex\b|\[Convert\]::|-join\b|-bxor\b/i.test(t)) sc.ps += 3;
    if (/^\s*(?:Dim|Set)\s+\w+|\bWScript\.|\bCreateObject\s*\(|\bSub\s+\w+|\bEnd\s+(?:Sub|Function)\b/im.test(t)) sc.vbs += 3;
    if (/^\s*@?echo\s+off|^\s*:\w+|\bgoto\s+\w+|%\w+(?::~-?\d+(?:,-?\d+)?)?%|^\s*set\s+"?\w+=/im.test(t)) sc.bat += 3;
    if (/^\s*(?:import\s+\w+|from\s+\w+\s+import|def\s+\w+\s*\(|class\s+\w+\s*[:(])|\bexec\s*\(|\bmarshal\.loads/m.test(t)) sc.py += 3;
    if (/^#!\s*\/(?:usr\/)?bin\/(?:env\s+)?(?:ba|z)?sh|\bchmod\s+\+x\b|\bcurl\s.*\|\s*(?:ba)?sh/m.test(t)) sc.sh += 3;
    const best = Object.entries(sc).sort((a, b) => b[1] - a[1]); if (best[0][1] >= 3 && best[0][1] > best[1][1]) return { id: best[0][0], conf: 60, basis: 'içerik sezgisi (uzantı bilinmiyor)', src: true };
    return { id: 'unknown', conf: 0, basis: 'içerikten tür belirlenemedi', src: false };
  }
  return { id: 'unknown', conf: 0, basis: String(s), src: false };
}

/* ----- obfuscation gostergeleri (kaynak) ----- */
const cnt = (t, re) => (t.match(re) || []).length;
function srcMetrics(t) { const ids = t.match(/\b[A-Za-z_$][\w$]{0,40}\b/g) || []; const uniq = new Set(ids); let sh = 0, hex = 0; for (const i of uniq) { if (i.length <= 2) sh++; if (/^_0x[0-9a-f]{3,}$/i.test(i)) hex++; } const lines = t.split('\n'); const maxL = lines.reduce((a, l) => Math.max(a, l.length), 0); return { n: ids.length, uniq: uniq.size, shortRatio: uniq.size ? sh / uniq.size : 0, hex, maxLine: maxL, lines: lines.length, avgLine: t.length / Math.max(1, lines.length) }; }
function obfDetectSource(lang, t) {
  const M = []; const add = (id, label, conf, ev, basis) => { if (conf > 0) M.push({ id, label, conf: Math.min(97, Math.round(conf)), ev: ev ? [].concat(ev).slice(0, 3).map((x) => clip(x, 120)) : [], basis: basis || 'heuristic' }); };
  const m = srcMetrics(t); const kb = Math.max(1, t.length / 1024);
  if (lang === 'js') {
    const hexIds = m.hex; if (hexIds >= 8) add('js_hexids', 'Rastgele onaltılık tanımlayıcılar (_0x…; obfuscator.io tarzı)', 60 + Math.min(35, hexIds), (t.match(/_0x[0-9a-f]{3,6}/gi) || []).slice(0, 3), 'fact');
    if (/var\s+_0x[0-9a-f]+\s*=\s*\[[^\]]{8,}/i.test(t) || /function\s+_0x[0-9a-f]+\(\)\s*\{\s*var\s+_0x[0-9a-f]+\s*=\s*\[/i.test(t)) add('js_stringarray', 'Dize dizisi + indeksli erişim (string array)', 80, ['dize dizisi tanımı'], 'fact');
    if (/\(function\s*\(\s*_0x[0-9a-f]+\s*,\s*_0x[0-9a-f]+\s*\)\s*\{[\s\S]{0,400}?\['push'\]\(\w+\['shift'\]\(\)\)/.test(t) || /\['push'\]\(\w+\['shift'\]\(\)\)/.test(t)) add('js_rotate', 'Dize dizisi döndürme (rotate)', 70, ["…['push'](…['shift']())"], 'fact');
    if (/eval\(function\(p,a,c,k,e,(?:d|r)\)/.test(t)) add('js_packer', 'Dean Edwards “packer” (eval(function(p,a,c,k,e,d)…)', 95, ['eval(function(p,a,c,k,e,d)'], 'fact');
    if (/^[\s\[\]()!+]{200,}$/.test(t.slice(0, 4000)) || (cnt(t.slice(0, 5000), /[^\[\]()!+\s]/g) < 20 && t.length > 400)) add('js_jsfuck', 'JSFuck ([]()!+ ile kodlama)', 97, ['yalnızca []()!+ karakterleri'], 'fact');
    if (/ﾟωﾟ|\$=~\[\];\$=\{___/.test(t)) add('js_aajj', 'aaencode/jjencode', 95, ['ﾟωﾟ / $=~[]'], 'fact');
    const esc = cnt(t, /\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/g); if (esc / kb > 6) add('js_escapes', 'Yoğun \\x/\\u kaçış dizileri', 25 + Math.min(40, (esc / kb) * 2), [esc + ' kaçış dizisi'], 'fact');
    const fcc = cnt(t, /String\.fromCharCode/g); if (fcc >= 5) add('js_charcode', 'String.fromCharCode ile dize oluşturma (' + fcc + ')', 20 + Math.min(40, fcc * 2), ['String.fromCharCode ×' + fcc], 'fact');
    const ev = cnt(t, /\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(\s*['"]/g); if (ev >= 1 && /atob\(|unescape\(|fromCharCode/.test(t)) add('js_evalchain', 'Çalışma anında kod üretimi (eval/Function + kodlama)', 35 + Math.min(30, ev * 5), ['eval/Function ×' + ev], 'inference');
    if (/while\s*\(\s*!!\s*\[\s*\]\s*\)\s*\{\s*switch\s*\(/.test(t) || /\.split\(['"]\|['"]\)[\s\S]{0,80}while\s*\(/.test(t)) add('js_cff', 'Kontrol akışı düzleştirme (switch + while(!![]))', 75, ['while(!![]){switch(…'], 'fact');
    if (m.uniq > 40 && m.shortRatio > 0.7 && !m.hex) add('js_minified', 'Kısa tanımlayıcılar (' + Math.round(m.shortRatio * 100) + '%) — sıkıştırma (minify) olabilir', 18, ['kısa isim oranı'], 'heuristic');
    if (/atob\(['"][A-Za-z0-9+/=]{60,}['"]\)/.test(t)) add('js_b64', 'Base64 gömülü büyük dize', 30, ['atob(…)'], 'fact');
  } else if (lang === 'ps') {
    const bt = cnt(t, /\w`\w/g); if (bt >= 4) add('ps_backtick', 'Sözcük içinde ters tırnak (`I`E`X)', 40 + Math.min(50, bt * 3), (t.match(/\w`\w[\w`]{2,12}/g) || []).slice(0, 3), 'fact');
    const ch = cnt(t, /\[char\]\s*(?:0x[0-9a-f]+|\d+)/gi); if (ch >= 4) add('ps_char', '[char] sayı dizileriyle dize kurma (' + ch + ')', 35 + Math.min(45, ch * 2), ['[char]NN ×' + ch], 'fact');
    if (/-join\s*\(?\s*\[char\[\]\]/i.test(t) || /\[char\[\]\]\s*\([\d,\s]{20,}\)/i.test(t)) add('ps_joinchar', 'Karakter dizisini -join ile birleştirme', 55, ['[char[]](…) -join'], 'fact');
    const fm = cnt(t, /['"][^'"]*\{\d+\}[^'"]*['"]\s*-f\b/gi); if (fm >= 2) add('ps_format', '-f biçim işleciyle dize parçalama (' + fm + ')', 35 + Math.min(40, fm * 6), ['"{0}{1}" -f …'], 'fact');
    const cc = cnt(t, /['"]\s*\+\s*['"]/g); if (cc >= 10) add('ps_concat', 'Sabit dizelerin + ile parçalanması (' + cc + ')', 20 + Math.min(40, cc), ["'a'+'b' ×" + cc], 'fact');
    if (/-(?:enc|encodedcommand|ec)\s+[A-Za-z0-9+/=]{40,}/i.test(t) || /FromBase64String\(/i.test(t)) add('ps_b64', 'Base64 kodlanmış komut/yük', 55, ['-EncodedCommand / FromBase64String'], 'fact');
    if (/IO\.Compression\.(?:Deflate|GZip)Stream/i.test(t)) add('ps_compress', 'Sıkıştırılmış yük (Deflate/GZip)', 50, ['IO.Compression.*Stream'], 'fact');
    if (/-bxor\b/i.test(t)) add('ps_xor', 'XOR ile şifre çözme (-bxor)', 45, ['-bxor'], 'fact');
    const toks = t.match(/\b[A-Za-z]{6,20}\b/g) || []; let mixed = 0; for (const x of toks) if (/[a-z][A-Z][a-z]/.test(x) && /^(?:[Ii][Nn][Vv][Oo][Kk][Ee]|[Ee][Xx][Pp][Rr][Ee][Ss]{2}[Ii][Oo][Nn]|[Dd][Oo][Ww][Nn][Ll][Oo][Aa][Dd]|[Ss][Tt][Rr][Ii][Nn][Gg]|[Oo][Bb][Jj][Ee][Cc][Tt])/.test(x) && x !== x.toLowerCase() && !/^[A-Z][a-z]+(?:[A-Z][a-z]+)*$/.test(x)) mixed++; if (mixed >= 3) add('ps_randcase', 'Rastgele büyük/küçük harf (iNvOkE-eXpReSsIoN)', 45, toks.filter((x) => /[a-z][A-Z][a-z]/.test(x)).slice(0, 3), 'heuristic');
    if (/\$\{[^}]{1,30}\}/.test(t) && cnt(t, /\$\{[^}]{1,30}\}/g) >= 5) add('ps_bracevars', '${…} ile gizlenmiş değişken adları', 25, ['${…}'], 'heuristic');
    if (/\.\s*\(\s*['"]\s*i\s*['"]\s*\+\s*['"]\s*ex\s*['"]\s*\)|&\s*\(\s*\$\w+\s*\[\s*\d+\s*\]/i.test(t)) add('ps_dynamic_iex', 'Parçalanmış IEX çağrısı', 70, ["'i'+'ex'"], 'fact');
  } else if (lang === 'vbs') {
    const c = cnt(t, /\bChrW?\$?\s*\(/gi); if (c >= 10) add('vbs_chr', 'Chr() ile dize kurma (' + c + ')', 30 + Math.min(55, c), ['Chr() ×' + c], 'fact');
    const cc = cnt(t, /"\s*&\s*"/g); if (cc >= 15) add('vbs_concat', 'Dizelerin & ile parçalanması (' + cc + ')', 20 + Math.min(40, cc / 2), ['"a" & "b" ×' + cc], 'fact');
    if (/\bStrReverse\s*\(|\bExecute(?:Global)?\s*\(?|\bEval\s*\(/i.test(t) && (c >= 3 || cc >= 5)) add('vbs_exec', 'Çalışma anında kod yürütme (Execute/Eval) + dize kurma', 55, ['Execute/Eval'], 'inference');
    if (m.uniq > 30 && cnt(t, /\b(?:Dim|Set)\s+[A-Za-z]{10,}\b/g) > 10) add('vbs_randnames', 'Uzun rastgele değişken adları', 30, ['uzun adlar'], 'heuristic');
    if (cnt(t, /^'.{0,200}$/gm) > 60 && cnt(t, /^'.{0,200}$/gm) / Math.max(1, m.lines) > 0.4) add('vbs_junk', 'Yoğun gereksiz yorum satırı (kod şişirme)', 30, ['yorum oranı yüksek'], 'heuristic');
  } else if (lang === 'bat') {
    const cr = cnt(t, /\^[A-Za-z0-9]/g); if (cr >= 8) add('bat_caret', 'Sözcük içinde ^ işareti (p^o^w^e^r)', 35 + Math.min(55, cr), (t.match(/(?:\w\^){3,}\w/g) || []).slice(0, 3), 'fact');
    const sub = cnt(t, /%[A-Za-z_]\w*:~-?\d+(?:,-?\d+)?%/g); if (sub >= 6) add('bat_substr', 'Değişken alt dizeleriyle komut kurma (%v:~1,1%) (' + sub + ')', 40 + Math.min(50, sub), ['%var:~n,m% ×' + sub], 'fact');
    if (/%[A-Za-z_]\w*:[^=%]{1,10}=[^%]*%/.test(t)) add('bat_replace', 'Değişken içinde değiştirme (%v:a=b%)', 25, ['%v:a=b%'], 'heuristic');
    if (/\bcmd(?:\.exe)?\s+\/v(?::on)?\b|setlocal\s+enabledelayedexpansion/i.test(t) && /![A-Za-z_]\w*(?::~-?\d+(?:,-?\d+)?)?!/.test(t)) add('bat_delayed', 'Gecikmeli genişletme (!var!) ile komut kurma', 35, ['enabledelayedexpansion + !var!'], 'heuristic');
  } else if (lang === 'py') {
    if (/(?:exec|eval)\s*\(\s*(?:\w+\.)*(?:b64decode|decompress|loads|fromhex|decode)/.test(t)) add('py_execdecode', 'exec/eval(decode(…)) zinciri', 80, [clip((/(?:exec|eval)\s*\(.{0,80}/.exec(t) || [''])[0], 100)], 'fact');
    if (/__pyarmor__|pyarmor_runtime|PYARMOR/.test(t)) add('py_pyarmor', 'PyArmor koruması', 97, ['pyarmor'], 'fact');
    if (/marshal\.loads\s*\(/.test(t)) add('py_marshal', 'marshal.loads ile gömülü bytecode', 75, ['marshal.loads'], 'fact');
    if (/\bzlib\.decompress\s*\(\s*(?:\w+\.)*b64decode/.test(t) || /\[::-1\]\s*\)\s*\)/.test(t) && /b64decode/.test(t)) add('py_zlib', 'zlib+base64 sarmalı', 60, ['zlib.decompress(b64decode(…))'], 'fact');
    const lam = cnt(t, /lambda\s+\w*\s*:/g); if (lam > 25) add('py_lambda', 'Aşırı lambda kullanımı', 25, ['lambda ×' + lam], 'heuristic');
    if (m.uniq > 30 && cnt(t, /\b[Il1O0]{6,}\b/g) > 10) add('py_names', 'Ayırt edilmesi zor adlar (Il1O0…)', 45, ['I/l/1/O/0 karışık adlar'], 'heuristic');
  } else if (lang === 'sh') {
    if (/base64\s+-d[\s\S]{0,40}\|\s*(?:ba|z)?sh\b/.test(t) || /\beval\s+["']?\$\(.*base64/.test(t)) add('sh_b64exec', 'base64 -d | sh (kodlanmış kabuk yükü)', 75, ['base64 -d | sh'], 'fact');
    if (/\\x[0-9a-f]{2}.{0,30}\\x[0-9a-f]{2}/i.test(t) && cnt(t, /\\x[0-9a-f]{2}/gi) > 20) add('sh_hex', 'Onaltılık kaçışlı komutlar', 45, ['\\xNN'], 'fact');
    if (/\$\{[A-Za-z_]\w*:\d+:\d+\}/.test(t) && cnt(t, /\$\{[A-Za-z_]\w*:\d+:\d+\}/g) > 8) add('sh_substr', 'Değişken alt dizeleriyle komut kurma', 45, ['${v:1:2}'], 'fact');
  }
  return M;
}
/* ----- obfuscation gostergeleri (ikili) ----- */
const PACKER_SEC = [[/^UPX\d?$/i, 'UPX'], [/^\.?themida$|^\.winlice$/i, 'Themida/WinLicense'], [/^\.vmp\d$/i, 'VMProtect'], [/^\.aspack$|^\.adata$/i, 'ASPack'], [/^\.enigma\d$/i, 'Enigma Protector'], [/^\.mpress\d$/i, 'MPRESS'], [/^\.petite$/i, 'Petite'], [/^\.nsp\d$|^nsp\d$/i, 'NsPack'], [/^pec\d?$|^pecompact/i, 'PECompact'], [/^\.packed$|^\.kkrunchy$/i, 'kkrunchy/özel paketleyici'], [/^\.boom$|^\.perplex$|^\.obsidium$/i, 'Obsidium/benzeri'], [/^\.reactor$/i, '.NET Reactor']];
const NET_MARK = [[/ConfusedByAttribute|Confuser(?:Ex)?\b/, 'ConfuserEx'], [/\{11111-22222-(?:10009|20001|20003|40001)-\d+\}|NETReactor|\.NET Reactor/i, '.NET Reactor'], [/Eazfuscator|EazGetStringRes?|Eazfuscator\.NET/i, 'Eazfuscator.NET'], [/SmartAssembly|PoweredByAttribute|Powered by SmartAssembly/i, 'SmartAssembly'], [/DotfuscatorAttribute|Dotfuscator/i, 'Dotfuscator'], [/BabelObfuscatorAttribute|Babel\.NET|Babel Obfuscator/i, 'Babel Obfuscator'], [/CliSecure|Agile\.NET|ObfuscatedByAgileDotNet/i, 'Agile.NET (CliSecure)'], [/ILProtector|ILProtectorAttribute/, 'ILProtector'], [/ObfuscatedByCodeWall|CodeWall/i, 'CodeWall'], [/Obfuscar|ObfuscatedByAttribute/i, 'Obfuscar/ObfuscatedBy']];
const JAVA_MARK = [[/ZKM|Zelix|com\/zelix/i, 'Zelix KlassMaster'], [/Allatori/i, 'Allatori'], [/Stringer Java Obfuscator|com\/licel\/stringer/i, 'Stringer'], [/DashO|com\/preemptive/i, 'DashO'], [/paramorphism/i, 'Paramorphism'], [/Skidfuscator|dev\/skidfuscator/i, 'Skidfuscator'], [/Obfuscated by|obfuscat/i, 'Genel “obfuscat…” izi'], [/ProGuard/i, 'ProGuard']];
const badName = (n) => !n || n.length <= 2 || /^[Il1O0o]{4,}$/.test(n) || /[^\x20-\x7e]/.test(n) || /^[a-z]{1,2}\d*$/.test(n);
async function obfDetectBinary(kind, u8, name, ctx) {
  const M = []; const add = (id, label, conf, ev, basis) => { if (conf > 0) M.push({ id, label, conf: Math.min(97, Math.round(conf)), ev: [].concat(ev || []).slice(0, 3).map((x) => clip(x, 120)), basis: basis || 'heuristic' }); };
  const scan = ctx.scan; const info = (scan && scan.info) || {}; const text = latin1(u8.subarray(0, Math.min(u8.length, 24e6)));
  const upx = /UPX!|UPX0|UPX1/.test(text.slice(0, 2e6)); if (upx) add('bin_upx', 'UPX paketleyici', 92, ['UPX! işareti'], 'fact');
  const secs = info.sections || []; if ((kind === 'pe' || kind === 'dotnet' || kind === 'elf' || kind === 'macho') && secs.length) {
    for (const s of secs) for (const [re, nm] of PACKER_SEC) if (re.test(s.n || '')) add('bin_packer_' + nm, nm + ' bölüm adı (' + s.n + ')', 88, ['bölüm ' + s.n], 'fact');
    const hi = secs.filter((s) => s.ent >= 7.2 && s.size > 4096); if (hi.length) add('bin_highent', 'Yüksek entropili bölüm(ler): ' + hi.map((s) => s.n + ' ' + s.ent).slice(0, 3).join(', '), 35 + Math.min(30, hi.length * 10), hi.map((s) => s.n + ' entropi ' + s.ent), 'heuristic');
    if (kind === 'pe' && info.importCount != null && info.importCount <= 6 && (info.entropy || 0) >= 7) add('bin_fewimports', 'Çok az import + yüksek entropi (paketleme göstergesi)', 45, ['import ' + info.importCount + ', entropi ' + info.entropy], 'heuristic');
    if (secs.some((s) => s.rwx)) add('bin_rwx', 'Hem yazılabilir hem çalıştırılabilir bölüm', 15, ['RWX bölüm'], 'heuristic');
  }
  if (kind === 'dotnet') {
    for (const [re, nm] of NET_MARK) if (re.test(text)) add('net_' + nm, nm + ' izi', 80, [nm], 'fact');
    try { const p = parsePE(u8); const n = parseNet(u8, p); if (n && n.names && n.names.total >= 20) { const r = n.names.weird / n.names.total; if (r >= 0.4) add('net_names', 'Anlamsız/yazdırılamayan tür-üye adları (%' + Math.round(r * 100) + ')', 40 + r * 50, [n.names.weird + ' / ' + n.names.total + ' ad'], 'fact'); } if (n && n.us != null && n.us < 40 && (n.counts && n.counts.MethodDef > 60)) add('net_fewstrings', 'Çok az kullanıcı dizesi (dizeler şifrelenmiş olabilir)', 30, ['#US ' + n.us + ' bayt, ' + n.counts.MethodDef + ' metot'], 'heuristic'); } catch (e) {}
  }
  if (kind === 'jar' || kind === 'java-class') {
    let tot = 0, bad = 0; const mk = new Map(); const classes = [];
    if (kind === 'java-class') classes.push(u8); else { try { const en = readZip(u8).filter((e) => /\.class$/.test(e.name) && !e.dir && !e.enc); let budget = OBF_LIM.jarBudget; for (const e of en.slice(0, 300)) { obfCheck(ctx); if (e.size > OBF_LIM.entryCap || budget < 0) continue; try { const d = await readEntry(u8, e, OBF_LIM.entryCap); budget -= d.length; classes.push(d); } catch (er) {} } const mf = readZip(u8).find((e) => /^META-INF\/MANIFEST\.MF$/i.test(e.name)); if (mf) { try { const d = await readEntry(u8, mf, 1e5); const tx = td8.decode(d); for (const [re, nm] of JAVA_MARK) if (re.test(tx)) mk.set(nm, 'MANIFEST'); } catch (er) {} } } catch (e) {} }
    for (const c of classes) { let pc = null; try { pc = parseClass(c, false); } catch (e) {} if (!pc) continue; tot++; const base = (pc.name || '').split('/').pop(); if (badName(base)) bad++; for (const m of pc.methods) { const mn = m.split('(')[0]; tot++; if (badName(mn) && mn !== '<init>' && mn !== '<clinit>') bad++; } const blob = pc.utf8.join('\n'); for (const [re, nm] of JAVA_MARK) if (nm !== 'Genel “obfuscat…” izi' || !mk.size) if (re.test(blob)) mk.set(nm, 'sınıf sabit havuzu'); }
    for (const [nm, where] of mk) add('jv_' + nm, nm + ' izi (' + where + ')', nm.startsWith('Genel') ? 45 : (nm === 'ProGuard' ? 55 : 80), [nm], 'fact');
    if (tot >= 30 && bad / tot >= 0.35) add('jv_names', 'Kısa/anlamsız sınıf-metot adları (%' + Math.round((bad / tot) * 100) + ')', 40 + (bad / tot) * 45, [bad + ' / ' + tot + ' ad'], 'fact');
    ctx.javaStat = { classes: classes.length, names: tot, bad };
  }
  if (kind === 'apk') { if (/proguard|r8|dexguard|dexprotector|bangcle|ijiami|qihoo|jiagu|ali\.?jiagu|libsecexe|libprotect/i.test(text.slice(0, 6e6))) add('apk_packer', 'Android koruyucu/obfuscator izi (ProGuard/R8/DexGuard/jiagu…)', 55, ['paketleyici/obfuscator dizeleri'], 'fact'); }
  return M;
}

/* ----- metin donusumleri (hepsi saf, statik) ----- */
function lit(s, q) { return q + String(s).replace(/\\/g, '\\\\').replace(new RegExp(q, 'g'), '\\' + q).replace(/\n/g, '\\n').replace(/\r/g, '\\r') + q; }
const toNum = (x) => (/^0x/i.test(x) ? parseInt(x, 16) : /^&h/i.test(x) ? parseInt(x.slice(2), 16) : parseInt(x, 10));
const printable = (c) => c >= 32 && c < 127;
function rx(t, re, fn) { let n = 0; const out = t.replace(re, (...a) => { const r = fn(...a); if (r === undefined || r === a[0]) return a[0]; n++; return r; }); return { text: out, n }; }
function loop(t, f, max) { let n = 0; for (let i = 0; i < (max || 12); i++) { const r = f(t); if (!r.n) break; t = r.text; n += r.n; } return { text: t, n }; }
const T = {
  jsUnescape: (t) => rx(t, /(["'])((?:(?!\1)[^\\\n]|\\.)*)\1/g, (m, q, body) => { if (!/\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|u\{[0-9a-fA-F]+\}|[0-7]{1,3})/.test(body)) return undefined; let ch = false; const nb = body.replace(/\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]+)\}|([0-7]{1,3}))/g, (mm, a, b, c, d) => { const code = a ? parseInt(a, 16) : b ? parseInt(b, 16) : c ? parseInt(c, 16) : parseInt(d, 8); if (!printable(code) || String.fromCharCode(code) === q || code === 92) return mm; ch = true; return String.fromCharCode(code); }); return ch ? q + nb + q : undefined; }),
  jsConcat: (t) => loop(t, (x) => rx(x, /(["'])((?:(?!\1)[^\\\n]|\\.)*)\1\s*\+\s*\1((?:(?!\1)[^\\\n]|\\.)*)\1/g, (m, q, a, b) => q + a + b + q), 40),
  jsFromCharCode: (t) => rx(t, /String\.fromCharCode\(\s*((?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+))*)\s*\)/g, (m, a) => { const cs = a.split(',').map((x) => toNum(x.trim())); if (cs.some((c) => isNaN(c) || c > 0x10ffff)) return undefined; return lit(String.fromCodePoint(...cs), '"'); }),
  jsBracket: (t) => rx(t, /(?<=[\w$)\]])\[\s*(["'])([A-Za-z_$][\w$]*)\1\s*\]/g, (m, q, id) => '.' + id),
  jsAtob: (t) => rx(t, /\batob\(\s*(["'])([A-Za-z0-9+/]{8,}={0,2})\1\s*\)/g, (m, q, b) => { const u = b64bytes(b); if (!u || printableRatio(u) < 0.9) return undefined; return lit(td8.decode(u), '"'); }),
  jsPacker: (t) => rx(t, /eval\(function\(p,a,c,k,e,(?:d|r)\)\{[\s\S]*?\}\('((?:[^'\\]|\\.)*)',\s*(\d+),\s*(\d+),\s*'((?:[^'\\]|\\.)*)'\.split\('\|'\),\s*0\s*,\s*\{\}\)\)/g, (m, p, a, c, k) => { a = +a; c = +c; if (!(a >= 2 && a <= 62) || c > 200000) return undefined; p = p.replace(/\\'/g, "'").replace(/\\\\/g, '\\'); const keys = k.replace(/\\'/g, "'").split('|'); const b = (n) => (n < a ? '' : b(Math.floor(n / a))) + ((n = n % a) > 35 ? String.fromCharCode(n + 29) : n.toString(36)); const d = new Map(); for (let i = c - 1; i >= 0; i--) d.set(b(i), keys[i] || b(i)); return p.replace(/\b\w+\b/g, (w) => (d.has(w) ? d.get(w) : w)); }),
  psBacktick: (t) => { let n = 0; const out = psSplit(t).map((s) => { if (s.q === "'") return s.s; if (s.q === '"') return s.s.replace(/`([^n tr abfv0`"$'])/g, (m, c) => { n++; return c; }); return s.s.replace(/`([^\r\n])/g, (m, c) => { n++; return c; }); }).join(''); return { text: out, n }; },
  psConcat: (t) => loop(t, (x) => { const a = rx(x, /'((?:[^']|'')*)'\s*\+\s*'((?:[^']|'')*)'/g, (m, p, q) => "'" + p + q + "'"); const b = rx(a.text, /"((?:[^"`$]|`.)*)"\s*\+\s*"((?:[^"`$]|`.)*)"/g, (m, p, q) => '"' + p + q + '"'); return { text: b.text, n: a.n + b.n }; }, 40),
  psChar: (t) => { const a = rx(t, /\[char\]\s*\(?\s*(0x[0-9a-fA-F]+|\d+)\s*\)?/gi, (m, v) => { const c = toNum(v); if (!printable(c) || c === 39) return undefined; return "'" + String.fromCharCode(c) + "'"; }); return a; },
  psJoinChars: (t) => rx(t, /(?:-join\s*\(?\s*)?\(?\s*\[char\[\]\]\s*\(\s*((?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+))*)\s*\)\s*\)?(?:\s*-join\s*(?:''|""))?/gi, (m, a) => { if (!/-join/i.test(m)) return undefined; const cs = a.split(',').map((x) => toNum(x.trim())); if (cs.some((c) => isNaN(c) || c > 0xffff)) return undefined; return "'" + String.fromCharCode(...cs).replace(/'/g, "''") + "'"; }),
  psFormat: (t) => rx(t, /(["'])((?:(?!\1)[^\\\n])*\{\d+\}(?:(?!\1)[^\\\n])*)\1\s*-f\s*((?:'(?:[^']|'')*'|"[^"`$]*")(?:\s*,\s*(?:'(?:[^']|'')*'|"[^"`$]*"))*)/gi, (m, q, tpl, args) => { const as = [...args.matchAll(/'((?:[^']|'')*)'|"([^"`$]*)"/g)].map((x) => (x[1] !== undefined ? x[1].replace(/''/g, "'") : x[2])); const out = tpl.replace(/\{(\d+)\}/g, (mm, i) => (as[+i] !== undefined ? as[+i] : mm)); if (/\{\d+\}/.test(out)) return undefined; return "'" + out.replace(/'/g, "''") + "'"; }),
  psReplace: (t) => rx(t, /'((?:[^']|'')*)'\s*\.\s*[Rr]eplace\(\s*'((?:[^']|'')*)'\s*,\s*'((?:[^']|'')*)'\s*\)/g, (m, s, a, b) => { if (!a) return undefined; return "'" + s.split(a).join(b) + "'"; }),
  psCase: (t) => { const W = ['Invoke-Expression', 'Invoke-WebRequest', 'Invoke-RestMethod', 'New-Object', 'Net.WebClient', 'DownloadString', 'DownloadFile', 'FromBase64String', 'Start-Process', 'Set-ExecutionPolicy', 'Add-Type', 'Get-Content', 'Out-String', 'ForEach-Object', 'Where-Object', 'IEX', 'Bypass', 'Hidden', 'NoProfile', 'WindowStyle', 'ExecutionPolicy', 'Reflection.Assembly', 'System.Text.Encoding', 'Convert', 'Join', 'Split', 'ToCharArray', 'Replace', 'Substring', 'Length']; let n = 0; let out = t; for (const w of W) { const re = new RegExp('(?<![\\w-])' + w.replace(/[.-]/g, (c) => '\\' + c) + '(?![\\w-])', 'gi'); out = out.replace(re, (m) => { if (m === w) return m; if (!/[a-z][A-Z]|[A-Z][a-z]*[A-Z]/.test(m) && m === m.toLowerCase() && w !== 'IEX') return m; n++; return w; }); } return { text: out, n }; },
  vbsChr: (t) => rx(t, /\bChrW?\$?\s*\(\s*(\d+|&[Hh][0-9a-fA-F]+)\s*\)/g, (m, v) => { const c = toNum(v); if (!printable(c)) return undefined; return '"' + (c === 34 ? '""' : String.fromCharCode(c)) + '"'; }),
  vbsConcat: (t) => loop(t, (x) => rx(x, /"((?:[^"\r\n]|"")*)"\s*&\s*"((?:[^"\r\n]|"")*)"/g, (m, a, b) => '"' + a + b + '"'), 60),
  batCaret: (t) => rx(t, /\^(?=[A-Za-z0-9])/g, () => ''),
  pyChr: (t) => { const a = rx(t, /\bchr\(\s*(\d+|0x[0-9a-fA-F]+)\s*\)/g, (m, v) => { const c = toNum(v); if (!printable(c) || c === 39 || c === 92) return undefined; return "'" + String.fromCharCode(c) + "'"; }); const b = loop(a.text, (x) => rx(x, /'((?:[^'\\\n]|\\.)*)'\s*\+\s*'((?:[^'\\\n]|\\.)*)'/g, (m, p, q) => "'" + p + q + "'"), 40); return { text: b.text, n: a.n + b.n }; }
};
function psSplit(t) { const out = []; let i = 0, cur = ''; const flush = () => { if (cur) out.push({ q: null, s: cur }); cur = ''; }; while (i < t.length) { const c = t[i]; if (c === "'") { flush(); let j = i + 1; while (j < t.length) { if (t[j] === "'") { if (t[j + 1] === "'") { j += 2; continue; } break; } j++; } out.push({ q: "'", s: t.slice(i, j + 1) }); i = j + 1; } else if (c === '"') { flush(); let j = i + 1; while (j < t.length) { if (t[j] === '`') { j += 2; continue; } if (t[j] === '"') { if (t[j + 1] === '"') { j += 2; continue; } break; } j++; } out.push({ q: '"', s: t.slice(i, j + 1) }); i = j + 1; } else if (c === '#' && /(^|\s)$/.test(cur.slice(-1) || ' ')) { flush(); let j = t.indexOf('\n', i); if (j < 0) j = t.length; out.push({ q: "'", s: t.slice(i, j) }); i = j; } else { cur += c; i++; } } flush(); return out; }
/* batch: set degiskenlerinin statik genisletilmesi */
function batExpand(t) {
  const vars = new Map(); for (const m of t.matchAll(/^\s*set\s+"?([A-Za-z_]\w*)=([^\r\n"%!]*)"?\s*$/gim)) vars.set(m[1].toLowerCase(), m[2]); if (!vars.size) return { text: t, n: 0 }; let n = 0;
  const out = t.split('\n').map((ln) => { if (/^\s*set\s/i.test(ln)) return ln; return ln.replace(/%([A-Za-z_]\w*)(?::~(-?\d+)(?:,(-?\d+))?)?%/g, (m, nm, s, l) => { const v = vars.get(nm.toLowerCase()); if (v === undefined) return m; let r = v; if (s !== undefined) { let st = +s; if (st < 0) st = Math.max(0, v.length + st); r = l === undefined ? v.slice(st) : (+l >= 0 ? v.substr(st, +l) : v.slice(st, v.length + +l)); } n++; return r; }); }).join('\n');
  return { text: out, n };
}
const PIPE = {
  js: [['jsPacker', 'Dean Edwards packer açıldı'], ['jsUnescape', '\\x/\\u/sekizlik kaçışlar çözüldü'], ['jsFromCharCode', 'String.fromCharCode dizileri harfe çevrildi'], ['jsAtob', 'atob("…") sabitleri çözüldü'], ['jsConcat', 'Bitişik dize birleştirmeleri katlandı'], ['jsBracket', "x['a'] → x.a"]],
  ps: [['psBacktick', 'Ters tırnak gizlemesi kaldırıldı'], ['psChar', '[char]NN sabitleri harfe çevrildi'], ['psJoinChars', '[char[]](…) -join dizileri çözüldü'], ['psConcat', "'a'+'b' birleştirmeleri katlandı"], ['psFormat', '-f biçim işleci katlandı'], ['psReplace', "'…'.Replace(…) sabitleri katlandı"], ['psCase', 'Rastgele büyük/küçük harf düzeltildi']],
  vbs: [['vbsChr', 'Chr()/ChrW() sabitleri harfe çevrildi'], ['vbsConcat', '"a" & "b" birleştirmeleri katlandı']],
  bat: [['batCaret', '^ gizlemesi kaldırıldı'], ['batExpand', 'set değişkenleri statik genişletildi']],
  py: [['pyChr', 'chr(N) + birleştirmeler katlandı'], ['jsUnescape', '\\x kaçışları çözüldü']],
  sh: [['jsUnescape', '\\x kaçışları çözüldü']]
};
T.batExpand = batExpand;
/* base64 / zlib / gzip katmanlari */
async function inflZ(u8, fmt) { const ds = new DecompressionStream(fmt); const rd = new Blob([u8]).stream().pipeThrough(ds).getReader(); const parts = []; let tot = 0; for (;;) { const r = await rd.read(); if (r.done) break; tot += r.value.length; if (tot > 16e6) { try { await rd.cancel(); } catch (e) {} throw new Error('limit'); } parts.push(r.value); } const o = new Uint8Array(tot); let p = 0; for (const x of parts) { o.set(x, p); p += x.length; } return o; }
async function tryLayer(u) {
  for (const f of [null, 'gzip', 'deflate', 'deflate-raw']) { let d = u; if (f) { if (f === 'gzip' && !(u[0] === 0x1f && u[1] === 0x8b)) continue; if (f === 'deflate' && !(u[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(u[1]))) continue; try { d = await inflZ(u, f); } catch (e) { continue; } }
    if (d.length > 8 && d[0] === 0x4d && d[1] === 0x5a) return { kind: 'pe', u: d, how: f || 'düz' }; if (d.length > 8 && d[0] === 0x50 && d[1] === 0x4b && d[2] === 3) return { kind: 'zip', u: d, how: f || 'düz' };
    if (printableRatio(d) > 0.9) return { kind: 'text', t: td8.decode(d), how: f || 'düz' };
    const t16 = tdU16.decode(d.subarray(0, Math.min(d.length, 4000))); if (d.length >= 8 && [...t16].filter((ch) => ch.charCodeAt(0) < 128 && ch.charCodeAt(0) >= 9).length / Math.max(1, t16.length) > 0.9) return { kind: 'text', t: tdU16.decode(d), how: (f || 'düz') + ', UTF-16' }; }
  return null;
}
async function peelLayers(t, lang, ctx, depth, out) {
  if (depth > OBF_LIM.layers) { ctx.limits.push('Katman çözme derinliği (' + OBF_LIM.layers + ') sınırına ulaşıldı.'); return; }
  const seen = new Set(); const lits = [];
  for (const m of t.slice(0, 6e6).matchAll(/(?:["'])([A-Za-z0-9+/]{60,}={0,2})(?:["'])/g)) lits.push(m[1]);
  const enc = /-(?:enc|encodedcommand|ec)\s+([A-Za-z0-9+/=]{40,})/i.exec(t); if (enc) lits.unshift(enc[1]);
  for (const b of lits.slice(0, 30)) { obfCheck(ctx); if (seen.has(b.slice(0, 60))) continue; seen.add(b.slice(0, 60)); const u = b64bytes(b); if (!u || u.length < 24) continue; const r = await tryLayer(u); if (!r) continue; const id = out.layers.length + 1; if (r.kind === 'text') { const nl = lang === 'ps' || /\bFunction|\$\w+\s*=|IEX/i.test(r.t) ? 'ps' : lang; let body = r.t; let done = []; const rr = await runPipe(body, nl, ctx); body = rr.text; out.layers.push({ id, from: 'base64 (' + r.how + ')', lang: nl, text: body, steps: rr.steps, size: body.length }); await peelLayers(body, nl, ctx, depth + 1, out); } else out.layers.push({ id, from: 'base64 (' + r.how + ')', bin: r.u, kind: r.kind, size: r.u.length }); if (out.layers.length >= 12) { ctx.limits.push('En fazla 12 katman çıkarıldı.'); return; } }
  if (lang === 'py') { for (const m of t.matchAll(/(?:b64decode|fromhex)\(\s*(?:b?["'])([A-Za-z0-9+/=]{40,}|[0-9a-fA-F]{40,})["']\s*\)/g)) { const s = m[1]; const u = /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0 ? hexBytes(s) : b64bytes(s); if (!u) continue; const r = await tryLayer(u); if (r && r.kind === 'text') { out.layers.push({ id: out.layers.length + 1, from: 'Python sarmalı (' + r.how + ')', lang: 'py', text: r.t, steps: [], size: r.t.length }); await peelLayers(r.t, 'py', ctx, depth + 1, out); } else if (u.length > 8 && u[0] === 0x63 || (u[0] === 0xe3)) { ctx.notes.push('Python marshal/bytecode benzeri veri bulundu; kaynak değil. uncompyle6/decompyle3/pycdc gibi harici araçla incelenmeli.'); } if (out.layers.length >= 12) return; } }
}
async function runPipe(text, lang, ctx) {
  const steps = []; let cur = text; const tf = PIPE[lang] || [];
  for (let pass = 0; pass < 3; pass++) { let any = false; for (const [k, label] of tf) { obfCheck(ctx); await obfTick(); const r = T[k](cur); if (r.n) { cur = r.text; any = true; const ex = steps.find((s) => s.id === k); if (ex) ex.n += r.n; else steps.push({ id: k, label, n: r.n }); } if (cur.length > OBF_LIM.outMax) { ctx.limits.push('Çıktı boyutu sınırına ulaşıldı; işlem durduruldu.'); return { text: cur, steps }; } } if (!any) break; }
  return { text: cur, steps };
}
/* basit, anlami degistirmeyen JS bicimlendirici (dize/yorum/regex korumali) */
function jsBeautify(src) {
  let out = '', ind = 0, i = 0, last = ''; const n = src.length; const nl = () => { out = out.replace(/[ \t]+$/, '') + '\n' + '  '.repeat(Math.max(0, ind)); };
  while (i < n) { const c = src[i];
    if (c === '"' || c === "'" || c === '`') { let j = i + 1; while (j < n && src[j] !== c) { if (src[j] === '\\') j++; j++; } out += src.slice(i, j + 1); i = j + 1; last = c; continue; }
    if (c === '/' && src[i + 1] === '/') { let j = src.indexOf('\n', i); if (j < 0) j = n; out += src.slice(i, j); i = j; continue; }
    if (c === '/' && src[i + 1] === '*') { let j = src.indexOf('*/', i + 2); j = j < 0 ? n : j + 2; out += src.slice(i, j); i = j; continue; }
    if (c === '/' && (/[(,=:[!&|?{};]/.test(last) || last === '' || /\breturn$|\btypeof$/.test(out.slice(-8)))) { let j = i + 1, cls = false; while (j < n && (src[j] !== '/' || cls) && src[j] !== '\n') { if (src[j] === '\\') j++; else if (src[j] === '[') cls = true; else if (src[j] === ']') cls = false; j++; } if (src[j] === '/') { j++; while (/[a-z]/i.test(src[j] || '')) j++; out += src.slice(i, j); i = j; last = ')'; continue; } }
    if (c === '{') { out += '{'; ind++; nl(); i++; last = c; while (/\s/.test(src[i] || '')) i++; continue; }
    if (c === '}') { ind--; nl(); out += '}'; i++; last = c; while (src[i] === ' ') i++; if (src[i] && !/[;,).\n]/.test(src[i]) && !/^\s*(else|catch|finally|while)\b/.test(src.slice(i, i + 9))) nl(); continue; }
    if (c === ';') { out += ';'; i++; last = c; const pf = out.slice(out.lastIndexOf('\n') + 1); if (!/^\s*for\s*\(/.test(pf) || /\)\s*;?$/.test(pf)) { while (/[ \t]/.test(src[i] || '')) i++; if (src[i] !== '\n' && i < n) nl(); } continue; }
    if (/\s/.test(c)) { if (c === '\n') { i++; continue; } if (!/\s$/.test(out)) out += ' '; i++; continue; }
    out += c; last = c; i++; }
  return out.replace(/\n\s*\n+/g, '\n').trim() + '\n';
}
/* ----- yapi dokumu (decompile DEGIL) ----- */
function javaOutline(pc, nm) {
  const L = ['// ' + nm, 'class ' + pc.name + (pc.sup ? ' extends ' + pc.sup : '') + (pc.ifaces.length ? ' implements ' + pc.ifaces.join(', ') : '') + ' { // sınıf sürümü ' + pc.major];
  for (const m of pc.methods.slice(0, 400)) L.push('  ' + m);
  L.push('}'); const st = [...new Set(pc.strings)].filter((s) => s.length >= 3).slice(0, 80); if (st.length) { L.push('// metin sabitleri (' + st.length + ')'); for (const s of st) L.push('//   ' + JSON.stringify(s.slice(0, 160))); }
  const rf = [...new Set(pc.refs)].filter((r) => !/^C:java\/lang\/(?:Object|String)$/.test(r)).slice(0, 120); if (rf.length) { L.push('// başvurulan sınıf/metotlar (' + rf.length + ')'); for (const r of rf) L.push('//   ' + r); }
  return L.join('\n') + '\n';
}
async function buildJavaOutline(u8, kind, name, ctx) {
  if (kind === 'java-class') { const pc = parseClass(u8, false); if (!pc) throw new Error('class dosyası ayrıştırılamadı'); return { text: javaOutline(pc, name), partial: false }; }
  const en = readZip(u8); const cls = en.filter((e) => /\.class$/.test(e.name) && !e.dir); let out = ['// ' + name + ' — yapı dökümü (kaynak kodu DEĞİLDİR): ' + cls.length + ' sınıf'], budget = OBF_LIM.jarBudget, partial = false, done = 0, skipped = 0, bad = 0; const mf = en.find((e) => /^META-INF\/MANIFEST\.MF$/i.test(e.name));
  if (mf) { try { out.push('// ---- MANIFEST.MF ----\n' + td8.decode(await readEntry(u8, mf, 1e5)).split('\n').map((x) => '// ' + x.trim()).join('\n')); } catch (e) {} }
  for (const e of cls.slice(0, OBF_LIM.entries)) { obfCheck(ctx); if (done % 20 === 0) { await obfTick(); obfProg(ctx, 50 + (done / Math.max(1, Math.min(cls.length, OBF_LIM.entries))) * 30, 'Sınıf dökümü ' + done + '/' + Math.min(cls.length, OBF_LIM.entries)); } if (e.enc || e.size > OBF_LIM.entryCap || budget < e.size) { skipped++; partial = true; continue; } try { const d = await readEntry(u8, e, OBF_LIM.entryCap); budget -= d.length; const pc = parseClass(d, false); if (!pc) { bad++; continue; } out.push(javaOutline(pc, e.name)); done++; } catch (er) { bad++; partial = true; } if (out.join('').length > OBF_LIM.outMax) { partial = true; ctx.limits.push('Çıktı boyutu sınırına ulaşıldı.'); break; } }
  if (cls.length > OBF_LIM.entries) { partial = true; ctx.limits.push('İlk ' + OBF_LIM.entries + ' sınıf dökümlendi (toplam ' + cls.length + ').'); }
  if (skipped) ctx.limits.push(skipped + ' sınıf boyut/şifre/bütçe sınırı nedeniyle atlandı.'); if (bad) ctx.limits.push(bad + ' sınıf ayrıştırılamadı.');
  return { text: out.join('\n\n'), partial, done };
}
function buildNetOutline(u8, name) {
  const p = parsePE(u8); const n = parseNet(u8, p); if (!n) throw new Error('.NET meta verisi okunamadı'); const L = ['// ' + name + ' — .NET yapı dökümü (C# kaynağı DEĞİLDİR; IL gövdeleri çözülmedi)', '// çalışma zamanı: ' + n.runtime]; if (n.asm) L.push('// assembly: ' + n.asm.name + ' ' + n.asm.version); if (n.partial) L.push('// UYARI: meta veri kısmen okundu: ' + n.partial);
  if (n.counts) L.push('// tablo satırları: ' + JSON.stringify(n.counts)); if (n.names) L.push('// ad kalitesi: ' + n.names.weird + ' / ' + n.names.total + ' ad anlamsız');
  const sec = (t, a, f) => { if (a && a.length) { L.push('', '// ---- ' + t + ' (' + a.length + ') ----'); for (const x of a.slice(0, 400)) L.push(f ? f(x) : x); } };
  sec('Başvurulan assembly\'ler', n.asmRefs); sec('P/Invoke (yerel çağrılar)', n.pinvoke, (x) => (x.dll || '?') + '!' + x.fn); sec('Kaynaklar', n.resources, (x) => (typeof x === 'string' ? x : JSON.stringify(x))); sec('Başvurulan türler', [...new Set(n.typeRefs || [])]); sec('Başvurulan üyeler', [...new Set(n.memberRefs || [])]);
  return { text: L.join('\n') + '\n', partial: !!n.partial };
}
const OBF_DISCLAIMER = 'Deobfuscation özgün kaynak kodu geri getirmeyi garanti etmez: yalnızca statik, anlamı koruyan metin dönüşümleri uygulanır; kod çalıştırmayı gerektiren (dize şifreleme, sanallaştırma, kontrol akışı düzleştirme) gizlemeler açılamaz. Yapı dökümü gerçek bir decompile çıktısı değildir. Tespit güveni istatistikseldir ve yanılabilir.';
function obfReportMd(r) {
  const L = ['# StatScan obfuscation raporu', '', '- Dosya: `' + r.file.name + '` (' + r.file.size + ' bayt)' + (r.file.sha256 ? '\n- SHA-256: `' + r.file.sha256 + '`' : ''), '- Tür: ' + (r.kind ? r.kind.label + ' (güven %' + r.kind.conf + '; dayanak: ' + r.kind.basis + ')' : 'belirlenemedi'), '- Durum: **' + r.statusLabel + '**' + (r.reason ? ' — ' + r.reason : ''), '- Tarih: ' + new Date().toISOString(), ''];
  L.push('## Obfuscation analizi', '', r.obfuscation.summary || '—', ''); for (const m of r.obfuscation.methods) L.push('- **' + m.label + '** — güven %' + m.conf + ' · ' + ({ fact: 'Gözlem', inference: 'Çıkarım', heuristic: 'Sezgisel' }[m.basis] || m.basis) + (m.ev.length ? ' · kanıt: ' + m.ev.join(' | ') : '') + (m.resolved === false ? ' · **otomatik açılamadı**: ' + (m.why || '') : m.resolved ? ' · açıldı' : ''));
  L.push('', '## Tamamlanan işlemler', ''); for (const s of r.steps) L.push('- [' + ({ done: 'tamam', partial: 'kısmi', skipped: 'atlandı', unsupported: 'yapılmıyor', failed: 'başarısız', na: 'uygulanamaz' }[s.status] || s.status) + '] ' + s.label + (s.note ? ' — ' + s.note : ''));
  L.push('', '## Araçlar', '', '- Yerleşik: ' + (r.tools.builtin.join(', ') || '—'), '- Harici (kullanılan): ' + (r.tools.used.join(', ') || 'yok'), '- Harici (bu tür için uygun adaylar): ' + (r.externalPlan.join(', ') || 'yok'));
  if (r.outputs.length) { L.push('', '## Çıktılar', ''); for (const o of r.outputs) if (o.kind !== 'report') L.push('- `' + o.name + '` — ' + o.note + (o.partial ? ' **(KISMİ)**' : '')); }
  if (r.limits.length || r.notes.length) { L.push('', '## Sınırlar ve notlar', ''); for (const x of r.limits.concat(r.notes)) L.push('- ' + x); }
  L.push('', '> ' + OBF_DISCLAIMER, ''); return L.join('\n');
}
const OBF_UNRES = { js_hexids: 'anlamsız tanımlayıcı adları geri getirilemez (özgün adlar dosyada yok)', py_names: 'özgün adlar geri getirilemez', vbs_randnames: 'özgün adlar geri getirilemez', ps_bracevars: 'değişken adları geri getirilemez', js_stringarray: 'dize dizisi kod çalıştırmadan çözülemez', js_rotate: 'döndürme/şifre çözme işlevi çalıştırmayı gerektirir', js_cff: 'kontrol akışı düzleştirme otomatik geri alınmaz', js_jsfuck: 'JSFuck yalnızca çalıştırılarak çözülür', js_aajj: 'aaencode/jjencode yalnızca çalıştırılarak çözülür', js_evalchain: 'eval içeriği üretildiği an görülür; çalıştırılmadı', py_pyarmor: 'PyArmor çalışma zamanı anahtarı gerektirir', py_marshal: 'bytecode; harici decompiler gerekir', ps_xor: 'XOR anahtarı/akışı statik olarak çözülmedi', ps_compress: 'sıkıştırılmış yük yalnızca yazım biçimi uygunsa açılır', vbs_exec: 'Execute/Eval içeriği çalıştırılmadı', bat_delayed: '!var! genişletmesi statik çözülmedi', bat_replace: '%v:a=b% değiştirmeleri çözülmedi', sh_b64exec: 'kabuğa borulanan yük çalıştırılmadı' };

/* ----- ana giris ----- */
async function obfRun(u8, name, opts) {
  opts = opts || {}; const ctx = { signal: opts.signal, onProgress: opts.onProgress, scan: opts.scan || null, steps: [], limits: [], notes: [] };
  const res = { tool: 'StatScan', feature: 'obfuscation', version: '4.9.4', file: { name, size: u8.length, sha256: null }, status: 'failed', statusLabel: 'Başarısız', reason: '', kind: null, supported: false, obfuscation: { detected: null, confidence: 0, level: '', methods: [], summary: '' }, steps: ctx.steps, outputs: [], tools: { builtin: [], external: [], used: [] }, externalPlan: [], limits: ctx.limits, notes: ctx.notes, disclaimer: OBF_DISCLAIMER };
  const base = baseName(name).replace(/\.[^.]*$/, '') || 'cikti'; const out = (n, mime, text, note, kind, extra) => { const o = Object.assign({ name: n, mime, note, kind: kind || 'output' }, extra || {}); if (typeof text === 'string') o.text = text; else o.bytes = text; res.outputs.push(o); return o; };
  const finish = (status, reason) => { res.status = status; res.statusLabel = { done: 'Tamamlandı', partial: 'Kısmi', unsupported: 'Desteklenmiyor', refused: 'Durduruldu', failed: 'Başarısız', cancelled: 'İptal edildi' }[status]; res.reason = reason || res.reason; if (status !== 'done' && status !== 'partial') for (const o of res.outputs) if (o.kind !== 'report') o.partial = true; out('rapor.md', 'text/markdown', obfReportMd(res), 'İnsan okunur rapor', 'report'); out('rapor.json', 'application/json', JSON.stringify(Object.assign({}, res, { outputs: res.outputs.filter((o) => o.kind !== 'report').map((o) => ({ name: o.name, note: o.note, partial: !!o.partial, size: o.text ? o.text.length : (o.bytes ? o.bytes.length : 0) })) }), null, 2), 'Makine okunur rapor', 'report'); return res; };
  try {
    obfProg(ctx, 2, 'Dosya türü belirleniyor'); res.file.sha256 = await digest('SHA-256', u8); obfCheck(ctx);
    const k = obfKind(u8, name); res.kind = { id: k.id, label: OBF_LABEL[k.id] || k.id, conf: k.conf, basis: k.basis }; res.tools.builtin.push('tür tespiti (imza/uzantı/içerik)');
    obfStep(ctx, 'kind', 'Dosya türü tespiti', k.id === 'unknown' ? 'failed' : 'done', res.kind.label + ' — ' + k.basis + (k.conf < 80 ? ' (güven düşük: uzantı yok, içerik sezgisi)' : ''));
    if (k.id === 'unknown') { res.obfuscation.summary = 'Tür belirlenemediği için analiz yapılmadı.'; return finish('unsupported', 'Dosya türü belirlenemedi veya desteklenmiyor. Desteklenenler: JavaScript, PowerShell, VBScript/VBA, batch, Python, kabuk betiği; .NET, Java (.class/JAR), APK, ELF, Mach-O ve yerel PE (yalnızca obfuscation analizi).'); }
    if (k.id === 'document' || k.id === 'archive') { res.obfuscation.summary = 'Bu tür bir ' + (k.id === 'document' ? 'belge' : 'arşiv') + 'tir; doğrudan obfuscation analizi uygulanmaz.'; return finish('unsupported', 'Belge/arşiv türleri için önce ana tarayıcıdaki içerik çözümlemesini kullan; içindeki betik/ikili dosyayı ayrıca ver.'); }
    res.supported = true; const lim = k.src ? OBF_LIM.srcMax : OBF_LIM.binMax; if (u8.length > lim) { res.obfuscation.summary = 'Dosya çok büyük olduğu için analiz yapılmadı.'; return finish('refused', 'Dosya boyutu (' + Math.round(u8.length / 1048576) + ' MB) bu tür için güvenli sınırı (' + Math.round(lim / 1048576) + ' MB) aşıyor; arayüzü kilitlememek için işlem durduruldu.'); }
    let M = [];
    if (k.src) {
      obfProg(ctx, 10, 'Kaynak kodu okunuyor'); const text = decodeText(u8); res.tools.builtin.push('kaynak obfuscation göstergeleri'); await obfTick(); obfCheck(ctx); M = obfDetectSource(k.id, text); obfProg(ctx, 30, 'Obfuscation analizi'); const conf = noisyOr(M.filter((m) => m.id !== 'js_minified').map((m) => m.conf)); const hasMin = M.some((m) => m.id === 'js_minified');
      res.obfuscation = { detected: conf >= 40 ? true : (conf >= 20 ? null : false), confidence: conf, level: lvl(conf), methods: M, summary: conf >= 40 ? 'Obfuscation tespit edildi (güven %' + conf + ', ' + lvl(conf) + '): ' + M.slice(0, 4).map((m) => m.label).join('; ') + '.' : (conf >= 20 ? 'Olası obfuscation (güven %' + conf + '); kanıtlar zayıf, kesin söylenemez.' : 'Obfuscation tespit edilmedi' + (hasMin ? ' (yalnızca sıkıştırma/minify izleri var)' : '') + '.') };
      obfStep(ctx, 'detect', 'Obfuscation analizi', 'done', res.obfuscation.summary);
      if (conf >= 20) {
        obfProg(ctx, 40, 'Deobfuscation dönüşümleri'); res.tools.builtin.push('statik metin dönüşümleri (eval/çalıştırma yok)'); const rr = await runPipe(text, k.id, ctx); let body = rr.text; const nChange = rr.steps.reduce((a, s) => a + s.n, 0);
        const lay = { layers: [] }; obfProg(ctx, 65, 'Kodlanmış katmanlar'); await peelLayers(text, k.id, ctx, 1, lay); 
        let pretty = false; if (k.id === 'js' && (nChange || M.some((m) => m.id === 'js_packer')) ) { try { const b = jsBeautify(body); if (b.length < OBF_LIM.outMax) { body = b; pretty = true; } } catch (e) {} }
        for (const s of rr.steps) obfStep(ctx, s.id, s.label, 'done', s.n + ' yerde');
        if (!rr.steps.length) obfStep(ctx, 'transform', 'Güvenli dönüşümler', 'skipped', 'Uygulanabilir sabit dönüşüm bulunamadı');
        const ext = { js: 'js', ps: 'ps1', vbs: 'vbs', bat: 'bat', py: 'py', sh: 'sh' }[k.id];
        if (nChange || pretty) out(base + '.deobf.' + ext, 'text/plain', body, 'Statik olarak çözülmüş/okunabilir hâl' + (pretty ? ' (biçimlendirildi; anlam değişmez)' : '') + '. Orijinal dosyadan farklıdır; özgün kaynak olmayabilir.');
        for (const l of lay.layers) { if (l.text !== undefined) out(base + '.katman' + l.id + '.' + ({ ps: 'ps1', py: 'py', js: 'js', vbs: 'vbs', bat: 'bat', sh: 'sh' }[l.lang] || 'txt'), 'text/plain', l.text, 'Kodlanmış katman ' + l.id + ' — ' + l.from); else out(base + '.katman' + l.id + '.bin', 'application/octet-stream', l.bin, 'Kodlanmış katman ' + l.id + ' (' + l.kind.toUpperCase() + ', ' + l.size + ' bayt) — ' + l.from + '. Çalıştırılmadı; ayrıca taranabilir.'); }
        if (lay.layers.length) obfStep(ctx, 'layers', 'Base64/sıkıştırma katmanları açıldı', 'done', lay.layers.length + ' katman'); else obfStep(ctx, 'layers', 'Base64/sıkıştırma katmanları', 'skipped', 'Çözülebilir katman bulunamadı');
        obfProg(ctx, 85, 'Doğrulama'); const after = obfDetectSource(k.id, body).filter((m) => m.id !== 'js_minified'); const conf2 = noisyOr(after.map((m) => m.conf));
        for (const m of M) { if (OBF_UNRES[m.id]) { m.resolved = false; m.why = OBF_UNRES[m.id]; } else if (nChange || lay.layers.length) m.resolved = after.every((a) => a.id !== m.id); if (m.resolved === false) m.why = 'çıktıda gösterge hâlâ görülüyor'; }
        if (nChange || lay.layers.length) obfStep(ctx, 'verify', 'Çıktı yeniden analiz edildi', 'done', 'kalan obfuscation güveni %' + conf2 + ' (önce %' + conf + ')');
        const unres = M.filter((m) => m.resolved === false); if (unres.length) { obfStep(ctx, 'unresolved', 'Otomatik açılamayan yöntemler', 'partial', unres.map((m) => m.label).join('; ')); ctx.notes.push('Açılamayan yöntemler çıktıda hâlâ gizli kalabilir: ' + unres.map((m) => m.label + ' (' + m.why + ')').join('; ')); }
        if (!nChange && !lay.layers.length && !pretty) ctx.notes.push('Obfuscation göstergeleri var ama güvenli statik dönüşümlerle değiştirilebilen bir şey bulunamadı; çıktı üretilmedi.');
        const hasOut = res.outputs.length > 0; return finish(hasOut && !unres.length ? 'done' : (hasOut ? 'partial' : 'done'), hasOut ? (unres.length ? 'Bazı gizleme yöntemleri otomatik açılamadı.' : '') : 'Çıktı üretilmedi.');
      }
      obfStep(ctx, 'transform', 'Deobfuscation', 'skipped', 'Obfuscation tespit edilmediği için uygulanmadı'); return finish('done', '');
    }
    /* ikili turler */
    obfProg(ctx, 12, 'İkili yapı inceleniyor'); res.tools.builtin.push('ikili obfuscation göstergeleri'); res.externalPlan = OBF_TOOLS[k.id] || []; await obfTick(); obfCheck(ctx);
    M = await obfDetectBinary(k.id, u8, name, ctx); const conf = noisyOr(M.map((m) => m.conf));
    res.obfuscation = { detected: conf >= 40 ? true : (conf >= 20 ? null : false), confidence: conf, level: lvl(conf), methods: M, summary: conf >= 40 ? 'Obfuscation/paketleme tespit edildi (güven %' + conf + ', ' + lvl(conf) + '): ' + M.slice(0, 4).map((m) => m.label).join('; ') + '.' : (conf >= 20 ? 'Olası obfuscation/paketleme (güven %' + conf + '); kanıtlar zayıf.' : 'Obfuscation tespit edilmedi.') };
    if (!ctx.scan && (k.id === 'pe' || k.id === 'dotnet' || k.id === 'elf' || k.id === 'macho')) ctx.notes.push('Bölüm entropisi/import gibi göstergeler için ana tarama sonucu verilmedi; yalnızca bayt desenleri kullanıldı.');
    obfStep(ctx, 'detect', 'Obfuscation/paketleme analizi', 'done', res.obfuscation.summary); obfProg(ctx, 40, 'Yapı dökümü');
    if (k.id === 'java-class' || k.id === 'jar') { const r = await buildJavaOutline(u8, k.id, name, ctx); res.tools.builtin.push('yerleşik Java sınıf yapı dökümü'); out(base + '.yapi.txt', 'text/plain', r.text, 'Sınıf/metot/dize/başvuru dökümü — gerçek decompile DEĞİL', 'output', { partial: !!r.partial }); obfStep(ctx, 'outline', 'Java yapı dökümü', r.partial ? 'partial' : 'done', (r.done || 1) + ' sınıf'); obfStep(ctx, 'decompile', 'Java decompile (CFR/Procyon/jadx)', 'unsupported', 'Yerleşik değil; makinede kurulu bir decompiler varsa masaüstü uygulamasında onayla çalıştırılabilir'); }
    else if (k.id === 'dotnet') { const r = buildNetOutline(u8, name); res.tools.builtin.push('yerleşik .NET meta veri dökümü'); out(base + '.yapi.txt', 'text/plain', r.text, '.NET meta veri dökümü — gerçek decompile DEĞİL', 'output', { partial: !!r.partial }); obfStep(ctx, 'outline', '.NET meta veri dökümü', r.partial ? 'partial' : 'done', 'türler, üyeler, P/Invoke, kaynaklar'); obfStep(ctx, 'decompile', '.NET decompile (ilspycmd)', 'unsupported', 'Yerleşik değil; kurulu ilspycmd varsa masaüstü uygulamasında onayla çalıştırılabilir'); }
    else if (k.id === 'asar') {
      const a = asarParse(u8); if (!a) { obfStep(ctx, 'unpack', 'asar açma', 'failed', 'Başlık okunamadı'); } else {
        res.tools.builtin.push('yerleşik asar okuyucu'); const app = a.files.filter((f) => f.offset >= 0 && f.size > 0 && !/(^|\/)node_modules\//.test(f.path)); let nOut = 0, bytes = 0, nDeobf = 0, skipped = 0; const nm = a.files.filter((f) => /(^|\/)node_modules\//.test(f.path)).length;
        for (const f of app) {
          if (nOut >= OBF_LIM.entries || bytes + f.size > OBF_LIM.outMax || a.base + f.offset + f.size > u8.length) { skipped++; continue; } obfCheck(ctx); const data = u8.slice(a.base + f.offset, a.base + f.offset + f.size); bytes += f.size; nOut++;
          out('asar-icerik/' + f.path, 'application/octet-stream', data, 'asar içinden çıkarıldı (değiştirilmedi)', 'output');
          if (/\.(?:js|cjs|mjs)$/i.test(f.path) && f.size <= 2e6) { const t = decodeText(data); const mm = obfDetectSource('js', t); const cf = noisyOr(mm.filter((m) => m.id !== 'js_minified').map((m) => m.conf)); if (cf >= 20) { const rr = await runPipe(t, 'js', ctx); if (rr.steps.some((x) => x.n > 0)) { nDeobf++; out('asar-deobf/' + f.path.replace(/\.[^.]*$/, '') + '.deobf.js', 'text/javascript', rr.text, 'Statik dönüşümler uygulandı (eval/çalıştırma yok); orijinal kaynak olmayabilir', 'output'); } M.push({ id: 'asar_js_' + nOut, label: f.path + ' dosyasında obfuscation (güven %' + cf + ')', conf: cf, ev: mm.slice(0, 2).map((x) => x.label), basis: 'heuristic', resolved: false, why: 'statik dönüşümler tam çözüm sağlamayabilir' }); } }
          if (nOut % 25 === 0) { obfProg(ctx, Math.min(80, 40 + nOut / 5), 'asar içeriği çıkarılıyor'); await obfTick(); }
        }
        obfStep(ctx, 'unpack', 'asar içeriği çıkarıldı', skipped ? 'partial' : 'done', nOut + ' dosya' + (nm ? ' · ' + nm + ' node_modules dosyası atlandı' : '') + (skipped ? ' · ' + skipped + ' dosya sınır nedeniyle çıkarılmadı' : '') + (nDeobf ? ' · ' + nDeobf + ' JS dosyasına statik deobfuscation uygulandı' : '')); if (skipped) ctx.limits.push({ kind: 'out', msg: skipped + ' dosya çıktı sınırı nedeniyle çıkarılmadı.' });
        const unp = a.files.filter((f) => f.unpacked).length; if (unp) ctx.notes.push(unp + ' dosya .asar.unpacked klasöründe; bu dosyada bulunmadığı için çıkarılamadı.');
        res.obfuscation = Object.assign(res.obfuscation, { methods: M }); const cf2 = noisyOr(M.map((m) => m.conf)); res.obfuscation = { detected: cf2 >= 40 ? true : (cf2 >= 20 ? null : false), confidence: cf2, level: lvl(cf2), methods: M, summary: cf2 >= 40 ? 'Uygulama JS dosyalarında obfuscation tespit edildi (güven %' + cf2 + ').' : (cf2 >= 20 ? 'Olası obfuscation (güven %' + cf2 + ').' : 'Obfuscation tespit edilmedi.') };
      }
    }
    else if (k.id === 'apk') { obfStep(ctx, 'decompile', 'APK/DEX decompile (jadx)', 'unsupported', 'Yerleşik değil; kurulu jadx varsa masaüstü uygulamasında onayla çalıştırılabilir'); }
    else {
      if (k.id === 'pe' || k.id === 'elf') {
        obfProg(ctx, 55, 'Yerel kod disassembly / işlev keşfi'); await obfTick(); let nr = null; try { nr = natAnalyze(u8, {}); } catch (e) { obfStep(ctx, 'native', 'Yerel kod disassembly', 'failed', String(e && e.message || e).slice(0, 100)); }
        if (nr && !nr.ok) obfStep(ctx, 'native', 'Yerel kod disassembly', 'unsupported', nr.reason || 'Desteklenmiyor');
        else if (nr) {
          res.tools.builtin.push('yerleşik x86/x64 disassembler + işlev keşfi (çalıştırma yok)'); const mn = nr.main; const part = !!(nr.limits.length || nr.undecoded || mn.level === 'bulunamadı');
          out(base + '.ana-kod.asm', 'text/plain', nr.mainText, 'Ana kod ' + (mn.addr !== null ? '[' + mn.level + ']' : '[bulunamadı]') + ' + doğrudan çağırdığı işlevler — birebir disassembly, tahmin/decompile DEĞİL', 'output', { partial: part });
          out(base + '.tum-kod.asm', 'text/plain', nr.allText, nr.funcs.length + ' işlevin tamamı (keşfedilebilen kod) — birebir disassembly', 'output', { partial: part });
          out(base + '.cagri-grafigi.txt', 'text/plain', nr.graphText, 'İşlev çağrı grafiği, import ve çözülemeyen dolaylı çağrılar', 'report');
          obfStep(ctx, 'native', 'Yerel kod disassembly ve ana kod', part ? 'partial' : 'done', nr.funcs.length + ' işlev, ' + nr.total + ' komut · ana kod: ' + (mn.addr !== null ? '0x' + natHex(mn.addr) + ' [' + mn.level + ']' : 'bulunamadı') + ' — ' + mn.method + (nr.undecoded ? ' · ' + nr.undecoded + ' yerde komut çözülemedi' : ''));
          for (const n of nr.notes) ctx.notes.push(n); for (const l of nr.limits) ctx.limits.push({ kind: 'native', msg: l }); if (mn.level === 'sezgisel' || mn.level === 'giriş-noktası') ctx.notes.push('Ana kod ' + (mn.level === 'sezgisel' ? 'kalıp eşleştirmesiyle' : 'CRT deseni bulunamadığı için giriş noktası olarak') + ' belirlendi; kanıtlar ana-kod.asm başlığında. Komut listesi birebirdir, ana işlev seçimi kesin değildir.');
          if (res.obfuscation.detected) ctx.notes.push('Paketleme/obfuscation tespit edildi: disassembly paketleyici/açıcı kodunu gösteriyor olabilir; gerçek program için önce açılması gerekir.');
        }
      }
      obfStep(ctx, 'decompile', 'Yerel kod → C (decompile)', 'unsupported', 'Yerleşik C benzeri decompiler YOK (tahmin üretmemek için bilerek). ' + (k.id === 'pe' || k.id === 'elf' ? 'Yerine birebir disassembly ve ana kod listesi üretildi. ' : '') + 'Masaüstü uygulamasında makinede kurulu IDA Pro (Hex-Rays) veya Ghidra onayınla çalıştırılabilir.' + (res.obfuscation.detected ? ' DİKKAT: paketleme/obfuscation tespit edildi; paketli dosyada çıktı çoğunlukla anlamsızdır, önce açılması gerekir.' : ''));
    }
    if (k.id === 'pe' || k.id === 'elf') {
      let ex = null; try { ex = await pyiExtract(u8, { cap: OBF_LIM.outMax }); } catch (e) { obfStep(ctx, 'unpack', 'PyInstaller içeriği', 'failed', String(e && e.message || e).slice(0, 80)); }
      if (ex && ex.info && !ex.info.bad) {
        res.tools.builtin.push('yerleşik PyInstaller açıcı (çalıştırma yok)'); let nOut = 0, bytes = 0, skipped = 0; const idx = ['# PyInstaller içeriği', '', ex.info.py + ' · giriş betikleri: ' + (ex.info.scripts.join(', ') || '—'), 'Not: .pyc dosyaları StatScan içinde DECOMPILE edilmedi. Kaynak için masaüstü uygulamasındaki düğmeyi veya güvenli bir ortamda pycdc/uncompyle6/decompyle3 kullan.', ''];
        for (const f of ex.files) { if (f.lib || f.kind === 'binary') { continue; } if (nOut >= OBF_LIM.entries || bytes + f.bytes.length > OBF_LIM.outMax) { skipped++; continue; } nOut++; bytes += f.bytes.length; out('pyinstaller/' + f.path, 'application/octet-stream', f.bytes, f.kind === 'data' ? 'veri girdisi' : '.pyc (başlık eklendi; decompile edilmedi)', 'output'); idx.push('- ' + f.path + ' (' + f.bytes.length + ' bayt)'); }
        const strs = []; for (const f of ex.files) if ((f.kind === 'script' || (f.kind === 'module' && !f.lib)) && f.raw) strs.push('## ' + f.path, ...pyConstText(f.raw).slice(0, 400)); if (strs.length) out('pyinstaller/sabit-dizeler.txt', 'text/plain', strs.join('\n'), 'Betik/modüllerdeki dize sabitleri (marshal verisinden)', 'output');
        out('pyinstaller/ozet.md', 'text/markdown', idx.join('\n') + '\n', 'Çıkarılan dosyaların listesi', 'report');
        obfStep(ctx, 'unpack', 'PyInstaller içeriği çıkarıldı', ex.info.encrypted || skipped ? 'partial' : 'done', nOut + ' dosya · ' + ex.info.ownMods + ' özgün modül, ' + ex.info.libMods + ' kütüphane modülü (kütüphaneler çıkarılmadı)' + (ex.info.encrypted ? ' · ARŞİV ŞİFRELİ: içerik eksik' : '') + (skipped ? ' · ' + skipped + ' dosya sınır nedeniyle atlandı' : ''));
        obfStep(ctx, 'pydecomp', 'Python bytecode decompile', 'unsupported', 'Yerleşik decompiler yok; .pyc dosyaları çıkarıldı. Masaüstü uygulamasında kurulu pycdc/decompyle3/uncompyle6 varsa aşağıdaki düğmeyle (onayla) çevrilir');
        if (ex.info.encrypted) ctx.notes.push('PYZ şifreli olduğu için modüllerin bir kısmı çıkarılamadı; çıktı eksiktir.'); if (skipped) ctx.limits.push({ kind: 'out', msg: skipped + ' dosya çıktı sınırı nedeniyle çıkarılmadı.' });
      }
    }
    if (k.id !== 'asar') obfStep(ctx, 'deobf', 'Otomatik deobfuscation', res.obfuscation.detected ? 'unsupported' : 'skipped', res.obfuscation.detected ? 'İkili dosyalarda otomatik açma yapılmaz (ör. UPX açma/ConfuserEx temizleme için harici, güvenilir araçlar gerekir)' : 'Gerek yok');
    const encr = ctx.steps.some((x) => x.id === 'unpack' && x.status === 'partial'); const ps = res.outputs.some((o) => o.partial) || ctx.limits.length || encr; return finish(ps ? 'partial' : 'done', ps ? (encr && !ctx.limits.length ? 'Paketin içeriği tam açılamadı (ör. şifreli arşiv); çıktı eksik.' : 'Bazı girdiler sınırlar nedeniyle atlandı.') : '');
  } catch (e) {
    if (e && e.cancelled) { obfStep(ctx, 'cancel', 'İşlem', 'failed', 'Kullanıcı iptal etti'); return finish('cancelled', 'İşlem kullanıcı tarafından iptal edildi; çıktılar eksik.'); }
    obfStep(ctx, 'error', 'İşlem', 'failed', String((e && e.message) || e)); return finish('failed', 'Analiz tamamlanamadı: ' + String((e && e.message) || e) + '. Üretilen kısmi çıktılar güvenilir sayılmamalı.');
  }
}
