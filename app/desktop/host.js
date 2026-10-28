'use strict';
/* StatScan masaustu: ana surec ile arayuz arasindaki (IPC) kopru.
 * Electron'a dogrudan bagimli degildir; test icin sahte nesnelerle calisir.
 * Arayuz (renderer) yalnizca burada tanimli kanallari cagirabilir; keyfi komut, klasor veya yol gonderemez. */
const D = require('../dyn/statscan-dyn.js');
const fs = require('fs'); const path = require('path');
/* --- harici decompiler koprusu (eski obf.js; guncelleyici yeni dosya yoluna izin vermedigi icin burada) --- */
const OBFMOD = (() => { const module = { exports: {} }; const exports = module.exports;
'use strict';
/* StatScan masaustu: harici decompiler koprusu (yalnizca ONAYLA, yalnizca YEREL, sessiz indirme/kurulum YOK).
 * - Yalnizca makinede zaten kurulu bilinen araclari bulur (PATH ve <userData>/tools icindeki .jar dosyalari).
 * - Arayuz arac yolu/komut gonderemez; yalnizca bilinen arac kimligi (ilspycmd, cfr, procyon, jadx) secebilir.
 * - Arac shell olmadan, arguman dizisiyle, zaman asimiyla ve kendi gecici klasorunde calistirilir.
 * - Incelenen dosya hicbir zaman calistirilir degildir: arac onu yalnizca OKUR.
 * - Cikti her zaman ayri bir klasore yazilir; orijinal dosyaya hicbir sey yazilmaz. */
const fs = require('fs'); const path = require('path'); const os = require('os'); const cp = require('child_process'); const crypto = require('crypto');

const MAX_IN = 200 * 1024 * 1024; const MAX_OUT_FILES = 20000; const MAX_OUT_BYTES = 500 * 1024 * 1024; const TAIL = 8192;
const TOOLS = {
  ilspycmd: { label: 'ILSpy (ilspycmd)', kinds: ['dotnet'], exe: ['ilspycmd'], args: (i, o) => ['-o', o, i], inExt: ['.dll', '.exe'] },
  cfr: { label: 'CFR', kinds: ['jar', 'java-class'], exe: ['cfr', 'cfr-decompiler'], jar: /^cfr[-_.\d\w]*\.jar$/i, args: (i, o) => [i, '--outputdir', o], inExt: ['.jar', '.class'] },
  procyon: { label: 'Procyon', kinds: ['jar', 'java-class'], exe: ['procyon-decompiler', 'procyon'], jar: /^procyon-decompiler[-_.\d\w]*\.jar$/i, args: (i, o) => ['-o', o, i], inExt: ['.jar', '.class'] },
  jadx: { label: 'jadx', kinds: ['apk', 'jar'], exe: ['jadx'], args: (i, o) => ['-d', o, i], inExt: ['.apk', '.jar', '.dex'] },
  /* Python bytecode (.pyc) -> kaynak: yalnizca kullanicinin KENDI kurdugu araclar; startPyc ile calisir */
  pycdc: { label: 'pycdc', kinds: ['pyc'], pyc: true, exe: ['pycdc'], mode: 'stdout', note: 'pycdc her .pyc dosyasını okuyup Python kaynağı üretir; desteklenmeyen bytecode için kısmi/eksik çıktı verebilir.' },
  decompyle3: { label: 'decompyle3', kinds: ['pyc'], pyc: true, exe: ['decompyle3'], mode: 'outdir', note: 'Python 3.7–3.8 bytecode için.' },
  uncompyle6: { label: 'uncompyle6', kinds: ['pyc'], pyc: true, exe: ['uncompyle6'], mode: 'outdir', note: 'Python 2.x–3.8 bytecode için; daha yeni sürümlerde çalışmaz.' },
  /* yerel kod: kullanicinin KENDI kurulu IDA / Ghidra'si. Betikleri StatScan sabit olarak uretir (girdiden gelmez). */
  ida: { label: 'IDA Pro (Hex-Rays)', kinds: ['pe', 'elf', 'macho'], exe: ['idat64', 'idat'], native: true, timeout: 3600000, maxTimeout: 14400000, inExt: ['.exe', '.dll', '.sys', '.so', '.elf', '.bin', '.dylib'], valid: /^idat(64)?(\.exe)?$/i,
    note: 'IDA dosyayı yalnızca yükleyip analiz eder (çalıştırmaz). IDA kendi ayarlarına göre PDB/sembol aramaya çalışabilir; ağ gerekmesin diye IDA ayarlarında sembol sunucusunu kapalı tut.',
    script: { name: 'statscan_ida.py', body: "import io, os, traceback\nOUT = os.environ.get('STATSCAN_OUT', '.')\nST = {'tool': 'ida', 'functions': 0, 'decompiled': 0, 'failed': 0, 'skipped': 0, 'hexrays': 'bilinmiyor', 'error': ''}\nMAXF = int(os.environ.get('STATSCAN_MAXF', '1000000'))\nMAXC = 400000000\ndef finish():\n    try:\n        with io.open(os.path.join(OUT, '_statscan_status.txt'), 'w', encoding='utf-8') as f:\n            for k in ST:\n                f.write(u'%s=%s\\n' % (k, ST[k]))\n    except Exception:\n        pass\n    try:\n        import ida_pro\n        ida_pro.qexit(0)\n    except Exception:\n        import idc\n        idc.qexit(0)\ntry:\n    import ida_auto, idc, idautils, ida_funcs, ida_hexrays\n    ida_auto.auto_wait()\n    try:\n        idc.gen_file(idc.OFILE_ASM, os.path.join(OUT, 'disassembly.asm'), 0, idc.BADADDR, 0)\n    except Exception as e:\n        ST['error'] += 'asm:' + str(e) + ' '\n    hx = False\n    try:\n        hx = bool(ida_hexrays.init_hexrays_plugin())\n    except Exception:\n        hx = False\n    ST['hexrays'] = 'var' if hx else 'yok (bu mimari i\u00e7in lisans/eklenti bulunamad\u0131; yaln\u0131zca disassembly \u00fcretildi)'\n    chars = 0\n    with io.open(os.path.join(OUT, 'functions.txt'), 'w', encoding='utf-8') as fl, io.open(os.path.join(OUT, 'decompiled.c'), 'w', encoding='utf-8') as dc:\n        for ea in idautils.Functions():\n            ST['functions'] += 1\n            f = ida_funcs.get_func(ea)\n            nm = idc.get_func_name(ea)\n            fl.write(u'%x\\t%s\\t%d\\n' % (ea, nm, (f.end_ea - f.start_ea) if f else 0))\n            if not hx or ST['functions'] > MAXF or chars > MAXC or (f is not None and (f.flags & ida_funcs.FUNC_LIB or f.flags & ida_funcs.FUNC_THUNK)):\n                ST['skipped'] += 1\n                continue\n            try:\n                cf = ida_hexrays.decompile(ea)\n                s = str(cf)\n                dc.write(u'// %s @ 0x%x\\n%s\\n\\n' % (nm, ea, s))\n                chars += len(s)\n                ST['decompiled'] += 1\n            except Exception:\n                ST['failed'] += 1\nexcept Exception:\n    ST['error'] += traceback.format_exc().replace('\\n', ' | ')[:600]\nfinish()\n" }, args: (i, o, c) => ['-c', '-A', '-S' + c.script, c.base], altArgs: (i, o, c) => ['-c', '-A', '-Ohexrays:-errs:decompiled:ALL', c.base] },
  ghidra: { label: 'Ghidra (headless)', kinds: ['pe', 'elf', 'macho'], exe: ['analyzeHeadless'], winExt: ['.bat'], native: true, timeout: 3600000, maxTimeout: 14400000, inExt: ['.exe', '.dll', '.sys', '.so', '.elf', '.bin', '.dylib'], valid: /^analyzeHeadless(\.bat)?$/i,
    note: 'Ghidra dosyayı yalnızca içe aktarıp analiz eder (çalıştırmaz); proje geçici klasörde oluşturulur ve işlem bitince silinir. Çalışması için Ghidra\'nın kendi JDK\'sı kurulu olmalı.',
    script: { name: 'StatScanDecompile.java', body: "import ghidra.app.script.GhidraScript;\nimport ghidra.app.decompiler.DecompInterface;\nimport ghidra.app.decompiler.DecompileResults;\nimport ghidra.program.model.listing.Function;\nimport ghidra.program.model.listing.FunctionIterator;\nimport java.io.File;\nimport java.io.FileOutputStream;\nimport java.io.OutputStreamWriter;\nimport java.io.Writer;\nimport java.nio.charset.StandardCharsets;\n\npublic class StatScanDecompile extends GhidraScript {\n  @Override\n  public void run() throws Exception {\n    String out = System.getenv(\"STATSCAN_OUT\");\n    if (out == null) out = \".\";\n    int total = 0, ok = 0, fail = 0, skipped = 0;\n    long chars = 0;\n    final int MAXF = 1000000;\n    final long MAXC = 400000000L;\n    String err = \"\";\n    DecompInterface di = new DecompInterface();\n    boolean opened = di.openProgram(currentProgram);\n    if (!opened) err = \"decompiler acilamadi\";\n    try (Writer c = new OutputStreamWriter(new FileOutputStream(new File(out, \"decompiled.c\")), StandardCharsets.UTF_8);\n         Writer fl = new OutputStreamWriter(new FileOutputStream(new File(out, \"functions.txt\")), StandardCharsets.UTF_8)) {\n      FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);\n      while (it.hasNext() && !monitor.isCancelled()) {\n        Function f = it.next();\n        total++;\n        fl.write(f.getEntryPoint() + \"\\t\" + f.getName() + \"\\t\" + f.getBody().getNumAddresses() + \"\\n\");\n        if (!opened || f.isThunk() || f.isExternal() || total > MAXF || chars > MAXC) { skipped++; continue; }\n        try {\n          DecompileResults r = di.decompileFunction(f, 30, monitor);\n          if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {\n            String s = r.getDecompiledFunction().getC();\n            c.write(\"// \" + f.getName() + \" @ \" + f.getEntryPoint() + \"\\n\" + s + \"\\n\\n\");\n            chars += s.length();\n            ok++;\n          } else { fail++; }\n        } catch (Exception e) { fail++; }\n      }\n    }\n    di.dispose();\n    try (Writer st = new OutputStreamWriter(new FileOutputStream(new File(out, \"_statscan_status.txt\")), StandardCharsets.UTF_8)) {\n      st.write(\"tool=ghidra\\nfunctions=\" + total + \"\\ndecompiled=\" + ok + \"\\nfailed=\" + fail + \"\\nskipped=\" + skipped + \"\\nerror=\" + err + \"\\n\");\n    }\n  }\n}\n" }, args: (i, o, c) => [c.projDir, 'statscan', '-import', i, '-scriptPath', c.work, '-postScript', 'StatScanDecompile.java', '-analysisTimeoutPerFile', '600', '-deleteProject'] }
};
const isWin = () => process.platform === 'win32';
function isExec(p) { try { const s = fs.statSync(p); if (!s.isFile()) return false; if (!isWin()) fs.accessSync(p, fs.constants.X_OK); return true; } catch (e) { return false; } }
function which(names, pathEnv, winExt) { for (const dir of String(pathEnv || '').split(path.delimiter)) { if (!dir) continue; for (const n of names) { const cand = path.join(dir, isWin() ? n + (winExt && winExt[0] || '.exe') : n); if (isExec(cand)) return cand; } } return null; }
/* IDA/Ghidra: bilinen kurulum konumlari + IDADIR/GHIDRA_INSTALL_DIR + <tools>/paths.json. Yalnizca bilinen dosya adlari kabul edilir. */
function nativeCandidates(id, env) {
  const t = TOOLS[id]; const out = []; const names = id === 'ida' ? (isWin() ? ['idat64.exe', 'idat.exe'] : ['idat64', 'idat']) : [isWin() ? 'analyzeHeadless.bat' : 'analyzeHeadless'];
  const addDir = (d, via) => { if (!d) return; for (const sub of id === 'ghidra' ? ['support', '.', 'ghidra/support'] : ['.']) for (const n of names) { const c = path.join(d, sub, n); if (isExec(c)) out.push({ path: c, via }); } };
  const E = env || {}; const pe = (k) => (E[k] !== undefined ? E[k] : process.env[k]);
  if (E.userToolsDir) { try { const cfg = JSON.parse(fs.readFileSync(path.join(E.userToolsDir, 'paths.json'), 'utf8')); const p = cfg && typeof cfg[id] === 'string' ? cfg[id] : ''; if (p && path.isAbsolute(p) && t.valid.test(path.basename(p)) && isExec(p)) out.push({ path: p, via: 'tools/paths.json' }); } catch (e) { /* yok */ } }
  addDir(id === 'ida' ? pe('IDADIR') : pe('GHIDRA_INSTALL_DIR'), id === 'ida' ? 'IDADIR' : 'GHIDRA_INSTALL_DIR');
  const roots = E.scanDirs || (isWin() ? [process.env.SystemDrive ? process.env.SystemDrive + '\\' : 'C:\\', process.env.ProgramFiles, process.env['ProgramFiles(x86)'], process.env.USERPROFILE && path.join(process.env.USERPROFILE, 'Downloads'), process.env.USERPROFILE && path.join(process.env.USERPROFILE, 'Desktop'), process.env.USERPROFILE] : []);
  const re = id === 'ida' ? /^IDA(\b|[ _-])/i : /^ghidra/i;
  for (const r of roots) { if (!r) continue; let ents = []; try { ents = fs.readdirSync(r, { withFileTypes: true }); } catch (e) { continue; } for (const e of ents) { if (!e.isDirectory() || e.isSymbolicLink() || !re.test(e.name)) continue; const d = path.join(r, e.name); addDir(d, 'bilinen konum'); if (id === 'ghidra') { try { for (const e2 of fs.readdirSync(d, { withFileTypes: true })) if (e2.isDirectory() && !e2.isSymbolicLink() && re.test(e2.name)) addDir(path.join(d, e2.name), 'bilinen konum'); } catch (e3) {} } } }
  return out;
}
/* env: { path, userToolsDir } */
function detectTools(env) {
  env = env || {}; const out = []; const java = which(['java'], env.path !== undefined ? env.path : process.env.PATH);
  const jars = []; if (env.userToolsDir) { try { for (const f of fs.readdirSync(env.userToolsDir)) { const full = path.join(env.userToolsDir, f); if (/\.jar$/i.test(f) && fs.statSync(full).isFile()) jars.push(full); } } catch (e) {} }
  for (const [id, t] of Object.entries(TOOLS)) {
    if (t.native) { const c = nativeCandidates(id, env); const pe = which(t.exe, env.path !== undefined ? env.path : process.env.PATH, t.winExt); if (pe) c.unshift({ path: pe, via: 'PATH' }); if (c.length) out.push({ id, label: t.label, kinds: t.kinds, path: c[0].path, via: c[0].via }); continue; }
    const exe = which(t.exe, env.path !== undefined ? env.path : process.env.PATH);
    if (exe) { out.push({ id, label: t.label, kinds: t.kinds, path: exe, via: 'PATH' }); continue; }
    if (t.jar && java) { const j = jars.find((x) => t.jar.test(path.basename(x))); if (j) out.push({ id, label: t.label, kinds: t.kinds, path: j, java, via: 'tools klasörü (java -jar)' }); }
  }
  return out;
}
const safeName = (n, d) => { let s = String(n || d || 'cikti').split(/[\\/]/).pop().replace(/[\u0000-\u001f<>:"|?*]/g, '_').replace(/^\.+/, '_').slice(0, 120); return s || d || 'cikti'; };
function minimalEnv() { const e = {}; for (const k of ['PATH', 'SYSTEMROOT', 'SystemRoot', 'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'LANG', 'JAVA_HOME', 'DOTNET_ROOT', 'DOTNET_CLI_HOME']) if (process.env[k]) e[k] = process.env[k]; /* arac ag kullanmaya kalkarsa gecersiz vekile yonlendir (kesin engel degil) */ e.HTTP_PROXY = e.HTTPS_PROXY = e.http_proxy = e.https_proxy = 'http://127.0.0.1:9'; e.NO_PROXY = ''; e.DOTNET_CLI_TELEMETRY_OPTOUT = '1'; return e; }
function toolEnv(t, outDir) { const e = minimalEnv(); e.STATSCAN_OUT = outDir; if (t.native) { /* lisans/yapilandirma icin gerekli degiskenler */ for (const k of ['APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'ProgramFiles', 'ProgramFiles(x86)', 'ComSpec', 'PATHEXT', 'windir', 'USERNAME', 'IDADIR', 'IDAUSR', 'GHIDRA_INSTALL_DIR', 'JAVA_HOME', 'JDK_HOME', 'XDG_CONFIG_HOME', 'DISPLAY']) if (process.env[k]) e[k] = process.env[k]; } return e; }
function walk(root) { const files = []; let bytes = 0; const rec = (d, depth) => { if (depth > 40 || files.length > MAX_OUT_FILES) return; let ents = []; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { return; } for (const e of ents) { const p = path.join(d, e.name); if (e.isSymbolicLink()) continue; if (e.isDirectory()) rec(p, depth + 1); else if (e.isFile()) { const s = fs.statSync(p); bytes += s.size; files.push({ rel: path.relative(root, p).split(path.sep).join('/'), size: s.size }); } } }; rec(root, 0); return { files, bytes }; }
/* ---- decompile edilmis koda fonksiyon bazli risk siralamasi (sezgisel; hukum degil) ---- */
const RISK_GROUPS = [
  ['inject', 22, 'Süreç enjeksiyonu API’leri', /\b(VirtualAllocEx|NtAllocateVirtualMemory|CreateRemoteThread(?:Ex)?|NtCreateThreadEx|RtlCreateUserThread|QueueUserAPC|NtQueueApcThread|SetThreadContext|NtMapViewOfSection|NtWriteVirtualMemory)\b/g, true],
  ['procmem', 6, 'Başka sürecin belleğini okuma/yazma', /\b(WriteProcessMemory|ReadProcessMemory)\b/g, true],
  ['hollow', 25, 'Süreç oyma (unmap section)', /\b(NtUnmapViewOfSection|ZwUnmapViewOfSection)\b/g],
  ['persist', 14, 'Kalıcılık (servis/Run anahtarı/zamanlanmış görev)', /\b(CreateService[AW]?|schtasks|RegSetValueEx[AW]?)\b|CurrentVersion[\\]+Run|Start Menu[\\]+Programs[\\]+Startup/gi],
  ['download', 14, 'İndirme / ağdan veri çekme', /\b(URLDownloadToFile[AW]?|InternetOpenUrl[AW]?|InternetReadFile|WinHttpReadData|HttpSendRequest[AW]?|WinHttpSendRequest)\b/g],
  ['exec', 8, 'Süreç başlatma', /\b(CreateProcess[AW]?|ShellExecute(?:Ex)?[AW]?|WinExec)\s*\(/g],
  ['crypto', 6, 'Şifreleme API’leri', /\b(CryptEncrypt|BCryptEncrypt|CryptGenKey|BCryptGenerateSymmetricKey)\b/g],
  ['cred', 22, 'Kimlik/oturum/tarayıcı verisi göstergesi', /Login Data|[\\]Local State|[\\]Cookies|key4\.db|logins\.json|leveldb|CryptUnprotectData|launcher_accounts|launcher_profiles|accessToken|discord(?:app)?\.com\/api\/(?:v\d+\/)?webhooks|api\.telegram\.org\/bot|wallet\.dat/gi, false, true],
  ['keylog', 16, 'Klavye kancası', /\b(SetWindowsHookEx[AW]?|GetRawInputData)\b/g],
  ['screen', 8, 'Ekran görüntüsü alma', /\b(BitBlt|CreateCompatibleBitmap|GetDIBits|PrintWindow)\b/g],
  ['antidbg', 8, 'Analiz/hata ayıklayıcı kaçınma', /\b(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|NtSetInformationThread|__rdtsc)\b|VMware|VBoxService|vboxguest|SbieDll/g],
  ['dynapi', 5, 'API’leri dinamik çözme', /\b(GetProcAddress|LdrGetProcedureAddress)\b/g],
  ['uac', 10, 'UAC atlatma göstergesi', /fodhelper|eventvwr\.exe|sdclt\.exe|ComputerDefaults|["']runas["']/gi],
  ['exfil', 8, 'Ağ üzerinden veri gönderme', /\b(WSASend|InternetWriteFile|WinHttpWriteData|curl_easy_perform)\b/g]
];
/* java/javaw.exe hedefli bellek erisimi: calma belirtisi yoksa puanlanmaz (cred grubu = calma belirtisi) */
async function rankRisk(file, opts) {
  opts = opts || {}; const readline = require('readline'); const funcs = []; let cur = null; let javaTarget = false, theft = false, total = 0;
  const flush = () => { if (cur) { funcs.push(cur); cur = null; } };
  const rl = readline.createInterface({ input: fs.createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity });
  for await (const line of rl) {
    let m = /^\/\/ (.+?) @ (\S+)\s*$/.exec(line) || /^\/\/-{5,}\s*\(([0-9A-Fa-f]+)\)/.exec(line);
    if (m) { flush(); total++; cur = { fn: m.length > 2 ? m[1] : 'sub_' + m[1], addr: m.length > 2 ? m[2] : '0x' + m[1], g: new Map() }; continue; }
    if (!cur) continue; if (!javaTarget && /\bjavaw?\.exe\b/i.test(line)) javaTarget = true;
    for (const [id, , , re, , isTheft] of RISK_GROUPS) { re.lastIndex = 0; let x; let n = 0; while ((x = re.exec(line)) && n < 3) { n++; if (isTheft) theft = true; let e = cur.g.get(id); if (!e) { e = []; cur.g.set(id, e); } if (e.length < 3 && !e.includes(x[0])) e.push(x[0]); if (x[0] === '') re.lastIndex++; } }
  }
  flush(); const exempt = javaTarget && !theft; const out = [];
  for (const f of funcs) {
    if (!f.g.size) continue; let s = 0; const gl = []; let counted = 0;
    for (const [id, ev] of f.g) { const gd = RISK_GROUPS.find((q) => q[0] === id); const neutral = exempt && gd[4]; if (neutral) { gl.push({ id, label: gd[2] + ' (java/javaw.exe hedefi, çalma belirtisi yok → puanlanmadı)', ev, w: 0 }); continue; } s += gd[1]; counted++; gl.push({ id, label: gd[2], ev, w: gd[1] }); }
    if (counted >= 3) s += 10; if (f.g.has('inject') && !exempt && (f.g.has('download') || f.g.has('exec') || f.g.has('persist'))) s += 15; if (f.g.has('cred') && (f.g.has('exfil') || f.g.has('download'))) s += 15;
    out.push({ fn: f.fn, addr: f.addr, score: Math.min(100, s), groups: gl });
  }
  out.sort((a, b) => b.score - a.score); const top = out.filter((x) => x.score > 0).slice(0, opts.top || 25);
  return { functions: total, flagged: out.filter((x) => x.score > 0).length, top, javaTarget, theft, exempt, note: 'Sezgisel sıralama: yalnızca API/dize göstergelerine bakar, hüküm değildir; iyi huylu programlar da bu API’leri kullanır.' + (exempt ? ' Dosyada java/javaw.exe hedefi var ve çalma belirtisi bulunmadı: bellek/enjeksiyon API’leri puanlanmadı (muafiyet).' : (javaTarget && theft ? ' java/javaw.exe hedefi VAR ama çalma belirtisi de var: muafiyet UYGULANMADI.' : '')) };
}
function riskMd(r) { const L = ['# Fonksiyon risk sıralaması', '', r.note, '', 'Fonksiyon: ' + r.functions + ' · göstergesi olan: ' + r.flagged, '']; for (const f of r.top) L.push('- **' + f.score + '** ' + f.fn + ' @ ' + f.addr + ' — ' + f.groups.map((g) => g.label + ' [' + g.ev.join(', ') + ']').join('; ')); return L.join('\n') + '\n'; }
function nativeStatus(dir) { try { const o = {}; for (const l of fs.readFileSync(path.join(dir, '_statscan_status.txt'), 'utf8').split(/\r?\n/)) { const m = /^(\w+)=(.*)$/.exec(l); if (m) o[m[1]] = m[2]; } return o.functions !== undefined ? o : null; } catch (e) { return null; } }
const stamp = () => new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);

/* deps: { outputRoot, userToolsDir, spawn?, env? , showItemInFolder?, confirm? } */
function createObfHost(deps) {
  const spawn = deps.spawn || cp.spawn; const dirs = new Map(); const jobs = new Map();
  const tools = () => detectTools(Object.assign({}, deps.env || {}, { userToolsDir: deps.userToolsDir }));
  function newDir(baseName) { const root = deps.outputRoot; fs.mkdirSync(root, { recursive: true }); const dir = path.join(root, safeName(baseName, 'cikti').replace(/\.[^.]*$/, '') + '-' + stamp() + '-' + crypto.randomBytes(2).toString('hex')); fs.mkdirSync(dir); const token = crypto.randomBytes(8).toString('hex'); dirs.set(token, dir); return { token, dir }; }
  function dirFor(token, baseName) { if (token && dirs.has(token)) return { token, dir: dirs.get(token) }; return newDir(baseName); }
  async function save(req) {
    if (!req || !Array.isArray(req.outputs) || !req.outputs.length) return { error: 'empty', message: 'Kaydedilecek çıktı yok.' };
    if (req.outputs.length > 200) return { error: 'too-many', message: 'Çok fazla çıktı dosyası.' };
    const { token, dir } = dirFor(req.dirToken, req.name); const written = [];
    for (const o of req.outputs) {
      const nm = safeName(o.name, 'cikti.txt'); let data; if (typeof o.text === 'string') data = Buffer.from(o.text, 'utf8'); else if (o.bytes && o.bytes.byteLength !== undefined) data = Buffer.from(o.bytes.buffer ? o.bytes.buffer : o.bytes, o.bytes.byteOffset || 0, o.bytes.byteLength); else continue;
      if (data.length > 200 * 1024 * 1024) continue; let target = path.join(dir, nm), i = 1; while (fs.existsSync(target)) { const ext = path.extname(nm); target = path.join(dir, nm.slice(0, nm.length - ext.length) + '-' + (++i) + ext); }
      fs.writeFileSync(target, data, { flag: 'wx' }); written.push({ name: path.basename(target), size: data.length, partial: !!o.partial });
    }
    return { ok: true, dir, dirToken: token, files: written };
  }
  /* decompiler calistir (onayli) */
  async function start(req) {
    req = req || {}; const t = TOOLS[req.tool]; if (!t) return { error: 'tool', message: 'Bilinmeyen araç.' };
    const found = tools().find((x) => x.id === req.tool); if (!found) return { error: 'missing', message: t.label + ' bu bilgisayarda bulunamadı. Araç sessizce indirilmez/kurulmaz; kurduktan sonra tekrar dene.' };
    if (t.pyc) return { error: 'kind', message: t.label + ' yalnızca .pyc dosyaları içindir.' };
    if (!t.kinds.includes(req.kind)) return { error: 'kind', message: t.label + ' bu dosya türünü işleyemez.' };
    if (!req.data || req.data.byteLength === undefined) return { error: 'data', message: 'Dosya verisi alınamadı.' };
    if (req.data.byteLength > MAX_IN) return { error: 'size', message: 'Dosya çok büyük (' + Math.round(req.data.byteLength / 1048576) + ' MB); güvenli sınır ' + MAX_IN / 1048576 + ' MB.' };
    if (deps.confirm) { const ok = await deps.confirm({ title: 'Harici decompiler çalıştır', message: t.label + ' çalıştırılacak:\n\n' + found.path + (t.note ? '\n\n' + t.note : '') + '\n\nİncelenen dosya ÇALIŞTIRILMAZ; araç onu yalnızca okur. Araç ağ erişimini kendisi yönetir (burada işletim sistemi düzeyinde engellenmez; bilinen decompiler\'lar ağ kullanmaz). Çıktı ayrı bir klasöre yazılır, orijinal dosyaya dokunulmaz.\n\nDevam edilsin mi?' }); if (!ok) return { error: 'declined', message: 'İşlem onaylanmadı; araç çalıştırılmadı.' }; }
    const id = crypto.randomBytes(6).toString('hex'); const base = safeName(req.name, 'girdi'); const { token, dir } = dirFor(req.dirToken, base); const outDir = path.join(dir, 'decompiled-' + req.tool); fs.mkdirSync(outDir, { recursive: true });
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'statscan-obf-')); let ext = path.extname(base).toLowerCase(); if (!t.inExt.includes(ext)) ext = t.inExt[0]; const input = path.join(work, 'input' + ext);
    fs.writeFileSync(input, Buffer.from(req.data.buffer ? req.data.buffer : req.data, req.data.byteOffset || 0, req.data.byteLength), { flag: 'wx', mode: 0o600 });
    const job = { id, state: 'running', tool: req.tool, label: t.label, startedAt: Date.now(), dir, dirToken: token, outDir, files: [], stdout: '', stderr: '', exitCode: null, timedOut: false, cancelled: false, message: '' }; jobs.set(id, job);
    if (t.script) fs.writeFileSync(path.join(work, t.script.name), t.script.body, { flag: 'wx', mode: 0o600 });
    const projDir = path.join(work, 'proj'); if (t.native) fs.mkdirSync(projDir);
    const launch = (variant) => {
    let cmd = found.java ? found.java : found.path; let args = (found.java ? ['-jar', found.path] : []).concat((variant && t.altArgs ? t.altArgs : t.args)(input, outDir, { work, base: path.basename(input), script: t.script && t.script.name, projDir }));
    let verbatim = false;
    if (isWin() && /\.(bat|cmd)$/i.test(cmd)) { /* .bat dogrudan spawn edilemez; cmd.exe icin yalnizca guvenli karakterli yollar */ const all = [cmd].concat(args); if (all.some((x) => /[&^%!"<>|\r\n]/.test(x))) { job.state = 'failed'; job.message = 'Yolda cmd için güvenli olmayan karakter var (& ^ % ! " < > |); aracı/çıktı klasörünü bu karakterler olmayan bir yola taşı.'; cleanup(work); return { id, state: job.state, message: job.message }; } args = ['/d', '/s', '/c', '"' + all.map((x) => '"' + x + '"').join(' ') + '"']; cmd = process.env.ComSpec || 'cmd.exe'; verbatim = true; } const timeoutMs = Math.max(5000, Math.min(t.maxTimeout || 600000, +req.timeoutMs || t.timeout || 180000));
    let child; try { child = spawn(cmd, args, { shell: false, cwd: work, env: toolEnv(t, outDir), windowsHide: true, detached: !isWin(), windowsVerbatimArguments: verbatim, stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { job.state = 'failed'; job.message = 'Araç başlatılamadı: ' + e.message; cleanup(work); return { id, state: job.state, message: job.message }; }
    job.kill = () => { try { if (isWin()) cp.spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' }); else process.kill(-child.pid, 'SIGKILL'); } catch (e) { try { child.kill('SIGKILL'); } catch (e2) {} } };
    const tm = setTimeout(() => { job.timedOut = true; job.kill(); }, timeoutMs);
    const cap = (k) => (d) => { job[k] = (job[k] + d.toString('utf8')).slice(-TAIL); }; if (child.stdout) child.stdout.on('data', cap('stdout')); if (child.stderr) child.stderr.on('data', cap('stderr'));
    child.on('error', (e) => { job.error = e.message; });
    child.on('close', (code) => { clearTimeout(tm); job.exitCode = code;
      if (!job.cancelled && !job.timedOut && !job.error && code !== 0 && t.altArgs && !job.alt && /unknown file extension|python/i.test(job.stdout + job.stderr)) { job.alt = true; job.stdout = ''; job.stderr = ''; const f2 = launch(true); if (f2) { Object.assign(job, { state: f2.state, message: f2.message }); } return; }
      if (job.alt && !job.cancelled) { try { const o = fs.readFileSync(path.join(work, 'decompiled.c')); if (o.length) { fs.writeFileSync(path.join(outDir, 'decompiled.c'), o); const n = (o.toString('utf8').match(/^\/\/-----/gm) || []).length; fs.writeFileSync(path.join(outDir, '_statscan_status.txt'), 'tool=ida\nfunctions=' + n + '\ndecompiled=' + n + '\nfailed=0\nskipped=0\nhexrays=var (toplu mod; IDAPython kullanılamadı)\nerror=\n'); } } catch (e) { /* cikti yok */ } }
      const w = walk(outDir); job.files = w.files.slice(0, 5000); job.bytes = w.bytes; try { fs.writeFileSync(path.join(outDir, '_statscan_arac-log.txt'), 'cikis kodu: ' + code + '\n\n--- stdout ---\n' + job.stdout + '\n\n--- stderr ---\n' + job.stderr + '\n'); } catch (e) { /* yoksay */ } cleanup(work);
      if (job.cancelled) { job.state = 'cancelled'; job.message = 'İptal edildi; çıktı eksik olabilir.'; } else if (job.timedOut) { job.state = 'failed'; job.message = 'Zaman aşımı (' + Math.round(timeoutMs / 1000) + ' sn); çıktı eksik, güvenilmemeli.'; } else if (job.error) { job.state = 'failed'; job.message = 'Araç çalıştırılamadı: ' + job.error; } else if (code !== 0) { job.state = 'failed'; job.message = 'Araç hata koduyla çıktı (' + code + '). Üretilen dosyalar kısmidir ve güvenilmemeli. Ayrıntı: ' + (String(job.stderr || job.stdout).trim().split(/\r?\n/).filter(Boolean).slice(-4).join(' | ').slice(0, 500) || 'araç çıktı yazmadı') + ' (tam kayıt: _statscan_arac-log.txt)'; } else if (!w.files.length) { job.state = 'failed'; job.message = 'Araç çıktı üretmedi.'; } else if (t.native) { const sv = nativeStatus(outDir); job.stats = sv; if (!sv) { job.state = 'failed'; job.message = t.label + ' betiği tamamlanmadı (durum dosyası yok): lisans, sürüm ya da JDK sorunu olabilir. Çıktı güvenilmemeli.'; } else if (+sv.decompiled === 0) { job.state = 'failed'; job.message = 'Hiçbir fonksiyon decompile edilemedi' + (sv.hexrays && !/^var/.test(sv.hexrays) ? ' (Hex-Rays: ' + sv.hexrays + ')' : '') + (sv.error ? ' — ' + sv.error : '') + '.'; } else if (+sv.decompiled < +sv.functions) { job.state = 'partial'; job.message = sv.decompiled + '/' + sv.functions + ' fonksiyon decompile edildi (kalan: ' + (sv.failed || 0) + ' hata, ' + (sv.skipped || 0) + ' atlandı: kütüphane/thunk/sınır). Orijinal kaynak geri kazanılmış değildir.'; } else { job.state = 'done'; job.message = sv.decompiled + ' fonksiyon decompile edildi. Orijinal kaynak geri kazanılmış değildir.'; } } else if (w.bytes > MAX_OUT_BYTES || w.files.length > MAX_OUT_FILES) { job.state = 'partial'; job.message = 'Çıktı boyut/dosya sınırını aştı; liste kısaltıldı.'; } else { job.state = 'done'; job.message = w.files.length + ' dosya üretildi.'; } 
      if (t.native && (job.state === 'done' || job.state === 'partial') && fs.existsSync(path.join(outDir, 'decompiled.c'))) { const fin = { state: job.state, message: job.message }; job.state = 'running'; job.message = 'Fonksiyonlar risk sırasına konuyor…'; rankRisk(path.join(outDir, 'decompiled.c')).then((r) => { job.risk = r; try { fs.writeFileSync(path.join(outDir, '_statscan_risk.md'), riskMd(r)); } catch (e) { /* yoksay */ } }).catch((e) => { job.riskError = String(e && e.message || e); }).then(() => { job.state = fin.state; job.message = fin.message + (job.risk ? ' Risk sıralaması: _statscan_risk.md.' : ' (Risk sıralaması yapılamadı.)'); }); }
});
    };
    { const f1 = launch(false); if (f1) return f1; }
    return { id, state: 'running', dir, dirToken: token };
  }
  /* .pyc dosyalarini kurulu pycdc/decompyle3/uncompyle6 ile cevir (onayli, dosya basina zaman asimi, sirali) */
  async function startPyc(req) {
    req = req || {}; const t = TOOLS[req.tool]; if (!t || !t.pyc) return { error: 'tool', message: 'Bilinmeyen araç.' };
    const found = tools().find((x) => x.id === req.tool); if (!found) return { error: 'missing', message: t.label + ' bu bilgisayarda bulunamadı. Araç sessizce indirilmez/kurulmaz; kurduktan sonra tekrar dene.' };
    const list = Array.isArray(req.files) ? req.files : []; if (!list.length) return { error: 'data', message: 'Çevrilecek .pyc dosyası yok.' }; if (list.length > 60) return { error: 'too-many', message: 'En fazla 60 .pyc dosyası çevrilir; kalanları elle çevir.' };
    let total = 0; const files = []; const seen = new Set();
    for (const f of list) { const bytes = f && f.bytes && f.bytes.byteLength !== undefined ? Buffer.from(f.bytes.buffer ? f.bytes.buffer : f.bytes, f.bytes.byteOffset || 0, f.bytes.byteLength) : null; if (!bytes || bytes.length > 8 * 1024 * 1024) continue; total += bytes.length; if (total > 100 * 1024 * 1024) break; let nm = safeName(f.name, 'modul').replace(/\.pyc$/i, '').replace(/[^\w.-]/g, '_') || 'modul'; let k = nm, i = 1; while (seen.has(k)) k = nm + '-' + (++i); seen.add(k); files.push({ nm: k, bytes }); }
    if (!files.length) return { error: 'data', message: 'Geçerli .pyc verisi alınamadı (dosya başına en çok 8 MB).' };
    if (deps.confirm) { const ok = await deps.confirm({ title: 'Python decompiler çalıştır', message: t.label + ' çalıştırılacak:\n\n' + found.path + '\n\n' + files.length + ' .pyc dosyası çevrilecek. Dosyalar ÇALIŞTIRILMAZ; araç bytecode’u yalnızca okur. ' + (t.note || '') + '\nÇıktı ayrı bir klasöre yazılır.\n\nDevam edilsin mi?' }); if (!ok) return { error: 'declined', message: 'İşlem onaylanmadı; araç çalıştırılmadı.' }; }
    const id = crypto.randomBytes(6).toString('hex'); const { token, dir } = dirFor(req.dirToken, safeName(req.name, 'python')); const outDir = path.join(dir, 'decompiled-' + req.tool); fs.mkdirSync(outDir, { recursive: true });
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'statscan-pyc-')); const job = { id, state: 'running', tool: req.tool, label: t.label, startedAt: Date.now(), dir, dirToken: token, outDir, files: [], stdout: '', stderr: '', exitCode: null, message: '', cancelled: false, results: [] }; jobs.set(id, job);
    const perMs = Math.max(1000, +deps.pycTimeoutMs || 120000); let cur = null; job.kill = () => { try { if (cur) { if (isWin()) cp.spawn('taskkill', ['/pid', String(cur.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' }); else process.kill(-cur.pid, 'SIGKILL'); } } catch (e) { try { cur.kill('SIGKILL'); } catch (e2) { /* yoksay */ } } };
    (async () => {
      for (const f of files) {
        if (job.cancelled) break; const input = path.join(work, f.nm + '.pyc'); fs.writeFileSync(input, f.bytes, { flag: 'wx', mode: 0o600 }); const target = path.join(outDir, f.nm + '.py'); const args = t.mode === 'stdout' ? [input] : ['-o', outDir, input];
        const r = await new Promise((resolve) => { let out = Buffer.alloc(0), err = '', timedOut = false, child; try { child = spawn(found.path, args, { shell: false, cwd: work, env: toolEnv(t, outDir), windowsHide: true, detached: !isWin(), stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return resolve({ code: -1, error: e.message, out, err, timedOut }); } cur = child; const tm = setTimeout(() => { timedOut = true; job.kill(); }, perMs);
          if (child.stdout) child.stdout.on('data', (d) => { if (out.length < 20 * 1024 * 1024) out = Buffer.concat([out, d]); }); if (child.stderr) child.stderr.on('data', (d) => { err = (err + d.toString('utf8')).slice(-2000); });
          child.on('error', (e) => { clearTimeout(tm); resolve({ code: -1, error: e.message, out, err, timedOut }); }); child.on('close', (code) => { clearTimeout(tm); resolve({ code, out, err, timedOut }); }); });
        let produced = 0; if (t.mode === 'stdout') { if (r.out.length) { fs.writeFileSync(target, r.out); produced = r.out.length; } } else { try { produced = fs.statSync(target).size; } catch (e) { produced = 0; } }
        const state = job.cancelled ? 'cancelled' : (r.code === 0 && produced > 0 && !r.timedOut ? 'ok' : (produced > 0 ? 'partial' : 'failed')); job.results.push({ name: f.nm, state, code: r.code, timedOut: r.timedOut, size: produced, error: (r.error || r.err || '').slice(0, 300) }); job.stderr = (job.stderr + '[' + f.nm + '] ' + (r.error || r.err || '') + '\n').slice(-8192);
      }
      const okN = job.results.filter((x) => x.state === 'ok').length, partN = job.results.filter((x) => x.state === 'partial').length, failN = job.results.filter((x) => x.state === 'failed').length;
      try { fs.writeFileSync(path.join(outDir, '_statscan_status.txt'), 'tool=' + req.tool + '\nfiles=' + files.length + '\nok=' + okN + '\npartial=' + partN + '\nfailed=' + failN + '\n\n' + job.results.map((x) => x.name + ': ' + x.state + (x.error ? ' — ' + x.error.replace(/\s+/g, ' ') : '')).join('\n') + '\n'); fs.writeFileSync(path.join(outDir, '_statscan_arac-log.txt'), job.stderr); } catch (e) { /* yoksay */ }
      const w = walk(outDir); job.files = w.files.slice(0, 5000); job.bytes = w.bytes; cleanup(work);
      if (job.cancelled) { job.state = 'cancelled'; job.message = 'İptal edildi; çıktı eksik olabilir.'; } else if (okN === files.length) { job.state = 'done'; job.message = files.length + ' .pyc dosyası çevrildi. Çıktı insan okumasına yardımcıdır; orijinal kaynakla birebir değildir.'; } else if (okN + partN > 0) { job.state = 'partial'; job.message = okN + ' tam, ' + partN + ' kısmi, ' + failN + ' başarısız. Kısmi dosyalar eksik/yanlış olabilir, güvenme (ayrıntı: _statscan_status.txt).'; } else { job.state = 'failed'; job.message = 'Hiçbir dosya çevrilemedi (bytecode sürümü araç tarafından desteklenmiyor olabilir; ayrıntı: _statscan_status.txt).'; }
    })().catch((e) => { job.state = 'failed'; job.message = 'Beklenmeyen hata: ' + e.message; cleanup(work); });
    return { id, state: 'running', dir, dirToken: token };
  }
  const cleanup = (w) => { try { fs.rmSync(w, { recursive: true, force: true }); } catch (e) {} };
  function job(id) { const j = jobs.get(String(id)); if (!j) return { error: 'nojob', message: 'İş bulunamadı.' }; const { kill, ...pub } = j; return pub; }
  function cancel(id) { const j = jobs.get(String(id)); if (!j) return { error: 'nojob', message: 'İş bulunamadı.' }; if (j.state === 'running') { j.cancelled = true; j.kill && j.kill(); } return { ok: true }; }
  const handlers = {
    'obf:startpyc': async (_e, req) => { try { return await startPyc(req); } catch (e) { return { error: 'start', message: String(e.message || e) }; } },
    'obf:tools': async () => ({ tools: tools().map((x) => ({ id: x.id, label: x.label, kinds: x.kinds, path: x.path, via: x.via })), outputRoot: deps.outputRoot, toolsDir: deps.userToolsDir }),
    'obf:save': async (_e, req) => { try { const r = await save(req); if (r.ok && deps.showItemInFolder) deps.showItemInFolder(r.dir); return r; } catch (e) { return { error: 'save', message: 'Kaydedilemedi: ' + e.message }; } },
    'obf:start': async (_e, req) => { try { return await start(req); } catch (e) { return { error: 'start', message: String(e.message || e) }; } },
    'obf:job': async (_e, id) => job(id),
    'obf:cancel': async (_e, id) => cancel(id)
  };
  return { handlers, tools, save, start, job, cancel };
}
module.exports = { createObfHost, detectTools, TOOLS, safeName, rankRisk, riskMd };

return module.exports; })();

const RISKY = ['clipboard', 'networking', 'printer', 'audioInput', 'videoInput', 'vGPU'];
const VT_RE = /^https:\/\/www\.virustotal\.com\/gui\/file\/[0-9a-f]{64}$/;
const RISK_TEXT = { networking: 'Ağ erişimi', clipboard: 'Pano paylaşımı', printer: 'Yazıcı paylaşımı', audioInput: 'Mikrofon', videoInput: 'Kamera', vGPU: 'Sanal GPU (vGPU)' };

/* --- Java derleyici (Kovan "Derleyici"): .java -> javac -> jar -> jdeps -> jpackage (app-image). Yalnizca kullanicinin KENDI JDK'si;
 * hicbir sey indirilmez/kurulmaz. Derlenen program ASLA calistirilmaz (javac -proc:none: aciklama islemcileri de calismaz).
 * Arayuz yalnizca dosya adi + bayt + ana sinif + uygulama adi gonderebilir; komut/yol gonderemez. Cikti: <Indirilenler>/Kovan-Derleme/<ad>/ */
const COMPMOD = (() => {
  const fs = require('fs'); const path = require('path'); const os = require('os'); const cp = require('child_process');
  const isWin = () => process.platform === 'win32';
  const LIM = { files: 50, one: 2 * 1024 * 1024, total: 10 * 1024 * 1024 }; const TAIL = 12000; const MIN_MAJOR = 17;
  const NAME_RE = /^[A-Za-z][A-Za-z0-9_-]{0,39}$/; const CLASS_RE = /^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$/; const FILE_RE = /^[A-Za-z_$][\w$]{0,99}\.java$/;
  const bin = (home, n) => path.join(home, 'bin', n + (isWin() ? '.exe' : ''));
  const isFile = (p) => { try { return fs.statSync(p).isFile(); } catch (e) { return false; } };
  const ls = (d) => { try { return fs.readdirSync(d); } catch (e) { return []; } };
  function homeOf(p) { /* ...\bin\javac(.exe) -> JDK kok dizini; sembolik baglantilari cozer */ try { const r = fs.realpathSync(p); return path.dirname(path.dirname(r)); } catch (e) { return null; } }
  function candidates(env, extra) {
    const out = []; const add = (d) => { if (d && !out.includes(d)) out.push(d); };
    if (env.JAVA_HOME) add(env.JAVA_HOME);
    for (const dir of String(env.PATH || env.Path || '').split(path.delimiter)) { if (dir && isFile(path.join(dir, 'javac' + (isWin() ? '.exe' : '')))) add(homeOf(path.join(dir, 'javac' + (isWin() ? '.exe' : '')))); }
    const roots = [];
    if (isWin()) { for (const pf of [env.ProgramFiles, env['ProgramFiles(x86)'], env.ProgramW6432].filter(Boolean)) for (const v of ['Java', 'Eclipse Adoptium', 'Microsoft', 'Amazon Corretto', 'Zulu', 'BellSoft', 'Semeru', 'Eclipse Foundation', 'AdoptOpenJDK', 'OpenJDK']) roots.push(path.join(pf, v)); }
    else if (process.platform === 'darwin') { roots.push('/Library/Java/JavaVirtualMachines'); }
    else roots.push('/usr/lib/jvm');
    const home = env.USERPROFILE || env.HOME; if (home) roots.push(path.join(home, '.jdks'), path.join(home, '.sdkman', 'candidates', 'java'));
    for (const r of roots) for (const n of ls(r)) { const d = path.join(r, n); add(process.platform === 'darwin' && isFile(path.join(d, 'Contents', 'Home', 'bin', 'javac')) ? path.join(d, 'Contents', 'Home') : d); }
    for (const e of extra || []) add(e);
    return out;
  }
  function parseMajor(txt) { const m = /javac\s+(\d+)(?:\.(\d+))?/.exec(String(txt)); if (!m) return 0; return m[1] === '1' ? +m[2] || 0 : +m[1]; }
  function runSync(file, args, env, ms) { const r = cp.spawnSync(file, args, { env, encoding: 'utf8', timeout: ms || 15000, windowsHide: true, shell: false }); return { code: r.status, out: String(r.stdout || '') + String(r.stderr || ''), err: r.error }; }
  function cleanEnv(base) { const e = Object.assign({}, base || process.env); for (const k of ['JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'CLASSPATH']) delete e[k]; return e; }
  function findJdks(o) {
    o = o || {}; const env = cleanEnv(o.env); const list = []; const seen = new Set();
    for (const h of (o.only ? o.only : candidates(env, o.extra))) {
      const real = (() => { try { return fs.realpathSync(h); } catch (e) { return h; } })(); if (seen.has(real)) continue; seen.add(real);
      const need = ['javac', 'jar', 'jpackage', 'jdeps']; const missing = need.filter((n) => !isFile(bin(h, n)));
      if (missing.includes('javac')) continue; const v = runSync(bin(h, 'javac'), ['-version'], env); const major = parseMajor(v.out);
      list.push({ home: h, major, version: (/javac\s+(\S+)/.exec(v.out) || [])[1] || '?', missing, ok: !missing.length && major >= MIN_MAJOR, why: missing.length ? 'Eksik araç: ' + missing.join(', ') + ' (JRE değil, tam JDK gerekir)' : major < MIN_MAJOR ? 'JDK ' + MIN_MAJOR + ' veya üstü gerekir (bulunan: ' + (major || '?') + ')' : '' });
    }
    list.sort((a, b) => (b.ok - a.ok) || (b.major - a.major));
    return { found: !!(list[0] && list[0].ok), best: list[0] && list[0].ok ? list[0] : null, all: list, minMajor: MIN_MAJOR };
  }
  const safeOutName = (n) => String(n || '').trim();
  function validate(req) {
    if (!req || typeof req !== 'object') return 'Geçersiz istek.';
    const f = req.files; if (!Array.isArray(f) || !f.length) return 'Hiç .java dosyası verilmedi.'; if (f.length > LIM.files) return 'En fazla ' + LIM.files + ' dosya.';
    let total = 0; const seen = new Set();
    for (const x of f) { if (!x || typeof x.name !== 'string' || !FILE_RE.test(x.name)) return 'Geçersiz dosya adı (yalnızca düz "Ad.java"): ' + String(x && x.name).slice(0, 60); if (seen.has(x.name)) return 'Aynı adlı iki dosya: ' + x.name; seen.add(x.name); const b = x.bytes; const len = b && (b.byteLength !== undefined ? b.byteLength : b.length); if (!len) return 'Boş dosya: ' + x.name; if (len > LIM.one) return 'Dosya çok büyük (en çok 2 MB): ' + x.name; total += len; }
    if (total > LIM.total) return 'Toplam boyut çok büyük (en çok 10 MB).';
    if (typeof req.mainClass !== 'string' || !CLASS_RE.test(req.mainClass.replace(/\$/g, '.'))) return 'Ana sınıf adı geçersiz.';
    if (typeof req.name !== 'string' || !NAME_RE.test(req.name)) return 'Uygulama adı geçersiz (harfle başlamalı; harf, rakam, - ve _; en çok 40).';
    if (!['auto', 'yes', 'no'].includes(req.console || 'auto')) return 'Konsol seçimi geçersiz.';
    return null;
  }
  const STEPS = [['jdk', 'JDK bulundu'], ['javac', 'Derleniyor (javac)'], ['jar', 'JAR oluşturuluyor'], ['deps', 'Gerekli modüller çözümleniyor (jdeps)'], ['pack', 'Uygulama paketleniyor (jpackage)'], ['save', 'İndirilenler klasörüne kaydediliyor']];
  function uniqueDir(root, name) { let d = path.join(root, name), i = 2; while (fs.existsSync(d)) d = path.join(root, name + '-' + i++); return d; }
  function createCompileHost(deps) {
    deps = deps || {}; const jobs = new Map(); let seq = 0; let active = null; const errE = (message, extra) => Object.assign({ error: 'compile', message }, extra || {});
    const root = () => path.join(deps.outputBase || deps.downloadsDir || os.homedir(), 'Kovan-Derleme');
    const handlers = {
      'compile:jdk': async () => { try { return findJdks({ env: deps.env, extra: deps.jdkDirs, only: deps.onlyJdkDirs }); } catch (e) { return errE(String(e && e.message || e)); } },
      'compile:start': async (_e, req) => {
        const bad = validate(req); if (bad) return errE(bad); if (active) return errE('Başka bir derleme sürüyor.');
        const jdks = findJdks({ env: deps.env, extra: deps.jdkDirs, only: deps.onlyJdkDirs }); if (!jdks.found) return errE('Uygun JDK bulunamadı. JDK ' + MIN_MAJOR + '+ (javac, jar, jdeps, jpackage içeren tam JDK) kurun.', { needJdk: true, jdks: jdks.all });
        const id = String(++seq); const job = { id, state: 'running', steps: STEPS.map(([k, l]) => ({ id: k, label: l, status: 'wait', detail: '' })), log: '', result: null, error: null, started: Date.now() }; jobs.set(id, job); active = job; if (jobs.size > 8) jobs.delete(jobs.keys().next().value);
        run(job, req, jdks.best).catch((e) => { job.state = 'failed'; job.error = String(e && e.message || e); }).finally(() => { active = null; });
        return { id };
      },
      'compile:job': async (_e, id) => { const j = jobs.get(String(id)); if (!j) return errE('İş bulunamadı.'); return { id: j.id, state: j.state, steps: j.steps, log: j.log.slice(-TAIL), result: j.result, error: j.error }; },
      'compile:cancel': async (_e, id) => { const j = jobs.get(String(id)); if (!j) return errE('İş bulunamadı.'); j.canceled = true; try { j.child && j.child.kill(); } catch (e) { /* bitmis */ } return { ok: true }; },
      'compile:open': async (_e, id) => { const j = jobs.get(String(id)); if (!j || !j.result || !j.result.launcher) return errE('Açılacak çıktı yok.'); if (deps.showItemInFolder) deps.showItemInFolder(j.result.launcher); return { ok: true }; }
    };
    function exec(job, file, args, cwd, ms) {
      return new Promise((resolve) => {
        const env = cleanEnv(deps.env); let out = ''; let done = false; let timer;
        const fin = (r) => { if (done) return; done = true; clearTimeout(timer); job.child = null; resolve(r); };
        let c; try { c = cp.spawn(file, args, { cwd, env, windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return fin({ code: -1, out: String(e && e.message || e) }); }
        job.child = c; const add = (d) => { out += d; if (out.length > 200000) out = out.slice(-100000); }; c.stdout.on('data', add); c.stderr.on('data', add);
        timer = setTimeout(() => { try { c.kill(); } catch (e) { /* bitmis */ } fin({ code: -2, out: out + '\n[zaman aşımı]' }); }, ms || 120000);
        c.on('error', (e) => fin({ code: -1, out: out + String(e && e.message || e) })); c.on('close', (code) => fin({ code, out }));
      });
    }
    async function run(job, req, jdk) {
      const S = (k) => job.steps.find((s) => s.id === k); const step = (k, st, d) => { const s = S(k); s.status = st; if (d !== undefined) s.detail = d; };
      const logp = (t) => { job.log += t + '\n'; }; const work = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-java-'));
      const fail = (k, msg, extra) => { step(k, 'fail', msg); job.state = 'failed'; job.error = msg; if (extra) job.result = extra; };
      try {
        step('jdk', 'ok', 'JDK ' + jdk.version + ' — ' + jdk.home);
        const src = path.join(work, 'src'), cls = path.join(work, 'classes'), inp = path.join(work, 'input'), dst = path.join(work, 'dest'); for (const d of [src, cls, inp, dst]) fs.mkdirSync(d, { recursive: true });
        const files = []; for (const f of req.files) { const p = path.join(src, f.name); fs.writeFileSync(p, Buffer.from(f.bytes)); files.push(p); }
        step('javac', 'run'); let r = await exec(job, bin(jdk.home, 'javac'), ['-proc:none', '-encoding', 'UTF-8', '-Xlint:none', '-d', cls, ...files], work, 120000); logp('$ javac ...\n' + r.out);
        if (job.canceled) { job.state = 'canceled'; step('javac', 'fail', 'İptal edildi'); return; }
        if (r.code !== 0) return fail('javac', 'Derleme hatası (javac). Ayrıntı için günlüğe bak.', { javacOutput: r.out.slice(-TAIL).replace(new RegExp(work.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&'), 'g'), '.') });
        step('javac', 'ok');
        const mainPath = path.join(cls, ...req.mainClass.split('.')) + '.class'; if (!fs.existsSync(mainPath)) return fail('jar', 'Ana sınıf derlenmiş çıktıda yok: ' + req.mainClass);
        step('jar', 'run'); const jar = path.join(inp, 'app.jar'); r = await exec(job, bin(jdk.home, 'jar'), ['--create', '--file', jar, '--main-class', req.mainClass, '-C', cls, '.'], work, 60000); logp('$ jar ...\n' + r.out);
        if (r.code !== 0) return fail('jar', 'JAR oluşturulamadı.'); step('jar', 'ok');
        step('deps', 'run'); let mods = 'java.base'; r = await exec(job, bin(jdk.home, 'jdeps'), ['--print-module-deps', '--ignore-missing-deps', '--multi-release', 'base', jar], work, 60000); logp('$ jdeps ...\n' + r.out);
        const last = r.out.trim().split(/\r?\n/).pop(); if (r.code === 0 && /^[a-z][\w.]*(,[a-z][\w.]*)*$/.test(last)) { mods = last; step('deps', 'ok', mods); } else step('deps', 'ok', 'jdeps çözemedi; varsayılan: java.base' + (/awt|swing/.test(req.mainClass) ? '' : ''));
        if (!/(^|,)java\.base(,|$)/.test(mods)) mods = 'java.base,' + mods; const gui = req.console === 'no' ? true : req.console === 'yes' ? false : /java\.desktop|javafx/.test(mods); const consoleOn = !gui;
        step('pack', 'run'); const args = ['--type', 'app-image', '--name', req.name, '--input', inp, '--main-jar', 'app.jar', '--main-class', req.mainClass, '--dest', dst, '--add-modules', mods, '--jlink-options', '--strip-debug --no-header-files --no-man-pages']; if (isWin() && consoleOn) args.push('--win-console');
        r = await exec(job, bin(jdk.home, 'jpackage'), args, work, 600000); logp('$ jpackage ...\n' + r.out); if (job.canceled) { job.state = 'canceled'; step('pack', 'fail', 'İptal edildi'); return; }
        if (r.code !== 0) return fail('pack', 'Paketleme başarısız (jpackage). Ayrıntı için günlüğe bak.', { jpackageOutput: r.out.slice(-TAIL) });
        const made = ls(dst); if (made.length !== 1) return fail('pack', 'jpackage beklenen çıktıyı üretmedi.'); step('pack', 'ok');
        step('save', 'run'); fs.mkdirSync(root(), { recursive: true }); const outDir = uniqueDir(root(), req.name); fs.cpSync(path.join(dst, made[0]), outDir, { recursive: true }); fs.copyFileSync(jar, path.join(outDir, req.name + '.jar'));
        const launcher = isWin() ? path.join(outDir, req.name + '.exe') : process.platform === 'darwin' ? outDir : path.join(outDir, 'bin', req.name); if (!fs.existsSync(launcher)) return fail('save', 'Çalıştırıcı dosya bulunamadı: ' + path.basename(launcher));
        let size = 0; const walk = (d) => { for (const n of ls(d)) { const p = path.join(d, n); try { const s = fs.lstatSync(p); if (s.isDirectory()) walk(p); else size += s.size; } catch (e) { /* atla */ } } }; walk(outDir);
        step('save', 'ok', outDir); job.result = { outDir, launcher, launcherName: path.basename(launcher), jar: path.join(outDir, req.name + '.jar'), size, modules: mods, gui, console: consoleOn, jdk: { version: jdk.version, home: jdk.home }, windows: isWin() };
        job.state = 'done'; if (deps.notify) { try { deps.notify('Kovan Derleyici', 'Hazır: ' + path.basename(launcher) + ' (İndirilenler\\Kovan-Derleme)'); } catch (e) { /* bildirim yok */ } }
      } finally { try { fs.rmSync(work, { recursive: true, force: true }); } catch (e) { /* gecici klasor */ } if (job.state === 'running') job.state = 'failed'; }
    }
    return { handlers };
  }
  return { createCompileHost, findJdks, validate, LIM, MIN_MAJOR };
})();

function riskyList(ui) {
  const out = []; ui = ui || {};
  for (const k of RISKY) if (ui[k] && ui[k] !== 'Disable') out.push(RISK_TEXT[k]);
  if (ui.defender === 'disable') out.push('Sandbox içinde Defender kapalı');
  return out;
}

function errObj(e) { return { error: (e && e.code) || 'error', message: String((e && e.message) || e), status: (e && e.status) || 500, extra: (e && e.extra) || null }; }

/* deps: { service, confirm(msg)->Promise<boolean>, openExternal(url), showItemInFolder(path), spawn, configPath, enableDeps, version } */
/* ---------- Klasor izleme (yalnizca okur, calistirmaz) ---------- */
function createWatcher(deps) {
  const TEMP = /\.(crdownload|part|partial|tmp|download|opdownload|temp|filepart)$/i; const MAXB = deps.maxBytes || 64 * 1024 * 1024; const TICK = deps.tickMs || 1000;
  const folders = new Map(); const pending = new Map(); const queue = []; const log = []; const seen = new Map(); let timer = null; let seq = 0;
  const norm = (p) => path.resolve(String(p)); const inside = (child, parent) => { const r = path.relative(parent, child); return r === '' || (!r.startsWith('..') && !path.isAbsolute(r)); };
  const addLog = (kind, text, extra) => { log.unshift(Object.assign({ t: new Date().toISOString(), kind, text }, extra || {})); if (log.length > 200) log.length = 200; };
  const excluded = (p) => !!deps.excludeDir && inside(p, norm(deps.excludeDir));
  function validate(dir) {
    if (typeof dir !== 'string' || !dir || dir.length > 1024 || dir.includes('\0')) return 'Geçersiz klasör.'; const d = norm(dir);
    if (path.parse(d).root === d) return 'Sürücü/kök dizin izlenemez; bir alt klasör seç.';
    let st; try { st = fs.statSync(d); } catch (e) { return 'Klasör bulunamadı.'; } if (!st.isDirectory()) return 'Bu bir klasör değil.';
    if (excluded(d) || (deps.excludeDir && inside(norm(deps.excludeDir), d))) return 'StatScan çıktı klasörü (veya onu içeren klasör) izlenemez.'; return null;
  }
  function consider(dir, name) {
    if (!name || TEMP.test(name)) return; const full = path.join(dir, String(name)); if (excluded(full)) return;
    let st; try { st = fs.lstatSync(full); } catch (e) { pending.delete(full); return; } if (!st.isFile()) return; const sig = st.size + ':' + Math.floor(st.mtimeMs); if (seen.get(full) === sig) return;
    const p = pending.get(full); if (!p) pending.set(full, { dir, name: String(name), size: -1, stable: 0, since: Date.now() }); }
  function tick() {
    for (const [full, p] of [...pending]) {
      let st; try { st = fs.lstatSync(full); } catch (e) { pending.delete(full); continue; } if (!st.isFile()) { pending.delete(full); continue; }
      if (st.size === p.size && st.size > 0) p.stable++; else { p.size = st.size; p.stable = 0; }
      if (Date.now() - p.since > 6 * 3600e3) { pending.delete(full); addLog('skip', p.name + ' — indirme tamamlanmadı, izleme bırakıldı', { name: p.name }); continue; }
      if (p.stable >= 2) { pending.delete(full); seen.set(full, st.size + ':' + Math.floor(st.mtimeMs)); if (seen.size > 5000) seen.delete(seen.keys().next().value); queue.push({ id: ++seq, full, dir: p.dir, name: p.name, size: st.size }); }
    }
  }
  function stop() { for (const f of folders.values()) { try { f.close(); } catch (e) { /* yoksay */ } } folders.clear(); pending.clear(); if (timer) { clearInterval(timer); timer = null; } }
  function setFolders(list) {
    const want = []; const errors = []; for (const d of Array.isArray(list) ? list.slice(0, 12) : []) { const e = validate(d); if (e) errors.push({ dir: String(d), message: e }); else want.push(norm(d)); }
    for (const [d, f] of [...folders]) if (!want.includes(d)) { try { f.close(); } catch (e) { /* yoksay */ } folders.delete(d); addLog('info', 'İzleme durdu: ' + d); }
    for (const d of want) if (!folders.has(d)) {
      try { const w = fs.watch(d, { persistent: false }, (_ev, name) => consider(d, name)); w.on('error', (e) => { addLog('error', d + ': ' + e.message); folders.delete(d); }); folders.set(d, w); addLog('info', 'İzleme başladı: ' + d + ' (yalnızca bundan sonra gelen dosyalar)'); } catch (e) { errors.push({ dir: d, message: 'İzlenemedi: ' + e.message }); }
    }
    if (folders.size && !timer) { timer = setInterval(tick, TICK); if (timer.unref) timer.unref(); } if (!folders.size && timer) { clearInterval(timer); timer = null; }
    return { folders: [...folders.keys()], errors };
  }
  function take() {
    const it = queue.shift(); if (!it) return { item: null }; if (it.size > MAXB) { addLog('skip', it.name + ' — ' + Math.round(it.size / 1048576) + ' MB, izleme sınırını (' + Math.round(MAXB / 1048576) + ' MB) aşıyor; elle tara', { name: it.name }); return { item: { id: it.id, name: it.name, dir: it.dir, size: it.size, tooBig: true } }; }
    try { const buf = fs.readFileSync(it.full); return { item: { id: it.id, name: it.name, dir: it.dir, size: buf.length, bytes: new Uint8Array(buf.buffer, buf.byteOffset, buf.length) } }; } catch (e) { addLog('error', it.name + ' okunamadı: ' + e.message, { name: it.name }); return { item: { id: it.id, name: it.name, dir: it.dir, size: it.size, error: 'Okunamadı: ' + e.message } }; }
  }
  return { validate, setFolders, take, stop, log: () => log.slice(0, 100), addLog, folders: () => [...folders.keys()], _tick: tick, _consider: consider };
}

function createHost(deps) {
  const svc = deps.service;
  const handlers = {
    'dyn:status': async () => Object.assign({ desktop: true }, svc.status()),
    'dyn:start': async (_e, req) => {
      try {
        req = req || {};
        if (req.consent !== true) return { error: 'no-consent', message: 'Kullanıcı onayı olmadan dinamik analiz başlatılmaz.', status: 400 };
        const risks = riskyList(req.ui);
        if (risks.length) {
          const ok = await deps.confirm({ title: 'Riskli Sandbox ayarları', message: 'Bu ayarlar Sandbox’ı ana bilgisayarına daha açık hâle getirir:\n\n• ' + risks.join('\n• ') + '\n\nYine de devam edilsin mi?', ok: 'Yine de çalıştır', cancel: 'Vazgeç' });
          if (!ok) return { error: 'declined', message: 'Riskli ayarlar onaylanmadı; analiz başlatılmadı.', status: 400 };
        }
        const data = req.data && req.data.byteLength !== undefined ? Buffer.from(req.data.buffer ? req.data.buffer : req.data, req.data.byteOffset || 0, req.data.byteLength) : null;
        if (!data) return { error: 'data', message: 'Dosya verisi alınamadı.', status: 400 };
        return svc.start({ name: String(req.name || 'sample'), data, ui: req.ui || {}, staticScore: req.staticScore });
      } catch (e) { return errObj(e); }
    },
    'dyn:job': async (_e, id) => { try { return svc.job(id); } catch (e) { return errObj(e); } },
    'dyn:cancel': async (_e, id) => { try { return svc.cancel(id); } catch (e) { return errObj(e); } },
    'dyn:enable': async () => {
      try {
        const ok = await deps.confirm({ title: 'Windows Sandbox’ı etkinleştir', message: 'Windows’un “Windows Sandbox” özelliği etkinleştirilecek. Windows yönetici izni isteyecek (UAC penceresi) ve işlem bittikten sonra bilgisayarı yeniden başlatman gerekecek.\n\nDevam edilsin mi?', ok: 'Etkinleştir', cancel: 'Vazgeç' });
        if (!ok) return { error: 'declined', message: 'Etkinleştirme iptal edildi.', status: 400 };
        return D.enableSandboxFeature(Object.assign({ prereq: D.checkPrerequisites(deps.prereqDeps) }, deps.enableDeps || {}));
      } catch (e) { return errObj(e); }
    },
    'dyn:features': async () => { try { if (process.platform !== 'win32' && !deps.spawn) return { error: 'platform', message: 'Yalnızca Windows’ta.' }; (deps.spawn || require('child_process').spawn)('optionalfeatures.exe', [], { detached: true, stdio: 'ignore', windowsHide: false }).unref(); return { ok: true }; } catch (e) { return errObj(e); } },
    'app:openVT': async (_e, url) => { if (typeof url !== 'string' || !VT_RE.test(url)) return { error: 'url', message: 'Adres izin verilen biçimde değil.' }; await deps.openExternal(url); return { ok: true }; },
    'app:showConfig': async () => { if (deps.configPath) deps.showItemInFolder(deps.configPath); return { ok: true, path: deps.configPath || null }; },
    'app:info': async () => ({ version: deps.version || '', platform: process.platform, configPath: deps.configPath || null })
  };
  /* Kovan ayarlari (masaustu): yalnizca beyaz listedeki bool anahtarlar; asil islemler deps.settings ile (test icin degistirilebilir) */
  if (deps.settings) {
    const SK = new Set(['openAtLogin', 'startMinimized', 'autoUpdate']);
    const snap = () => { const S = deps.settings; const au = S.autostartSupport(); return { desktop: true, platform: process.platform, version: deps.version || '', autostart: au, openAtLogin: au.supported ? !!S.getLogin() : false, startMinimized: !!S.getApp().startMinimized, autoUpdate: !!S.getApp().auto, feedUrl: S.getApp().feedUrl || '' }; };
    handlers['settings:get'] = async () => { try { return snap(); } catch (e) { return errObj(e); } };
    handlers['settings:set'] = async (_e, key, val) => {
      try {
        if (typeof key !== 'string' || !SK.has(key) || typeof val !== 'boolean') return { error: 'bad', message: 'Geçersiz ayar isteği.' };
        const S = deps.settings;
        if (key === 'openAtLogin') { const au = S.autostartSupport(); if (!au.supported) return { error: 'unsupported', message: au.reason }; S.setLogin(val); if (!!S.getLogin() !== val) return { error: 'failed', message: 'İşletim sistemi ayarı uygulamadı; değişiklik yapılmadı.' }; }
        else if (key === 'startMinimized') S.setApp({ startMinimized: val });
        else S.setApp({ auto: val });
        return snap();
      } catch (e) { return errObj(e); }
    };
    handlers['settings:checkUpdate'] = async () => { try { if (deps.settings.checkUpdate) await deps.settings.checkUpdate(); return { ok: true }; } catch (e) { return errObj(e); } };
  }
  /* Java derleyici (yalnizca kullanicinin kendi JDK'si; bkz. COMPMOD) */
  if (deps.compile !== false) { const ch = COMPMOD.createCompileHost({ downloadsDir: deps.downloadsDir, outputBase: deps.compileOutputBase, env: deps.compileEnv, jdkDirs: deps.compileJdkDirs, onlyJdkDirs: deps.compileOnlyJdkDirs, notify: deps.notify, showItemInFolder: deps.showItemInFolder }); Object.assign(handlers, ch.handlers); }
  /* harici decompiler koprusu (yalnizca onayli, yalnizca yerel; bkz. OBFMOD) */
  const obf = OBFMOD.createObfHost({ outputRoot: deps.obfOutputRoot, userToolsDir: deps.obfToolsDir, showItemInFolder: deps.showItemInFolder, confirm: deps.confirm, spawn: deps.obfSpawn, env: deps.obfEnv });
  if (deps.obfOutputRoot) Object.assign(handlers, obf.handlers);
  const watcher = createWatcher({ excludeDir: deps.obfOutputRoot, maxBytes: deps.watchMaxBytes, tickMs: deps.watchTickMs });
  Object.assign(handlers, {
    'watch:suggest': async () => { const out = []; const add = (label, p) => { try { if (p && fs.statSync(p).isDirectory()) out.push({ label, path: p }); } catch (e) { /* yok */ } }; if (deps.downloadsDir) add('İndirilenler', deps.downloadsDir); if (deps.modsDirs) deps.modsDirs.forEach((m) => add(m.label, m.path)); return { suggestions: out }; },
    'watch:choose': async () => { if (!deps.chooseFolder) return { error: 'na', message: 'Klasör seçimi yok.' }; const d = await deps.chooseFolder(); if (!d) return { canceled: true }; const e = watcher.validate(d); return e ? { error: 'bad', message: e } : { path: d }; },
    'watch:set': async (_e, list) => watcher.setFolders(list),
    'watch:take': async () => watcher.take(),
    'watch:log': async () => ({ log: watcher.log(), folders: watcher.folders() }),
    'watch:note': async (_e, kind, text, name) => { const k = ['scan', 'alert', 'info', 'error'].includes(kind) ? kind : 'info'; watcher.addLog(k, String(text || '').slice(0, 400), { name: String(name || '').slice(0, 200) }); return { ok: true }; },
    'watch:notify': async (_e, title, body) => { if (deps.notify) deps.notify(String(title || '').slice(0, 100), String(body || '').slice(0, 300)); return { ok: true }; }
  });
  /* kalici ayar deposu: yalnizca bilinen anahtarlar, yalnizca dize degerler, boyut sinirli, atomik yazim */
  if (deps.storePath) {
    const KEYS = new Set(['policy', 'watch']); const readStore = () => { try { const o = JSON.parse(fs.readFileSync(deps.storePath, 'utf8')); return o && typeof o === 'object' ? o : {}; } catch (e) { return {}; } };
    handlers['store:get'] = async (_e, key) => (KEYS.has(key) && typeof readStore()[key] === 'string' ? readStore()[key] : null);
    handlers['store:set'] = async (_e, key, val) => { try { if (!KEYS.has(key) || typeof val !== 'string' || val.length > 4e6) return { error: 'bad', message: 'Geçersiz depo isteği.' }; const o = readStore(); o[key] = val; fs.mkdirSync(path.dirname(deps.storePath), { recursive: true }); const tmp = deps.storePath + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(o), { mode: 0o600 }); fs.renameSync(tmp, deps.storePath); return { ok: true }; } catch (e) { return { error: 'write', message: String(e.message || e) }; } };
  }
  return { handlers, obf, register(ipcMain) { for (const [k, fn] of Object.entries(handlers)) ipcMain.handle(k, fn); }, svc };
}

module.exports = { createHost, createWatcher, riskyList, VT_RE, obfModule: OBFMOD, compileModule: COMPMOD };
