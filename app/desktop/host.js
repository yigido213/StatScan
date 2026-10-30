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
  let platOverride = null; const isWin = () => (platOverride || process.platform) === 'win32';
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
  function nativeEnv(base) { const e = cleanEnv(base); for (const k of ['CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'OBJC_INCLUDE_PATH', 'LIBRARY_PATH', 'GCC_EXEC_PREFIX', 'COMPILER_PATH', 'DEPENDENCIES_OUTPUT', 'SUNPRO_DEPENDENCIES', 'RUSTFLAGS', 'RUSTC_WRAPPER', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP', 'GOFLAGS', 'GOEXPERIMENT', 'GOROOT_FINAL', 'FPCOPT', 'DFLAGS', 'DMD_FLAGS', 'LDC_FLAGS', 'DOTNET_STARTUP_HOOKS', 'MSBUILDLOGASYNC', 'DOTNET_CLI_UI_LANGUAGE']) delete e[k]; return e; }
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
    if (req.lang !== undefined && req.lang !== 'java') return validateNative(req);
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
  /* ---------- Cok dilli (yerel arac zinciri): C, C++, Rust, C#, Go, Zig, Kotlin, Pascal, Fortran, D ----------
   * Arayuz yalniz dil kimligi + dosya adi/bayt + secenek (sabit liste) gonderebilir. Komut satiri BURADA, sabit kalipla kurulur.
   * Hicbir sey indirilmez/kurulmaz (crate, modul, NuGet, ... yok); derlenen program ASLA calistirilmaz. */
  const LANGS = {
    c: { name: 'C', src: ['c'], aux: ['h'] },
    cpp: { name: 'C++', src: ['cpp', 'cc', 'cxx', 'c++', 'cp', 'c'], aux: ['hpp', 'hh', 'hxx', 'h++', 'inl', 'ipp', 'tpp', 'h'] },
    rust: { name: 'Rust', src: ['rs'], aux: [] }, csharp: { name: 'C#', src: ['cs'], aux: [] }, go: { name: 'Go', src: ['go'], aux: [] }, zig: { name: 'Zig', src: ['zig'], aux: [] },
    kotlin: { name: 'Kotlin', src: ['kt'], aux: [] }, pascal: { name: 'Pascal', src: ['pas', 'pp', 'lpr', 'dpr'], aux: ['inc'] },
    fortran: { name: 'Fortran', src: ['f90', 'f95', 'f03', 'f08', 'f18', 'f', 'for', 'f77', 'ftn'], aux: ['inc'] }, d: { name: 'D', src: ['d'], aux: [] }
  };
  const NATIVE_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9_.+-]{0,99}$/; const WIN_RESERVED = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;
  const extOf = (n) => { const m = /\.([A-Za-z0-9+]+)$/.exec(n); return m ? m[1].toLowerCase() : ''; };
  const ENUMS = {
    opt: ['default', 'debug', 'speed', 'size'],
    cstd: ['auto', 'c99', 'c11', 'c17', 'c23', 'gnu11', 'gnu17', 'gnu23'], cppstd: ['auto', 'c++14', 'c++17', 'c++20', 'c++23', 'gnu++17', 'gnu++20', 'gnu++23'],
    edition: ['2018', '2021', '2024'], fstd: ['gnu', 'legacy', 'f95', 'f2003', 'f2008', 'f2018'], pmode: ['default', 'fpc', 'objfpc', 'delphi'],
    gotarget: ['host', 'windows/amd64', 'windows/arm64', 'linux/amd64', 'linux/arm64', 'darwin/amd64', 'darwin/arm64'],
    zigtarget: ['host', 'x86_64-windows', 'aarch64-windows', 'x86_64-linux', 'aarch64-linux', 'x86_64-macos', 'aarch64-macos']
  };
  const WINLIBS = ['ws2_32', 'mswsock', 'comctl32', 'shell32', 'winmm', 'iphlpapi', 'bcrypt', 'crypt32', 'dwmapi', 'uxtheme', 'psapi', 'ole32', 'wininet', 'gdi32', 'user32', 'comdlg32'];
  const OPT_KEYS = { c: ['opt', 'std', 'static', 'winlibs'], cpp: ['opt', 'std', 'static', 'winlibs'], rust: ['opt', 'edition'], csharp: ['opt', 'implicitUsings', 'winforms'], go: ['opt', 'target'], zig: ['opt', 'target', 'libc'], kotlin: [], pascal: ['opt', 'mode'], fortran: ['opt', 'std', 'static'], d: ['opt'] };
  const bool = (v) => v === undefined || typeof v === 'boolean';
  function validateOptions(lang, o) {
    if (o === undefined || o === null) return null; if (typeof o !== 'object' || Array.isArray(o)) return 'Seçenekler geçersiz.';
    for (const k of Object.keys(o)) if (!OPT_KEYS[lang].includes(k)) return 'Bilinmeyen seçenek: ' + String(k).slice(0, 30);
    if (o.opt !== undefined && !ENUMS.opt.includes(o.opt)) return 'Optimizasyon seçimi geçersiz.';
    if (o.std !== undefined && !(lang === 'c' ? ENUMS.cstd : lang === 'cpp' ? ENUMS.cppstd : ENUMS.fstd).includes(o.std)) return 'Standart seçimi geçersiz.';
    if (o.edition !== undefined && !ENUMS.edition.includes(o.edition)) return 'Rust sürümü (edition) geçersiz.';
    if (o.mode !== undefined && !ENUMS.pmode.includes(o.mode)) return 'Pascal modu geçersiz.';
    if (o.target !== undefined && !(lang === 'go' ? ENUMS.gotarget : ENUMS.zigtarget).includes(o.target)) return 'Hedef platform geçersiz.';
    for (const k of ['static', 'libc', 'implicitUsings', 'winforms']) if (!bool(o[k])) return 'Seçenek (' + k + ') true/false olmalı.';
    if (o.winlibs !== undefined && (!Array.isArray(o.winlibs) || o.winlibs.length > 20 || o.winlibs.some((x) => !WINLIBS.includes(x)))) return 'Windows kitaplık listesi geçersiz.';
    return null;
  }
  function validateNative(req) {
    const L = LANGS[req.lang]; if (!L) return 'Desteklenmeyen dil.'; const f = req.files; if (!Array.isArray(f) || !f.length) return 'Hiç kaynak dosyası verilmedi.'; if (f.length > LIM.files) return 'En fazla ' + LIM.files + ' dosya.';
    let total = 0; const seen = new Set(); const okExt = new Set([...L.src, ...L.aux]); let anySrc = false;
    for (const x of f) {
      if (!x || typeof x.name !== 'string' || !NATIVE_NAME_RE.test(x.name) || /[.]$/.test(x.name) || WIN_RESERVED.test(x.name.replace(/\..*$/, ''))) return 'Geçersiz dosya adı: ' + String(x && x.name).slice(0, 60);
      if (!okExt.has(extOf(x.name))) return 'Bu dil için uygun olmayan dosya türü: ' + x.name; if (L.src.includes(extOf(x.name))) anySrc = true;
      const k = x.name.toLowerCase(); if (seen.has(k)) return 'Aynı adlı iki dosya: ' + x.name; seen.add(k);
      const b = x.bytes; const len = b && (b.byteLength !== undefined ? b.byteLength : b.length); if (!len) return 'Boş dosya: ' + x.name; if (len > LIM.one) return 'Dosya çok büyük (en çok 2 MB): ' + x.name; total += len;
    }
    if (!anySrc) return 'Derlenecek kaynak dosyası yok.'; if (total > LIM.total) return 'Toplam boyut çok büyük (en çok 10 MB).';
    if (typeof req.name !== 'string' || !NAME_RE.test(req.name)) return 'Uygulama adı geçersiz (harfle başlamalı; harf, rakam, - ve _; en çok 40).';
    if (!['auto', 'yes', 'no'].includes(req.console || 'auto')) return 'Konsol seçimi geçersiz.';
    const names = new Set(f.map((x) => x.name)); const m = req.main;
    if (['rust', 'zig', 'pascal'].includes(req.lang)) { if (typeof m !== 'string' || !names.has(m)) return 'Ana dosya geçersiz.'; }
    else if (req.lang === 'kotlin') { if (typeof m !== 'string' || !CLASS_RE.test(m)) return 'Ana sınıf adı geçersiz.'; }
    else if (req.lang === 'csharp') { if (m !== undefined && m !== '' && (typeof m !== 'string' || !CLASS_RE.test(m))) return 'Başlangıç sınıfı geçersiz.'; }
    if (req.order !== undefined) { if (!Array.isArray(req.order) || req.order.length > LIM.files || req.order.some((n) => !names.has(n))) return 'Derleme sırası geçersiz.'; }
    return validateOptions(req.lang, req.options);
  }
  /* --- arac bulma --- */
  const exeNames = (b) => (isWin() ? [b + '.exe'] : [b]);
  function toolDirs(env, extra) {
    const out = []; const add = (d) => { if (d && !out.includes(d)) out.push(d); }; for (const d of String(env.PATH || env.Path || '').split(path.delimiter)) if (d && path.isAbsolute(d)) add(d);
    const home = env.USERPROFILE || env.HOME || ''; if (home) { add(path.join(home, '.cargo', 'bin')); add(path.join(home, '.dotnet')); add(path.join(home, '.local', 'bin')); add(path.join(home, 'go', 'bin')); }
    if (isWin()) {
      const pf = [env.ProgramFiles, env['ProgramFiles(x86)'], env.ProgramW6432].filter(Boolean); const sd = env.SystemDrive || 'C:';
      for (const b of ['msys64\\ucrt64\\bin', 'msys64\\mingw64\\bin', 'msys64\\clang64\\bin', 'mingw64\\bin', 'mingw32\\bin', 'FPC', 'D', 'zig']) { const p = sd + '\\' + b; if (b === 'FPC' || b === 'D') { for (const v of ls(p)) { add(path.join(p, v, 'bin')); for (const t of ls(path.join(p, v, 'bin'))) add(path.join(p, v, 'bin', t)); } } else add(p); }
      for (const p of pf) { add(path.join(p, 'LLVM', 'bin')); add(path.join(p, 'Go', 'bin')); add(path.join(p, 'dotnet')); for (const v of ls(path.join(p, 'LDC'))) add(path.join(p, 'LDC', v, 'bin')); }
    } else { for (const d of ['/usr/local/bin', '/usr/bin', '/opt/homebrew/bin', '/usr/local/go/bin', '/usr/lib/dotnet', '/usr/share/dotnet']) add(d); }
    for (const e of extra || []) add(e); return out;
  }
  function whichIn(dirs, names) { for (const d of dirs) for (const n of names) { const p = path.join(d, n); if (isFile(p)) return p; } return null; }
  const lastVer = (txt) => { const line = String(txt).split(/\r?\n/).find((l) => /\d+\.\d+/.test(l)) || ''; const all = [...line.matchAll(/(\d+)\.(\d+)(?:\.(\d+))?/g)]; const m = all[all.length - 1]; return m ? { text: m[0], major: +m[1], minor: +m[2] } : { text: '?', major: 0, minor: 0 }; };
  const familyOf = (txt) => (/clang/i.test(txt) ? 'clang' : /gcc|g\+\+|GNU/i.test(txt) ? 'gcc' : 'other');
  const TOOL_SPEC = { c: { names: ['gcc', 'clang', 'cc'], ver: ['--version'] }, cpp: { names: ['g++', 'clang++', 'c++'], ver: ['--version'] }, rust: { names: ['rustc'], ver: ['--version'] }, go: { names: ['go'], ver: ['version'] }, zig: { names: ['zig'], ver: ['version'] }, pascal: { names: ['fpc'], ver: ['-iV'] }, fortran: { names: ['gfortran'], ver: ['--version'] }, d: { names: ['ldc2', 'dmd'], ver: ['--version'] } };
  function findTools(o) {
    o = o || {}; const env = cleanEnv(o.env); const dirs = o.only ? o.only : toolDirs(env, o.extra); const list = []; const byId = {};
    const push = (e) => { list.push(e); byId[e.id] = e; };
    for (const id of ['c', 'cpp', 'rust', 'go', 'zig', 'pascal', 'fortran', 'd']) {
      const sp = TOOL_SPEC[id]; let hit = null;
      for (const nm of sp.names) { const p = whichIn(dirs, exeNames(nm)); if (!p) continue; const r = runSync(p, sp.ver, env, 15000); if (r.code === 0) { const v = lastVer(r.out); hit = { tool: nm, path: p, version: v.text, major: v.major, minor: v.minor, family: familyOf(r.out) }; break; } }
      push(Object.assign({ id, name: LANGS[id].name, ok: !!hit, why: hit ? '' : sp.names.join(' / ') + ' bulunamadı' }, hit || {}));
    }
    { /* C#: SDK (yalnız çalışma zamanı yetmez) */
      const p = whichIn(dirs, exeNames('dotnet')); let hit = null; if (p) { const r = runSync(p, ['--list-sdks'], Object.assign({}, env, { DOTNET_NOLOGO: '1', DOTNET_CLI_TELEMETRY_OPTOUT: '1' }), 20000); let best = 0; if (r.code === 0) for (const l of r.out.split(/\r?\n/)) { const m = /^(\d+)\.(\d+)\.(\d+)/.exec(l.trim()); if (m && +m[1] > best) best = +m[1]; } if (best >= 6) hit = { tool: 'dotnet', path: p, version: String(best), major: best, minor: 0, family: 'dotnet' }; }
      push(Object.assign({ id: 'csharp', name: 'C#', ok: !!hit, why: hit ? '' : p ? '.NET SDK 6+ bulunamadı (yalnızca çalışma zamanı yetmez)' : 'dotnet bulunamadı' }, hit || {}));
    }
    const jdk = findJdks({ env: o.env, extra: o.jdkExtra, only: o.jdkOnly });
    { /* Kotlin: kotlinc betiği yerine derleyici JAR'ı doğrudan JDK ile çalıştırılır (Windows'ta .bat çalıştırmamak için) */
      const p = whichIn(dirs, ['kotlinc', 'kotlinc.bat']); let hit = null, why = 'kotlinc bulunamadı'; if (p) { let home = null; try { home = path.dirname(path.dirname(fs.realpathSync(p))); } catch (e) { /* yok */ } const pre = home && path.join(home, 'lib', 'kotlin-preloader.jar'), comp = home && path.join(home, 'lib', 'kotlin-compiler.jar'); if (home && isFile(pre) && isFile(comp)) { let ver = '?'; try { const m = /(\d+\.\d+(?:\.\d+)?)/.exec(fs.readFileSync(path.join(home, 'build.txt'), 'utf8')); if (m) ver = m[1]; } catch (e) { /* build.txt yok */ } if (ver === '?' && jdk.best) { const r = runSync(bin(jdk.best.home, 'java'), ['-cp', pre, 'org.jetbrains.kotlin.preloading.Preloader', '-cp', comp, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-version'], env, 20000); const m = /kotlinc-jvm\s+(\d+\.\d+(?:\.\d+)?)/.exec(r.out); if (m) ver = m[1]; } if (ver === '?') { const m = /kotlin-compiler-(\d+\.\d+(?:\.\d+)?)/.exec(ls(path.join(home, 'lib')).join(' ')); if (m) ver = m[1]; } hit = { tool: 'kotlinc', path: p, version: ver, home, preloader: pre, compiler: comp, major: parseInt(ver, 10) || 0, minor: 0, family: 'kotlin' }; why = ''; } else why = 'Kotlin derleyici kitaplıkları (lib/kotlin-compiler.jar) bulunamadı'; }
      const ok = !!hit && jdk.found; push(Object.assign({ id: 'kotlin', name: 'Kotlin', ok, why: ok ? '' : hit ? 'Kotlin için JDK ' + MIN_MAJOR + '+ (jpackage dahil) da gerekir' : why }, hit || {}));
    }
    push({ id: 'java', name: 'Java', ok: jdk.found, tool: 'javac', version: jdk.best ? jdk.best.version : '', path: jdk.best ? jdk.best.home : '', why: jdk.found ? '' : 'JDK ' + MIN_MAJOR + '+ bulunamadı' });
    return { list, byId, jdk, platform: process.platform, windows: isWin() };
  }
  /* --- komut kurucu (saf fonksiyon: test edilebilir) --- */
  const OPTARGS = { c: { default: ['-O2'], debug: ['-O0', '-g'], speed: ['-O3'], size: ['-Os'] }, rust: { default: '2', debug: '0', speed: '3', size: 's' }, zig: { default: 'ReleaseSafe', debug: 'Debug', speed: 'ReleaseFast', size: 'ReleaseSmall' }, pas: { default: ['-O2'], debug: ['-g', '-O-'], speed: ['-O3'], size: ['-Os'] }, ldc: { default: ['-O2'], debug: ['-O0', '-g'], speed: ['-O3'], size: ['-Os'] }, dmd: { default: ['-O'], debug: ['-g'], speed: ['-O', '-inline'], size: ['-O'] } };
  function cStd(std, tl, cpp) { if (!std || std === 'auto') return []; let s = std; const t = tl; if (!cpp && /23$/.test(s)) { const need = t.family === 'clang' ? 18 : 14; if (t.major < need) s = s.replace('23', '2x'); } return ['-std=' + s]; }
  function planNative(req, tl, d) {
    const L = req.lang, o = req.options || {}, W = isWin(), names = req.files.map((f) => f.name), opt = o.opt || 'default', conGui = req.console === 'no'; const T = tl.byId; const cmds = []; const gen = {}; const notes = []; let winOut = W, output, outName, env = {}, exe = req.name + (W ? '.exe' : '');
    const mk = (tool, args, cwd, label, ms, e) => cmds.push({ exe: tool.path, args, cwd, label, ms: ms || 300000, env: Object.assign({}, env, e || {}) });
    const isSrc = (n, lang) => LANGS[lang].src.includes(extOf(n));
    if (L === 'c' || L === 'cpp') {
      const cc = T.c, cxx = T.cpp; const cSrc = names.filter((n) => extOf(n) === 'c'); const xSrc = L === 'cpp' ? names.filter((n) => isSrc(n, 'cpp') && extOf(n) !== 'c') : []; const mixed = cSrc.length && xSrc.length; const link = []; if (W) { for (const l of o.winlibs || []) link.push('-l' + l); if (conGui) link.push('-mwindows'); } else link.push('-lm', '-pthread');
      const stat = o.static && process.platform !== 'darwin' ? ['-static'] : []; const strip = opt !== 'debug' && process.platform !== 'darwin' ? ['-s'] : []; const optA = OPTARGS.c[opt]; output = path.join(d.out, exe); outName = exe;
      if (!mixed) { const tool = xSrc.length ? cxx : cc; mk(tool, [...cStd(o.std, tool, !!xSrc.length), ...optA, '-o', output, ...(xSrc.length ? xSrc : cSrc), ...stat, ...strip, ...link], d.src, tool.tool + ' ' + (xSrc.length ? 'C++' : 'C')); }
      else { const objs = []; for (const n of names.filter((x) => isSrc(x, 'cpp'))) { const isC = extOf(n) === 'c'; const tool = isC ? cc : cxx; const obj = path.join(d.obj, n + '.o'); objs.push(obj); mk(tool, [...(isC ? cStd('c17', tool, false) : cStd(o.std, tool, true)), ...optA, '-c', n, '-o', obj], d.src, tool.tool + ' -c ' + n); } mk(cxx, [...objs, '-o', output, ...stat, ...strip, ...link], d.src, cxx.tool + ' (bağlama)'); }
    } else if (L === 'rust') {
      const t = T.rust; const crate = req.name.replace(/[^A-Za-z0-9_]/g, '_'); output = path.join(d.out, exe); outName = exe; env = { RUSTFLAGS: '', CARGO_ENCODED_RUSTFLAGS: '', RUSTC_WRAPPER: '', RUSTC_WORKSPACE_WRAPPER: '' };
      mk(t, ['--edition', o.edition || '2021', '-C', 'opt-level=' + OPTARGS.rust[opt], ...(opt === 'debug' ? ['-g'] : ['-C', 'strip=symbols']), '--crate-name', crate, '-o', output, req.main], d.src, 'rustc ' + req.main);
    } else if (L === 'go') {
      const t = T.go; const tg = o.target && o.target !== 'host' ? o.target.split('/') : null; winOut = tg ? tg[0] === 'windows' : W; exe = req.name + (winOut ? '.exe' : ''); output = path.join(d.out, exe); outName = exe;
      gen['go.mod'] = 'module kovanapp\n\ngo ' + (t.major + '.' + t.minor) + '\n';
      env = { GO111MODULE: 'on', GOFLAGS: '-mod=readonly', GOPROXY: 'off', GOSUMDB: 'off', GOTOOLCHAIN: 'local', GOWORK: 'off', GOENV: 'off', CGO_ENABLED: '0', GOCACHE: path.join(d.cache, 'go-build'), GOPATH: path.join(d.cache, 'gopath') }; if (tg) { env.GOOS = tg[0]; env.GOARCH = tg[1]; }
      const ld = (opt === 'debug' ? '' : '-s -w') + (winOut && conGui ? ' -H=windowsgui' : ''); mk(t, ['build', '-trimpath', ...(ld.trim() ? ['-ldflags', ld.trim()] : []), '-o', output, '.'], d.src, 'go build');
    } else if (L === 'zig') {
      const t = T.zig; const tg = o.target && o.target !== 'host' ? o.target : ''; winOut = tg ? /windows/.test(tg) : W; exe = req.name + (winOut ? '.exe' : ''); output = path.join(d.out, exe); outName = exe;
      mk(t, ['build-exe', req.main, '-O', OPTARGS.zig[opt], '-femit-bin=' + output, '--name', req.name, ...(tg ? ['-target', tg] : []), ...(o.libc ? ['-lc'] : []), ...(winOut && conGui ? ['--subsystem', 'windows'] : []), '--cache-dir', path.join(d.work, 'zig-local'), '--global-cache-dir', path.join(d.cache, 'zig-global')], d.src, 'zig build-exe ' + req.main, 600000);
    } else if (L === 'csharp') {
      const t = T.csharp; const tfm = 'net' + t.major + '.0' + (o.winforms ? '-windows' : ''); const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
      const cs = names.filter((n) => extOf(n) === 'cs'); const proj = path.join(d.src, 'kovanapp.csproj');
      gen['kovanapp.csproj'] = '<Project Sdk="Microsoft.NET.Sdk">\n  <PropertyGroup>\n    <OutputType>' + (conGui && (W || o.winforms) ? 'WinExe' : 'Exe') + '</OutputType>\n    <TargetFramework>' + tfm + '</TargetFramework>\n' + (o.winforms ? '    <UseWindowsForms>true</UseWindowsForms>\n' : '') + '    <AssemblyName>' + esc(req.name) + '</AssemblyName>\n    <RootNamespace>' + esc(req.name.replace(/[^A-Za-z0-9_]/g, '_')) + '</RootNamespace>\n    <ImplicitUsings>' + (o.implicitUsings === false ? 'disable' : 'enable') + '</ImplicitUsings>\n    <Nullable>disable</Nullable>\n    <LangVersion>latest</LangVersion>\n    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>\n    <GenerateDocumentationFile>false</GenerateDocumentationFile>\n    <SatelliteResourceLanguages>en</SatelliteResourceLanguages>\n    <NuGetAudit>false</NuGetAudit>\n    <DebugType>' + (opt === 'debug' ? 'portable' : 'none') + '</DebugType>\n    <Optimize>' + (opt === 'debug' ? 'false' : 'true') + '</Optimize>\n' + (req.main ? '    <StartupObject>' + esc(req.main) + '</StartupObject>\n' : '') + '  </PropertyGroup>\n  <ItemGroup>\n' + cs.map((n) => '    <Compile Include="' + esc(n) + '" />\n').join('') + '  </ItemGroup>\n</Project>\n';
      output = d.out; outName = req.name + (W ? '.exe' : ''); notes.push('framework');
      env = { DOTNET_CLI_HOME: path.join(d.work, 'dotnet-home'), NUGET_PACKAGES: path.join(d.work, 'nuget'), DOTNET_NOLOGO: '1', DOTNET_CLI_TELEMETRY_OPTOUT: '1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE: '1', MSBUILDDISABLENODEREUSE: '1', DOTNET_STARTUP_HOOKS: '', DOTNET_ADD_GLOBAL_TOOLS_TO_PATH: '0' };
      mk(t, ['build', proj, '-c', 'Release', '-o', d.out, '--nologo', '-v', 'q', '-nodeReuse:false', '-p:UseSharedCompilation=false', '-p:TreatWarningsAsErrors=false'], d.src, 'dotnet build', 600000);
    } else if (L === 'kotlin') {
      const t = T.kotlin; const jdk = tl.jdk.best; output = path.join(d.work, 'kt', 'app.jar'); const kt = names.filter((n) => extOf(n) === 'kt');
      mk({ path: bin(jdk.home, 'java') }, ['-Xmx1g', '-cp', t.preloader, 'org.jetbrains.kotlin.preloading.Preloader', '-cp', t.compiler, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-nowarn', '-include-runtime', '-d', output, ...kt], d.src, 'kotlinc', 600000);
    } else if (L === 'pascal') {
      const t = T.pascal; output = path.join(d.out, exe); outName = exe; const mode = o.mode && o.mode !== 'default' ? ['-M' + o.mode] : [];
      mk(t, ['-vewn', ...OPTARGS.pas[opt], ...(opt === 'debug' || process.platform === 'darwin' ? [] : ['-Xs']), ...mode, '-FU' + d.obj, '-FE' + d.out, '-o' + exe, req.main], d.src, 'fpc ' + req.main);
    } else if (L === 'fortran') {
      const t = T.fortran; output = path.join(d.out, exe); outName = exe; const order = (req.order || []).filter((n) => names.includes(n)); const src = names.filter((n) => LANGS.fortran.src.includes(extOf(n))); const files = [...order.filter((n) => src.includes(n)), ...src.filter((n) => !order.includes(n))];
      const stdA = !o.std || o.std === 'gnu' ? [] : [o.std === 'legacy' ? '-std=legacy' : '-std=' + o.std]; const stat = o.static ? (W ? ['-static'] : process.platform === 'darwin' ? [] : ['-static-libgfortran', '-static-libgcc']) : [];
      mk(t, [...stdA, ...OPTARGS.c[opt], '-ffree-line-length-none', '-J', d.obj, '-o', output, ...files, ...stat, ...(opt === 'debug' ? [] : ['-s'])], d.src, 'gfortran');
    } else if (L === 'd') {
      const t = T.d; output = path.join(d.out, exe); outName = exe; const ldc = t.tool === 'ldc2'; const files = names.filter((n) => extOf(n) === 'd');
      mk(t, [...(ldc ? OPTARGS.ldc[opt] : OPTARGS.dmd[opt]), '-of=' + output, '-od=' + d.obj, ...files], d.src, t.tool);
    }
    return { cmds, gen, output, outName, winOut, notes, tool: (T[L] || {}).tool, toolVersion: (T[L] || {}).version };
  }
  function createCompileHost(deps) {
    deps = deps || {}; const jobs = new Map(); let seq = 0; let active = null; const errE = (message, extra) => Object.assign({ error: 'compile', message }, extra || {});
    const root = () => path.join(deps.outputBase || deps.downloadsDir || os.homedir(), 'Kovan-Derleme');
    const handlers = {
      'compile:jdk': async () => { try { return findJdks({ env: deps.env, extra: deps.jdkDirs, only: deps.onlyJdkDirs }); } catch (e) { return errE(String(e && e.message || e)); } },
      'compile:tools': async () => { try { const t = findTools({ env: deps.env, extra: deps.toolDirs, only: deps.onlyToolDirs, jdkExtra: deps.jdkDirs, jdkOnly: deps.onlyJdkDirs }); return { list: t.list.map((x) => ({ id: x.id, name: x.name, ok: x.ok, tool: x.tool || '', version: x.version || '', path: x.path || '', why: x.why || '' })), windows: t.windows, platform: t.platform }; } catch (e) { return errE(String(e && e.message || e)); } },
      'compile:start': async (_e, req) => {
        const bad = validate(req); if (bad) return errE(bad); if (active) return errE('Başka bir derleme sürüyor.');
        if (req.lang && req.lang !== 'java') {
          const tl = findTools({ env: deps.env, extra: deps.toolDirs, only: deps.onlyToolDirs, jdkExtra: deps.jdkDirs, jdkOnly: deps.onlyJdkDirs }); const t = tl.byId[req.lang]; if (!t || !t.ok) return errE(LANGS[req.lang].name + ' derleyicisi bulunamadı: ' + (t ? t.why : ''), { needTool: true, lang: req.lang });
          if (req.lang === 'cpp' && req.files.some((f) => extOf(f.name) === 'c') && !tl.byId.c.ok) return errE('C dosyaları için C derleyicisi (gcc/clang) bulunamadı.', { needTool: true, lang: 'c' });
          if (req.lang === 'csharp' && req.options && req.options.winforms && !isWin()) return errE('Windows Forms yalnızca Windows’ta derlenir.');
          const id = String(++seq); const keys = req.lang === 'kotlin' ? ['tool', 'compile', 'deps', 'pack', 'save'] : ['tool', 'compile', 'save']; const job = { id, state: 'running', steps: keys.map((k) => ({ id: NSTEPS[k][0], label: NSTEPS[k][1], status: 'wait', detail: '' })), log: '', result: null, error: null, started: Date.now() }; jobs.set(id, job); active = job; if (jobs.size > 8) jobs.delete(jobs.keys().next().value);
          runNative(job, req, tl).catch((e) => { job.state = 'failed'; job.error = String(e && e.message || e); }).finally(() => { active = null; });
          return { id };
        }
        const jdks = findJdks({ env: deps.env, extra: deps.jdkDirs, only: deps.onlyJdkDirs }); if (!jdks.found) return errE('Uygun JDK bulunamadı. JDK ' + MIN_MAJOR + '+ (javac, jar, jdeps, jpackage içeren tam JDK) kurun.', { needJdk: true, jdks: jdks.all });
        const id = String(++seq); const job = { id, state: 'running', steps: STEPS.map(([k, l]) => ({ id: k, label: l, status: 'wait', detail: '' })), log: '', result: null, error: null, started: Date.now() }; jobs.set(id, job); active = job; if (jobs.size > 8) jobs.delete(jobs.keys().next().value);
        run(job, req, jdks.best).catch((e) => { job.state = 'failed'; job.error = String(e && e.message || e); }).finally(() => { active = null; });
        return { id };
      },
      'compile:job': async (_e, id) => { const j = jobs.get(String(id)); if (!j) return errE('İş bulunamadı.'); return { id: j.id, state: j.state, steps: j.steps, log: j.log.slice(-TAIL), result: j.result, error: j.error }; },
      'compile:cancel': async (_e, id) => { const j = jobs.get(String(id)); if (!j) return errE('İş bulunamadı.'); j.canceled = true; try { j.child && j.child.kill(); } catch (e) { /* bitmis */ } return { ok: true }; },
      'compile:open': async (_e, id) => { const j = jobs.get(String(id)); if (!j || !j.result || !j.result.launcher) return errE('Açılacak çıktı yok.'); if (deps.showItemInFolder) deps.showItemInFolder(j.result.launcher); return { ok: true }; }
    };
    function exec(job, file, args, cwd, ms, envx) {
      return new Promise((resolve) => {
        const env = Object.assign(nativeEnv(deps.env), envx || {}); let out = ''; let done = false; let timer;
        const fin = (r) => { if (done) return; done = true; clearTimeout(timer); job.child = null; resolve(r); };
        let c; try { c = cp.spawn(file, args, { cwd, env, windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return fin({ code: -1, out: String(e && e.message || e) }); }
        job.child = c; const add = (d) => { out += d; if (out.length > 200000) out = out.slice(-100000); }; c.stdout.on('data', add); c.stderr.on('data', add);
        timer = setTimeout(() => { try { c.kill(); } catch (e) { /* bitmis */ } fin({ code: -2, out: out + '\n[zaman aşımı]' }); }, ms || 120000);
        c.on('error', (e) => fin({ code: -1, out: out + String(e && e.message || e) })); c.on('close', (code) => fin({ code, out }));
      });
    }
    async function packApp(job, jdk, jar, inp, dst, name, mainClass, consoleMode, ctx, work) {
      const { step, logp, fail } = ctx; let r;
        step('deps', 'run'); let mods = 'java.base'; r = await exec(job, bin(jdk.home, 'jdeps'), ['--print-module-deps', '--ignore-missing-deps', '--multi-release', 'base', jar], work, 60000); logp('$ jdeps ...\n' + r.out);
        const last = r.out.trim().split(/\r?\n/).pop(); if (r.code === 0 && /^[a-z][\w.]*(,[a-z][\w.]*)*$/.test(last)) { mods = last; step('deps', 'ok', mods); } else step('deps', 'ok', 'jdeps çözemedi; varsayılan: java.base' + (/awt|swing/.test(mainClass) ? '' : ''));
        if (!/(^|,)java\.base(,|$)/.test(mods)) mods = 'java.base,' + mods; const gui = consoleMode === 'no' ? true : consoleMode === 'yes' ? false : /java\.desktop|javafx/.test(mods); const consoleOn = !gui;
        step('pack', 'run'); const args = ['--type', 'app-image', '--name', name, '--input', inp, '--main-jar', 'app.jar', '--main-class', mainClass, '--dest', dst, '--add-modules', mods, '--jlink-options', '--strip-debug --no-header-files --no-man-pages']; if (isWin() && consoleOn) args.push('--win-console');
        r = await exec(job, bin(jdk.home, 'jpackage'), args, work, 600000); logp('$ jpackage ...\n' + r.out); if (job.canceled) { job.state = 'canceled'; step('pack', 'fail', 'İptal edildi'); return; }
        if (r.code !== 0) return fail('pack', 'Paketleme başarısız (jpackage). Ayrıntı için günlüğe bak.', { jpackageOutput: r.out.slice(-TAIL) });
        const made = ls(dst); if (made.length !== 1) return fail('pack', 'jpackage beklenen çıktıyı üretmedi.'); step('pack', 'ok');
        step('save', 'run'); fs.mkdirSync(root(), { recursive: true }); const outDir = uniqueDir(root(), name); fs.cpSync(path.join(dst, made[0]), outDir, { recursive: true }); fs.copyFileSync(jar, path.join(outDir, name + '.jar'));
        const launcher = isWin() ? path.join(outDir, name + '.exe') : process.platform === 'darwin' ? outDir : path.join(outDir, 'bin', name); if (!fs.existsSync(launcher)) return fail('save', 'Çalıştırıcı dosya bulunamadı: ' + path.basename(launcher));
        let size = 0; const walk = (d) => { for (const n of ls(d)) { const p = path.join(d, n); try { const s = fs.lstatSync(p); if (s.isDirectory()) walk(p); else size += s.size; } catch (e) { /* atla */ } } }; walk(outDir);
        step('save', 'ok', outDir); job.result = { outDir, launcher, launcherName: path.basename(launcher), jar: path.join(outDir, name + '.jar'), size, modules: mods, gui, console: consoleOn, jdk: { version: jdk.version, home: jdk.home }, windows: isWin() };
        job.state = 'done'; if (deps.notify) { try { deps.notify('Kovan Derleyici', 'Hazır: ' + path.basename(launcher) + ' (İndirilenler\\Kovan-Derleme)'); } catch (e) { /* bildirim yok */ } }
    }
    const scrub = (out, work) => String(out).replace(new RegExp(work.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&'), 'g'), '.').replace(/\/tmp\/kovan-[A-Za-z0-9_-]+/g, '.');
    const NSTEPS = { tool: ['tool', 'Araç zinciri bulundu'], compile: ['compile', 'Derleniyor'], deps: ['deps', 'Gerekli modüller çözümleniyor (jdeps)'], pack: ['pack', 'Uygulama paketleniyor (jpackage)'], save: ['save', 'İndirilenler klasörüne kaydediliyor'] };
    async function runNative(job, req, tl) {
      const S = (k) => job.steps.find((x) => x.id === k); const step = (k, st, d) => { const x = S(k); if (!x) return; x.status = st; if (d !== undefined) x.detail = d; };
      const logp = (t) => { job.log += t + '\n'; }; const work = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-' + req.lang + '-'));
      const fail = (k, msg, extra) => { step(k, 'fail', msg); job.state = 'failed'; job.error = msg; if (extra) job.result = extra; };
      try {
        const t = tl.byId[req.lang]; step('tool', 'ok', t.tool + ' ' + t.version);
        const cache = path.join(os.tmpdir(), 'kovan-build-cache'); const d = { work, src: path.join(work, 'src'), out: path.join(work, 'out'), obj: path.join(work, 'obj'), cache }; for (const x of [d.src, d.out, d.obj, cache, path.join(work, 'kt')]) fs.mkdirSync(x, { recursive: true });
        for (const f of req.files) fs.writeFileSync(path.join(d.src, f.name), Buffer.from(f.bytes));
        const plan = planNative(req, tl, d); for (const [n, c] of Object.entries(plan.gen)) fs.writeFileSync(path.join(d.src, n), c);
        for (const c of plan.cmds) {
          step('compile', 'run', c.label); const r = await exec(job, c.exe, c.args, c.cwd, c.ms, Object.assign({ TMPDIR: work, TEMP: work, TMP: work }, c.env)); logp('$ ' + c.label + '\n' + scrub(r.out, work));
          if (job.canceled) { job.state = 'canceled'; step('compile', 'fail', 'İptal edildi'); return; }
          if (r.code !== 0) return fail('compile', 'Derleme hatası (' + c.label.split(' ')[0] + '). Ayrıntı için günlüğe bak.', { compilerOutput: scrub(r.out, work).slice(-TAIL), lang: req.lang });
        }
        step('compile', 'ok');
        if (req.lang === 'kotlin') {
          if (!fs.existsSync(plan.output)) return fail('compile', 'Kotlin derleyicisi JAR üretmedi.');
          const inp = path.join(work, 'input'), dst = path.join(work, 'dest'); fs.mkdirSync(inp); fs.mkdirSync(dst); const jar = path.join(inp, 'app.jar'); fs.copyFileSync(plan.output, jar);
          await packApp(job, tl.jdk.best, jar, inp, dst, req.name, req.main, req.console, { step, logp, fail }, work); if (job.result && job.state === 'done') Object.assign(job.result, { lang: 'kotlin', langName: 'Kotlin', tool: 'kotlinc ' + t.version, target: 'host' }); return;
        }
        if (!fs.existsSync(plan.output)) return fail('compile', 'Derleyici çıktı dosyasını üretmedi: ' + (plan.outName || ''));
        step('save', 'run'); fs.mkdirSync(root(), { recursive: true }); const outDir = uniqueDir(root(), req.name); fs.mkdirSync(outDir, { recursive: true }); let launcher;
        if (req.lang === 'csharp') { for (const n of ls(plan.output)) { if (/\.pdb$/i.test(n)) continue; const sp = path.join(plan.output, n); if (fs.statSync(sp).isFile()) fs.copyFileSync(sp, path.join(outDir, n)); } launcher = path.join(outDir, plan.outName); if (!fs.existsSync(launcher)) { const dll = path.join(outDir, req.name + '.dll'); if (!fs.existsSync(dll)) return fail('save', 'Çıktı bulunamadı: ' + plan.outName); launcher = dll; } }
        else { launcher = path.join(outDir, plan.outName); fs.copyFileSync(plan.output, launcher); try { if (!plan.winOut) fs.chmodSync(launcher, 0o755); } catch (e) { /* izin ayarlanamadı */ } }
        let size = 0; for (const n of ls(outDir)) { try { size += fs.statSync(path.join(outDir, n)).size; } catch (e) { /* atla */ } }
        const sha256 = require('crypto').createHash('sha256').update(fs.readFileSync(launcher)).digest('hex'); const tgt = (req.options && req.options.target) || 'host';
        step('save', 'ok', outDir); job.result = { outDir, launcher, launcherName: path.basename(launcher), size, sha256, lang: req.lang, langName: LANGS[req.lang].name, tool: plan.tool + ' ' + plan.toolVersion, target: tgt, windows: plan.winOut, runsHere: plan.winOut === isWin() && (tgt === 'host' || req.lang === 'csharp' || true), framework: req.lang === 'csharp', gui: req.console === 'no' };
        job.state = 'done'; if (deps.notify) { try { deps.notify('Kovan Derleyici', 'Hazır: ' + path.basename(launcher) + ' (İndirilenler\\Kovan-Derleme)'); } catch (e) { /* bildirim yok */ } }
      } finally { try { fs.rmSync(work, { recursive: true, force: true }); } catch (e) { /* gecici klasor */ } if (job.state === 'running') job.state = 'failed'; }
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
        return await packApp(job, jdk, jar, inp, dst, req.name, req.mainClass, req.console, { step, logp, fail }, work);
      } finally { try { fs.rmSync(work, { recursive: true, force: true }); } catch (e) { /* gecici klasor */ } if (job.state === 'running') job.state = 'failed'; }
    }
    return { handlers };
  }
  return { createCompileHost, findJdks, findTools, planNative, validate, validateNative, LANGS, LIM, MIN_MAJOR, _setPlatform: (p) => { platOverride = p; } };
})();

/* --- Kurulum kimligi + imzali engelli listesi + sahip modu + Notlarim (Kovan) ---
 * Tasarim (durust sinirlar README'de de var):
 *  - Kurulum kimligi: makine GUID'inin tuzlu SHA-256 ozetinden turetilen 16 karakterlik rastgele gorunumlu kimlik (geri cevrilemez; GUID yoksa rastgele uretilip saklanir).
 *    Hicbir yere OTOMATIK GONDERILMEZ (telemetri yok). Sahibi, kimligi ancak kullanici ona kendisi iletirse bilir.
 *  - Engelli listesi: herkese acik blocklist.json = { manifest, sig }. Ed25519 imzasi uygulamanin guven anahtariyla (guncelleme anahtari) dogrulanir; imzasiz/bozuk/eski (seq geri sarma) liste yok sayilir.
 *    Liste yalnizca kimlik listeler; istek kimlik/kullanici bilgisi GONDERMEZ (yalnizca GitHub raw adresine dogrudan GET). Ag hatasinda engel UYGULANMAZ (fail-open), ama daha once dogrulanmis onbellek uygulanir.
 *  - Sahip modu: private.pem dosyasini (yalnizca bellekte) sec -> uygulamanin guven anahtariyla eslesirse acilir. Anahtar diske yazilmaz/kopyalanmaz/gunluklenmez, arayuze gecmez.
 *    Kalici olan yalnizca "sahip" bayragi (Notlarim/Yonetim araclarinin gorunmesi; saf arayuz kolayligi). Liste IMZALAMAK icin anahtarin o oturumda yeniden secilmesi gerekir.
 *  - Notlarim: yalnizca bu cihazda (userData/notes.json), atomik yazim + .bak, aga hicbir sey gonderilmez. */
const ACCESSMOD = (() => {
  const fs = require('fs'); const path = require('path'); const crypto = require('crypto'); const cp = require('child_process'); const https = require('https');
  const EMBEDDED_PUBKEY = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAzd4sQ75S5pVxMGRgjONDV6fWeWB7qKwp7T2mYYXn2Wk=\n-----END PUBLIC KEY-----\n';
  const DEFAULT_URL = 'https://raw.githubusercontent.com/yigido213/StatScan/main/blocklist.json';
  /* Sahibin kurulum kimlikleri: bu kimlikteki kurulum anahtar secmeden sahip sayilir (Notlarim + Yonetim hemen gorunur). Kimlik makine GUID'inin tuzlu ozetidir; baska makine ayni kimligi uretemez. Liste imzalama yine private.pem ister. */
  const OWNER_IDS = ['OPAMWK7TX6YLR76T'];
  const ID_RE = /^[A-Z2-7]{16}$/; const LIM = { entries: 5000, text: 512 * 1024, note: 200, notice: 300, notes: 5000, noteText: 200000, notesTotal: 20 * 1024 * 1024, keyFile: 8192 };
  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function b32(buf) { let bits = 0, val = 0, out = ''; for (const b of buf) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } } if (bits > 0) out += B32[(val << (5 - bits)) & 31]; return out; }
  const fmtId = (n) => n.match(/.{4}/g).join('-'); const normId = (s) => String(s || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  const sha256 = (x) => crypto.createHash('sha256').update(x).digest();
  const readJson = (f) => { try { const o = JSON.parse(fs.readFileSync(f, 'utf8')); return o && typeof o === 'object' ? o : null; } catch (e) { return null; } };
  function writeAtomic(f, text, bak) { fs.mkdirSync(path.dirname(f), { recursive: true }); if (bak) { try { if (fs.existsSync(f)) fs.copyFileSync(f, f + '.bak'); } catch (e) { /* yedek alinamadi */ } } const tmp = f + '.tmp'; fs.writeFileSync(tmp, text, { mode: 0o600 }); fs.renameSync(tmp, f); }
  function machineGuid(platform) {
    const run = (cmd, args) => { const r = cp.spawnSync(cmd, args, { encoding: 'utf8', timeout: 5000, windowsHide: true, shell: false }); return r.status === 0 ? String(r.stdout || '') : ''; };
    if (platform === 'win32') { const m = /MachineGuid\s+REG_SZ\s+([0-9A-Fa-f-]{16,})/.exec(run('reg', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'])); return m ? m[1] : null; }
    if (platform === 'darwin') { const m = /"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{16,})"/.exec(run('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'])); return m ? m[1] : null; }
    for (const f of ['/etc/machine-id', '/var/lib/dbus/machine-id']) { try { const t = fs.readFileSync(f, 'utf8').trim(); if (/^[0-9a-f]{16,}$/i.test(t)) return t; } catch (e) { /* yok */ } } return null;
  }
  function trustedKey(pk) { for (const k of [pk, EMBEDDED_PUBKEY]) { if (!k) continue; try { const key = crypto.createPublicKey(k); if (key.asymmetricKeyType === 'ed25519') return key; } catch (e) { /* bu bicim degil */ } } return null; }
  const spkiOf = (k) => k.export({ type: 'spki', format: 'der' });
  /* ---- imzali liste: bicim { manifest: "<JSON>", sig: base64(Ed25519(manifest)) } ---- */
  function verifyBlocklist(text, pub) {
    if (typeof text !== 'string' || !text.length || text.length > LIM.text) return { ok: false, why: 'boyut' }; if (!pub) return { ok: false, why: 'anahtar yok' };
    let o; try { o = JSON.parse(text); } catch (e) { return { ok: false, why: 'JSON değil' }; } if (!o || typeof o.manifest !== 'string' || typeof o.sig !== 'string') return { ok: false, why: 'biçim' };
    const sig = Buffer.from(o.sig, 'base64'); if (sig.length !== 64) return { ok: false, why: 'imza biçimi' }; let good = false; try { good = crypto.verify(null, Buffer.from(o.manifest, 'utf8'), pub, sig); } catch (e) { good = false; } if (!good) return { ok: false, why: 'imza geçersiz' };
    let m; try { m = JSON.parse(o.manifest); } catch (e) { return { ok: false, why: 'manifest' }; }
    if (!m || m.format !== 1 || !Number.isInteger(m.seq) || m.seq < 1 || m.seq > 1e9 || !Array.isArray(m.entries) || m.entries.length > LIM.entries) return { ok: false, why: 'manifest alanları' };
    const entries = []; const seen = new Set(); for (const e of m.entries) { const id = normId(e && e.id); if (!ID_RE.test(id)) return { ok: false, why: 'kimlik biçimi' }; if (seen.has(id)) continue; seen.add(id); entries.push({ id, note: typeof e.note === 'string' ? e.note.slice(0, LIM.note) : '', added: typeof e.added === 'string' ? e.added.slice(0, 40) : '' }); }
    return { ok: true, seq: m.seq, created: typeof m.created === 'string' ? m.created : '', notice: typeof m.notice === 'string' ? m.notice.slice(0, LIM.notice) : '', entries };
  }
  function signBlocklist(priv, data) {
    const entries = (data.entries || []).map((e) => ({ id: normId(e.id), note: String(e.note || '').slice(0, LIM.note), added: String(e.added || '').slice(0, 40) })); if (entries.some((e) => !ID_RE.test(e.id))) throw new Error('Geçersiz kimlik.');
    if (!Number.isInteger(data.seq) || data.seq < 1) throw new Error('Geçersiz seq.'); const manifest = JSON.stringify({ format: 1, seq: data.seq, created: new Date().toISOString(), notice: String(data.notice || '').slice(0, LIM.notice), entries });
    const sig = crypto.sign(null, Buffer.from(manifest, 'utf8'), priv); return JSON.stringify({ manifest, sig: sig.toString('base64') }, null, 1) + '\n';
  }
  function fetchHttps(url, ms, hops) {
    return new Promise((resolve, reject) => {
      let u; try { u = new URL(url); } catch (e) { return reject(new Error('adres')); } if (u.protocol !== 'https:') return reject(new Error('yalnızca https'));
      const req = https.get(u, { headers: { 'User-Agent': 'Kovan', Accept: 'application/json' }, timeout: ms || 8000 }, (res) => {
        if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location) { res.resume(); if ((hops || 0) >= 3) return reject(new Error('çok yönlendirme')); let nu; try { nu = new URL(res.headers.location, u); } catch (e) { return reject(new Error('yönlendirme')); } if (!/(^|\.)(githubusercontent\.com|github\.com)$/.test(nu.hostname)) return reject(new Error('yönlendirme reddedildi')); return resolve(fetchHttps(nu.toString(), ms, (hops || 0) + 1)); }
        if (res.statusCode !== 200) { res.resume(); return reject(new Error('HTTP ' + res.statusCode)); } let n = 0; const chunks = []; res.on('data', (c) => { n += c.length; if (n > LIM.text) { req.destroy(new Error('çok büyük')); return; } chunks.push(c); }); res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8'))); res.on('error', reject);
      }); req.on('timeout', () => req.destroy(new Error('zaman aşımı'))); req.on('error', reject);
    });
  }
  function createAccessHost(deps) {
    deps = deps || {}; const dir = deps.dataDir; if (!dir) throw new Error('dataDir gerekli'); const F = (n) => path.join(dir, n); const now = deps.now || (() => Date.now());
    const pub = trustedKey(deps.publicKey); const pubFp = pub ? sha256(spkiOf(pub)).toString('hex').slice(0, 16) : '';
    const errE = (message, extra) => Object.assign({ error: 'access', message }, extra || {});
    /* kimlik */
    let id = null; { let guid = null; try { guid = deps.machineId ? deps.machineId() : machineGuid(deps.platform || process.platform); } catch (e) { guid = null; }
      if (guid && String(guid).trim()) id = b32(sha256('kovan-install-v1:' + String(guid).trim().toLowerCase()).subarray(0, 10));
      else { const o = readJson(F('install-id.json')); if (o && ID_RE.test(String(o.id || ''))) id = o.id; else { id = b32(crypto.randomBytes(10)); try { writeAtomic(F('install-id.json'), JSON.stringify({ v: 1, id })); } catch (e) { /* yazilamadi: bu oturumluk */ } } } }
    /* liste durumu */
    const st = { checked: 0, source: 'none', seq: 0, blocked: false, notice: '', error: '', count: 0 }; let seenSeq = (readJson(F('access-state.json')) || {}).seq | 0; let applied = null; let timer = null;
    const apply = (v, source) => { applied = v; st.blocked = v.entries.some((e) => e.id === id); st.notice = st.blocked ? v.notice : ''; st.seq = v.seq; st.source = source; st.count = v.entries.length; };
    { let text = null; try { text = fs.readFileSync(F('blocklist-cache.json'), 'utf8'); } catch (e) { /* yok */ } if (text) { const v = verifyBlocklist(text, pub); if (v.ok && v.seq >= seenSeq) apply(v, 'cache'); } }
    async function refresh() {
      st.error = ''; try { const text = await (deps.fetchText || fetchHttps)(deps.blocklistUrl || DEFAULT_URL); const v = verifyBlocklist(text, pub); if (!v.ok) st.error = 'Liste doğrulanamadı (' + v.why + '); yok sayıldı.'; else if (v.seq < seenSeq) st.error = 'Liste eski (seq ' + v.seq + ' < ' + seenSeq + '); yok sayıldı.'; else { try { writeAtomic(F('blocklist-cache.json'), text); seenSeq = v.seq; writeAtomic(F('access-state.json'), JSON.stringify({ seq: seenSeq })); } catch (e) { /* onbellek yazilamadi */ } apply(v, 'remote'); } }
      catch (e) { st.error = 'Liste alınamadı: ' + String(e && e.message || e); } st.checked = now(); return snapshot();
    }
    let priv = null; let persistErr = ''; /* anahtar bellekte dogrulandiysa sahip say (owner.json yazilamasa bile); yeniden aciliste dosya bayragi gecerli */
    const ownerIds = (deps.ownerIds || OWNER_IDS).map(normId); const ownerFlag = () => { if (priv || ownerIds.includes(id)) return true; const o = readJson(F('owner.json')); return !!(o && pubFp && o.fp === pubFp); };
    const snapshot = () => ({ id: fmtId(id), blocked: st.blocked, notice: st.notice, source: st.source, seq: st.seq, count: st.count, checked: st.checked, error: st.error, owner: ownerFlag(), unlocked: !!priv, trusted: !!pub });
    const needOwner = () => (ownerFlag() ? null : errE('Bu işlem yalnızca uygulamanın sahibi içindir.'));
    const needKey = () => (priv ? null : errE('Önce sahip anahtarını (private.pem) seç.', { needKey: true }));
    /* taslak */
    const draftRead = () => { const o = readJson(F('blocklist-draft.json')); if (o && Array.isArray(o.entries)) return { base: o.base | 0, notice: typeof o.notice === 'string' ? o.notice : '', entries: o.entries.filter((e) => e && ID_RE.test(String(e.id || ''))) }; return { base: applied ? applied.seq : 0, notice: applied ? applied.notice : '', entries: applied ? applied.entries.map((e) => ({ id: e.id, note: e.note, added: e.added })) : [] }; };
    const draftWrite = (d) => writeAtomic(F('blocklist-draft.json'), JSON.stringify(d));
    const draftView = (d) => ({ base: d.base, notice: d.notice, entries: d.entries.map((e) => ({ id: fmtId(e.id), note: e.note || '', added: e.added || '' })), self: fmtId(id) });
    async function unlockFromPath(file) {
      try { const sz = fs.statSync(file).size; if (sz > LIM.keyFile) return errE('Dosya çok büyük; bu bir özel anahtar dosyası değil.'); let key; try { key = crypto.createPrivateKey(fs.readFileSync(file)); } catch (e) { return errE('Anahtar okunamadı (şifreli PEM desteklenmez; make-ssu ile kullandığın private.pem’i seç).'); }
        if (key.asymmetricKeyType !== 'ed25519') return errE('Bu bir Ed25519 anahtarı değil.'); if (!pub) return errE('Uygulamada güvenilen anahtar yok.'); if (!spkiOf(crypto.createPublicKey(key)).equals(spkiOf(pub))) return errE('Bu anahtar, uygulamanın imza anahtarıyla eşleşmiyor.');
        priv = key; persistErr = ''; try { writeAtomic(F('owner.json'), JSON.stringify({ v: 1, fp: pubFp, at: new Date(now()).toISOString() })); } catch (e) { persistErr = String(e && e.message || e); /* bayrak yazilamadi: bu oturumda sahip, yeniden acilista anahtar gerekir */ } return { ok: true, owner: true, unlocked: true, persisted: !persistErr, persistError: persistErr };
      } catch (e) { return errE('Anahtar işlenemedi: ' + String(e && e.message || e)); }
    }
    const handlers = {
      'access:status': async () => snapshot(),
      'access:refresh': async () => refresh(),
      'owner:status': async () => ({ owner: ownerFlag(), unlocked: !!priv, trusted: !!pub }),
      'owner:unlock': async (_e, file) => { if (typeof file === 'string' && deps.allowPathUnlock) return unlockFromPath(file); if (!deps.chooseFile) return errE('Dosya seçimi yok.'); const f = await deps.chooseFile(); if (!f) return { canceled: true }; return unlockFromPath(f); },
      'owner:lock': async () => { priv = null; return { ok: true, owner: ownerFlag(), unlocked: false }; },
      'owner:off': async () => { priv = null; try { fs.rmSync(F('owner.json'), { force: true }); } catch (e) { /* yok */ } return { ok: true, owner: ownerFlag(), unlocked: false }; },
      'owner:bl:get': async () => needOwner() || { ok: true, draft: draftView(draftRead()), live: { seq: st.seq, count: st.count, source: st.source } },
      'owner:bl:add': async (_e, rawId, note) => { const bad = needOwner(); if (bad) return bad; const nid = normId(rawId); if (!ID_RE.test(nid)) return errE('Kimlik 16 karakter olmalı (A–Z ve 2–7), ör. ABCD-EFGH-IJKL-MNOP.'); if (nid === id) return errE('Kendi kimliğini engelleyemezsin.'); const d = draftRead(); if (d.entries.length >= LIM.entries) return errE('Liste dolu.'); if (d.entries.some((e) => e.id === nid)) return errE('Bu kimlik zaten listede.'); d.entries.push({ id: nid, note: String(note || '').slice(0, LIM.note), added: new Date(now()).toISOString().slice(0, 10) }); draftWrite(d); return { ok: true, draft: draftView(d) }; },
      'owner:bl:remove': async (_e, rawId) => { const bad = needOwner(); if (bad) return bad; const nid = normId(rawId); const d = draftRead(); const n = d.entries.length; d.entries = d.entries.filter((e) => e.id !== nid); if (d.entries.length === n) return errE('Bu kimlik listede yok.'); draftWrite(d); return { ok: true, draft: draftView(d) }; },
      'owner:bl:notice': async (_e, text) => { const bad = needOwner(); if (bad) return bad; const d = draftRead(); d.notice = String(text || '').slice(0, LIM.notice); draftWrite(d); return { ok: true, draft: draftView(d) }; },
      'owner:bl:publish': async () => {
        const bad = needOwner() || needKey(); if (bad) return bad; const d = draftRead(); const seq = Math.max(seenSeq, d.base | 0, st.seq) + 1; let text; try { text = signBlocklist(priv, { seq, entries: d.entries, notice: d.notice }); } catch (e) { return errE(String(e && e.message || e)); }
        const check = verifyBlocklist(text, pub); if (!check.ok) return errE('Üretilen liste kendi doğrulamasından geçmedi: ' + check.why);
        const out = path.join(deps.downloadsDir || dir, 'Kovan-Engel'); fs.mkdirSync(out, { recursive: true }); const file = path.join(out, 'blocklist.json'); fs.writeFileSync(file, text, { mode: 0o644 }); d.base = seq; draftWrite(d); if (deps.showItemInFolder) { try { deps.showItemInFolder(file); } catch (e) { /* yok */ } }
        return { ok: true, file, seq, count: d.entries.length, bytes: text.length };
      }
    };
    /* ---- Notlarim (yalnizca sahip; yalnizca yerel) ---- */
    const NF = F('notes.json'); let q = Promise.resolve(); const nid = () => 'n' + now().toString(36) + crypto.randomBytes(3).toString('hex');
    const readNotes = () => { const o = readJson(NF); const list = o && Array.isArray(o.notes) ? o.notes : []; return list.filter((n) => n && /^[a-z0-9]{4,32}$/.test(String(n.id || '')) && typeof n.text === 'string').map((n) => ({ id: n.id, text: n.text, pinned: !!n.pinned, created: +n.created || 0, updated: +n.updated || 0 })); };
    const writeNotes = (list) => { const text = JSON.stringify({ v: 1, notes: list }); if (text.length > LIM.notesTotal) throw new Error('Notlar çok büyük (en çok 20 MB).'); writeAtomic(NF, text, true); };
    const serial = (fn) => { const p = q.then(fn, fn); q = p.catch(() => {}); return p; };
    Object.assign(handlers, {
      'notes:list': async () => needOwner() || { ok: true, notes: readNotes() },
      'notes:save': async (_e, n) => needOwner() || serial(async () => {
        if (!n || typeof n !== 'object' || typeof n.text !== 'string' || n.text.length > LIM.noteText) return errE('Not geçersiz veya çok uzun (en çok 200.000 karakter).'); const list = readNotes(); let cur = n.id ? list.find((x) => x.id === n.id) : null;
        if (n.id && !/^[a-z0-9]{4,32}$/.test(String(n.id))) return errE('Not kimliği geçersiz.'); if (!cur) { if (list.length >= LIM.notes) return errE('En fazla ' + LIM.notes + ' not.'); cur = { id: n.id || nid(), text: '', pinned: false, created: now(), updated: now() }; list.unshift(cur); }
        cur.text = n.text; if (typeof n.pinned === 'boolean') cur.pinned = n.pinned; cur.updated = now(); try { writeNotes(list); } catch (e) { return errE('Not kaydedilemedi: ' + String(e && e.message || e)); } return { ok: true, note: Object.assign({}, cur) };
      }),
      'notes:delete': async (_e, noteId) => needOwner() || serial(async () => { const list = readNotes(); const i = list.findIndex((x) => x.id === String(noteId)); if (i < 0) return errE('Not bulunamadı.'); const [gone] = list.splice(i, 1); try { writeNotes(list); } catch (e) { return errE(String(e && e.message || e)); } return { ok: true, note: gone }; }),
      'notes:restore': async (_e, n) => needOwner() || serial(async () => { if (!n || typeof n.text !== 'string' || n.text.length > LIM.noteText || !/^[a-z0-9]{4,32}$/.test(String(n.id || ''))) return errE('Not geçersiz.'); const list = readNotes(); if (list.some((x) => x.id === n.id)) return { ok: true, note: list.find((x) => x.id === n.id) }; const note = { id: n.id, text: n.text, pinned: !!n.pinned, created: +n.created || now(), updated: +n.updated || now() }; list.push(note); try { writeNotes(list); } catch (e) { return errE(String(e && e.message || e)); } return { ok: true, note }; }),
      'notes:export': async () => { const bad = needOwner(); if (bad) return bad; const list = readNotes().sort((a, b) => (b.pinned - a.pinned) || (b.updated - a.updated)); const stamp = new Date(now()).toISOString().replace(/[-:T]/g, '').slice(0, 14); const out = path.join(deps.downloadsDir || dir, 'Kovan-Notlar'); fs.mkdirSync(out, { recursive: true }); const md = list.map((n) => '## ' + (n.text.split('\n')[0] || '(boş)').slice(0, 80) + '\n_' + new Date(n.updated).toISOString().slice(0, 16).replace('T', ' ') + (n.pinned ? ' · sabit' : '') + '_\n\n' + n.text + '\n').join('\n---\n\n'); const mdFile = path.join(out, 'notlar-' + stamp + '.md'); fs.writeFileSync(mdFile, md || '(not yok)\n'); fs.writeFileSync(path.join(out, 'notlar-' + stamp + '.json'), JSON.stringify(list, null, 1)); if (deps.showItemInFolder) { try { deps.showItemInFolder(mdFile); } catch (e) { /* yok */ } } return { ok: true, file: mdFile, count: list.length }; }
    });
    function start() { refresh(); if (!timer) { timer = setInterval(refresh, 6 * 3600 * 1000); if (timer.unref) timer.unref(); } }
    function stop() { if (timer) { clearInterval(timer); timer = null; } }
    return { handlers, start, stop, refresh, isBlocked: () => st.blocked, snapshot, id: () => id, fmtId };
  }
  return { createAccessHost, verifyBlocklist, signBlocklist, trustedKey, normId, fmtId, b32, machineGuid, EMBEDDED_PUBKEY, DEFAULT_URL, OWNER_IDS, ID_RE, LIM };
})();

/* --- Sistem araclari: Gorev Yoneticisi (Basic/Extended) + Gelismis Ag Izleyici (SYSMOD v0.0.1) ---
 * Yalnizca OKUR/GOSTERIR: dosya degistirmez, silmez, calistirmaz. Tek yazma islemi: kullanici onayiyla surec sonlandirma (sys:kill).
 * Arayuz komut/yol gonderemez; yalnizca tamsayi PID ve sabit kanallar. Ag: yalnizca yerel baglanti tablosu okunur; DNS/GeoIP sorgusu YOK.
 * Windows: PowerShell + WMI (CIM). Diger sistemler: /proc (yalnizca gelistirme/test icin; uygulama Windows hedefli). */
const SYSMOD = (() => {
  const fs = require('fs'); const path = require('path'); const os = require('os'); const cp = require('child_process');
  const NAMES_SYS = { 'svchost.exe': 'system32', 'lsass.exe': 'system32', 'csrss.exe': 'system32', 'winlogon.exe': 'system32', 'services.exe': 'system32', 'smss.exe': 'system32', 'wininit.exe': 'system32', 'taskhostw.exe': 'system32', 'spoolsv.exe': 'system32', 'dwm.exe': 'system32', 'conhost.exe': 'system32', 'fontdrvhost.exe': 'system32', 'sihost.exe': 'system32', 'ctfmon.exe': 'system32', 'dllhost.exe': 'system32', 'runtimebroker.exe': 'system32', 'searchindexer.exe': 'system32', 'explorer.exe': 'windows' };
  const SCRIPT_HOSTS = new Set(['powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'msbuild.exe', 'installutil.exe', 'wmic.exe']);
  const SUSP_ARGS = /(-enc(odedcommand)?\b|-e\s+[A-Za-z0-9+/=]{30,}|frombase64string|downloadstring|downloadfile|invoke-expression|\biex\b|-w(indowstyle)?\s+hidden|-nop\b|-noni\b|bypass|net\.webclient|invoke-webrequest|\bcurl\b.+http|urlcache|\/i:http|scrobj\.dll)/i;
  const BAD_DIRS = [/\\appdata\\local\\temp\\/i, /\\windows\\temp\\/i, /\\users\\public\\/i, /\\downloads\\/i, /\\\$recycle\.bin\\/i, /\\appdata\\roaming\\[^\\]+\.(exe|scr)$/i, /\\programdata\\[^\\]+\.(exe|scr)$/i];
  const SUSP_PORTS = { 4444: 'Metasploit varsayılanı', 1337: 'sık görülen arka kapı portu', 31337: 'klasik arka kapı portu', 6667: 'IRC (botnet C2)', 6697: 'IRC (TLS)', 5555: 'ADB/RAT portu', 9001: 'Tor yönlendirici', 9030: 'Tor dizin', 9050: 'Tor SOCKS', 9150: 'Tor Browser SOCKS', 8333: 'Bitcoin düğümü', 3333: 'madencilik havuzu (stratum)', 4443: 'sık görülen alternatif TLS', 2222: 'alternatif SSH', 12345: 'NetBus', 23: 'Telnet', 5900: 'VNC', 3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM (TLS)' };
  const MINER_PORTS = new Set([3333, 4444, 5555, 7777, 14444, 45560]);
  const swapped = (a, b) => { if (a.length !== b.length) return false; for (let i = 0; i < a.length - 1; i++) { if (a[i] !== b[i]) return a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2); } return false; };
  const lev = (a, b) => { const m = a.length, n = b.length; if (Math.abs(m - n) > 2) return 9; let p = Array.from({ length: n + 1 }, (_, i) => i); for (let i = 1; i <= m; i++) { const c = [i]; for (let j = 1; j <= n; j++) c[j] = Math.min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); p = c; } return p[n]; };

  /* ---- saf yardimcilar (test edilebilir) ---- */
  function ipClass(ip) {
    ip = String(ip || '').trim().toLowerCase(); if (!ip || ip === '*' || ip === '0.0.0.0' || ip === '::') return 'any';
    const m4 = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(ip); if (m4) ip = m4[1];
    if (ip.includes(':')) { if (ip === '::1') return 'loopback'; if (/^fe[89ab]/.test(ip)) return 'linklocal'; if (/^f[cd]/.test(ip)) return 'private'; if (/^ff/.test(ip)) return 'multicast'; return 'public'; }
    const p = ip.split('.').map(Number); if (p.length !== 4 || p.some((x) => !(x >= 0 && x <= 255))) return 'unknown';
    if (p[0] === 127) return 'loopback'; if (p[0] === 10) return 'private'; if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return 'private'; if (p[0] === 192 && p[1] === 168) return 'private';
    if (p[0] === 169 && p[1] === 254) return 'linklocal'; if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return 'cgnat'; if (p[0] >= 224 && p[0] <= 239) return 'multicast'; if (p[0] === 0 || p[0] >= 240) return 'unknown';
    return 'public';
  }
  const isExternal = (ip) => { const c = ipClass(ip); return c === 'public' || c === 'cgnat'; };
  /* ayni uzaga duzenli araliklarla yeni baglanti: beacon (C2 isareti) benzeri. times: ms zaman damgalari */
  function beaconScore(times) {
    const t = (times || []).slice().sort((a, b) => a - b); if (t.length < 6) return { beacon: false, n: t.length };
    const d = []; for (let i = 1; i < t.length; i++) d.push(t[i] - t[i - 1]); const mean = d.reduce((a, b) => a + b, 0) / d.length; if (mean < 4000 || mean > 3600000) return { beacon: false, n: t.length, mean };
    const sd = Math.sqrt(d.reduce((a, b) => a + (b - mean) * (b - mean), 0) / d.length); const cv = sd / mean;
    return { beacon: cv < 0.2, n: t.length, mean: Math.round(mean), cv: +cv.toFixed(3) };
  }
  function splitCmd(s) { return String(s || ''); }
  /* sureç icin sezgisel supheli puani (0-100) + gerekceler. sig: { status:'Valid'|'NotSigned'|'HashMismatch'|'NotTrusted'|'Unknown', signer } veya null */
  function scoreProc(p, sig, conns, ctx) {
    const why = []; let s = 0; const add = (n, t) => { s += n; why.push({ pts: n, text: t }); };
    const name = String(p.name || '').toLowerCase(); const exe = String(p.path || ''); const low = exe.toLowerCase();
    if (p.pid === 0 || p.pid === 4 || name === 'system' || name === 'system idle process' || name === 'registry' || name === 'memory compression' || name === 'secure system') return { score: 0, level: 'low', why };
    if (NAMES_SYS[name] && exe) { const want = NAMES_SYS[name] === 'windows' ? '\\windows\\' : '\\windows\\system32\\'; const okp = NAMES_SYS[name] === 'windows' ? /^[a-z]:\\windows\\explorer\.exe$/.test(low) : low.includes(want); if (!okp) add(45, 'Sistem süreci adını taşıyor ama beklenen konumda değil (taklit olabilir): ' + exe); }
    if (!NAMES_SYS[name] && !/^(taskhost|taskhostex)\.exe$/.test(name)) for (const k of Object.keys(NAMES_SYS)) { if (name !== k && name.length >= 6 && (lev(name, k) <= 1 || swapped(name, k))) { add(40, 'Adı sistem sürecine çok benziyor: ' + k); break; } }
    if (exe && BAD_DIRS.some((r) => r.test(exe))) add(20, 'Kullanıcının yazabildiği/geçici bir konumdan çalışıyor');
    if (SCRIPT_HOSTS.has(name) && SUSP_ARGS.test(p.cmd || '')) add(25, 'Komut satırında gizleme/kodlama/indirme kalıpları var');
    if (SCRIPT_HOSTS.has(name) && ctx && ctx.parentName && /^(winword|excel|powerpnt|outlook|acrord32|acrobat|msedge|chrome|firefox|java|javaw)\.exe$/.test(ctx.parentName)) add(25, 'Belge/tarayıcı/Java uygulamasının alt süreci olarak kabuk çalıştırıyor (' + ctx.parentName + ')');
    if (sig) { if (sig.status === 'HashMismatch') add(40, 'Dijital imza bozuk (dosya imzalandıktan sonra değiştirilmiş)'); else if (sig.status === 'NotTrusted') add(25, 'İmza güvenilir bir yayıncıya bağlanmıyor'); else if (sig.status === 'NotSigned') add(exe && /\\windows\\/i.test(low) ? 15 : 12, 'Dijital imzası yok'); }
    const ext = (conns || []).filter((c) => c.state === 'Established' && isExternal(c.remote));
    if (ext.length) { const bad = (sig && sig.status !== 'Valid') || (exe && BAD_DIRS.some((r) => r.test(exe))) || SCRIPT_HOSTS.has(name); if (bad) add(15, 'İmzasız/şüpheli konumlu veya kabuk süreci internete bağlı (' + ext.length + ' bağlantı)'); }
    if ((conns || []).some((c) => c.remote && SUSP_PORTS[c.rport] && isExternal(c.remote) && [4444, 1337, 31337, 6667, 5555, 12345, 9001, 9030, 9050, 9150].includes(c.rport))) add(20, 'Şüpheli porta bağlantı');
    if (p.pathMissing && !/^(system|registry|memory compression|secure system|system idle process)$/.test(name) && p.pid > 4) { why.push({ pts: 0, text: 'Yürütülebilir yol okunamadı (yetki yok olabilir; yönetici olarak açınca netleşir)' }); }
    s = Math.max(0, Math.min(100, s)); return { score: s, level: s >= 60 ? 'high' : s >= 25 ? 'mid' : 'low', why };
  }
  /* bir baglanti icin supheli bayraklari */
  function flagConn(c, proc, sig) {
    const f = []; const ext = isExternal(c.remote);
    if (c.state === 'Listen' && (c.local === '0.0.0.0' || c.local === '::') && proc && proc.pid > 4 && !/^(svchost|system|lsass|services|wininit|spoolsv|System)(\.exe)?$/i.test(proc.name || '')) f.push({ t: 'Tüm arayüzlerde dinliyor', sev: 1 });
    if (ext && SUSP_PORTS[c.rport]) f.push({ t: 'Port ' + c.rport + ': ' + SUSP_PORTS[c.rport], sev: [23, 3389, 5900, 5985, 5986, 2222].includes(c.rport) ? 1 : 2 });
    if (ext && MINER_PORTS.has(c.rport)) f.push({ t: 'Madencilik havuzu portu olabilir', sev: 2 });
    if (ext && c.state === 'Established' && proc && SCRIPT_HOSTS.has(String(proc.name || '').toLowerCase())) f.push({ t: 'Kabuk/betik süreci internete bağlı', sev: 2 });
    if (ext && c.state === 'Established' && proc && proc.path && BAD_DIRS.some((r) => r.test(proc.path))) f.push({ t: 'Geçici/kullanıcı klasöründeki süreç internete bağlı', sev: 2 });
    if (ext && c.state === 'Established' && sig && (sig.status === 'NotSigned' || sig.status === 'HashMismatch' || sig.status === 'NotTrusted')) f.push({ t: 'İmzasız/güvenilmez süreç internete bağlı', sev: 2 });
    if (c.beacon && c.beacon.beacon) f.push({ t: 'Düzenli aralıklı yeniden bağlanma (~' + Math.round(c.beacon.mean / 1000) + ' sn, ' + c.beacon.n + ' kez) — beacon benzeri', sev: 2 });
    return f;
  }
  const num = (x) => (Number.isFinite(+x) ? +x : 0);
  const STATES = { 1: 'Closed', 2: 'Listen', 3: 'SynSent', 4: 'SynReceived', 5: 'Established', 6: 'FinWait1', 7: 'FinWait2', 8: 'CloseWait', 9: 'Closing', 10: 'LastAck', 11: 'TimeWait', 12: 'DeleteTCB', 100: 'Bound' };
  const normState = (s) => { if (typeof s === 'number') return STATES[s] || String(s); const x = String(s || ''); return x ? x[0].toUpperCase() + x.slice(1) : ''; };

  /* ---- toplayicilar ---- */
  const winPS = (script, run, timeout) => run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ProgressPreference="SilentlyContinue";$ErrorActionPreference="SilentlyContinue";' + script], timeout || 25000);
  const defaultRun = (cmd, args, timeout) => new Promise((resolve, reject) => { cp.execFile(cmd, args, { timeout: timeout || 25000, windowsHide: true, maxBuffer: 96 * 1024 * 1024, encoding: 'utf8' }, (e, so, se) => (e && !so ? reject(e) : resolve(String(so || '')))); });
  const parseJson = (t) => { t = String(t || '').trim(); if (!t) return []; try { const v = JSON.parse(t.charCodeAt(0) === 0xfeff ? t.slice(1) : t); return Array.isArray(v) ? v : [v]; } catch (e) { return []; } };
  const J = (x) => 'ConvertTo-Json -InputObject @(' + x + ') -Compress -Depth 4';

  function createSysHost(deps) {
    deps = deps || {}; const plat = () => deps.platform || process.platform; const isWin = () => plat() === 'win32'; const run = deps.run || defaultRun; const now = deps.now || (() => Date.now());
    const NCPU = Math.max(1, (os.cpus() || []).length || 1);
    let prev = null; let prevCpu = null; let procCache = { t: 0, list: [] }; let sigCache = new Map(); let sigBusy = false; const hist = new Map(); let netStart = now(); let lastNet = null;
    const ownPid = deps.ownPid || process.pid;

    /* --- sureçler --- */
    async function readProcs() {
      if (isWin()) {
        const out = await winPS(J('Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,ThreadCount,HandleCount,WorkingSetSize,PrivateBytes=PageFileUsage,KernelModeTime,UserModeTime,ReadTransferCount,WriteTransferCount,@{n="start";e={if($_.CreationDate){[int64]([datetimeoffset]$_.CreationDate).ToUnixTimeMilliseconds()}}}'), run);
        return parseJson(out).map((r) => ({ pid: num(r.ProcessId), ppid: num(r.ParentProcessId), name: String(r.Name || ''), path: r.ExecutablePath || '', cmd: String(r.CommandLine || '').slice(0, 4000), threads: num(r.ThreadCount), handles: num(r.HandleCount), mem: num(r.WorkingSetSize), commit: num(r.PrivateBytes) * 1024, cpuT: (num(r.KernelModeTime) + num(r.UserModeTime)) / 1e4, ioR: num(r.ReadTransferCount), ioW: num(r.WriteTransferCount), start: num(r.start) || 0 }));
      }
      const out = []; const tick = 100; let pagesz = 4096; const up = (() => { try { return +fs.readFileSync('/proc/uptime', 'utf8').split(' ')[0]; } catch (e) { return 0; } })(); const bt = (() => { try { const m = /^btime (\d+)/m.exec(fs.readFileSync('/proc/stat', 'utf8')); return m ? +m[1] * 1000 : 0; } catch (e) { return 0; } })();
      for (const d of fs.readdirSync('/proc')) { if (!/^\d+$/.test(d)) continue; try { const st = fs.readFileSync('/proc/' + d + '/stat', 'utf8'); const i = st.lastIndexOf(')'); const nm = st.slice(st.indexOf('(') + 1, i); const f = st.slice(i + 2).split(' '); let exe = ''; try { exe = fs.readlinkSync('/proc/' + d + '/exe'); } catch (e) { exe = ''; } let cmd = ''; try { cmd = fs.readFileSync('/proc/' + d + '/cmdline', 'utf8').replace(/\0/g, ' ').trim(); } catch (e) { cmd = ''; } out.push({ pid: +d, ppid: +f[1], name: nm, path: exe, cmd: cmd.slice(0, 4000), threads: +f[17], handles: (() => { try { return fs.readdirSync('/proc/' + d + '/fd').length; } catch (e) { return 0; } })(), mem: +f[21] * pagesz, commit: +f[20], cpuT: ((+f[11] + +f[12]) / tick) * 1000, ioR: 0, ioW: 0, start: bt + (+f[19] / tick) * 1000 }); } catch (e) { /* surec bitti */ } }
      return out;
    }
    async function procs(force) {
      const t = now(); if (!force && procCache.list.length && t - procCache.t < 1200) return procCache.list;
      const list = await readProcs(); const dt = prev ? Math.max(1, t - prev.t) : 0;
      for (const p of list) { const o = prev && prev.m.get(p.pid); p.pathMissing = !p.path; if (o && o.start === p.start && dt) { p.cpu = Math.max(0, Math.min(100, ((p.cpuT - o.cpuT) / dt / NCPU) * 100)); p.ioRate = Math.max(0, (p.ioR + p.ioW - o.ioR - o.ioW) / (dt / 1000)); } else { p.cpu = 0; p.ioRate = 0; } }
      prev = { t, m: new Map(list.map((p) => [p.pid, p])) }; procCache = { t, list }; return list;
    }
    let connCache = { t: 0, list: [] };
    async function annotate(list) { /* Extended: imza onbellegi + baglantilarla supheli puani */
      const t = now(); if (t - connCache.t > 2500) connCache = { t, list: await readConns().catch(() => []) };
      const by = new Map(); for (const c of connCache.list) { if (!by.has(c.pid)) by.set(c.pid, []); by.get(c.pid).push(c); } const byPid = new Map(list.map((p) => [p.pid, p]));
      for (const p of list) { const sig = p.path ? sigCache.get(p.path) || null : null; const par = byPid.get(p.ppid); const cs = by.get(p.pid) || []; const sc = scoreProc(p, sig, cs, { parentName: par ? String(par.name).toLowerCase() : '' }); p.score = sc.score; p.level = sc.level; p.why = sc.why.map((w) => w.text); p.sig = sig ? sig.status : ''; p.signer = sig ? sig.signer : ''; p.nconn = cs.filter((c) => c.state === 'Established').length; }
    }
    function sysStats() {
      const cpus = os.cpus() || []; let idle = 0, tot = 0; for (const c of cpus) { for (const k of Object.keys(c.times)) tot += c.times[k]; idle += c.times.idle; } let cpu = 0; if (prevCpu && tot > prevCpu.tot) cpu = Math.max(0, Math.min(100, (1 - (idle - prevCpu.idle) / (tot - prevCpu.tot)) * 100)); prevCpu = { idle, tot };
      let disk = null; try { const root = isWin() ? (process.env.SystemDrive || 'C:') + '\\' : '/'; const s = fs.statfsSync(root); disk = { root, total: s.blocks * s.bsize, free: s.bavail * s.bsize }; } catch (e) { disk = null; }
      return { cpu, cores: NCPU, model: (cpus[0] && cpus[0].model) || '', memTotal: os.totalmem(), memFree: os.freemem(), uptime: os.uptime(), disk, host: os.hostname(), platform: plat() };
    }
    /* --- imza (Windows) --- */
    async function sigs(paths) {
      const need = [...new Set(paths.filter((p) => p && /^[A-Za-z]:\\/.test(p)))].filter((p) => !sigCache.has(p)).slice(0, 400); if (!isWin() || !need.length) return;
      const esc = need.map((p) => "'" + p.replace(/'/g, "''") + "'").join(',');
      const out = await winPS(J('@(' + esc + ') | ForEach-Object { $s = Get-AuthenticodeSignature -LiteralPath $_; [pscustomobject]@{ p=$_; st=[string]$s.Status; who=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{""} } }'), run, 120000);
      for (const r of parseJson(out)) sigCache.set(r.p, { status: r.st === 'Valid' ? 'Valid' : r.st === 'NotSigned' ? 'NotSigned' : r.st === 'HashMismatch' ? 'HashMismatch' : r.st === 'NotTrusted' || r.st === 'UnknownError' ? 'NotTrusted' : r.st || 'Unknown', signer: String(r.who || '').replace(/^.*?CN=([^,]+).*$/, '$1').slice(0, 120) });
      for (const p of need) if (!sigCache.has(p)) sigCache.set(p, { status: 'Unknown', signer: '' });
    }
    /* --- baglantilar --- */
    async function readConns() {
      if (isWin()) {
        const o = await winPS(J('Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,@{n="State";e={[string]$_.State}},OwningProcess') + ';"@@UDP@@";' + J('Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess'), run);
        const [a, b] = String(o).split('@@UDP@@'); const L = [];
        for (const r of parseJson(a)) L.push({ proto: 'TCP', local: String(r.LocalAddress), lport: num(r.LocalPort), remote: String(r.RemoteAddress || ''), rport: num(r.RemotePort), state: normState(r.State), pid: num(r.OwningProcess) });
        for (const r of parseJson(b)) L.push({ proto: 'UDP', local: String(r.LocalAddress), lport: num(r.LocalPort), remote: '', rport: 0, state: 'Bound', pid: num(r.OwningProcess) });
        return L;
      }
      const L = []; const inodePid = new Map(); for (const d of fs.readdirSync('/proc')) { if (!/^\d+$/.test(d)) continue; try { for (const fd of fs.readdirSync('/proc/' + d + '/fd')) { const l = fs.readlinkSync('/proc/' + d + '/fd/' + fd); const m = /^socket:\[(\d+)\]$/.exec(l); if (m) inodePid.set(m[1], +d); } } catch (e) { /* izin yok */ } }
      const hex4 = (h) => h.match(/../g).reverse().map((x) => parseInt(x, 16)).join('.'); const hex6 = (h) => { const w = h.match(/.{8}/g).map((x) => x.match(/../g).reverse().join('')); return w.join('').match(/.{4}/g).join(':').replace(/(^|:)0{1,3}/g, '$1').replace(/(:0)+:?$/, '::') || '::'; };
      const ST = { '01': 'Established', '02': 'SynSent', '03': 'SynReceived', '04': 'FinWait1', '05': 'FinWait2', '06': 'TimeWait', '07': 'Closed', '08': 'CloseWait', '09': 'LastAck', '0A': 'Listen', '0B': 'Closing' };
      for (const [f, proto, v6] of [['tcp', 'TCP', false], ['tcp6', 'TCP', true], ['udp', 'UDP', false], ['udp6', 'UDP', true]]) { let t = ''; try { t = fs.readFileSync('/proc/net/' + f, 'utf8'); } catch (e) { continue; } for (const ln of t.split('\n').slice(1)) { const c = ln.trim().split(/\s+/); if (c.length < 10) continue; const [la, lp] = c[1].split(':'); const [ra, rp] = c[2].split(':'); L.push({ proto, local: v6 ? hex6(la) : hex4(la), lport: parseInt(lp, 16), remote: parseInt(rp, 16) || (v6 ? ra !== '0'.repeat(32) : ra !== '00000000') ? (v6 ? hex6(ra) : hex4(ra)) : '', rport: parseInt(rp, 16), state: proto === 'UDP' ? 'Bound' : ST[c[3]] || c[3], pid: inodePid.get(c[9]) || 0 }); } }
      return L;
    }
    async function net() {
      const t = now(); const list = await procs(false); const byPid = new Map(list.map((p) => [p.pid, p])); const conns = await readConns();
      await sigs(conns.filter((c) => c.state === 'Established' && isExternal(c.remote)).map((c) => (byPid.get(c.pid) || {}).path));
      const seenNow = new Set(); const out = [];
      for (const c of conns) {
        const p = byPid.get(c.pid); c.name = p ? p.name : (c.pid ? '(pid ' + c.pid + ')' : 'Sistem'); c.path = p ? p.path : ''; c.dir = c.state === 'Listen' || c.proto === 'UDP' ? 'listen' : (c.remote && !isExternal(c.remote) ? 'local' : 'out');
        if (c.remote && c.state !== 'Listen' && c.proto === 'TCP' && c.state !== 'TimeWait' && c.state !== 'Closed') { const key = c.pid + '|' + c.remote + '|' + c.rport; seenNow.add(key + '|' + c.lport); let h = hist.get(key); if (!h) { h = { pid: c.pid, name: c.name, remote: c.remote, rport: c.rport, first: t, last: t, locals: new Set(), times: [], total: 0 }; hist.set(key, h); } h.last = t; h.name = c.name; if (!h.locals.has(c.lport)) { h.locals.add(c.lport); h.times.push(t); h.total++; if (h.times.length > 60) h.times.shift(); if (h.locals.size > 400) h.locals = new Set([...h.locals].slice(-200)); } c.since = h.first; c.hits = h.total; c.beacon = beaconScore(h.times); }
        const sig = c.path ? sigCache.get(c.path) : null; c.sig = sig ? sig.status : ''; c.flags = flagConn(c, p, sig); out.push(c);
      }
      for (const [k, h] of hist) if (t - h.last > 6 * 3600 * 1000) hist.delete(k); if (hist.size > 5000) for (const k of [...hist.keys()].slice(0, hist.size - 4000)) hist.delete(k);
      const est = out.filter((c) => c.state === 'Established'); const sum = { total: out.length, established: est.length, external: est.filter((c) => isExternal(c.remote)).length, listening: out.filter((c) => c.state === 'Listen').length, flagged: out.filter((c) => c.flags.length).length, since: netStart, procs: new Set(est.filter((c) => isExternal(c.remote)).map((c) => c.pid)).size };
      lastNet = { t, conns: out }; return { conns: out, summary: sum, t };
    }
    function history() { const L = [...hist.values()].map((h) => ({ pid: h.pid, name: h.name, remote: h.remote, rport: h.rport, first: h.first, last: h.last, total: h.total, beacon: beaconScore(h.times), external: isExternal(h.remote) })); return L.sort((a, b) => b.last - a.last).slice(0, 2000); }

    /* --- ayrintilar --- */
    const asPid = (v) => { const n = Number(v); return Number.isInteger(n) && n >= 0 && n < 0x7fffffff ? n : null; };
    async function detail(pid) {
      const list = await procs(false); const p = list.find((x) => x.pid === pid); if (!p) return { error: 'gone', message: 'Süreç artık yok.' };
      const parent = list.find((x) => x.pid === p.ppid); const kids = list.filter((x) => x.ppid === pid).map((x) => ({ pid: x.pid, name: x.name }));
      const d = { pid, name: p.name, path: p.path, cmd: p.cmd, ppid: p.ppid, parent: parent ? parent.name : '', children: kids.slice(0, 50), threads: p.threads, handles: p.handles, mem: p.mem, commit: p.commit, start: p.start, modules: [], services: [], owner: '', sha256: '', size: 0, version: '', company: '', sig: null };
      if (p.path) { try { const st = fs.statSync(p.path); d.size = st.size; d.mtime = st.mtimeMs; } catch (e) { /* okunamadi */ } }
      if (isWin() && p.path) {
        const lp = "'" + p.path.replace(/'/g, "''") + "'";
        const [o1, o2] = await Promise.all([
          winPS('$p=Get-Process -Id ' + pid + ';$m=@($p.Modules|ForEach-Object{[pscustomobject]@{n=$_.ModuleName;p=$_.FileName;v=$_.FileVersionInfo.CompanyName}});$o="";try{$o=(Get-CimInstance Win32_Process -Filter "ProcessId=' + pid + '"|Invoke-CimMethod -MethodName GetOwner|ForEach-Object{$_.Domain+"\\"+$_.User})}catch{};$s=@(Get-CimInstance Win32_Service -Filter "ProcessId=' + pid + '"|ForEach-Object{[pscustomobject]@{n=$_.Name;d=$_.DisplayName;s=$_.State}});$fv=(Get-Item -LiteralPath ' + lp + ').VersionInfo;[pscustomobject]@{mods=$m;owner=$o;svcs=$s;ver=$fv.FileVersion;co=$fv.CompanyName;desc=$fv.FileDescription}|ConvertTo-Json -Compress -Depth 4', run, 30000).catch(() => ''),
          winPS('$h=(Get-FileHash -LiteralPath ' + lp + ' -Algorithm SHA256).Hash;$s=Get-AuthenticodeSignature -LiteralPath ' + lp + ';[pscustomobject]@{h=$h;st=[string]$s.Status;who=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{""}}|ConvertTo-Json -Compress', run, 60000).catch(() => '')
        ]);
        const a = parseJson(o1)[0]; if (a) { d.modules = (Array.isArray(a.mods) ? a.mods : a.mods ? [a.mods] : []).slice(0, 600).map((m) => ({ name: m.n, path: m.p, company: m.v || '' })); d.owner = a.owner || ''; d.services = Array.isArray(a.svcs) ? a.svcs : a.svcs ? [a.svcs] : []; d.version = a.ver || ''; d.company = a.co || ''; d.desc = a.desc || ''; }
        const b = parseJson(o2)[0]; if (b) { d.sha256 = String(b.h || '').toLowerCase(); d.sig = { status: b.st === 'Valid' ? 'Valid' : b.st === 'NotSigned' ? 'NotSigned' : b.st === 'HashMismatch' ? 'HashMismatch' : 'NotTrusted', signer: String(b.who || '').replace(/^.*?CN=([^,]+).*$/, '$1').slice(0, 120) }; sigCache.set(p.path, d.sig); }
      } else if (p.path) { try { const crypto = require('crypto'); if (d.size < 200 * 1048576) d.sha256 = crypto.createHash('sha256').update(fs.readFileSync(p.path)).digest('hex'); } catch (e) { /* okunamadi */ } }
      const conns = (lastNet ? lastNet.conns : await readConns().catch(() => [])).filter((c) => c.pid === pid); d.conns = conns.slice(0, 200).map((c) => ({ proto: c.proto, local: c.local, lport: c.lport, remote: c.remote, rport: c.rport, state: c.state }));
      const sc = scoreProc(p, d.sig || sigCache.get(p.path) || null, d.conns, { parentName: String(d.parent || '').toLowerCase() }); d.score = sc.score; d.level = sc.level; d.why = sc.why; return d;
    }
    /* --- listeler (Extended) --- */
    async function listOf(kind) {
      if (!isWin()) return { items: [], note: 'Bu liste yalnızca Windows’ta okunur.' };
      const Q = {
        services: J('Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName,ProcessId,Description'),
        drivers: J('Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,State,StartMode,PathName,ServiceType'),
        startup: J('$r=@();foreach($k in "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce","HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce","HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"){$i=Get-ItemProperty -Path $k;if($i){$i.PSObject.Properties|Where-Object{$_.Name -notmatch "^PS"}|ForEach-Object{$r+=[pscustomobject]@{Name=$_.Name;Command=[string]$_.Value;Location=$k}}}};foreach($f in "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup","$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"){Get-ChildItem -LiteralPath $f -File|ForEach-Object{$r+=[pscustomobject]@{Name=$_.Name;Command=$_.FullName;Location=$f}}};$r'),
        tasks: J('Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\\Microsoft\\Windows\\*" } | ForEach-Object { [pscustomobject]@{Name=$_.TaskName;Path=$_.TaskPath;State=[string]$_.State;Command=(($_.Actions|ForEach-Object{($_.Execute+" "+$_.Arguments).Trim()}) -join " ; ");Author=[string]$_.Principal.UserId} }')
      }; if (!Q[kind]) return { error: 'bad', message: 'Geçersiz liste.' };
      const items = parseJson(await winPS(Q[kind], run, 60000)); return { items: items.slice(0, 5000) };
    }
    return {
      procs, sysStats, net, history, detail, listOf, sigs, ipClass, sigCache: () => sigCache,
      handlers: {
        'sys:procs': async (_e, ext) => { try { const list = await procs(false); if (ext === true) await annotate(list); const stats = sysStats(); return { procs: list, stats, platform: plat(), self: ownPid }; } catch (e) { return errObj(e); } },
        'sys:sigs': async () => { try { if (sigBusy) return { busy: true }; sigBusy = true; try { const list = await procs(false); await sigs(list.map((p) => p.path)); } finally { sigBusy = false; } return { ok: true, count: sigCache.size }; } catch (e) { return errObj(e); } },
        'sys:detail': async (_e, pid) => { try { const n = asPid(pid); if (n === null) return { error: 'bad', message: 'Geçersiz PID.' }; return await detail(n); } catch (e) { return errObj(e); } },
        'sys:list': async (_e, kind) => { try { return await listOf(String(kind)); } catch (e) { return errObj(e); } },
        'sys:net': async () => { try { return await net(); } catch (e) { return errObj(e); } },
        'sys:nethist': async () => { try { return { hist: history(), since: netStart }; } catch (e) { return errObj(e); } },
        'sys:netreset': async () => { hist.clear(); netStart = now(); return { ok: true, since: netStart }; },
        'sys:reveal': async (_e, pid) => { try { const n = asPid(pid); const p = (procCache.list || []).find((x) => x.pid === n); if (!p || !p.path) return { error: 'nopath', message: 'Bu sürecin dosya yolu okunamadı.' }; if (deps.showItemInFolder) deps.showItemInFolder(p.path); return { ok: true }; } catch (e) { return errObj(e); } },
        'sys:kill': async (_e, pid) => {
          try {
            const n = asPid(pid); if (n === null || n <= 4) return { error: 'bad', message: 'Bu süreç sonlandırılamaz.' }; if (n === ownPid) return { error: 'self', message: 'StatScan kendi sürecini buradan sonlandırmaz.' };
            const p = (procCache.list || []).find((x) => x.pid === n); if (!p) return { error: 'gone', message: 'Süreç artık yok.' };
            if (isWin() && /^(csrss|wininit|winlogon|services|lsass|smss|system|registry|memory compression|secure system)(\.exe)?$/i.test(p.name)) return { error: 'critical', message: 'Bu kritik bir Windows sürecidir; sonlandırmak sistemi çökertir. İşlem yapılmadı.' };
            const ok = deps.confirm ? await deps.confirm({ title: 'Süreç sonlandırılsın mı?', message: p.name + ' (PID ' + n + ') zorla kapatılacak. Kaydedilmemiş veriler kaybolabilir.' + (p.path ? '\n\n' + p.path : ''), ok: 'Sonlandır', cancel: 'Vazgeç' }) : false; if (!ok) return { error: 'declined', message: 'İptal edildi.', status: 400 };
            (deps.kill || process.kill)(n); procCache = { t: 0, list: [] }; return { ok: true };
          } catch (e) { return errObj(e); }
        }
      }
    };
  }
  return { createSysHost, ipClass, isExternal, beaconScore, scoreProc, flagConn, SUSP_PORTS };
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
  if (deps.compile !== false) { const ch = COMPMOD.createCompileHost({ downloadsDir: deps.downloadsDir, outputBase: deps.compileOutputBase, env: deps.compileEnv, jdkDirs: deps.compileJdkDirs, onlyJdkDirs: deps.compileOnlyJdkDirs, notify: deps.notify, showItemInFolder: deps.showItemInFolder, toolDirs: deps.compileToolDirs, onlyToolDirs: deps.compileOnlyToolDirs }); Object.assign(handlers, ch.handlers); }
  /* Gorev Yoneticisi + Ag Izleyici (salt okunur; bkz. SYSMOD) */
  if (deps.sys !== false) { const sh = SYSMOD.createSysHost(Object.assign({ confirm: deps.confirm, showItemInFolder: deps.showItemInFolder }, deps.sys || {})); Object.assign(handlers, sh.handlers); }
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
  /* kurulum kimligi + engelli liste + sahip modu + Notlarim (bkz. ACCESSMOD). Engelliyse ayricalikli islemler reddedilir; ayarlar/guncelleme/erisim islemleri acik kalir. */
  let access = null;
  if (deps.access && deps.access.dataDir) {
    access = ACCESSMOD.createAccessHost(Object.assign({ downloadsDir: deps.downloadsDir, showItemInFolder: deps.showItemInFolder }, deps.access)); Object.assign(handlers, access.handlers);
    for (const [k, fn] of Object.entries(handlers)) { if (/^(access|owner|notes|settings):|^app:/.test(k)) continue; handlers[k] = async (...a) => (access.isBlocked() ? { error: 'blocked', message: 'Bu kurulumun erişimi geliştirici tarafından kapatıldı.' } : fn(...a)); }
  }
  return { handlers, obf, access, register(ipcMain) { for (const [k, fn] of Object.entries(handlers)) ipcMain.handle(k, fn); }, svc };
}

module.exports = { createHost, createWatcher, riskyList, VT_RE, obfModule: OBFMOD, compileModule: COMPMOD, accessModule: ACCESSMOD, sysModule: SYSMOD };
