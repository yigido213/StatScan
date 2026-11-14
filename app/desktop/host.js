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
module.exports = {
  createObfHost, detectTools, TOOLS, safeName, rankRisk, riskMd };

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

/* --- Karsi Secim (Kovan 'lolcounter' v0.0.1) ---
 * League of Legends icin Blitz tarzi "rakibe karsi ne secmeli" araci. Tarayici ACMAZ: veriyi arka planda host cekip onbellege alir.
 * Veri katmanlari (dürüst etiketli): (1) Riot Data Dragon (resmi, herkese acik) -> sampiyon istatistikleri + "rakip ipuclari"; bunlardan TAHMINI avantaj hesaplanir,
 * ISTATISTIK DEGILDIR. (2) Kisisel mac kaydi (kullanici "kazandim/kaybettim" der) -> kisisel kazanma orani, sampiyon havuzuna gore kisisellestirme.
 * (3) Istege bagli: kullanicinin KENDI verdigi https veri adresi (statsUrl; yalnizca onay penceresiyle). Ucuncu taraf site (counterpick.lol) YALNIZ kullanici anahtari + onay ile, sayi olarak okunur.
 * League ISTEMCISI (LCU) yalnizca OKUNUR: sampiyon secimi ekranindaki secimleri 127.0.0.1 yerel API'sinden GET ile okur; oyun surecine enjekte etmez, bellegine bakmaz,
 * hicbir sey yazmaz/POST etmez. Arayuz URL/dosya yolu GONDEREMEZ (yalniz sampiyon kimligi + rol); statsUrl yalniz host onayi ile ayarlanir. */
const LOLMOD = (() => {
  const fs = require('fs'); const path = require('path'); const https = require('https'); const cp = require('child_process');
  const ROLES = ['top', 'jungle', 'mid', 'bot', 'support'];
  const LIM = { pool: 40, hist: 3000, body: 8 * 1024 * 1024, statsBody: 5 * 1024 * 1024, ms: 12000, top: 200, defTop: 12, snaps: 3000, matches: 3000, details: 15, icon: 200 * 1024, rank: 900 * 1024, recent: 30, urlLen: 400 };
  const ID_RE = /^[A-Za-z0-9]{1,32}$/; const DD_HOST = 'ddragon.leagueoflegends.com'; const CD_HOST = 'raw.communitydragon.org'; const CD_RANK = '/latest/plugins/rcp-fe-lol-static-assets/global/default/images/ranked-emblem/'; const LOCALES = ['tr_TR', 'en_US'];
  const ROLE_HOST = 'cdn.merakianalytics.com'; const ROLE_PATH = '/riot/lol/resources/latest/en-US/champions.json'; const ROLE_MAX = 16 * 1024 * 1024; const ROLE_TTL = 7 * 24 * 3600 * 1000; const MERAKI_POS = { TOP: 'top', JUNGLE: 'jungle', MIDDLE: 'mid', BOTTOM: 'bot', SUPPORT: 'support' };
  const LCU_ROLE = { top: 'top', jungle: 'jungle', middle: 'mid', bottom: 'bot', utility: 'support' };
  const errE = (message, extra) => Object.assign({ error: 'lol', message }, extra || {});
  const clamp = (x, a, b) => Math.max(a, Math.min(b, x));

  /* ---------- sampiyon verisi (Data Dragon champion.json ozeti) ---------- */
  function normChamp(c) {
    if (!c || typeof c !== 'object' || !ID_RE.test(String(c.id || ''))) return null; const s = c.stats || {}; const i = c.info || {}; const n = (x, d) => (Number.isFinite(Number(x)) ? Number(x) : d);
    return { id: String(c.id), key: String(c.key || ''), name: String(c.name || c.id), tags: Array.isArray(c.tags) ? c.tags.map(String) : [], attack: n(i.attack, 5), defense: n(i.defense, 5), magic: n(i.magic, 5), difficulty: n(i.difficulty, 5),
      range: n(s.attackrange, 175), ms: n(s.movespeed, 340), hp: n(s.hp, 600) + 8 * n(s.hpperlevel, 90), armor: n(s.armor, 30) + 8 * n(s.armorperlevel, 4), mr: n(s.spellblock, 32) + 8 * n(s.spellblockperlevel, 1.3) };
  }
  function parseChampions(json) { const d = json && json.data; if (!d || typeof d !== 'object') return []; return Object.keys(d).map((k) => normChamp(d[k])).filter(Boolean).sort((a, b) => a.name.localeCompare(b.name)); }
  /* Meraki Analytics champions.json -> { "<sayisal anahtar>": ['top',...] } (yalniz hat listesi; lore/yetenek/kostum atilir) */
  function parseRoles(json) {
    if (!json || typeof json !== 'object') return null; const out = {}; let n = 0;
    for (const k of Object.keys(json)) { const v = json[k]; if (!v || typeof v !== 'object' || !Number.isFinite(Number(v.id))) continue; n++; const pos = Array.isArray(v.positions) ? v.positions.map((x) => MERAKI_POS[String(x).toUpperCase()]).filter(Boolean) : []; const u = pos.filter((x, i) => pos.indexOf(x) === i); if (u.length) out[String(Math.round(Number(v.id)))] = u; }
    return n >= 50 && Object.keys(out).length >= 50 ? out : null;
  }
  function rosterZ(list) {
    const f = (fn) => { const v = list.map(fn); const m = v.reduce((a, b) => a + b, 0) / (v.length || 1); const sd = Math.sqrt(v.reduce((a, b) => a + (b - m) ** 2, 0) / (v.length || 1)) || 1; return (x) => (fn(x) - m) / sd; };
    return { armor: f((c) => c.armor), mr: f((c) => c.mr), hp: f((c) => c.hp) };
  }
  /* Hat uyumu: gercek hat verisi (Meraki `positions`, c.pos) varsa YALNIZ ona bakar; yoksa (yeni sampiyon / veri alinamadi) ana siniftan kaba tahmin. */
  const roleFit = (c, role) => {
    if (Array.isArray(c.pos) && c.pos.length) return c.pos.includes(role);
    const t = c.tags; const p0 = t[0];
    if (role === 'top') return p0 === 'Fighter' || p0 === 'Tank' || (t.includes('Fighter') && p0 !== 'Support' && p0 !== 'Marksman');
    if (role === 'jungle') return (p0 === 'Fighter' || p0 === 'Assassin' || p0 === 'Tank') && p0 !== 'Support';
    if (role === 'mid') return p0 === 'Mage' || p0 === 'Assassin' || (t.includes('Fighter') && c.range >= 300 && p0 !== 'Support');
    if (role === 'bot') return p0 === 'Marksman' || t.includes('Marksman');
    if (role === 'support') return t.includes('Support') || (p0 === 'Tank' && c.range >= 300);
    return false;
  };

  /* a'nin b'ye karsi tahmini avantaji (kaba kurallar; gercek maclardan ogrenilmis degildir). Neden kodlari arayuzde cevrilir. */
  function adv(a, b, role, Z) {
    let d = 0; const r = []; const rd = a.range - b.range; const w = role === 'jungle' || role === 'support' ? 0.5 : 1;
    if (rd >= 150) { d += Math.min(10, rd / 60) * w; r.push({ k: 'rangeEdge', v: [a.range, b.range] }); }
    const phys = b.attack - b.magic;
    if (phys >= 2 && Z.armor(a) > 0.5) { d += Math.min(8, Z.armor(a) * 4); r.push({ k: 'armorVsAd', v: [Math.round(a.armor)] }); } else if (phys <= -2 && Z.mr(a) > 0.5) { d += Math.min(8, Z.mr(a) * 4); r.push({ k: 'mrVsAp', v: [Math.round(a.mr)] }); }
    if (a.tags.includes('Assassin') && b.defense <= 3 && Z.hp(b) < -0.3) { d += 6; r.push({ k: 'assassinVsSquishy', v: [] }); }
    if (b.tags.includes('Assassin') && a.defense >= 6 && Z.hp(a) > 0.5) { d += 5; r.push({ k: 'tankVsAssassin', v: [] }); }
    if (a.magic >= 7 && b.defense >= 7) { d += 4; r.push({ k: 'magicVsTank', v: [] }); }
    return { d, r };
  }
  function heuristic(c, e, role, Z) { const f = adv(c, e, role, Z); const g = adv(e, c, role, Z); return { delta: clamp(f.d - g.d, -20, 20), pos: f.r, neg: g.r }; }

  /* ---------- kisisel kayit ---------- */
  const wilson = (w, n) => { if (!n) return 50; const p = w / n; const z = 1; return (100 * (p + (z * z) / (2 * n) - z * Math.sqrt((p * (1 - p) + (z * z) / (4 * n)) / n))) / (1 + (z * z) / n); };
  function personal(hist, me, enemy, role) { let g = 0; let w = 0; for (const h of hist) if (h.me === me && h.enemy === enemy && (!role || h.role === role)) { g++; if (h.win) w++; } return { games: g, wins: w }; }
  function personalAll(hist, me, role) { let g = 0; let w = 0; for (const h of hist) if (h.me === me && (!role || h.role === role)) { g++; if (h.win) w++; } return { games: g, wins: w }; }

  /* disaridan gelen istatistik: { matchups: [ { champ, wr, games } ] } (statsUrl sablonu {enemy} ve {role} icerir) */
  /* dis veri: run sayilari (Riot rune kimlikleri). Metin ALINMAZ; yalnizca tam sayilar. */
  function parseRunes(r) {
    if (!r || typeof r !== 'object') return null; const id = (x) => { const n = Number(x); return Number.isInteger(n) && n >= 5000 && n <= 9999 ? n : null; };
    const perks = Array.isArray(r.perks) ? r.perks.slice(0, 9).map(id).filter((x) => x !== null) : []; const prim = Number(r.primary); const sec = Number(r.secondary); const treeOk = (n) => Number.isInteger(n) && n >= 8000 && n <= 8500;
    if (!perks.length) return null; return { perks, primary: treeOk(prim) ? prim : null, secondary: treeOk(sec) ? sec : null };
  }

  /* ---------- counterpick.lol (isteğe bağlı, kullanıcı anahtarı + onay): yalnız SAYILAR okunur ---------- */
  const CP_HOST = 'www.counterpick.lol';
  const cpKebab = (s) => String(s || '').toLowerCase().replace(/&/g, ' ').replace(/['’.]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  const cpKey = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const htmlText = (h) => String(h || '').replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]*>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&#0?39;|&apos;|&rsquo;/g, "'").replace(/\s+/g, ' ').trim();
  const CP_TREES = new Set([8000, 8100, 8200, 8300, 8400]);
  /* maç sayfası: "VS 48.2% 769 games" — oran SAYFADAKİ İLK şampiyonun (Akshan↔Anivia çiftinin iki yönüyle doğrulandı: 45.0 ve 54.2); ters yöndeki sayfa yaklaşık 100 − oran verir.
     Rünler: önce /lol/rune/<id>.webp kimlikleri; yoksa "Runes" bölümündeki metin sırasıyla (rün adı ya da "Rune <id>"). Yalnız tam sayı kimlikleri alınır; sıra/ağaç yapısı yine validateRunePage ile doğrulanır. */
  const runeKey = (x) => String(x || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const escRe = (x) => String(x).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  /* Data Dragon runesReforged (en_US) -> { byKey: normalleştirilmiş ad -> kimlik, list: adlar (uzun önce) } */
  function buildRuneNames(json) {
    const byKey = new Map(); const list = []; for (const tr of Array.isArray(json) ? json : []) for (const sl of (tr && tr.slots) || []) for (const r of (sl && sl.runes) || []) { if (r && Number.isInteger(r.id) && r.name) { byKey.set(runeKey(r.name), r.id); list.push(String(r.name).slice(0, 40)); } }
    list.sort((a, b) => b.length - a.length); return byKey.size >= 20 ? { byKey, list } : null;
  }
  function cpRunesFromText(t, names) {
    const seg0 = String(t || ''); const a = seg0.search(/\bRunes\b/); const seg = a >= 0 ? seg0.slice(a) : seg0; const parts = []; if (names && names.list.length) parts.push('\\b(?:' + names.list.map(escRe).join('|') + ')(?![A-Za-z])'); parts.push('\\bRune\\s+(\\d{4})\\b');
    const re = new RegExp(parts.join('|'), 'gi'); const ids = []; let m; while ((m = re.exec(seg)) && ids.length < 6) {
      let id = null; if (m[1]) id = Number(m[1]); else if (names) id = names.byKey.get(runeKey(m[0])) || null; if (Number.isInteger(id) && id >= 8000 && id <= 9999 && !CP_TREES.has(id) && !ids.includes(id)) ids.push(id);
    }
    return ids.length === 6 ? ids : null;
  }
  function parseCpMatchup(html, names) {
    const t = htmlText(html); const m = /\bVS\s+(\d{1,2}(?:\.\d+)?)\s*%\s*(\d[\d.,\s]*?)\s*games\b/i.exec(t); if (!m) return null; const wr = Number(m[1]); const games = Number(m[2].replace(/[^\d]/g, '')); if (!(wr >= 0 && wr <= 100) || !(games >= 0 && games <= 1e8)) return null;
    const ids = []; for (const x of String(html).matchAll(/\/lol\/rune\/(\d{4})\.(?:webp|png|jpg)/gi)) { const n = Number(x[1]); if (!ids.includes(n)) ids.push(n); }
    const trees = ids.filter((n) => CP_TREES.has(n)); const perks = ids.filter((n) => n >= 8000 && !CP_TREES.has(n)).slice(0, 6);
    let runes = perks.length >= 4 ? parseRunes({ perks, primary: trees[0], secondary: trees[1] }) : null;
    if (!runes || runes.perks.length !== 6) { const tp = cpRunesFromText(t.slice(m.index + m[0].length), names); if (tp) runes = parseRunes({ perks: tp }); }
    return { wr, games: Math.round(games), runes };
  }
  /* counters sayfası: <a href=".../matchup/<konu>-vs-<rakip>/"> + yakınında "NN.N% WR" (konu şampiyonun oranı) → rakibin oranı = 100 - değer */
  function parseCpCounters(html, subjectSlug) {
    const out = []; const seen = new Set(); const src = String(html); const re = /href="[^"]*\/matchup\/([a-z0-9-]+)-vs-([a-z0-9-]+)\/?"/gi; let m;
    while ((m = re.exec(src)) && out.length < 60) {
      if (m[1] !== subjectSlug || seen.has(m[2])) continue; const rest = htmlText(src.slice(m.index, m.index + 1500)); const w = /(\d{1,2}(?:\.\d+)?)\s*%\s*WR/i.exec(rest); if (!w) continue; const v = Number(w[1]); if (!(v >= 0 && v <= 100)) continue;
      seen.add(m[2]); out.push({ slug: m[2], wr: Math.round((100 - v) * 10) / 10 });
    }
    return out;
  }
  /* kendi maç geçmişinden rün önerisi (yalnız bu bilgisayardaki kayıt): önce bu eşleşme (≥2 maç), yoksa aynı şampiyon + hat (≥3 maç); en iyi Wilson alt sınırı */
  function histRunes(matches, me, enemy, role) {
    const okQ = ['solo', 'flex', 'draft', 'blind', 'quick', 'swift', 'clash']; const all = Object.values(matches || {}); const anyRunes = all.some((m) => m && m.runes);
    const ms = all.filter((m) => m && !m.remake && m.win !== null && m.champ === me && m.runes && Array.isArray(m.runes.perks) && m.runes.perks.length === 6 && okQ.includes(m.queue));
    const best = (list) => { const by = new Map(); for (const m of list) { const k = m.runes.perks.join(','); const x = by.get(k) || { runes: m.runes, games: 0, wins: 0 }; x.games++; if (m.win) x.wins++; by.set(k, x); } let b = null; for (const x of by.values()) { x.low = wilson(x.wins, x.games); if (!b || x.low > b.low || (x.low === b.low && x.games > b.games)) b = x; } return { runes: b.runes, games: b.games, wr: Math.round((1000 * b.wins) / b.games) / 10 }; };
    const vs = ms.filter((m) => m.opp === enemy); if (vs.length >= 2) return Object.assign({ state: 'ok', scope: 'vs', total: vs.length }, best(vs));
    const rl = role ? ms.filter((m) => m.role === role) : ms; if (rl.length >= 3) return Object.assign({ state: 'ok', scope: 'champ', total: rl.length }, best(rl));
    if (!anyRunes) return { state: 'sync' }; if (!ms.length) return { state: 'none' }; return { state: 'few', vs: vs.length, champ: rl.length };
  }
  /* "Ad#ETİKET" → {name, tag}; Riot Kimliği: ad 3-16 karakter (güvenli tarafta 1-24), etiket 2-10 harf/rakam */
  function parsePlayerQuery(q) {
    const t = String(q == null ? '' : q).normalize('NFC').trim().replace(/\s+/g, ' '); const i = t.lastIndexOf('#'); if (i < 1) return null; const name = t.slice(0, i).trim(); const tag = t.slice(i + 1).trim();
    if (name.length < 1 || name.length > 24 || /[\u0000-\u001f#%&?\/\\<>]/.test(name) || !/^[A-Za-z0-9]{2,10}$/.test(tag)) return null; return { name, tag };
  }
  /* arkadaş listesi: yalnız ad/etiket/puuid/simge/durum, en çok 200 */
  function parseFriends(j) {
    const out = []; for (const f of Array.isArray(j) ? j : []) { if (!f || typeof f !== 'object') continue; const puuid = String(f.puuid || '').slice(0, 100); const name = String(f.gameName || f.name || '').slice(0, 30); if (!/^[A-Za-z0-9_-]{20,100}$/.test(puuid) || !name) continue;
      out.push({ puuid, name, tag: String(f.gameTag || f.tagLine || '').slice(0, 10), icon: Math.round(Number(f.icon || f.profileIconId)) || 0, status: String(f.availability || f.statusMessage && 'chat' || 'offline').slice(0, 16) }); if (out.length >= 200) break; }
    const rk = (x) => (x.status === 'dnd' || x.status === 'chat' || x.status === 'away' || x.status === 'mobile' ? 0 : 1); return out.sort((a, b) => rk(a) - rk(b) || a.name.localeCompare(b.name));
  }
  function parseStats(json) {
    const arr = json && Array.isArray(json.matchups) ? json.matchups : null; if (!arr) return null; const out = new Map();
    for (const x of arr.slice(0, 400)) { if (!x || !ID_RE.test(String(x.champ || ''))) continue; const wr = Number(x.wr); const g = Number(x.games); if (!(wr >= 0 && wr <= 100) || !(g >= 0 && g <= 1e9)) continue; out.set(String(x.champ), { wr, games: Math.round(g), runes: parseRunes(x.runes), src: 'url' }); }
    return out;
  }

  /* ---------- rank kovalari: eslesme detayi (kaynaktan bagimsiz) ----------
     Kaynak (kullanicinin muUrl adresi; ileride Lolalytics donusturucusu) rank basina KOVA verir:
     { matchup: { patch, ranks: { emerald: { games, wr, items: { start|boots|core|slot4|slot5|slot6: [ { id, games, wr } ] } } } } }.
     'Tum ranklar' = Emerald+ (Emerald, Diamond, Master, Grandmaster, Challenger): kovalar OYUN SAYISIYLA AGIRLIKLI toplanir (oranlarin duz ortalamasi DEGIL).
     Yalniz sayi okunur; esya adi kaynaktan ALINMAZ (kimlikten Data Dragon adi). */
  const MU_RANKS = ['iron', 'bronze', 'silver', 'gold', 'platinum', 'emerald', 'diamond', 'master', 'grandmaster', 'challenger'];
  const MU_ALL = ['emerald', 'diamond', 'master', 'grandmaster', 'challenger'];
  const MU_SLOTS = ['start', 'boots', 'core', 'slot4', 'slot5', 'slot6'];
  const NOTE_MAX = 600; const NOTES_MAX = 300; const noteKey = (me, enemy, role) => me + '|' + enemy + '|' + role;
  function muRankSet(sel) { if (sel === 'all') return MU_ALL.slice(); return MU_RANKS.includes(sel) ? [sel] : null; }
  function parseMu(json) {
    const m = json && typeof json === 'object' ? json.matchup : null; if (!m || typeof m !== 'object' || !m.ranks || typeof m.ranks !== 'object') return null; const out = {}; let n = 0;
    for (const rk of MU_RANKS) {
      const b = m.ranks[rk]; if (!b || typeof b !== 'object') continue; const g = Number(b.games); const wr = Number(b.wr); if (!Number.isFinite(g) || !Number.isFinite(wr) || g < 0 || g > 1e9 || wr < 0 || wr > 100) continue;
      const items = {}; for (const slot of MU_SLOTS) {
        const arr = b.items && Array.isArray(b.items[slot]) ? b.items[slot].slice(0, 12) : []; const L = [];
        for (const it of arr) { if (!it || !/^\d{3,6}$/.test(String(it.id))) continue; const ig = Number(it.games); const iw = Number(it.wr); if (!Number.isFinite(ig) || !Number.isFinite(iw) || ig < 0 || ig > 1e9 || iw < 0 || iw > 100) continue; L.push({ id: String(it.id), games: Math.round(ig), wr: iw }); }
        if (L.length) items[slot] = L;
      }
      out[rk] = { games: Math.round(g), wr, items }; n++;
    }
    if (!n) return null; const patch = /^\d{1,3}\.\d{1,3}(\.\d{1,3})?$/.test(String(m.patch || '')) ? String(m.patch) : null; return { patch, ranks: out };
  }
  function aggMu(parsed, sel) {
    const set = muRankSet(sel); if (!parsed || !set) return null; const used = []; const missing = []; let games = 0; let wins = 0; const slots = {};
    for (const rk of set) {
      const b = parsed.ranks[rk]; if (!b || !b.games) { missing.push(rk); continue; } used.push(rk); games += b.games; wins += (b.wr * b.games) / 100;
      for (const slot of Object.keys(b.items)) { const S = slots[slot] || (slots[slot] = new Map()); for (const it of b.items[slot]) { const x = S.get(it.id) || { id: it.id, games: 0, wins: 0 }; x.games += it.games; x.wins += (it.wr * it.games) / 100; S.set(it.id, x); } }
    }
    if (!games) return { empty: true, rank: sel, ranksUsed: [], missing };
    const items = {}; for (const slot of MU_SLOTS) { const S = slots[slot]; if (!S) continue; items[slot] = [...S.values()].filter((x) => x.games > 0).sort((a, b) => b.games - a.games || a.id.localeCompare(b.id)).slice(0, 6).map((x) => ({ id: x.id, games: x.games, wr: Math.round((1000 * x.wins) / x.games) / 10 })); }
    return { rank: sel, ranksUsed: used, missing, games, wr: Math.round((1000 * wins) / games) / 10, patch: parsed.patch, items };
  }

  /* ana siralama: tahmin (+ varsa dis veri) + kisisel kayit + havuz. */
  function rank(roster, enemyId, role, opts) {
    opts = opts || {}; const enemy = roster.find((c) => c.id === enemyId); if (!enemy) return { error: 'enemy' }; const Z = rosterZ(roster); const hist = opts.hist || []; const pool = opts.pool || []; const ext = opts.ext || null;
    let cands = roster.filter((c) => c.id !== enemy.id);
    if (opts.poolOnly) cands = cands.filter((c) => pool.includes(c.id)); else if (opts.anyRole) { /* rol filtresi yok: oyundaki tum sampiyonlar */ } else cands = cands.filter((c) => pool.includes(c.id) || roleFit(c, role) || (ext && ext.has(c.id)) || personal(hist, c.id, enemy.id, role).games > 0);
    const rows = cands.map((c) => {
      const h = heuristic(c, enemy, role, Z); let score = 50 + h.delta; const sources = ['est']; const e = ext ? ext.get(c.id) : null; let extInfo = null;
      if (e) { const conf = Math.min(1, (e.games || (e.approx ? 120 : 0)) / 300); const x = 50 + (e.wr - 50) * conf; score = 0.7 * x + 0.3 * score; sources.push('ext'); extInfo = { wr: e.wr, games: e.games, runes: e.runes || null, approx: !!e.approx }; }
      const p = personal(hist, c.id, enemy.id, role); if (p.games) { const wgt = Math.min(1, p.games / 8) * 0.6; score = (1 - wgt) * score + wgt * wilson(p.wins, p.games); sources.push('personal'); }
      const inPool = pool.includes(c.id); if (inPool) score += 4;
      return { id: c.id, name: c.name, tags: c.tags, difficulty: c.difficulty, score: Math.round(clamp(score, 0, 100)), sources, reasons: h.pos.map((x) => Object.assign({ side: 'pos' }, x)).concat(h.neg.map((x) => Object.assign({ side: 'neg' }, x))), personal: p, ext: extInfo, inPool };
    });
    rows.sort((a, b) => b.score - a.score || b.personal.games - a.personal.games || a.name.localeCompare(b.name));
    return { enemy: { id: enemy.id, name: enemy.name, tags: enemy.tags, difficulty: enemy.difficulty }, role, picks: rows.slice(0, clamp(Math.round(opts.limit) || LIM.defTop, 1, LIM.top)), total: rows.length };
  }

  /* ---------- LCU (League istemcisi) okuma-yalniz yardimcilari ---------- */
  function parseLcuCmd(text) { const p = /--app-port=(\d{2,5})/.exec(String(text || '')); const t = /--remoting-auth-token=([A-Za-z0-9_\-]{8,128})/.exec(String(text || '')); if (!p || !t) return null; const port = Number(p[1]); if (!(port > 0 && port < 65536)) return null; return { port, token: t[1] }; }
  function mapSession(s, byKey) {
    if (!s || typeof s !== 'object') return null; const me = Array.isArray(s.myTeam) ? s.myTeam : []; const th = Array.isArray(s.theirTeam) ? s.theirTeam : []; const cell = s.localPlayerCellId; const mine = me.find((x) => x && x.cellId === cell) || null;
    const nm = (x) => { const k = String((x && (x.championId || x.championPickIntent)) || 0); return k !== '0' && byKey.has(k) ? byKey.get(k) : null; }; const rl = (x) => LCU_ROLE[String((x && x.assignedPosition) || '').toLowerCase()] || null;
    return { myRole: mine ? rl(mine) : null, myPick: mine ? nm(mine) : null, allies: me.map((x) => ({ id: nm(x), role: rl(x), me: x === mine })).filter((x) => x.id), enemies: th.map((x) => ({ id: nm(x), role: rl(x) })).filter((x) => x.id) };
  }

  /* ---------- profil / derece / LP / maclar (League istemcisinden SALT-OKUNUR cekilir, yalniz bu bilgisayarda saklanir) ---------- */
  const TIERS = ['IRON', 'BRONZE', 'SILVER', 'GOLD', 'PLATINUM', 'EMERALD', 'DIAMOND', 'MASTER', 'GRANDMASTER', 'CHALLENGER']; const DIVN = { I: 3, II: 2, III: 1, IV: 0 };
  const absLp = (tier, div, lp) => { const i = TIERS.indexOf(String(tier || '').toUpperCase()); const p = Number(lp); if (i < 0 || !Number.isFinite(p)) return null; if (i >= 7) return 2800 + p; return i * 400 + (DIVN[String(div || '').toUpperCase()] || 0) * 100 + p; };
  const QSTAT = { RANKED_SOLO_5x5: 'solo', RANKED_FLEX_SR: 'flex' };
  const numOr0 = (x) => (Number.isFinite(Number(x)) ? Number(x) : 0);
  function normRank(e) {
    if (!e || typeof e !== 'object') return null; const q = QSTAT[e.queueType]; if (!q) return null; const tier = String(e.tier || '').toUpperCase();
    /* İstemci başka oyuncular için 'losses' vermeyebilir; 0 yazmak '%100 WR' gibi uydurma sonuç üretir → noL bayrağı (arayüz '—' gösterir) */
    const noL = e.losses === undefined || e.losses === null; const flag = noL ? { noL: true } : {};
    if (!TIERS.includes(tier)) return Object.assign({ q, unranked: true, w: numOr0(e.wins), l: numOr0(e.losses) }, flag);
    return Object.assign({ q, tier, div: TIERS.indexOf(tier) >= 7 ? '' : String(e.division || '').toUpperCase().slice(0, 3), lp: numOr0(e.leaguePoints), w: numOr0(e.wins), l: numOr0(e.losses), series: e.miniSeriesProgress ? String(e.miniSeriesProgress).replace(/[^LWN]/g, '').slice(0, 7) : '' }, flag);
  }
  /* maç listesi yanıtı: bilinen biçimler; tanınmazsa null (boş liste ile karıştırılmaz) */
  const gamesOf = (j) => { if (!j || typeof j !== 'object') return null; const g = j.games; if (Array.isArray(g)) return g; if (g && Array.isArray(g.games)) return g.games; if (Array.isArray(j.matches)) return j.matches; return null; };
  function parseRanked(j) { const out = { solo: null, flex: null }; const qs = j && Array.isArray(j.queues) ? j.queues : []; for (const e of qs) { const r = normRank(e); if (r && !out[r.q]) out[r.q] = r; } return out; }
  function addSnap(list, r, t, cap) {
    if (!r || r.unranked) return false; let last = null; for (let i = list.length - 1; i >= 0; i--) if (list[i].q === r.q) { last = list[i]; break; }
    if (last && last.tier === r.tier && last.div === r.div && last.lp === r.lp && last.w === r.w && last.l === r.l) return false;
    list.push({ t, q: r.q, tier: r.tier, div: r.div, lp: r.lp, w: r.w, l: r.l }); if (list.length > cap) list.splice(0, list.length - cap); return true;
  }
  function lpSeries(snaps, q) { return snaps.filter((s) => s.q === q).sort((a, b) => a.t - b.t).map((s) => ({ t: s.t, abs: absLp(s.tier, s.div, s.lp), tier: s.tier, div: s.div, lp: s.lp, w: s.w, l: s.l })).filter((p) => p.abs !== null); }
  function lpEvents(snaps, q) {
    const ser = lpSeries(snaps, q); const ev = [];
    for (let i = 1; i < ser.length; i++) { const a = ser[i - 1]; const b = ser[i]; if (a.tier === b.tier && a.div === b.div) continue; const ab = absLp(a.tier, a.div, 0); const bb = absLp(b.tier, b.div, 0); ev.push({ t: b.t, type: bb > ab ? 'up' : 'down', from: { tier: a.tier, div: a.div }, to: { tier: b.tier, div: b.div } }); }
    return ev.reverse();
  }
  const dayStart = (ms) => { const d = new Date(ms); d.setHours(0, 0, 0, 0); return d.getTime(); };
  function todayLp(snaps, q, t0) {
    const ser = lpSeries(snaps, q); if (!ser.length) return null; const cur = ser[ser.length - 1]; if (cur.t < t0) return 0; let base = null; for (const p of ser) if (p.t < t0) base = p; if (!base) base = ser.find((p) => p.t >= t0); return base ? cur.abs - base.abs : 0;
  }

  const QUEUES = { 420: 'solo', 440: 'flex', 400: 'draft', 430: 'blind', 480: 'swift', 490: 'quick', 450: 'aram', 700: 'clash', 1700: 'arena', 900: 'urf', 1900: 'urf', 830: 'coop', 840: 'coop', 850: 'coop', 0: 'custom' };
  const QG = { ranked: ['solo', 'flex'], normal: ['draft', 'blind', 'quick', 'swift'] }; const FILTERS = ['all', 'ranked', 'solo', 'flex', 'normal', 'aram', 'other'];
  const mkFilter = (q) => { if (!q || q === 'all') return () => true; if (QG[q]) return (m) => QG[q].includes(m.queue); if (q === 'other') return (m) => !['solo', 'flex', 'draft', 'blind', 'quick', 'swift', 'aram'].includes(m.queue); return (m) => m.queue === q; };
  const laneRole = (tl) => { if (!tl) return null; const lane = String(tl.lane || '').toUpperCase(); const role = String(tl.role || '').toUpperCase(); if (lane === 'TOP') return 'top'; if (lane === 'JUNGLE') return 'jungle'; if (lane === 'MIDDLE' || lane === 'MID') return 'mid'; if (lane === 'BOTTOM' || lane === 'BOT') return role.includes('SUPPORT') ? 'support' : 'bot'; if (role.includes('SUPPORT')) return 'support'; return null; };
  function normMatch(g, myPuuid, champOf) {
    if (!g || typeof g !== 'object' || !Number.isFinite(Number(g.gameId))) return null; const parts = Array.isArray(g.participants) ? g.participants : []; const ids = Array.isArray(g.participantIdentities) ? g.participantIdentities : [];
    const idOf = new Map(ids.map((x) => [x && x.participantId, (x && x.player) || {}])); let me = null;
    for (const p of parts) { const pl = idOf.get(p && p.participantId) || {}; if (myPuuid && pl.puuid === myPuuid) { me = p; break; } } if (!me && parts.length === 1) me = parts[0]; if (!me || !me.stats) return null;
    const s = me.stats; const rn = parseRunes({ perks: [0, 1, 2, 3, 4, 5].map((i) => s['perk' + i]), primary: s.perkPrimaryStyle, secondary: s.perkSubStyle }); const runes = rn && rn.perks.length === 6 ? rn : null; let t = numOr0(g.gameCreation); if (!t && g.gameCreationDate) t = Date.parse(g.gameCreationDate) || 0; const dur = numOr0(g.gameDuration); const remake = !!s.gameEndedInEarlySurrender || (dur > 0 && dur < 240);
    const win = s.win === true || s.win === 'Win'; const role = laneRole(me.timeline); const full = parts.length >= 2;
    const spellIds = [me.spell1Id, me.spell2Id].map((x) => { const n = Number(x); return Number.isInteger(n) && n > 0 && n <= 999999 ? n : null; });
    const stat = (v, max) => { const n = Number(v); return v != null && Number.isFinite(n) && n >= 0 && n <= max ? Math.floor(n) : null; };
    const players = full ? parts.map((p) => { const pl = idOf.get(p.participantId) || {}; const ps = p.stats || {}; const cs = stat(ps.totalMinionsKilled, 1000000); const jungle = stat(ps.neutralMinionsKilled, 1000000); return { champ: champOf(p.championId), name: String(pl.gameName || pl.summonerName || '').slice(0, 30), tag: String(pl.tagLine || '').slice(0, 10), team: numOr0(p.teamId), me: p === me, puuid: String(pl.puuid || '').slice(0, 90), role: laneRole(p.timeline), k: stat(ps.kills, 100000), d: stat(ps.deaths, 100000), a: stat(ps.assists, 100000), cs: cs === null || jungle === null ? null : cs + jungle, gold: stat(ps.goldEarned, 100000000), dmg: stat(ps.totalDamageDealtToChampions, 100000000), vision: stat(ps.visionScore, 100000), items: Array.from({ length: 7 }, (_, i) => stat(ps['item' + i], 999999)).filter((x) => x !== null && x > 0) }; }) : [];
    const opp = role && full ? ((players.find((x) => !x.me && x.team !== numOr0(me.teamId) && x.role === role) || {}).champ || null) : null;
    return { id: String(Math.round(Number(g.gameId))), t, dur, queue: QUEUES[numOr0(g.queueId)] || 'other', queueId: numOr0(g.queueId), win: remake ? null : win, remake, champ: champOf(me.championId), role, k: numOr0(s.kills), d: numOr0(s.deaths), a: numOr0(s.assists), cs: numOr0(s.totalMinionsKilled) + numOr0(s.neutralMinionsKilled), gold: numOr0(s.goldEarned), dmg: numOr0(s.totalDamageDealtToChampions), vision: numOr0(s.visionScore), lvl: numOr0(s.champLevel), items: [0, 1, 2, 3, 4, 5, 6].map((i) => numOr0(s['item' + i])).filter((x) => x > 0), team: numOr0(me.teamId), players, opp, partial: !full, runes, spells: spellIds.some(Boolean) ? spellIds : null };
  }
  const wlOf = (ms) => { const r = ms.filter((m) => !m.remake); const w = r.filter((m) => m.win).length; return { w, l: r.length - w }; };
  const r1 = (x) => Math.round(x * 10) / 10; const r2 = (x) => Math.round(x * 100) / 100;
  function overview(ms, now) {
    const real = ms.filter((m) => !m.remake); const n = real.length; const w = real.filter((m) => m.win).length; const sum = (f) => real.reduce((a, m) => a + f(m), 0); const mins = sum((m) => m.dur) / 60;
    let streak = null; if (n) { const t = real[0].win; let c = 0; for (const m of real) { if (m.win !== t) break; c++; } streak = { win: t, n: c }; }
    const roles = {}; for (const m of real) if (m.role) roles[m.role] = (roles[m.role] || 0) + 1; const fav = Object.keys(roles).sort((a, b) => roles[b] - roles[a])[0] || null;
    const t0 = dayStart(now); const td = real.filter((m) => m.t >= t0); const recent = real.filter((m) => m.t >= now - 4 * 3600e3).slice(0, 3); const l10 = real.slice(0, 10);
    return { games: n, wins: w, losses: n - w, wr: n ? r1((100 * w) / n) : 0, last10: { w: l10.filter((m) => m.win).length, l: l10.filter((m) => !m.win).length }, last20: real.slice(0, 20).map((m) => !!m.win), streak,
      kda: n ? r2((sum((m) => m.k) + sum((m) => m.a)) / Math.max(1, sum((m) => m.d))) : 0, k: n ? r1(sum((m) => m.k) / n) : 0, d: n ? r1(sum((m) => m.d) / n) : 0, a: n ? r1(sum((m) => m.a) / n) : 0,
      csm: mins ? r1(sum((m) => m.cs) / mins) : 0, gpm: mins ? Math.round(sum((m) => m.gold) / mins) : 0, avgMin: n ? Math.round(mins / n) : 0, fav, today: { games: td.length, w: td.filter((m) => m.win).length, l: td.filter((m) => !m.win).length }, tilt: recent.length === 3 && recent.every((m) => !m.win) };
  }
  function champStats(ms) {
    const by = new Map(); for (const m of ms) { if (m.remake || !m.champ) continue; const x = by.get(m.champ) || { champ: m.champ, games: 0, wins: 0, k: 0, d: 0, a: 0, cs: 0, sec: 0, gold: 0, dmg: 0, last: 0 }; x.games++; if (m.win) x.wins++; x.k += m.k; x.d += m.d; x.a += m.a; x.cs += m.cs; x.sec += m.dur; x.gold += m.gold; x.dmg += m.dmg; x.last = Math.max(x.last, m.t); by.set(m.champ, x); }
    return [...by.values()].map((x) => ({ champ: x.champ, games: x.games, wins: x.wins, wr: r1((100 * x.wins) / x.games), kda: r2((x.k + x.a) / Math.max(1, x.d)), k: r1(x.k / x.games), d: r1(x.d / x.games), a: r1(x.a / x.games), csm: x.sec ? r1(x.cs / (x.sec / 60)) : 0, gpm: x.sec ? Math.round(x.gold / (x.sec / 60)) : 0, dmg: Math.round(x.dmg / x.games), last: x.last })).sort((a, b) => b.games - a.games || b.wr - a.wr || a.champ.localeCompare(b.champ));
  }
  /* Blitz 'Sampiyon havuzu': hat basina sampiyonlar (galibiyet, KDA) + yalniz KESIN hesaplanan LP farklarinin toplami (bilinmiyorsa lp:null) */
  function roleChampStats(ms, delta) {
    const out = [];
    for (const role of ROLES) {
      const rm = ms.filter((m) => m.role === role && !m.remake); if (!rm.length) continue; const wins = rm.filter((m) => m.win).length; let lp = null;
      for (const m of rm) if (delta && delta.has(m.id)) lp = (lp || 0) + delta.get(m.id);
      const champs = champStats(rm).slice(0, 30).map((c) => { let cl = null; for (const m of rm) if (m.champ === c.champ && delta && delta.has(m.id)) cl = (cl || 0) + delta.get(m.id); return Object.assign({}, c, { lp: cl }); });
      out.push({ role, games: rm.length, wins, losses: rm.length - wins, lp, champs });
    }
    return out.sort((a, b) => b.games - a.games);
  }
  function roleStats(ms) { const by = {}; for (const m of ms) { if (m.remake || !m.role) continue; const x = by[m.role] || (by[m.role] = { role: m.role, games: 0, wins: 0 }); x.games++; if (m.win) x.wins++; } return Object.values(by).map((x) => Object.assign(x, { wr: r1((100 * x.wins) / x.games) })).sort((a, b) => b.games - a.games); }
  function partnerStats(ms) {
    const full = ms.filter((m) => !m.partial && !m.remake); const by = new Map();
    for (const m of full) for (const p of m.players) { if (p.me || p.team !== m.team) continue; const key = p.puuid || (p.name + '#' + p.tag); if (!key || key === '#') continue; const x = by.get(key) || { key, name: p.name, tag: p.tag, games: 0, wins: 0, last: 0, champs: {} }; x.games++; if (m.win) x.wins++; x.last = Math.max(x.last, m.t); if (p.champ) x.champs[p.champ] = (x.champs[p.champ] || 0) + 1; by.set(key, x); }
    const rows = [...by.values()].map((x) => ({ name: x.name, tag: x.tag, games: x.games, wins: x.wins, wr: r1((100 * x.wins) / x.games), last: x.last, top: Object.keys(x.champs).sort((a, b) => x.champs[b] - x.champs[a]).slice(0, 3) })).sort((a, b) => b.games - a.games || b.last - a.last).slice(0, 60);
    return { rows, covered: full.length, total: ms.filter((m) => !m.remake).length };
  }
  /* LP farki: yalniz maci KESIN olarak cevreleyen iki anlik goruntu varsa ve araya baska ayni-kuyruk maci girmediyse */
  function attrLp(ms, snaps) {
    const out = new Map(); const ranked = ms.filter((m) => m.queue === 'solo' || m.queue === 'flex');
    for (const m of ranked) {
      if (m.remake) continue; const ser = lpSeries(snaps, m.queue); const end = m.t + m.dur * 1000; let pre = null; let post = null; for (const p of ser) { if (p.t <= m.t) pre = p; else if (p.t >= end && !post) post = p; }
      if (!pre || !post) continue; const between = ranked.filter((x) => x.queue === m.queue && !x.remake && x.t + x.dur * 1000 > pre.t && x.t < post.t).length; if (between !== 1) continue; out.set(m.id, post.abs - pre.abs);
    }
    return out;
  }
  function banPicks(roster, pool, role, hist, limit) {
    const Z = rosterZ(roster); const mine = roster.filter((c) => pool.includes(c.id)); if (!mine.length) return { needPool: true }; const rows = [];
    for (const e of roster) {
      if (!roleFit(e, role) && !(hist || []).some((h) => h.enemy === e.id && h.role === role)) continue; let sum = 0; let n = 0; let worst = null;
      for (const c of mine) { if (c.id === e.id) continue; const h = heuristic(c, e, role, Z); let s = 50 + h.delta; const p = personal(hist || [], c.id, e.id, role); if (p.games) { const w = Math.min(1, p.games / 8) * 0.6; s = (1 - w) * s + w * wilson(p.wins, p.games); } sum += s; n++; if (!worst || s < worst.score) worst = { id: c.id, name: c.name, score: Math.round(s) }; }
      if (n) rows.push({ id: e.id, name: e.name, tags: e.tags, avg: Math.round(sum / n), worst });
    }
    rows.sort((a, b) => a.avg - b.avg || a.name.localeCompare(b.name)); return { role, bans: rows.slice(0, clamp(Math.round(limit) || 8, 1, 20)), pool: mine.map((c) => c.id) };
  }
  function teamProfile(list) { let ad = 0; let ap = 0; let tanks = 0; let ranged = 0; let assassins = 0; for (const c of list) { ad += c.attack; ap += c.magic; if (c.tags.includes('Tank') || c.defense >= 7) tanks++; if (c.range >= 500) ranged++; if (c.tags.includes('Assassin')) assassins++; } return { n: list.length, apPct: Math.round((100 * ap) / (ad + ap || 1)), tanks, ranged, assassins }; }
  function compAnalysis(roster, allies, enemies) {
    const by = new Map(roster.map((c) => [c.id, c])); const a = teamProfile((allies || []).map((x) => by.get(x)).filter(Boolean)); const e = teamProfile((enemies || []).map((x) => by.get(x)).filter(Boolean)); const notes = [];
    if (a.n >= 3 && a.apPct <= 22) notes.push({ side: 'ally', k: 'allAD' }); if (a.n >= 3 && a.apPct >= 78) notes.push({ side: 'ally', k: 'allAP' }); if (a.n >= 4 && !a.tanks) notes.push({ side: 'ally', k: 'noTank' }); if (a.n >= 4 && a.ranged === 0) notes.push({ side: 'ally', k: 'noRange' });
    if (e.n >= 3 && e.apPct <= 22) notes.push({ side: 'enemy', k: 'enemyAD' }); if (e.n >= 3 && e.apPct >= 78) notes.push({ side: 'enemy', k: 'enemyAP' }); if (e.n >= 4 && e.assassins >= 2) notes.push({ side: 'enemy', k: 'enemyAssassins' }); if (e.n >= 4 && !e.tanks) notes.push({ side: 'enemy', k: 'enemyNoTank' });
    return { ally: a, enemy: e, notes };
  }
  /* ---------- ESYA ONERISI (Data Dragon item.json; KABA kurallar — gercek kazanma verisi DEGIL) ---------- */
  /* Elle yazilmis KISA liste: yara azaltma (Grievous Wounds) gerekcesi olabilecek yuksek iyilesme/can calan sampiyonlar. Eksik/guncel olmayabilir. */
  const SUSTAIN = new Set(['Soraka', 'Aatrox', 'Warwick', 'Vladimir', 'DrMundo', 'Swain', 'Yuumi', 'Sona', 'Briar']);
  /* item.json -> yalniz Summoner's Rift (harita 11) tamamlanmis esyalar + son kademe ayakkabilar; yalniz sayilar/etiketler/ad saklanir */
  function parseItems(json) {
    const d = json && json.data; if (!d || typeof d !== 'object') return []; const n = (x) => (Number.isFinite(Number(x)) ? Number(x) : 0); const out = [];
    for (const id of Object.keys(d)) {
      if (!/^\d{3,6}$/.test(id) || Number(id) >= 200000) continue; const it = d[id]; if (!it || typeof it !== 'object') continue; const g = it.gold || {};
      if (g.purchasable === false || it.inStore === false || it.consumed || it.requiredChampion || it.requiredAlly) continue; if (!(it.maps && it.maps['11'] === true)) continue; if (Array.isArray(it.into) && it.into.length) continue;
      const tags = Array.isArray(it.tags) ? it.tags.map(String) : []; if (tags.some((t) => /^(Consumable|Trinket|Lane|Jungle|Vision|GoldPer)$/.test(t))) continue;
      const total = n(g.total); const boots = tags.includes('Boots'); if (total < (boots ? 900 : 1600)) continue; const s = it.stats || {}; const desc = String(it.description || '');
      out.push({ id, name: String(it.name || id).slice(0, 40), gold: total, tags, boots, st: { armor: n(s.FlatArmorMod), mr: n(s.FlatSpellBlockMod), hp: n(s.FlatHPPoolMod), ad: n(s.FlatPhysicalDamageMod), ap: n(s.FlatMagicDamageMod) },
        gw: /Grievous Wounds/i.test(desc), penP: tags.includes('ArmorPenetration') || /Lethality|Armor Penetration/i.test(desc), penM: tags.includes('MagicPenetration') || /Magic Penetration/i.test(desc) });
    }
    return out;
  }
  /* Rakip takimin hasar dagilimi/on hat/iyilesme durumuna gore SITUASYONEL esya onerisi. Sampiyonun hasar turu (AD/AP/Tank) bilgisine gore filtrelenir. */
  function buildItemAdvice(roster, meId, enemyIds, role, items, names, version) {
    const by = new Map(roster.map((c) => [c.id, c])); const me = by.get(meId); if (!me) return null; const en = (enemyIds || []).map((x) => by.get(x)).filter(Boolean);
    const T = me.tags[0] === 'Tank' ? 'tank' : me.magic > me.attack ? 'ap' : 'ad'; const base = { me: meId, role: role || null, type: T, version: version || null, enemies: en.map((c) => c.id) };
    if (role === 'support') return Object.assign(base, { support: true, sections: [] });
    const p = teamProfile(en); const heal = en.filter((c) => SUSTAIN.has(c.id)); const nm = (it) => (names && names[it.id]) || it.name;
    const off = (it) => (T === 'ap' ? it.st.ap : T === 'ad' ? it.st.ad : 0); const bad = (it) => (T === 'ap' ? it.st.ad > 0 && !(it.st.ap > 0) : T === 'ad' ? it.st.ap > 0 && !(it.st.ad > 0) : it.st.ap > 0);
    const card = (it) => ({ id: it.id, name: nm(it), gold: it.gold });
    const top = (f, sc) => { const c = items.filter((it) => !it.boots && !bad(it) && f(it)); const cmp = (a, b) => sc(b) - sc(a) || a.name.localeCompare(b.name); const pool = T === 'tank' ? c.sort(cmp) : c.filter((it) => off(it) > 0).sort(cmp).concat(c.filter((it) => off(it) <= 0).sort(cmp)); return pool.slice(0, 3).map(card); };
    const def = (it) => it.st.armor + it.st.mr + 0.08 * it.st.hp; const S = []; const add = (k, pri, why, list) => { if (list.length) S.push({ k, pri, why, items: list }); };
    const adPri = p.n ? (p.apPct <= 35 ? 'high' : p.apPct <= 60 ? 'mid' : null) : null; const apPri = p.n ? (p.apPct >= 65 ? 'high' : p.apPct >= 40 ? 'mid' : null) : null;
    const whyDmg = p.apPct <= 35 ? [{ k: 'adHeavy', v: [100 - p.apPct] }] : p.apPct >= 65 ? [{ k: 'apHeavy', v: [p.apPct] }] : [{ k: 'mixedDmg', v: [p.apPct] }];
    if (adPri) add('armor', adPri, whyDmg, top((it) => it.st.armor > 0, (it) => it.st.armor + 0.08 * it.st.hp + 0.25 * off(it)));
    if (apPri) add('mr', apPri, whyDmg, top((it) => it.st.mr > 0, (it) => it.st.mr + 0.08 * it.st.hp + 0.25 * off(it)));
    if (heal.length) add('antiheal', heal.length >= 2 ? 'high' : 'mid', [{ k: 'healers', v: [heal.map((c) => c.name).join(', ')] }], top((it) => it.gw && (T !== 'tank' || def(it) > 0), (it) => off(it) + def(it)));
    if (T !== 'tank' && p.tanks >= 2) add('pen', p.tanks >= 3 ? 'high' : 'mid', [{ k: 'tanks', v: [p.tanks] }], top((it) => (T === 'ap' ? it.penM : it.penP), (it) => off(it) + 0.08 * it.st.hp));
    const boots = []; for (const [pri, tag] of [[adPri, 'Armor'], [apPri, 'SpellBlock']]) if (pri) for (const it of items.filter((x) => x.boots && x.tags.includes(tag)).sort((a, b) => a.name.localeCompare(b.name)).slice(0, 2)) if (!boots.some((b) => b.id === it.id)) boots.push(it);
    if (boots.length) add('boots', adPri === 'high' || apPri === 'high' ? 'high' : 'mid', whyDmg, boots.map(card));
    const order = { high: 0, mid: 1 }; S.sort((a, b) => order[a.pri] - order[b.pri]);
    return Object.assign(base, { partial: p.n > 0 && p.n < 3, profile: { n: p.n, apPct: p.apPct, tanks: p.tanks, assassins: p.assassins, healers: heal.map((c) => c.id) }, sections: S });
  }
  const LCU_OK = [/^\/lol-champ-select\/v1\/session$/, /^\/lol-summoner\/v1\/current-summoner$/, /^\/lol-ranked\/v1\/current-ranked-stats$/, /^\/lol-match-history\/v1\/products\/lol\/current-summoner\/matches\?begIndex=\d{1,4}&endIndex=\d{1,4}$/, /^\/lol-match-history\/v1\/games\/\d{1,15}$/, /^\/lol-perks\/v1\/pages$/, /^\/lol-perks\/v1\/currentpage$/, /^\/lol-summoner\/v1\/alias\/lookup\?gameName=[A-Za-z0-9%._~-]{1,120}&tagLine=[A-Za-z0-9]{2,10}$/, /^\/lol-summoner\/v1\/summoners\?name=[A-Za-z0-9%._~-]{1,140}$/, /^\/lol-summoner\/v1\/summoners-by-puuid-cached\/[A-Za-z0-9_-]{20,100}$/, /^\/lol-ranked\/v1\/ranked-stats\/[A-Za-z0-9_-]{20,100}$/, /^\/lol-match-history\/v1\/products\/lol\/[A-Za-z0-9_-]{20,100}\/matches\?begIndex=\d{1,4}&endIndex=\d{1,4}$/, /^\/lol-chat\/v1\/friends$/, /^\/lol-perks\/v1\/recommended-pages\/champion\/\d{1,4}\/position\/(top|jungle|middle|bottom|utility)\/map\/\d{1,3}$/];
  /* LCU-WRITE-BEGIN: League istemcisine TEK yazma türü — kendi 'Kovan' rün sayfamız (oluştur/sil). Başka uç nokta yazılamaz. */
  const LCU_WRITE_OK = [['POST', /^\/lol-perks\/v1\/pages$/], ['DELETE', /^\/lol-perks\/v1\/pages\/\d{1,12}$/]];
  /* LCU-WRITE-END */


  /* ---------- CANLI MAC (Riot'un yerel Live Client Data API'si: 127.0.0.1:2999, yalniz GET, yalniz okuma) ---------- */
  const LIVE_OK = /^\/liveclientdata\/allgamedata$/; const LIVE_POS = { TOP: 'top', JUNGLE: 'jungle', MIDDLE: 'mid', MID: 'mid', BOTTOM: 'bot', BOT: 'bot', UTILITY: 'support', SUPPORT: 'support' };
  const spellsOf = (p) => { const s = (p && p.summonerSpells) || {}; return [s.summonerSpellOne, s.summonerSpellTwo].map((x) => String((x && (x.rawDisplayName || x.displayName)) || '')); };
  const hasSpell = (p, re) => spellsOf(p).some((x) => re.test(x));
  /* sampiyon etiketlerinden hat agirliklari (KABA tahmin; gercek hat dagilimi verisi degildir) + cagirdigi buyuler + oyunun verdigi hat */
  function roleWeights(c, p) {
    const w = { top: 0.06, jungle: 0.06, mid: 0.06, bot: 0.06, support: 0.06 };
    if (c) { const t = c.tags;
      if (t.includes('Fighter')) { w.top += 0.9; w.jungle += 0.5; } if (t.includes('Tank')) { w.top += 0.6; w.jungle += 0.5; w.support += 0.2; } if (t.includes('Mage')) { w.mid += 0.9; if (c.range <= 550 && c.hp >= 650) w.top += 0.4; if (c.range >= 550) w.bot += 0.1; w.support += t.includes('Support') ? 0 : 0.1; }
      if (t.includes('Assassin')) { w.mid += 0.8; w.jungle += 0.6; w.top += 0.2; } if (t.includes('Marksman')) { w.bot += 1.3; w.mid += 0.1; } if (t.includes('Support')) { w.support += 1.2; } if (t.includes('Fighter') && c.range >= 300) w.mid += 0.3; }
    const mul = (r, k) => { w[r] *= k; };
    if (c && Array.isArray(c.pos) && c.pos.length) { for (const r of Object.keys(w)) mul(r, c.pos.includes(r) ? 8 : 0.1); }
    if (hasSpell(p, /Smite/i)) { for (const r of Object.keys(w)) mul(r, r === 'jungle' ? 40 : 0.02); }
    if (hasSpell(p, /Teleport/i)) { mul('top', 2); mul('mid', 1.5); mul('bot', 0.3); mul('support', 0.2); mul('jungle', 0.3); }
    if (hasSpell(p, /Heal|Barrier/i)) { mul('bot', 2.5); mul('mid', 1.3); mul('support', 0.7); }
    if (hasSpell(p, /Exhaust/i)) { mul('support', 2.5); mul('mid', 1.3); mul('bot', 0.6); }
    if (hasSpell(p, /Dot|Ignite/i)) { mul('support', 1.4); mul('mid', 1.3); mul('top', 1.3); }
    const pos = LIVE_POS[String((p && p.position) || '').toUpperCase()]; if (pos) { for (const r of Object.keys(w)) mul(r, r === pos ? 1000 : 0.001); }
    return w;
  }
  const PERMS = (() => { const out = []; const rec = (a, rest) => { if (!rest.length) { out.push(a); return; } for (let i = 0; i < rest.length; i++) rec(a.concat(rest[i]), rest.slice(0, i).concat(rest.slice(i + 1))); }; rec([], [0, 1, 2, 3, 4]); return out; })();
  const ROLE_ORDER = ['top', 'jungle', 'mid', 'bot', 'support'];
  /* 5 oyuncu → 5 hat: tum atamalari olasilikla agirliklar; her oyuncu icin en olasi hat + o hattin marjinal olasiligi */
  function assignRoles(weights) {
    if (weights.length !== 5) return null; let best = null; let total = 0; const marg = weights.map(() => ({ top: 0, jungle: 0, mid: 0, bot: 0, support: 0 }));
    for (const perm of PERMS) { let pr = 1; for (let i = 0; i < 5; i++) pr *= weights[i][ROLE_ORDER[perm[i]]]; total += pr; for (let i = 0; i < 5; i++) marg[i][ROLE_ORDER[perm[i]]] += pr; if (!best || pr > best.pr) best = { pr, perm }; }
    if (!(total > 0)) return null; return weights.map((_, i) => { const m = marg[i]; const role = ROLE_ORDER[best.perm[i]]; const probs = {}; for (const r of ROLE_ORDER) probs[r] = Math.round((1000 * m[r]) / total) / 1000; return { role, conf: probs[role], probs }; });
  }
  /* oyun ici tablodaki esya degeri: Live Client her esya icin `price` (esya fiyati) ve `count` verir; cebindeki/harcanmis altin YOK */
  const clampN = (x, lo, hi) => { const n = Number(x); return Number.isFinite(n) ? Math.max(lo, Math.min(hi, Math.round(n))) : 0; };
  function goldOf(p) { const L = Array.isArray(p && p.items) ? p.items.slice(0, 12) : []; let s = 0; for (const it of L) { if (!it || typeof it !== 'object') continue; s += clampN(it.price, 0, 6000) * Math.max(1, clampN(it.count, 1, 20)); } return s; }
  function parseLive(j, byName, byId) {
    if (!j || typeof j !== 'object' || !Array.isArray(j.allPlayers)) return null; const gd = j.gameData || {}; const ap = j.activePlayer || {}; const meName = String(ap.riotId || ap.summonerName || ''); const meGame = String(ap.riotIdGameName || '');
    const champId = (p) => { const raw = String(p.rawChampionName || '').replace(/^game_character_displayname_/i, ''); if (byId.has(raw)) return raw; const nm = String(p.championName || ''); const hit = byName.get(nm); return hit ? hit.id : (byId.has(nm.replace(/[^A-Za-z0-9]/g, '')) ? nm.replace(/[^A-Za-z0-9]/g, '') : null); };
    const mk = (p) => { const rn = p.runes && typeof p.runes === 'object' ? p.runes : null; const nm = (x) => (x && typeof x.displayName === 'string' ? x.displayName.slice(0, 40) : null); return { champ: champId(p), name: String(p.riotIdGameName || p.summonerName || '').slice(0, 30), tag: String(p.riotIdTagLine || '').slice(0, 10), team: p.team === 'CHAOS' ? 'CHAOS' : 'ORDER', level: Math.round(Number(p.level)) || 0, gold: goldOf(p), k: clampN(p.scores && p.scores.kills, 0, 999), bot: !!p.isBot, pos: LIVE_POS[String(p.position || '').toUpperCase()] || null, smite: hasSpell(p, /Smite/i), spells: spellsOf(p).map((x) => (/Smite/i.test(x) ? 'smite' : /Teleport/i.test(x) ? 'teleport' : /Flash/i.test(x) ? 'flash' : /Heal/i.test(x) ? 'heal' : /Barrier/i.test(x) ? 'barrier' : /Exhaust/i.test(x) ? 'exhaust' : /Dot|Ignite/i.test(x) ? 'ignite' : /Haste|Ghost/i.test(x) ? 'ghost' : /Boost|Cleanse/i.test(x) ? 'cleanse' : 'other')), runes: rn ? { keystone: nm(rn.keystone), primary: nm(rn.primaryRuneTree), secondary: nm(rn.secondaryRuneTree) } : null, _raw: p, me: !!meName && (String(p.riotId || '') === meName || (meGame && String(p.riotIdGameName || '') === meGame) || String(p.summonerName || '') === meName) }; };
    const all = j.allPlayers.slice(0, 10).map(mk); return { mode: String(gd.gameMode || '').slice(0, 20), time: Math.max(0, Math.round(Number(gd.gameTime) || 0)), players: all };
  }
  function analyzeLive(parsed, roster, opts) {
    opts = opts || {}; const by = new Map(roster.map((c) => [c.id, c])); const me = parsed.players.find((x) => x.me) || null; const classic = parsed.mode === 'CLASSIC';
    const teams = { ORDER: parsed.players.filter((x) => x.team === 'ORDER'), CHAOS: parsed.players.filter((x) => x.team === 'CHAOS') };
    for (const k of ['ORDER', 'CHAOS']) { const L = teams[k]; if (classic && L.length === 5) { const a = assignRoles(L.map((x) => roleWeights(by.get(x.champ) || null, x._raw))); if (a) L.forEach((x, i) => { x.role = a[i].role; x.conf = a[i].conf; x.probs = a[i].probs; x.known = !!x.pos; }); } }
    for (const x of parsed.players) { delete x._raw; if (!x.role) { x.role = null; x.conf = 0; x.probs = null; x.known = false; } }
    const myTeam = me ? me.team : null; const enemies = myTeam ? teams[myTeam === 'ORDER' ? 'CHAOS' : 'ORDER'] : []; const allies = myTeam ? teams[myTeam] : [];
    const lane = me && me.role ? enemies.find((x) => x.role === me.role) || null : null;
    return { mode: parsed.mode, time: parsed.time, classic, me: me ? { champ: me.champ, name: me.name, role: me.role, conf: me.conf, level: me.level } : null, allies, enemies, lane: lane ? lane.champ : null };
  }

  /* rün sayfası yapısı: perk0 = anahtar taş (ağaç A, slot 0), perk1-3 = A'nın 1,2,3. slotları, perk4-5 = ağaç B (≠A) farklı iki slot (1-3) */
  function validateRunePage(p, idx) {
    if (!Array.isArray(p) || p.length !== 6 || !idx) return null; const x = p.map((id) => idx[id]); if (x.some((e) => !e)) return null; const A = x[0].t; if (x[0].s !== 0 || x[1].t !== A || x[2].t !== A || x[3].t !== A || x[1].s !== 1 || x[2].s !== 2 || x[3].s !== 3) return null;
    const B = x[4].t; if (B === A || x[5].t !== B || x[4].s < 1 || x[5].s < 1 || x[4].s === x[5].s) return null; return { primary: A, sub: B };
  }
  function createLolHost(deps) {
    deps = deps || {}; const dataDir = deps.dataDir || null; const stateFile = dataDir ? path.join(dataDir, 'lolcounter.json') : null; const cacheDir = dataDir ? path.join(dataDir, 'lolcounter-cache') : null;
    const now = deps.now || (() => Date.now());
    const run = deps.run || ((cmd, args, ms) => new Promise((resolve, reject) => { cp.execFile(cmd, args, { timeout: ms || 10000, windowsHide: true, maxBuffer: 4 * 1024 * 1024, encoding: 'utf8' }, (e, so) => (e && !so ? reject(e) : resolve(String(so || '')))); }));
    let state = { v: 1, pool: {}, hist: [], statsUrl: null, me: null, rank: null, lp: [], matches: {}, murank: 'all', muUrl: null, notes: {}, ov: { on: false, secs: 20 }, gold: { on: true } }; if (stateFile) { try { const o = JSON.parse(fs.readFileSync(stateFile, 'utf8')); if (o && typeof o === 'object') state = Object.assign(state, o); } catch (e) { /* ilk kullanim */ } }
    if (!state.pool || typeof state.pool !== 'object') state.pool = {}; if (!Array.isArray(state.hist)) state.hist = []; if (!Array.isArray(state.lp)) state.lp = []; if (!state.matches || typeof state.matches !== 'object' || Array.isArray(state.matches)) state.matches = {};
    if (muRankSet(state.murank) === null) state.murank = 'all'; if (!state.notes || typeof state.notes !== 'object' || Array.isArray(state.notes)) state.notes = {}; if (!state.ov || typeof state.ov !== 'object') state.ov = { on: false, secs: 20 }; state.ov = { on: state.ov.on === true, secs: clamp(Math.round(Number(state.ov.secs)) || 20, 8, 60) }; if (typeof state.muUrl !== 'string') state.muUrl = null; state.gold = { on: !(state.gold && state.gold.on === false) };
    const save = () => { if (!stateFile) return; try { fs.mkdirSync(path.dirname(stateFile), { recursive: true }); const t = stateFile + '.tmp'; fs.writeFileSync(t, JSON.stringify(state)); fs.renameSync(t, stateFile); } catch (e) { /* bellekte kalir */ } };

    /* --- ag: yalniz Data Dragon (sabit sunucu) --- */
    const httpGet = deps.get || ((host, p, maxBody) => new Promise((resolve, reject) => {
      const req = https.get({ host, path: p, headers: { 'User-Agent': 'StatScan-Kovan', Accept: 'application/json, text/html;q=0.9' }, timeout: LIM.ms }, (res) => {
        if (res.statusCode !== 200) { res.resume(); return reject(new Error('HTTP ' + res.statusCode)); } const parts = []; let n = 0;
        res.on('data', (d) => { n += d.length; if (n > (maxBody || LIM.body)) { req.destroy(new Error('yanıt çok büyük')); return; } parts.push(d); }); res.on('end', () => resolve(Buffer.concat(parts).toString('utf8'))); res.on('error', reject);
      }); req.on('timeout', () => req.destroy(new Error('zaman aşımı'))); req.on('error', reject);
    }));
    const httpBin = deps.getBin || ((host, p, maxBody) => new Promise((resolve, reject) => {
      const req = https.get({ host, path: p, headers: { 'User-Agent': 'StatScan-Kovan' }, timeout: LIM.ms }, (res) => {
        if (res.statusCode !== 200) { res.resume(); return reject(new Error('HTTP ' + res.statusCode)); } const parts = []; let n = 0;
        res.on('data', (d) => { n += d.length; if (n > (maxBody || LIM.icon)) { req.destroy(new Error('yanıt çok büyük')); return; } parts.push(d); }); res.on('end', () => resolve(Buffer.concat(parts))); res.on('error', reject);
      }); req.on('timeout', () => req.destroy(new Error('zaman aşımı'))); req.on('error', reject);
    }));
    let iconActive = 0; const iconWait = []; const iconMem = new Map();
    const iconSlot = (fn) => new Promise((res, rej) => { const go = () => { iconActive++; Promise.resolve().then(fn).then(res, rej).finally(() => { iconActive--; const nx = iconWait.shift(); if (nx) nx(); }); }; if (iconActive < 6) go(); else iconWait.push(go); });
    let roster = null; let rosterMeta = null; const tipsCache = new Map(); let itemData = null;
    const cacheRead = (name) => { if (!cacheDir) return null; try { return JSON.parse(fs.readFileSync(path.join(cacheDir, name), 'utf8')); } catch (e) { return null; } };
    const cacheWrite = (name, obj) => { if (!cacheDir) return; try { fs.mkdirSync(cacheDir, { recursive: true }); fs.writeFileSync(path.join(cacheDir, name), JSON.stringify(obj)); } catch (e) { /* onbellek zorunlu degil */ } };
    const cacheNewest = (prefix) => { if (!cacheDir) return null; try { const f = fs.readdirSync(cacheDir).filter((x) => x.startsWith(prefix) && x.endsWith('.json')).sort().pop(); return f ? { name: f, json: cacheRead(f) } : null; } catch (e) { return null; } };
    /* hat verisi: haftada bir indirilir (yalniz sabit sunucu), onbellekte kucuk ozet olarak saklanir; olmazsa eski onbellek, o da yoksa etiket tahmini */
    async function loadRoles() {
      let c = cacheRead('roles.json'); const fresh = c && c.map && Number(c.t) > 0 && now() - Number(c.t) < ROLE_TTL;
      if (!fresh) { try { const m = parseRoles(JSON.parse(await httpGet(ROLE_HOST, ROLE_PATH, ROLE_MAX))); if (m) { c = { t: now(), map: m }; cacheWrite('roles.json', c); } } catch (e) { /* eski onbellek ya da etiket tahmini */ } }
      return c && c.map && typeof c.map === 'object' ? c.map : null;
    }
    async function loadRoster(force) {
      if (roster && !force) return { ok: true, meta: rosterMeta };
      let ver = null; let list = null; let loc = null; let offline = false; let why = '';
      try { const v = JSON.parse(await httpGet(DD_HOST, '/api/versions.json', 200000)); ver = Array.isArray(v) && /^\d+\.\d+(\.\d+)?$/.test(String(v[0])) ? String(v[0]) : null; if (!ver) throw new Error('sürüm okunamadı'); } catch (e) { why = String(e && e.message || e); }
      if (ver) { for (const l of LOCALES) { const nm = 'champions-' + ver + '-' + l + '.json'; let j = cacheRead(nm); if (!j) { try { j = JSON.parse(await httpGet(DD_HOST, '/cdn/' + ver + '/data/' + l + '/champion.json', LIM.body)); cacheWrite(nm, j); } catch (e) { why = String(e && e.message || e); j = null; } } const L = j ? parseChampions(j) : []; if (L.length) { list = L; loc = l; break; } } }
      if (!list) { for (const l of LOCALES) { const c = cacheNewest('champions-'); if (c && c.json) { const L = parseChampions(c.json); if (L.length) { list = L; offline = true; const m = /^champions-(.+)-([a-z]{2}_[A-Z]{2})\.json$/.exec(c.name); ver = m ? m[1] : ver; loc = m ? m[2] : l; break; } } } }
      if (!list) return errE('Şampiyon verisi alınamadı' + (why ? ' (' + why + ')' : '') + '. İlk kullanımda internet gerekir; sonra önbellekten çalışır.', { offline: true });
      let rm = null; try { rm = await loadRoles(); } catch (e) { rm = null; } let withPos = 0; if (rm) for (const c of list) { const p = rm[c.key]; if (Array.isArray(p) && p.length) { c.pos = p.slice(); withPos++; } }
      roster = list; rosterMeta = { version: ver, locale: loc, count: list.length, offline, roles: withPos }; tipsCache.clear(); itemData = null; return { ok: true, meta: rosterMeta };
    }
    const byKeyMap = () => new Map(roster.map((c) => [c.key, c.id]));
    const needRoster = async () => { const r = await loadRoster(false); return r.error ? r : null; };
    const validRole = (r) => (ROLES.includes(r) ? r : null);
    const validChamp = (id) => (typeof id === 'string' && ID_RE.test(id) && roster && roster.find((c) => c.id === id) ? id : null);

    /* --- dis veri adresi (kullanicinin kendisi; yalniz https; sabit sablon) --- */
    function statsTemplateOk(u) { if (typeof u !== 'string' || u.length > LIM.urlLen) return null; let x; try { x = new URL(u.replace('{enemy}', 'E').replace('{role}', 'r')); } catch (e) { return null; } if (x.protocol !== 'https:' || x.username || x.password || !x.hostname.includes('.')) return null; if (/^(localhost|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|\[)/i.test(x.hostname)) return null; return x; }
    /* eslesme detayi (rank kovalari): kullanicinin muUrl sablonu ({me} {enemy} {role}); yalniz GET, >=0.5 sn aralik, 6 sa onbellek, yalniz sayi */
    const muCache = new Map(); let muLast = 0; const muDelay = deps.muDelay === undefined ? 500 : deps.muDelay;
    const muTemplateOk = (u) => (typeof u === 'string' && u.includes('{me}') && u.includes('{enemy}') ? statsTemplateOk(u.split('{me}').join('M')) : null);
    async function muFetch(me, enemy, role) {
      const x = state.muUrl ? muTemplateOk(state.muUrl) : null; if (!x) return { state: 'off' };
      const key = me + '|' + enemy + '|' + role; const hit = muCache.get(key); const t0 = Date.now(); if (hit && t0 - hit.t < hit.ttl) return hit.v;
      const wait = muLast + muDelay - t0; if (wait > 0) await new Promise((r) => setTimeout(r, wait)); muLast = Date.now(); let v;
      try { const u = new URL(state.muUrl.split('{me}').join(encodeURIComponent(me)).split('{enemy}').join(encodeURIComponent(enemy)).split('{role}').join(encodeURIComponent(role))); const j = JSON.parse(await httpGet(u.hostname, u.pathname + u.search, LIM.statsBody)); const p = parseMu(j); v = p ? { state: 'ok', parsed: p } : { state: 'none' }; }
      catch (e) { v = { state: /HTTP 404/.test(String(e && e.message || e)) ? 'none' : 'net' }; }
      muCache.set(key, { t: Date.now(), v, ttl: v.state === 'ok' ? 6 * 3600e3 : 10 * 60e3 }); return v;
    }
    async function muItemNames(ids) { const out = {}; const D = await loadItems(); if (D.error) return out; const by = new Map(D.list.map((q) => [q.id, q.name])); for (const id of ids) { const nm = (D.names && D.names[id]) || by.get(id); if (nm) out[id] = nm; } return out; }
    /* counterpick.lol: yalnız kullanıcı anahtarı açıkken; önbellek 6 sa, istekler arası >=1 sn, honest User-Agent; yalnız GET */
    const cpCache = new Map(); let cpLast = 0; const cpDelay = deps.cpDelay === undefined ? 1000 : deps.cpDelay;
    const cpErrs = new Map(); let runeNameIdx = null;
    const cpGet = async (p) => {
      if (!state.cp || !/^\/(matchup|champion)\/[a-z0-9\/-]+\/$/.test(p)) return null; const hit = cpCache.get(p); const nowT = Date.now(); if (hit && nowT - hit.t < hit.ttl) return hit.v;
      const wait = cpLast + cpDelay - nowT; if (wait > 0) await new Promise((r) => setTimeout(r, wait)); cpLast = Date.now(); let v = null; try { v = await httpGet(CP_HOST, p, 2 * 1024 * 1024); cpErrs.delete(p); } catch (e) { v = null; cpErrs.set(p, /HTTP 404/.test(String(e && e.message || e)) ? '404' : 'net'); }
      cpCache.set(p, { t: Date.now(), v, ttl: v ? 6 * 3600e3 : 10 * 60e3 }); return v;
    };
    /* rün adı → kimlik (en_US runesReforged; counterpick sayfası rünleri ad olarak yazıyor) */
    async function runeNames() {
      if (runeNameIdx) return runeNameIdx; if (!rosterMeta) return null; const ver = rosterMeta.version; const nm = 'runes-' + ver + '-en_US.json'; let j = cacheRead(nm);
      if (!j) { try { j = JSON.parse(await httpGet(DD_HOST, '/cdn/' + ver + '/data/en_US/runesReforged.json', LIM.body)); cacheWrite(nm, j); } catch (e) { return null; } }
      runeNameIdx = buildRuneNames(j); return runeNameIdx;
    }
    const cpSlugs = (id) => { const c = roster && roster.find((x) => x.id === id); if (!c) return []; return Array.from(new Set([cpKebab(c.name), cpKebab(c.id)].filter(Boolean))); };
    /* eşleşme sayfası: önce ben-vs-rakip; site her çifti tutmadığı ve çoğu çifti tek yönde listelediği için yoksa rakip-vs-ben (oran 100 − x, rün YOK: rünler öbür şampiyonun) */
    async function cpMatchup(me, enemy, diag) {
      diag = diag || {}; const names = await runeNames();
      const tryOrder = async (A, B) => { for (const a of cpSlugs(A)) for (const b of cpSlugs(B)) { const pth = '/matchup/' + a + '-vs-' + b + '/'; const h = await cpGet(pth); if (!h) { if (cpErrs.get(pth) === 'net') diag.net = true; continue; } const r = parseCpMatchup(h, names); if (r) return r; diag.parse = true; } return null; };
      const d = await tryOrder(me, enemy); if (d) return Object.assign({ dir: 'direct' }, d);
      const r = await tryOrder(enemy, me); if (r) return { dir: 'rev', wr: Math.round((100 - r.wr) * 10) / 10, games: r.games, runes: null };
      return null;
    }
    async function cpCounters(enemy) {
      for (const a of cpSlugs(enemy)) { const h = await cpGet('/champion/' + a + '/counters/'); const rows = h ? parseCpCounters(h, a) : []; if (!rows.length) continue; const keys = new Map(); for (const c of roster) { keys.set(cpKey(c.id), c.id); keys.set(cpKey(c.name), c.id); }
        const m = new Map(); for (const r of rows) { const id = keys.get(cpKey(r.slug)); if (id && id !== enemy) m.set(id, { wr: r.wr, games: 0, approx: true, runes: null }); } if (m.size) return m; }
      return null;
    }
    async function fetchExt(enemy, role, me, diag) {
      diag = diag || {}; let map = null;
      if (state.statsUrl && statsTemplateOk(state.statsUrl)) { diag.url = 'none'; const u = new URL(state.statsUrl.replace('{enemy}', encodeURIComponent(enemy)).replace('{role}', encodeURIComponent(role))); try { map = parseStats(JSON.parse(await httpGet(u.hostname, u.pathname + u.search, LIM.statsBody))); diag.url = map && map.size ? 'ok' : 'none'; } catch (e) { map = null; diag.url = 'net'; } }
      if (!state.cp) diag.cp = 'off';
      else { diag.cp = 'none'; try { const cm = await cpCounters(enemy); if (cm) { map = map || new Map(); for (const [k, v] of cm) if (!map.has(k)) map.set(k, v); }
        if (me) { const d = {}; const mm = await cpMatchup(me, enemy, d); if (mm) { map = map || new Map(); const prev = map.get(me); if (!prev || !prev.games) map.set(me, { wr: mm.wr, games: mm.games, runes: mm.runes, src: 'cp', approx: mm.dir === 'rev' }); diag.cp = mm.dir === 'rev' ? 'rev' : mm.runes ? 'ok' : 'norunes'; } else diag.cp = d.net ? 'net' : d.parse ? 'norunes' : 'none'; } } catch (e) { diag.cp = 'net'; /* ağ/ayrıştırma: sessizce tahmine düş */ } }
      return map;
    }

    /* --- baska oyuncu profili: yalniz bellekte (diske YAZILMAZ), 10 dk, en cok 6 kayit --- */
    const playerCache = new Map(); const PLAYER_TTL = 10 * 60e3; let lastLookup = 0;
    const playerKeep = (puuid, ent) => { playerCache.set(puuid, ent); if (playerCache.size > 6) playerCache.delete(playerCache.keys().next().value); };
    const playerView = (ent, req) => {
      req = req || {}; const q = FILTERS.includes(req.queue) ? req.queue : 'all'; const role = ROLES.includes(req.role) ? req.role : null; const off = clamp(Math.round(Number(req.offset)) || 0, 0, 500); const lim = clamp(Math.round(Number(req.limit)) || 20, 1, 50);
      const all = ent.matches.slice().sort((a, b) => b.t - a.t); const byQ = all.filter(mkFilter(q)); const f = role ? byQ.filter((m) => m.role === role) : byQ;
      return { queue: q, role, total: byQ.length, overview: overview(f, now()), champs: champStats(f).slice(0, 100), roles: roleStats(all), partners: partnerStats(all), rows: byQ.slice(off, off + lim), aram: wlOf(all.filter(mkFilter('aram'))), normal: wlOf(all.filter(mkFilter('normal'))), streak: overview(all, now()).streak };
    };
    /* --- LCU --- */
    const POS_LCU = { top: 'top', jungle: 'jungle', mid: 'middle', bot: 'bottom', support: 'utility' };
    /* İstemcinin kendi önerilen rün sayfası (şampiyon + hat; eşleşmeye özel DEĞİL). Uç nokta belgesiz: şekil bellekten, savunmacı okunur; doğrulanamazsa yok sayılır. */
    async function lcuRecRunes(me, role, R) {
      const c = roster && roster.find((x) => x.id === me); if (!c || !/^\d{1,4}$/.test(c.key) || !POS_LCU[role]) return { state: 'none' }; const info = await lcuFind(); if (!info) return { state: 'noclient' };
      let j; try { j = await lcuRead(info, '/lol-perks/v1/recommended-pages/champion/' + c.key + '/position/' + POS_LCU[role] + '/map/11'); } catch (e) { return { state: 'net' }; }
      const pages = Array.isArray(j) ? j : j && Array.isArray(j.pages) ? j.pages : j && typeof j === 'object' ? [j] : [];
      for (const pg of pages.slice(0, 8)) { const ids = pg && Array.isArray(pg.selectedPerkIds) ? pg.selectedPerkIds.slice(0, 6).map(Number) : []; const v = validateRunePage(ids, R.idx); if (v) return { state: 'ok', runes: { perks: ids, primary: v.primary, secondary: v.sub } }; }
      return { state: 'none' };
    }
    const lcuFind = deps.lcu && deps.lcu.find ? deps.lcu.find : async () => { if ((deps.platform || process.platform) !== 'win32') return null; try { return parseLcuCmd(await run('powershell', ['-NoProfile', '-NonInteractive', '-Command', "(Get-CimInstance Win32_Process -Filter \"name='LeagueClientUx.exe'\" | Select-Object -First 1).CommandLine"], 10000)); } catch (e) { return null; } };
    const lcuGet = deps.lcu && deps.lcu.get ? deps.lcu.get : (info, p, ms) => new Promise((resolve, reject) => {
      /* yalniz 127.0.0.1, yalniz GET; Riot'un yerel kendinden imzali sertifikasi nedeniyle dogrulama kapali (disari cikmaz) */
      const req = https.request({ host: '127.0.0.1', port: info.port, path: p, method: 'GET', rejectUnauthorized: false, timeout: Number(ms) > 0 ? Math.min(Number(ms), 30000) : 4000, headers: { Authorization: 'Basic ' + Buffer.from('riot:' + info.token).toString('base64'), Accept: 'application/json' } }, (res) => {
        if (res.statusCode === 404) { res.resume(); return resolve(null); } if (res.statusCode !== 200) { res.resume(); return reject(new Error('HTTP ' + res.statusCode)); } const parts = []; let n = 0; res.on('data', (d) => { n += d.length; if (n > 2 * 1024 * 1024) { req.destroy(new Error('büyük')); return; } parts.push(d); });
        res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(parts).toString('utf8'))); } catch (e) { reject(e); } });
      }); req.on('timeout', () => req.destroy(new Error('zaman aşımı'))); req.on('error', reject); req.end();
    });

    /* Canli mac: yalniz 127.0.0.1:2999, yalniz GET /liveclientdata/allgamedata */
    const liveGet = deps.live && deps.live.get ? deps.live.get : (p) => new Promise((resolve, reject) => {
      const req = https.request({ host: '127.0.0.1', port: 2999, path: p, method: 'GET', rejectUnauthorized: false, timeout: 2500, headers: { Accept: 'application/json' } }, (res) => {
        if (res.statusCode !== 200) { res.resume(); return resolve(null); } const parts = []; let n = 0; res.on('data', (d) => { n += d.length; if (n > 4 * 1024 * 1024) { req.destroy(new Error('büyük')); return; } parts.push(d); });
        res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(parts).toString('utf8'))); } catch (e) { reject(e); } });
      }); req.on('timeout', () => req.destroy(new Error('zaman aşımı'))); req.on('error', reject); req.end();
    });
    const liveRead = async (p) => { if (!LIVE_OK.test(p)) throw new Error('izin verilmeyen uç nokta'); return liveGet(p); };
    let runeMap = null; let runePending = null; let spellMap = null; let spellPending = null;
    const safeRuneIcon = (v) => typeof v === 'string' && /^perk-images\/[A-Za-z0-9_/-]+\.png$/.test(v) && v.length < 240 ? v : null;
    const safeSpellIcon = (v) => typeof v === 'string' && /^[A-Za-z0-9_-]+\.png$/.test(v) && v.length < 100 ? v : null;
    async function loadSpells() {
      if (spellMap) return spellMap; if (spellPending) return spellPending;
      spellPending = (async () => {
        const nm = 'summoner-' + rosterMeta.version + '-' + rosterMeta.locale + '.json'; let j = cacheRead(nm);
        if (!j) { j = JSON.parse(await httpGet(DD_HOST, '/cdn/' + rosterMeta.version + '/data/' + rosterMeta.locale + '/summoner.json', LIM.body)); cacheWrite(nm, j); }
        const out = {}; for (const r of Object.values((j && j.data) || {})) { const id = Number(r && r.key); const image = safeSpellIcon(r && r.image && r.image.full); if (Number.isInteger(id) && id > 0 && id <= 999999 && image) out[id] = { name: String(r.name || '').slice(0, 60), image }; }
        spellMap = out; return out;
      })().finally(() => { spellPending = null; }); return spellPending;
    }
    function loadRunes() {
      if (runeMap) return Promise.resolve(runeMap); if (runePending) return runePending;
      runePending = readRunes().finally(() => { runePending = null; }); return runePending;
    }
    async function readRunes() {
      if (runeMap) return runeMap; const nm = 'runes-' + rosterMeta.version + '-' + rosterMeta.locale + '.json'; let j = cacheRead(nm);
      if (!j) { try { j = JSON.parse(await httpGet(DD_HOST, '/cdn/' + rosterMeta.version + '/data/' + rosterMeta.locale + '/runesReforged.json', LIM.body)); cacheWrite(nm, j); } catch (e) { return errE('Rün verisi alınamadı (' + String(e && e.message || e) + ').'); } }
      const m = { perks: {}, trees: {}, idx: {}, icons: {} }; for (const tr of Array.isArray(j) ? j : []) { if (!tr || !Number.isInteger(tr.id)) continue; m.trees[tr.id] = String(tr.name || '').slice(0, 30); if (safeRuneIcon(tr.icon)) m.icons[tr.id] = tr.icon; (tr.slots || []).forEach((sl, si) => { for (const r of sl.runes || []) if (r && Number.isInteger(r.id)) { m.perks[r.id] = String(r.name || '').slice(0, 40); m.idx[r.id] = { t: tr.id, s: si }; if (safeRuneIcon(r.icon)) m.icons[r.id] = r.icon; } }); }
      runeMap = m; return m;
    }
    /* esya verisi: mantik icin en_US item.json (aciklama metni 'Grievous Wounds' vb. icin), gorunen adlar icin yerel dil; yalniz kucuk ozet onbellege yazilir */
    async function loadItems() {
      if (itemData) return itemData; const ver = rosterMeta.version; const nm = 'items-' + ver + '.json'; let list = null; const c0 = cacheRead(nm); if (c0 && c0.v === 1 && Array.isArray(c0.list) && c0.list.length) list = c0.list;
      if (!list) { let why = ''; try { list = parseItems(JSON.parse(await httpGet(DD_HOST, '/cdn/' + ver + '/data/en_US/item.json', LIM.body))); if (list.length) cacheWrite(nm, { v: 1, list }); } catch (e) { why = String(e && e.message || e); list = null; }
        if (!list || !list.length) { const old = cacheNewest('items-'); list = old && old.json && Array.isArray(old.json.list) && old.json.list.length ? old.json.list : null; if (!list) return errE('Eşya verisi alınamadı' + (why ? ' (' + why + ')' : '') + '. İlk kullanımda internet gerekir; sonra önbellekten çalışır.'); } }
      let names = {}; const loc = rosterMeta.locale; if (loc && loc !== 'en_US') { const nn = 'itemnames-' + ver + '-' + loc + '.json'; let j = cacheRead(nn);
        if (!j) { try { const raw = JSON.parse(await httpGet(DD_HOST, '/cdn/' + ver + '/data/' + loc + '/item.json', LIM.body)); j = {}; for (const id of Object.keys((raw && raw.data) || {})) if (/^\d{3,6}$/.test(id) && raw.data[id] && raw.data[id].name) j[id] = String(raw.data[id].name).slice(0, 40); cacheWrite(nn, j); } catch (e) { j = null; } } names = j && typeof j === 'object' ? j : {}; }
      itemData = { list, names, version: ver }; return itemData;
    }
    /* LCU: yalniz beyaz listedeki GET uc noktalari (yazma/degistirme yok) */
    const lcuRead = async (info, p, ms) => { if (!LCU_OK.some((re) => re.test(p))) throw new Error('izin verilmeyen uç nokta'); return lcuGet(info, p, ms); };
    /* ---- Riot API (istemci KAPALIYKEN, kullanicinin KENDI kisisel anahtariyla; yalniz GET, anahtar yalniz bu bilgisayarda lolriot.json (0600), arayuze/loga ASLA donmez) ---- */
    const RIOT_REG = { tr1: 'europe', euw1: 'europe', eun1: 'europe', ru: 'europe', me1: 'europe', na1: 'americas', br1: 'americas', la1: 'americas', la2: 'americas', oc1: 'sea', kr: 'asia', jp1: 'asia', sg2: 'sea', ph2: 'sea', th2: 'sea', tw2: 'sea', vn2: 'sea' };
    const RIOT_KEY_RE = /^RGAPI-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/; const RIOT_ID_RE = /^[^#\/\\?%\s][^#\/\\?%]{1,30}#[A-Za-z0-9]{2,6}$/;
    const riotFile = dataDir ? path.join(dataDir, 'lolriot.json') : null; let riot = { key: '', id: '', region: 'tr1' }; let riotAt = 0; let riotBlock = 0; const RIOT_EVERY = 120000; const RIOT_MATCHES = 10;
    try { if (riotFile && fs.existsSync(riotFile)) { const j = JSON.parse(fs.readFileSync(riotFile, 'utf8')); if (j && typeof j === 'object') riot = { key: RIOT_KEY_RE.test(String(j.key || '')) ? String(j.key) : '', id: RIOT_ID_RE.test(String(j.id || '')) ? String(j.id) : '', region: RIOT_REG[j.region] ? j.region : 'tr1' }; } } catch (e) { /* ayar okunamadi: bos */ }
    const riotSave = () => { if (!riotFile) return; try { fs.mkdirSync(path.dirname(riotFile), { recursive: true }); const t = riotFile + '.tmp'; fs.writeFileSync(t, JSON.stringify(riot), { mode: 0o600 }); fs.renameSync(t, riotFile); } catch (e) { /* bellekte kalir */ } };
    const riotReady = () => !!(riot.key && riot.id);
    const riotGet = deps.riot && deps.riot.get ? deps.riot.get : (host, p, key) => new Promise((resolve, reject) => {
      const req = https.get({ host, path: p, headers: { 'X-Riot-Token': key, Accept: 'application/json', 'User-Agent': 'Kovan' }, timeout: 10000 }, (res) => {
        const parts = []; let n = 0; res.on('data', (d) => { n += d.length; if (n > 2e6) { req.destroy(new Error('yanit cok buyuk')); return; } parts.push(d); });
        res.on('end', () => { let j = null; try { j = JSON.parse(Buffer.concat(parts).toString('utf8')); } catch (e) { j = null; } resolve({ status: res.statusCode, body: j, retry: Number(res.headers['retry-after']) || 0 }); });
      }); req.on('timeout', () => req.destroy(new Error('zaman asimi'))); req.on('error', reject);
    });
    const riotCall = async (host, p) => { /* host listesi sabit: yalniz api.riotgames.com altlari */
      if (!/^[a-z0-9]+\.api\.riotgames\.com$/.test(host)) throw new Error('izin verilmeyen adres'); const r = await riotGet(host, p, riot.key);
      if (r.status === 401 || r.status === 403) throw Object.assign(new Error('Riot API anahtarı geçersiz ya da süresi dolmuş.'), { fatal: true });
      if (r.status === 429) { riotBlock = Date.now() + Math.min(Math.max(r.retry, 5), 120) * 1000; throw Object.assign(new Error('Riot API istek sınırına takıldı; birazdan tekrar denenecek.'), { fatal: true }); }
      if (r.status === 404) return null; if (r.status !== 200) throw new Error('Riot API ' + r.status); return r.body;
    };
    /* match-v5 -> LCU biciminde oyun nesnesi (normMatch ayni yolu kullanir; tek hesap kodu) */
    function riotGame(info, myPuuid) {
      if (!info || typeof info !== 'object' || !Array.isArray(info.participants)) return null; const POS = { TOP: { lane: 'TOP' }, JUNGLE: { lane: 'JUNGLE' }, MIDDLE: { lane: 'MIDDLE' }, BOTTOM: { lane: 'BOTTOM', role: 'CARRY' }, UTILITY: { lane: 'BOTTOM', role: 'SUPPORT' } };
      const participants = []; const participantIdentities = [];
      info.participants.slice(0, 10).forEach((p, i) => { const id = i + 1; const st = (p.perks && Array.isArray(p.perks.styles)) ? p.perks.styles : []; const sel = (k) => (st[k] && Array.isArray(st[k].selections) ? st[k].selections.map((x) => x && x.perk) : []);
        const perks = sel(0).slice(0, 4).concat(sel(1).slice(0, 2)); const stats = { kills: p.kills, deaths: p.deaths, assists: p.assists, totalMinionsKilled: p.totalMinionsKilled, neutralMinionsKilled: p.neutralMinionsKilled, goldEarned: p.goldEarned, totalDamageDealtToChampions: p.totalDamageDealtToChampions, visionScore: p.visionScore, champLevel: p.champLevel, win: p.win === true, gameEndedInEarlySurrender: p.gameEndedInEarlySurrender === true, perkPrimaryStyle: st[0] && st[0].style, perkSubStyle: st[1] && st[1].style };
        for (let k = 0; k < 7; k++) stats['item' + k] = p['item' + k]; for (let k = 0; k < 6; k++) stats['perk' + k] = perks[k];
        participants.push({ participantId: id, teamId: p.teamId, championId: p.championId, spell1Id: p.summoner1Id, spell2Id: p.summoner2Id, stats, timeline: POS[p.teamPosition] || null }); participantIdentities.push({ participantId: id, player: { puuid: p.puuid, gameName: p.riotIdGameName, tagLine: p.riotIdTagline, summonerName: p.summonerName } }); });
      const idn = String(info.gameId || ''); return { gameId: Number(idn), gameCreation: info.gameCreation, gameDuration: info.gameDuration, queueId: info.queueId, participants, participantIdentities };
    }
    async function riotSync(force) {
      if (!riotReady()) return { state: 'noclient' }; const t = now();
      if (Date.now() < riotBlock) return { state: 'ok', source: 'riot', throttled: true, added: 0, snaps: 0, notes: ['Riot API sınırı: biraz bekleniyor.'], me: state.me, total: Object.keys(state.matches).length };
      if (!force && riotAt && Date.now() - riotAt < RIOT_EVERY) return { state: 'ok', source: 'riot', throttled: true, added: 0, snaps: 0, notes: [], me: state.me, total: Object.keys(state.matches).length };
      riotAt = Date.now(); const notes = []; const msg = (e) => String(e && e.message || e).slice(0, 120); const reg = RIOT_REG[riot.region]; const plat = riot.region + '.api.riotgames.com'; const regional = reg + '.api.riotgames.com'; const co = champOf();
      try {
        const [gn, tg] = riot.id.split('#'); const acc = await riotCall(regional, '/riot/account/v1/accounts/by-riot-id/' + encodeURIComponent(gn) + '/' + encodeURIComponent(tg));
        if (!acc || !acc.puuid) return { state: 'ok', source: 'riot', added: 0, snaps: 0, notes: ['Riot Kimliği bulunamadı: ' + riot.id], me: state.me, total: Object.keys(state.matches).length };
        const puuid = String(acc.puuid).slice(0, 90); const prev = state.me && state.me.puuid === puuid ? state.me : {};
        state.me = { puuid, name: String(acc.gameName || gn).slice(0, 40), tag: String(acc.tagLine || tg).slice(0, 10), level: prev.level || 0, icon: prev.icon || 0 };
        let snaps = 0; try { const ent = await riotCall(plat, '/lol/league/v4/entries/by-puuid/' + encodeURIComponent(puuid)); const rk = parseRanked({ queues: (Array.isArray(ent) ? ent : []).map((e) => Object.assign({}, e, { division: e && e.rank })) }); for (const q of ['solo', 'flex']) if (addSnap(state.lp, rk[q], t, LIM.snaps)) snaps++; state.rank = { solo: rk.solo, flex: rk.flex, t }; } catch (e) { if (e.fatal) throw e; notes.push('derece: ' + msg(e)); }
        let added = 0; let updated = 0; try { const ids = await riotCall(regional, '/lol/match/v5/matches/by-puuid/' + encodeURIComponent(puuid) + '/ids?start=0&count=' + RIOT_MATCHES);
          for (const mid of (Array.isArray(ids) ? ids : []).slice(0, RIOT_MATCHES)) { const num = String(mid).split('_')[1]; const old = state.matches[num]; const fullStats = (ps) => Array.isArray(ps) && ps.length >= 2 && ps.every((p) => p && ['k', 'd', 'a', 'cs', 'gold', 'dmg', 'vision'].every((k) => Number.isFinite(p[k]))); if (!/^\d{5,14}$/.test(num) || (old && old.spells !== undefined && fullStats(old.players))) continue; const m = await riotCall(regional, '/lol/match/v5/matches/' + encodeURIComponent(mid)); const g = m && riotGame(Object.assign({}, m.info, { gameId: Number(num) }), puuid); const nm = g && normMatch(g, puuid, co); if (nm) { if (!old) added++; else updated++; state.matches[nm.id] = nm; } }
          const keys = Object.keys(state.matches); if (keys.length > LIM.matches) { keys.sort((a, b) => state.matches[a].t - state.matches[b].t); for (const k of keys.slice(0, keys.length - LIM.matches)) delete state.matches[k]; }
        } catch (e) { if (e.fatal) throw e; notes.push('maçlar: ' + msg(e)); }
        save(); return { state: 'ok', source: 'riot', me: state.me, added, updated, snaps, notes, total: Object.keys(state.matches).length };
      } catch (e) { return { state: 'ok', source: 'riot', added: 0, snaps: 0, notes: [msg(e)], me: state.me, total: Object.keys(state.matches).length, riotError: msg(e) }; }
    }
    const lcuSend = deps.lcu && deps.lcu.write ? deps.lcu.write : (info, method, p, body) => new Promise((resolve, reject) => {
      const data = body === undefined ? null : Buffer.from(JSON.stringify(body)); const headers = { Authorization: 'Basic ' + Buffer.from('riot:' + info.token).toString('base64'), Accept: 'application/json' }; if (data) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = data.length; }
      const req = https.request({ host: '127.0.0.1', port: info.port, path: p, method, rejectUnauthorized: false, timeout: 5000, headers }, (res) => { const parts = []; res.on('data', (d) => { if (parts.length < 64) parts.push(d); }); res.on('end', () => { if (res.statusCode >= 300) return reject(new Error('HTTP ' + res.statusCode)); try { resolve(parts.length ? JSON.parse(Buffer.concat(parts).toString('utf8')) : null); } catch (e) { resolve(null); } }); });
      req.on('timeout', () => req.destroy(new Error('zaman aşımı'))); req.on('error', reject); if (data) req.write(data); req.end();
    });
    const lcuWrite = async (info, method, p, body) => { if (!LCU_WRITE_OK.some(([m, re]) => m === method && re.test(p))) throw new Error('izin verilmeyen yazma'); return lcuSend(info, method, p, body); };
    const champOf = () => { const m = byKeyMap(); return (k) => m.get(String(k)) || null; };
    const autoHist = () => Object.values(state.matches).filter((m) => !m.remake && m.opp && m.role && m.champ).map((m) => ({ role: m.role, me: m.champ, enemy: m.opp, win: !!m.win }));
    const handlers = {
      'lol:status': async () => { const r = await loadRoster(false); return { roles: ROLES, ready: !r.error, meta: r.error ? null : r.meta, error: r.error ? r.message : null, poolCounts: Object.fromEntries(ROLES.map((x) => [x, (state.pool[x] || []).length])), games: state.hist.length, statsUrl: !!state.statsUrl, windows: (deps.platform || process.platform) === 'win32' }; },
      'lol:champs': async (_e, force) => { const r = await loadRoster(force === true); if (r.error) return r; return { meta: r.meta, champs: roster.map((c) => ({ id: c.id, name: c.name, tags: c.tags, difficulty: c.difficulty, pos: c.pos || null })) }; },
      'lol:pool': async () => ({ pool: Object.fromEntries(ROLES.map((x) => [x, (state.pool[x] || []).slice()])) }),
      'lol:pool:set': async (_e, role, ids) => {
        try { const bad = await needRoster(); if (bad) return bad; const r = validRole(role); if (!r) return errE('Rol geçersiz.'); if (!Array.isArray(ids) || ids.length > LIM.pool) return errE('Havuz en fazla ' + LIM.pool + ' şampiyon olabilir.'); const out = []; for (const x of ids) { const c = validChamp(x); if (c && !out.includes(c)) out.push(c); }
          state.pool[r] = out; save(); return { ok: true, role: r, pool: out };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:suggest': async (_e, req) => {
        try { const bad = await needRoster(); if (bad) return bad; req = req || {}; const role = validRole(req.role); if (!role) return errE('Rol geçersiz.'); const enemy = validChamp(req.enemy); if (!enemy) return errE('Rakip şampiyon bulunamadı.');
          const pool = state.pool[role] || []; if (req.poolOnly === true && !pool.length) return { needPool: true, role };
          const ext = await fetchExt(enemy, role); const out = rank(roster, enemy, role, { hist: state.hist.concat(autoHist()), pool, poolOnly: req.poolOnly === true, anyRole: req.anyRole === true, ext, limit: req.limit });
          if (out.error) return errE('Rakip şampiyon bulunamadı.'); out.extUsed = !!ext; out.statsConfigured = !!(state.statsUrl || state.cp); out.cp = !!state.cp; out.meta = rosterMeta; return out;
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:tips': async (_e, enemy) => {
        try { const bad = await needRoster(); if (bad) return bad; const id = validChamp(enemy); if (!id) return errE('Şampiyon bulunamadı.'); if (tipsCache.has(id)) return tipsCache.get(id); const nm = 'tips-' + rosterMeta.version + '-' + rosterMeta.locale + '-' + id + '.json'; let j = cacheRead(nm);
          if (!j) { try { j = JSON.parse(await httpGet(DD_HOST, '/cdn/' + rosterMeta.version + '/data/' + rosterMeta.locale + '/champion/' + id + '.json', LIM.body)); cacheWrite(nm, j); } catch (e) { return errE('İpuçları alınamadı (' + String(e && e.message || e) + ').'); } }
          /* NOT: Data Dragon'daki 'enemytips' Riot tarafindan guncellenmiyor (ornegin eski Aatrox R dirilisi) → KULLANILMAZ. Yerine ayni yamanin guncel yetenek metinleri gosterilir. */
          const d = j && j.data && j.data[id]; const clean = (s, n) => String(s == null ? '' : s).replace(/<br\s*\/?>/gi, ' ').replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim().slice(0, n);
          const abilities = []; if (d && d.passive) abilities.push({ key: 'P', name: clean(d.passive.name, 60), cd: '', desc: clean(d.passive.description, 320) }); if (d && Array.isArray(d.spells)) d.spells.slice(0, 4).forEach((s, i) => abilities.push({ key: 'QWER'[i], name: clean(s.name, 60), cd: clean(s.cooldownBurn, 40), desc: clean(s.description, 320) }));
          const r = { id, name: d ? String(d.name || id) : id, tips: [], abilities, patch: rosterMeta.version, source: 'Riot Data Dragon (yama ' + rosterMeta.version + ')' }; tipsCache.set(id, r); return r;
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:log': async (_e, req) => {
        try { const bad = await needRoster(); if (bad) return bad; req = req || {}; const role = validRole(req.role); const me = validChamp(req.me); const enemy = validChamp(req.enemy); if (!role || !me || !enemy || typeof req.win !== 'boolean') return errE('Kayıt eksik ya da geçersiz.');
          state.hist.push({ t: now(), role, me, enemy, win: req.win }); if (state.hist.length > LIM.hist) state.hist.splice(0, state.hist.length - LIM.hist); save(); return { ok: true, total: state.hist.length, pair: personal(state.hist, me, enemy, role) };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:hist': async () => { const rec = state.hist.slice(-LIM.recent).reverse(); const by = new Map(); for (const h of state.hist) { const k = h.role + '|' + h.me; const v = by.get(k) || { role: h.role, me: h.me, games: 0, wins: 0 }; v.games++; if (h.win) v.wins++; by.set(k, v); } return { total: state.hist.length, recent: rec, byChamp: [...by.values()].sort((a, b) => b.games - a.games).slice(0, 20) }; },
      'lol:hist:undo': async () => { if (!state.hist.length) return errE('Silinecek kayıt yok.'); const x = state.hist.pop(); save(); return { ok: true, removed: x, total: state.hist.length }; },
      'lol:hist:clear': async () => {
        try { if (!state.hist.length) return { ok: true, total: 0 }; if (!deps.confirm) return errE('Onay penceresi yok; silinmedi.'); const okc = await deps.confirm({ title: 'Maç kayıtları silinsin mi?', message: state.hist.length + ' maç kaydı silinecek. Bu geri alınamaz.', ok: 'Sil', cancel: 'Vazgeç' }); if (!okc) return { canceled: true }; state.hist = []; save(); return { ok: true, total: 0 };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:cp:get': async () => ({ on: !!state.cp, host: CP_HOST }),
      'lol:cp:set': async (_e, on) => {
        try { if (on !== true) { state.cp = false; save(); return { ok: true, on: false }; } if (!deps.confirm) return errE('Onay penceresi yok; açılmadı.');
          const okc = await deps.confirm({ title: 'counterpick.lol kullanılsın mı?', message: 'Karşı seçim ve canlı maçta, şampiyon adlarıyla bu sunucudan eşleşme sayfaları çekilir (en fazla saniyede 1 istek, 6 saat önbellek):\n\n' + CP_HOST + '\n\nSite Riot ile ilgili değildir ve kullanım şartlarını senin kontrol etmen gerekir. Gelen sayfadan yalnızca oran, oyun sayısı ve rün kimlikleri (sayı) okunur. Veri yalnızca ana hattı kapsar ve doğruluğu garanti değildir.', ok: 'Aç', cancel: 'Vazgeç' }); if (!okc) return { canceled: true };
          state.cp = true; save(); return { ok: true, on: true };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:statsurl:get': async () => ({ configured: !!state.statsUrl, host: state.statsUrl && statsTemplateOk(state.statsUrl) ? statsTemplateOk(state.statsUrl).hostname : null }),
      'lol:statsurl:set': async (_e, url) => {
        try { if (url === null || url === '') { state.statsUrl = null; save(); return { ok: true, configured: false }; } const x = statsTemplateOk(url); if (!x || !String(url).includes('{enemy}')) return errE('Adres geçersiz: https olmalı, genel bir sunucuya gitmeli ve {enemy} (isteğe bağlı {role}) içermeli.');
          if (!deps.confirm) return errE('Onay penceresi yok; kaydedilmedi.'); const okc = await deps.confirm({ title: 'Dış veri adresi eklensin mi?', message: 'Karşı seçim hesaplanırken bu sunucuya şampiyon adı ve rol gönderilir:\n\n' + x.hostname + '\n\nYalnızca güvendiğin bir kaynağı ekle. Gelen veri yalnızca sayı olarak okunur.', ok: 'Ekle', cancel: 'Vazgeç' }); if (!okc) return { canceled: true };
          state.statsUrl = url; save(); return { ok: true, configured: true, host: x.hostname };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      /* ---- eslesme detayi: rank secimi + rank kovalarindan toplanan oran/esya (veri yoksa TAHMIN YAPILMAZ) ---- */
      'lol:mu:cfg': async () => ({ rank: state.murank, ranks: MU_RANKS, all: MU_ALL, configured: !!(state.muUrl && muTemplateOk(state.muUrl)), host: state.muUrl && muTemplateOk(state.muUrl) ? muTemplateOk(state.muUrl).hostname : null }),
      'lol:mu:rank': async (_e, r) => { if (muRankSet(r) === null) return errE('Rank geçersiz.'); state.murank = r; save(); return { ok: true, rank: r }; },
      'lol:mu:url:set': async (_e, url) => {
        try { if (url === null || url === '') { state.muUrl = null; muCache.clear(); save(); return { ok: true, configured: false }; } const x = muTemplateOk(url); if (!x) return errE('Adres geçersiz: https olmalı, genel bir sunucuya gitmeli ve {me} ile {enemy} (isteğe bağlı {role}) içermeli.');
          if (!deps.confirm) return errE('Onay penceresi yok; kaydedilmedi.'); const okc = await deps.confirm({ title: 'Eşleşme veri adresi eklensin mi?', message: 'Eşleşme verisi için bu sunucuya şampiyon adları ve rol gönderilir:\n\n' + x.hostname + '\n\nYalnızca güvendiğin bir kaynağı ekle. Gelen veri yalnızca sayı olarak okunur (en fazla yarım saniyede 1 istek, 6 saat önbellek).', ok: 'Ekle', cancel: 'Vazgeç' }); if (!okc) return { canceled: true };
          state.muUrl = url; muCache.clear(); save(); return { ok: true, configured: true, host: x.hostname };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:mu': async (_e, req) => {
        try { const bad = await needRoster(); if (bad) return bad; req = req || {}; const me = validChamp(req.me); const enemy = validChamp(req.enemy); const role = validRole(req.role); if (!me || !enemy || !role) return errE('İstek geçersiz.');
          const sel = muRankSet(req.rank) !== null ? req.rank : state.murank; const note = state.notes[noteKey(me, enemy, role)] || ''; const base = { me, enemy, role, rank: sel, note, configured: !!(state.muUrl && muTemplateOk(state.muUrl)) };
          const f = await muFetch(me, enemy, role); if (f.state !== 'ok') return Object.assign(base, { state: f.state });
          const a = aggMu(f.parsed, sel); if (!a || a.empty) return Object.assign(base, { state: 'norank', missing: a ? a.missing : [], available: Object.keys(f.parsed.ranks) });
          const ids = new Set(); for (const sl of Object.keys(a.items)) for (const it of a.items[sl]) ids.add(it.id); const names = await muItemNames([...ids]); for (const sl of Object.keys(a.items)) for (const it of a.items[sl]) it.name = names[it.id] || null;
          return Object.assign(base, a, { state: 'ok', src: 'url' });
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      /* eslesmeye ozel KISISEL not (kendi yazdigin ipuclari; yalniz bu bilgisayarda) */
      'lol:note:set': async (_e, req) => {
        try { const bad = await needRoster(); if (bad) return bad; req = req || {}; const me = validChamp(req.me); const enemy = validChamp(req.enemy); const role = validRole(req.role); if (!me || !enemy || !role) return errE('İstek geçersiz.');
          const text = String(req.text == null ? '' : req.text).replace(/\r\n/g, '\n').slice(0, NOTE_MAX).trim(); const k = noteKey(me, enemy, role);
          if (!text) delete state.notes[k]; else { delete state.notes[k]; state.notes[k] = text; const keys = Object.keys(state.notes); if (keys.length > NOTES_MAX) for (const x of keys.slice(0, keys.length - NOTES_MAX)) delete state.notes[x]; }
          save(); return { ok: true, saved: !!text };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      /* maç açılış bindirmesi ayarı (pencereyi ana süreç açar; burada yalnız tercih saklanır) */
      'lol:ov:get': async () => ({ on: state.ov.on, secs: state.ov.secs }),
      'lol:ov:set': async (_e, req) => { req = req || {}; if (typeof req.on === 'boolean') state.ov.on = req.on; if (req.secs != null) state.ov.secs = clamp(Math.round(Number(req.secs)) || 20, 8, 60); save(); return { ok: true, on: state.ov.on, secs: state.ov.secs }; },
      /* Tab'a basinca altin farki bindirmesi: ayar + tek hesap (yalniz GET /liveclientdata/allgamedata) */
      'lol:gold:get': async () => ({ on: state.gold.on }),
      'lol:gold:set': async (_e, req) => { req = req || {}; if (typeof req.on === 'boolean') state.gold.on = req.on; save(); return { ok: true, on: state.gold.on }; },
      'lol:gold': async () => {
        try {
          const bad = await needRoster(); if (bad) return { state: 'nogame' }; let j = null; try { j = await liveRead('/liveclientdata/allgamedata'); } catch (e) { j = null; } if (!j) return { state: 'nogame' };
          const parsed = parseLive(j, new Map(roster.map((c) => [c.name, c])), new Map(roster.map((c) => [c.id, c]))); if (!parsed) return { state: 'nogame' };
          const a = analyzeLive(parsed, roster); const nm = new Map(roster.map((c) => [c.id, c.name])); return goldCompare(a, (id) => (id && nm.get(id)) || id || '?');
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:sync': async (_e, req) => {
        try {
          const bad = await needRoster(); if (bad) return bad; const info = await lcuFind(); if (!info) return riotReady() ? await riotSync(req && req.force === true) : { state: 'noclient' };
          const notes = []; const t = now(); const co = champOf(); const msg = (e) => String(e && e.message || e).slice(0, 80);
          let sum = null; try { sum = await lcuRead(info, '/lol-summoner/v1/current-summoner'); } catch (e) { notes.push('profil: ' + msg(e)); }
          if (sum && typeof sum === 'object' && sum.puuid) state.me = { puuid: String(sum.puuid).slice(0, 90), name: String(sum.gameName || sum.displayName || sum.summonerName || '').slice(0, 40), tag: String(sum.tagLine || '').slice(0, 10), level: Math.round(Number(sum.summonerLevel)) || 0, icon: Math.round(Number(sum.profileIconId)) || 0 };
          let snaps = 0; try { const rk = parseRanked(await lcuRead(info, '/lol-ranked/v1/current-ranked-stats')); for (const q of ['solo', 'flex']) if (addSnap(state.lp, rk[q], t, LIM.snaps)) snaps++; state.rank = { solo: rk.solo, flex: rk.flex, t }; } catch (e) { notes.push('derece: ' + msg(e)); }
          let added = 0; let updated = 0; const me = state.me; const want = req && req.deep === true ? 100 : 20;
          if (me) {
            let budget = LIM.details;
            for (let beg = 0; beg < want; beg += 20) {
              let list = null; try { const j = await lcuRead(info, '/lol-match-history/v1/products/lol/current-summoner/matches?begIndex=' + beg + '&endIndex=' + (beg + 20)); list = j && j.games && Array.isArray(j.games.games) ? j.games.games : []; } catch (e) { notes.push('maçlar: ' + msg(e)); break; }
              for (const g of list) {
                const id = String(Math.round(Number(g && g.gameId))); const old = state.matches[id];
                if (old && !old.partial) {
                  const hasTeamStats = (ps) => Array.isArray(ps) && ps.length >= 2 && ps.every((p) => p && ['k', 'd', 'a', 'cs', 'gold', 'dmg', 'vision'].every((k) => Number.isFinite(p[k])));
                  if (old.runes === undefined || old.spells === undefined || !hasTeamStats(old.players)) {
                    let mr = normMatch(g, me.puuid, co); let retry = false;
                    const missing = () => !mr || (old.runes === undefined && !mr.runes) || (old.spells === undefined && !mr.spells) || (!hasTeamStats(old.players) && !hasTeamStats(mr.players));
                    if (missing()) { if (budget > 0) { budget--; try { const detail = normMatch(await lcuRead(info, '/lol-match-history/v1/games/' + id), me.puuid, co); if (detail) mr = detail; } catch (e) { retry = true; } } else retry = true; }
                    if (!retry) { updated++; if (old.runes === undefined) old.runes = mr ? mr.runes : null; if (old.spells === undefined) old.spells = mr ? mr.spells : null; if (!hasTeamStats(old.players) && hasTeamStats(mr && mr.players)) old.players = mr.players; }
                  }
                  continue;
                }
                let m = normMatch(g, me.puuid, co); if (!m) continue;
                if (m.partial && budget > 0) { budget--; try { const m2 = normMatch(await lcuRead(info, '/lol-match-history/v1/games/' + id), me.puuid, co); if (m2) m = m2; } catch (e) { /* ayrinti alinamadi */ } }
                if (!old) added++; state.matches[id] = m;
              }
              if (list.length < 20) break;
            }
            const keys = Object.keys(state.matches); if (keys.length > LIM.matches) { keys.sort((a, b) => state.matches[a].t - state.matches[b].t); for (const k of keys.slice(0, keys.length - LIM.matches)) delete state.matches[k]; }
          }
          save(); return { state: 'ok', me: state.me, added, updated, snaps, notes, total: Object.keys(state.matches).length };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:riot:get': async () => ({ hasKey: !!riot.key, id: riot.id, region: riot.region, regions: Object.keys(RIOT_REG) }),
      'lol:riot:set': async (_e, req) => {
        try { req = req || {}; if (req.clear === true) { riot = { key: '', id: riot.id, region: riot.region }; riotSave(); return { ok: true, hasKey: false }; }
          if (typeof req.key === 'string' && req.key.trim()) { const k = req.key.trim(); if (!RIOT_KEY_RE.test(k)) return errE('Anahtar biçimi geçersiz (RGAPI-… ile başlayan 36 karakterlik anahtar).'); riot.key = k; }
          if (typeof req.id === 'string' && req.id.trim()) { const v = req.id.trim(); if (!RIOT_ID_RE.test(v)) return errE('Riot Kimliği "Ad#ETİKET" biçiminde olmalı.'); riot.id = v; }
          if (typeof req.region === 'string' && req.region) { if (!RIOT_REG[req.region]) return errE('Bölge geçersiz.'); riot.region = req.region; }
          riotSave(); riotAt = 0; riotBlock = 0; return { ok: true, hasKey: !!riot.key, id: riot.id, region: riot.region };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:profile': async () => {
        try {
          const t = now(); const t0 = dayStart(t); const all = Object.values(state.matches).sort((a, b) => b.t - a.t); const o = overview(all, t); const rk = state.rank || null;
          return { me: state.me, rank: rk ? { solo: rk.solo, flex: rk.flex } : null, lastSync: rk ? rk.t : null, matches: all.length, snaps: state.lp.length, today: { games: o.today.games, w: o.today.w, l: o.today.l, lp: { solo: todayLp(state.lp, 'solo', t0), flex: todayLp(state.lp, 'flex', t0) } }, tilt: o.tilt, streak: o.streak,
            aram: wlOf(all.filter(mkFilter('aram'))), normal: wlOf(all.filter(mkFilter('normal'))), spark: { solo: lpSeries(state.lp, 'solo').slice(-30), flex: lpSeries(state.lp, 'flex').slice(-30) } };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:lp': async (_e, q) => {
        try {
          const qq = q === 'flex' ? 'flex' : 'solo'; const ser = lpSeries(state.lp, qq); let peak = null; for (const p of ser) if (!peak || p.abs > peak.abs) peak = p;
          return { queue: qq, points: ser.slice(-600), events: lpEvents(state.lp, qq).slice(0, 40), peak, current: ser.length ? ser[ser.length - 1] : null, count: ser.length, since: ser.length ? ser[0].t : null };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:matches': async (_e, req) => {
        try {
          req = req || {}; const q = FILTERS.includes(req.queue) ? req.queue : 'all'; const off = clamp(Math.round(Number(req.offset)) || 0, 0, 5000); const lim = clamp(Math.round(Number(req.limit)) || 20, 1, 50);
          const all = Object.values(state.matches).sort((a, b) => b.t - a.t); const delta = attrLp(all, state.lp); const f = all.filter(mkFilter(q));
          return { total: f.length, rows: f.slice(off, off + lim).map((m) => Object.assign({}, m, { lpDelta: delta.has(m.id) ? delta.get(m.id) : null })) };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:stats': async (_e, req) => {
        try {
          req = req || {}; const q = FILTERS.includes(req.queue) ? req.queue : 'all'; const role = ROLES.includes(req.role) ? req.role : null; const all = Object.values(state.matches).sort((a, b) => b.t - a.t).filter(mkFilter(q)); const f = role ? all.filter((m) => m.role === role) : all;
          return { queue: q, role, overview: overview(f, now()), champs: champStats(f).slice(0, 100), roles: roleStats(all), roleChamps: roleChampStats(all, attrLp(all, state.lp)), partners: partnerStats(all) };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      /* başka sihirdarı ara (Riot Kimliği) ve genel profilini oku: yalnız GET, kalıcı kayıt YOK, kendi profilimizle aynı hesaplar */
      'lol:player:search': async (_e, req) => {
        try {
          const bad = await needRoster(); if (bad) return bad; req = req || {}; let who = null; let puuid = null;
          if (req.puuid != null) { puuid = String(req.puuid); if (!/^[A-Za-z0-9_-]{20,100}$/.test(puuid)) return errE('Oyuncu kimliği geçersiz.'); } else { who = parsePlayerQuery(req.query); if (!who) return { state: 'badquery' }; }
          const info = await lcuFind(); if (!info) return { state: 'noclient' };
          const wait = lastLookup + 1000 - now(); if (wait > 0) await new Promise((r) => setTimeout(r, wait)); lastLookup = now();
          const msg = (e) => String(e && e.message || e).slice(0, 80); const nf = (e) => /404|not.?found/i.test(String(e && e.message || e)); const notes = [];
          let player = { puuid, name: who ? who.name : '', tag: who ? who.tag : '', level: 0, icon: 0 };
          if (!puuid) {
            let j = null; try { j = await lcuRead(info, '/lol-summoner/v1/alias/lookup?gameName=' + encodeURIComponent(who.name) + '&tagLine=' + encodeURIComponent(who.tag)); } catch (e) { if (!nf(e)) notes.push('arama: ' + msg(e)); }
            if (!j || !j.puuid) { try { j = await lcuRead(info, '/lol-summoner/v1/summoners?name=' + encodeURIComponent(who.name + '#' + who.tag)); } catch (e) { if (!nf(e)) notes.push('arama2: ' + msg(e)); } }
            if (!j || typeof j !== 'object' || !/^[A-Za-z0-9_-]{20,100}$/.test(String(j.puuid || ''))) return { state: notes.length ? 'error' : 'notfound', notes };
            puuid = String(j.puuid); player.puuid = puuid; if (j.gameName) player.name = String(j.gameName).slice(0, 30); if (j.tagLine) player.tag = String(j.tagLine).slice(0, 10);
          }
          /* maçsız (başarısız) sonuç önbellekten dönmez: yeniden arama gerçekten yeniden dener */
          const hit = playerCache.get(puuid); if (hit && hit.matches.length && now() - hit.t < PLAYER_TTL && req.fresh !== true) return { state: 'ok', player: hit.player, rank: hit.rank, cached: true, notes: hit.notes || [], view: playerView(hit, req.view), counts: { matches: hit.matches.length, details: hit.details } };
          try { const sj = await lcuRead(info, '/lol-summoner/v1/summoners-by-puuid-cached/' + puuid); if (sj && typeof sj === 'object') { if (sj.gameName) player.name = String(sj.gameName).slice(0, 30); if (sj.tagLine) player.tag = String(sj.tagLine).slice(0, 10); player.level = Math.round(Number(sj.summonerLevel)) || 0; player.icon = Math.round(Number(sj.profileIconId)) || 0; } } catch (e) { notes.push('profil: ' + msg(e)); }
          let rank = null; try { const rk = parseRanked(await lcuRead(info, '/lol-ranked/v1/ranked-stats/' + puuid)); rank = { solo: rk.solo, flex: rk.flex }; for (const qk of ['solo', 'flex']) { const rr = rank[qk]; if (rr && rr.l === 0 && rr.w >= 10) rr.noL = true; /* istemci başkası için losses'ı 0 yollar: '%100 WR' uydurma */ } } catch (e) { notes.push('derece: ' + msg(e)); }
          const co = champOf(); const matches = new Map(); let budget = 10; let details = 0; let denied = false;
          for (let beg = 0; beg < 40 && !denied; beg += 20) {
            /* 404 (lcuGet null döner) ve tanınmayan yanıt SESSİZCE '0 maç' olmasın: sebep nota yazılır; 2. sayfa sorunu ilk sayfadan gelen maçları bozmaz */
            let list = null; try { const mp = '/lol-match-history/v1/products/lol/' + puuid + '/matches?begIndex=' + beg + '&endIndex=' + (beg + 20); let j; try { j = await lcuRead(info, mp, 15000); } catch (e1) { if (!/zaman aşımı/.test(String(e1 && e1.message || e1))) throw e1; j = await lcuRead(info, mp, 15000); } list = gamesOf(j); if (list === null) { if (!matches.size) notes.push(j == null ? 'maçlar: istemci bu oyuncunun maç geçmişini vermedi (boş yanıt / 404)' : 'maçlar: istemci yanıtının biçimi tanınmadı'); denied = true; break; } } catch (e) { if (!matches.size) notes.push('maçlar: ' + msg(e)); denied = true; break; }
            for (const g of list) { let m = normMatch(g, puuid, co); if (!m) continue; if (m.partial && budget > 0) { budget--; try { const m2 = normMatch(await lcuRead(info, '/lol-match-history/v1/games/' + Math.round(Number(g.gameId)), 8000), puuid, co); if (m2) { m = m2; details++; } } catch (e) { /* ayrıntı alınamadı */ } } matches.set(m.id, m); }
            if (list.length < 20) break;
          }
          if (!matches.size && !notes.some((x) => /^maçlar/.test(x))) notes.push('maçlar: istemci boş liste döndürdü (oyuncu geçmişini gizli tutuyor ya da istemci başkasının geçmişini vermiyor olabilir)');
          const ent = { t: now(), player, rank, matches: [...matches.values()], details, notes: notes.slice() }; playerKeep(puuid, ent);
          return { state: 'ok', player, rank, cached: false, notes, view: playerView(ent, req.view), counts: { matches: ent.matches.length, details } };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      /* önbellekteki oyuncunun filtre/sayfa görünümü (ağ yok) */
      'lol:player:view': async (_e, req) => {
        try { req = req || {}; const ent = playerCache.get(String(req.puuid || '')); if (!ent || now() - ent.t > PLAYER_TTL) return { state: 'expired' }; return { state: 'ok', view: playerView(ent, req) }; } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:friends': async () => {
        try { const info = await lcuFind(); if (!info) return { state: 'noclient' }; let j; try { j = await lcuRead(info, '/lol-chat/v1/friends'); } catch (e) { return { state: 'error', notes: [String(e && e.message || e).slice(0, 80)] }; } return { state: 'ok', friends: parseFriends(j) }; } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:bans': async (_e, req) => {
        try {
          const bad = await needRoster(); if (bad) return bad; const role = validRole(req && req.role); if (!role) return errE('Rol geçersiz.'); const out = banPicks(roster, state.pool[role] || [], role, state.hist.concat(autoHist()), req && req.limit); if (out.needPool) return { needPool: true, role }; return out;
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:comp': async (_e, req) => {
        try { const bad = await needRoster(); if (bad) return bad; const ok = (l) => (Array.isArray(l) ? l.slice(0, 5).map((x) => validChamp(x)).filter(Boolean) : []); return compAnalysis(roster, ok(req && req.allies), ok(req && req.enemies)); } catch (e) { return errE(String(e && e.message || e)); }
      },
      /* rakip takimina gore situasyonel esya onerisi (Data Dragon verisinden kaba kurallar; kazanma orani DEGIL) */
      'lol:items': async (_e, req) => {
        try { const bad = await needRoster(); if (bad) return bad; req = req || {}; const me = validChamp(req.me); if (!me) return errE('Şampiyon geçersiz.'); const role = req.role ? validRole(req.role) : null; if (req.role && !role) return errE('Rol geçersiz.');
          const enemies = (Array.isArray(req.enemies) ? req.enemies.slice(0, 5) : []).map((x) => validChamp(x)).filter(Boolean); if (!enemies.length) return errE('Rakip şampiyon yok.');
          const D = await loadItems(); if (D.error) return D; return buildItemAdvice(roster, me, enemies, role, D.list, D.names, D.version);
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:icon': async (_e, req) => {
        try {
          req = req || {}; const kind = req.kind; const id = String(req.id); let p; let host = DD_HOST; let max = LIM.icon; let ver = ''; let name = ''; let unversioned = false;
          if (kind === 'rank') { if (!TIERS.map((x) => x.toLowerCase()).includes(id)) return errE('Derece geçersiz.'); host = CD_HOST; max = LIM.rank; p = CD_RANK + 'emblem-' + id + '.png'; } else { const bad = await needRoster(); if (bad) return bad; ver = rosterMeta.version; }
          if (kind === 'rank') { /* yukarida */ } else if (kind === 'champion') { if (!validChamp(id)) return errE('Şampiyon bulunamadı.'); p = 'champion/' + id + '.png'; } else if (kind === 'item') { if (!/^\d{3,6}$/.test(id)) return errE('Eşya geçersiz.'); p = 'item/' + id + '.png'; } else if (kind === 'profile') { if (!/^\d{1,6}$/.test(id)) return errE('Simge geçersiz.'); p = 'profileicon/' + id + '.png'; } else if (kind === 'spell') {
            if (!/^\d{1,6}$/.test(id)) return errE('Büyü geçersiz.'); const spells = await loadSpells(); const entry = spells[id]; if (!entry) return errE('Büyü bulunamadı.'); p = 'spell/' + entry.image; name = entry.name;
          } else if (kind === 'rune') {
            if (!/^\d{4}$/.test(id)) return errE('Rün geçersiz.'); const R = await loadRunes(); if (R.error || !R.icons[id]) return errE('Rün bulunamadı.'); p = '/cdn/img/' + R.icons[id]; name = R.perks[id] || R.trees[id] || ''; unversioned = true;
          } else return errE('Simge türü geçersiz.');
          const key = kind + '-' + id + (ver ? '-' + ver : ''); if (iconMem.has(key)) return { data: iconMem.get(key), name };
          const isPng = (b) => Buffer.isBuffer(b) && b.length >= 64 && b[0] === 0x89 && b[1] === 0x50; const file = cacheDir ? path.join(cacheDir, 'icons', key + '.png') : null; let buf = null; if (file) { try { buf = fs.readFileSync(file); } catch (e) { buf = null; } if (!isPng(buf)) buf = null; }
          if (!buf) { buf = await iconSlot(() => httpBin(host, kind === 'rank' || unversioned ? p : '/cdn/' + ver + '/img/' + p, max)); if (!isPng(buf)) return errE('Simge alınamadı.'); if (file) { try { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, buf); } catch (e) { /* onbellek zorunlu degil */ } } }
          const d = 'data:image/png;base64,' + buf.toString('base64'); if (iconMem.size > 800) iconMem.clear(); iconMem.set(key, d); return { data: d, name };
        } catch (e) { return errE('Simge alınamadı (' + String(e && e.message || e).slice(0, 60) + ').'); }
      },
      'lol:data:clear': async () => {
        try {
          if (!deps.confirm) return errE('Onay penceresi yok; silinmedi.'); const n = Object.keys(state.matches).length; const okc = await deps.confirm({ title: 'League verileri silinsin mi?', message: 'Bu bilgisayarda saklanan ' + n + ' maç, LP geçmişi ve profil bilgisi silinecek. Şampiyon havuzun ve elle girdiğin maç kayıtların silinmez. Bu geri alınamaz.', ok: 'Sil', cancel: 'Vazgeç' }); if (!okc) return { canceled: true };
          state.me = null; state.lp = []; state.matches = {}; state.rank = null; save(); return { ok: true };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:live': async () => {
        try {
          const bad = await needRoster(); if (bad) return bad; let j = null; try { j = await liveRead('/liveclientdata/allgamedata'); } catch (e) { j = null; } if (!j) return { state: 'nogame' };
          const parsed = parseLive(j, new Map(roster.map((c) => [c.name, c])), new Map(roster.map((c) => [c.id, c]))); if (!parsed) return { state: 'nogame' };
          const a = analyzeLive(parsed, roster); const out = Object.assign({ state: 'ingame' }, a); const myChamp = a.me && validChamp(a.me.champ); const opp = a.lane && validChamp(a.lane);
          if (myChamp && opp && a.me.role) {
            const role = a.me.role; const hist = state.hist.concat(autoHist()); const ext = await fetchExt(opp, role, myChamp); const pool = state.pool[role] || [];
            const all = rank(roster, opp, role, { hist, pool, ext, limit: 500 }); const fit = rank(roster, opp, role, { hist, pool, ext, limit: 8 });
            const mine = all.picks ? all.picks.find((x) => x.id === myChamp) : null; const pos = mine ? 1 + all.picks.filter((x) => x.score > mine.score).length : null;
            out.matchup = { role, enemy: opp, mine: mine || null, pos, total: all.total, best: fit.picks || [], list: (all.picks || []).slice(0, 200).map((x) => ({ id: x.id, name: x.name, score: x.score, wr: x.ext ? x.ext.wr : null, games: x.ext ? x.ext.games : 0, inPool: !!x.inPool })), extUsed: !!ext, statsConfigured: !!(state.statsUrl || state.cp), cp: !!state.cp };
          }
          return out;
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:runes': async () => { try { const bad = await needRoster(); if (bad) return bad; return await loadRunes(); } catch (e) { return errE(String(e && e.message || e)); } },
      /* şampiyon seçiminde: bu eşleşme için rün önerisi (yalnız dış veri/counterpick açıkken) */
      'lol:runes:suggest': async (_e, req) => {
        try { const bad = await needRoster(); if (bad) return bad; req = req || {}; const me = validChamp(req.me); const enemy = validChamp(req.enemy); const role = validRole(req.role); if (!me || !enemy || !role) return errE('İstek geçersiz.');
          const R = await loadRunes(); if (R.error) return R; const ok6 = (r) => (r && Array.isArray(r.perks) && r.perks.length === 6 && validateRunePage(r.perks, R.idx) ? r : null); const fill = (r) => { const v = validateRunePage(r.perks, R.idx); return { perks: r.perks.slice(0, 6), primary: v.primary, secondary: v.sub }; };
          const diag = {}; const ext = await fetchExt(enemy, role, me, diag); const e = ext ? ext.get(me) : null; const tried = []; let runes = null; let src = null; let hist = null;
          /* 1) dış veri adresi / counterpick.lol (eşleşmeye özel) */
          if (state.statsUrl) tried.push({ src: 'url', state: diag.url || 'none' });
          if (e && e.runes && ok6(e.runes)) { runes = fill(e.runes); src = e.src === 'url' ? 'url' : 'cp'; }
          tried.push({ src: 'cp', state: runes && src === 'cp' ? 'ok' : (diag.cp || 'off') }); if (runes && src === 'url') tried.splice(tried.findIndex((x) => x.src === 'cp'), 1);
          /* 2) kendi maç geçmişin */
          const hr = histRunes(state.matches, me, enemy, role); const hv = hr.state === 'ok' ? ok6(hr.runes) : null;
          if (!runes && hv) { runes = fill(hv); src = 'hist'; hist = { scope: hr.scope, games: hr.games, wr: hr.wr, total: hr.total }; tried.push({ src: 'hist', state: 'ok' }); } else if (!runes) tried.push({ src: 'hist', state: hr.state === 'ok' ? 'none' : hr.state, a: hr.vs, b: hr.champ });
          /* 3) istemcinin kendi önerisi (hat bazlı) */
          if (!runes) { const lr = await lcuRecRunes(me, role, R); if (lr.state === 'ok') { runes = fill(lr.runes); src = 'lcu'; } tried.push({ src: 'lcu', state: lr.state }); }
          return { me, enemy, role, wr: e ? e.wr : null, games: e ? e.games : 0, approx: !!(e && e.approx), runes, src, hist, tried, statsConfigured: !!(state.statsUrl || state.cp), cp: !!state.cp };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      /* rünleri League istemcisine yaz: YALNIZ 'Kovan …' adlı kendi sayfamız; diğer sayfalara dokunulmaz; onay penceresi; yapı doğrulanamazsa yazılmaz */
      'lol:runes:apply': async (_e, req) => {
        try {
          const bad = await needRoster(); if (bad) return bad; req = req || {}; const me = validChamp(req.me); const enemy = validChamp(req.enemy); const perks = Array.isArray(req.perks) ? req.perks.slice(0, 9).map(Number) : [];
          if (!me || !enemy || perks.length !== 6 || perks.some((n) => !Number.isInteger(n))) return errE('Rün verisi geçersiz.');
          const R = await loadRunes(); if (R.error) return R; const v = validateRunePage(perks, R.idx); if (!v) return errE('Rün sırası/ağaçları doğrulanamadı; League’e yazılmadı.');
          if (!deps.confirm) return errE('Onay penceresi yok; yazılmadı.'); const nameE = (roster.find((c) => c.id === enemy) || {}).name || enemy; const nameM = (roster.find((c) => c.id === me) || {}).name || me;
          const okc = await deps.confirm({ title: 'Rünler League’e yazılsın mı?', message: nameM + ' → ' + nameE + ' karşısında:\n\n' + perks.map((id) => R.perks[id] || id).join(' · ') + '\n\nİstemcide “Kovan …” adlı bir rün sayfası oluşturulur/yenilenir ve etkin yapılır. Diğer sayfalarına dokunulmaz. Şarj parçaları şu anki sayfandan alınır.', ok: 'Yaz', cancel: 'Vazgeç' }); if (!okc) return { canceled: true };
          const info = await lcuFind(); if (!info) return { error: 'lol', state: 'noclient', message: 'League istemcisi bulunamadı (açık mı?).' };
          let cur; let pages; try { cur = await lcuRead(info, '/lol-perks/v1/currentpage'); pages = await lcuRead(info, '/lol-perks/v1/pages'); } catch (e) { return errE('Rün sayfaları okunamadı (' + String(e && e.message || e) + ').'); }
          const shards = cur && Array.isArray(cur.selectedPerkIds) && cur.selectedPerkIds.length === 9 ? cur.selectedPerkIds.slice(6).map(Number) : null; if (!shards || shards.some((n) => !Number.isInteger(n) || n < 5000 || n > 5999)) return errE('Şarj parçaları şu anki sayfandan okunamadı; yazılmadı. Önce istemcide bir rün sayfası seç.');
          const list = Array.isArray(pages) ? pages : []; const name = ('Kovan vs ' + nameE).slice(0, 24);
          try { for (const pg of list.filter((x) => x && /^Kovan/.test(String(x.name)) && Number.isInteger(x.id) && x.isDeletable !== false)) await lcuWrite(info, 'DELETE', '/lol-perks/v1/pages/' + pg.id);
            await lcuWrite(info, 'POST', '/lol-perks/v1/pages', { name, primaryStyleId: v.primary, subStyleId: v.sub, selectedPerkIds: perks.concat(shards), current: true });
          } catch (e) { return errE('Rün sayfası yazılamadı (' + String(e && e.message || e) + '). Sayfa sınırı dolmuş ya da seçim ekranı kapalı olabilir.'); }
          let okRead = false; try { const after = await lcuRead(info, '/lol-perks/v1/pages'); okRead = Array.isArray(after) && after.some((x) => x && x.name === name && Array.isArray(x.selectedPerkIds) && x.selectedPerkIds.slice(0, 6).join() === perks.join()); } catch (e) { okRead = false; }
          return { ok: true, name, verified: okRead };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'lol:lcu': async () => {
        try { const bad = await needRoster(); if (bad) return bad; const info = await lcuFind(); if (!info) return { state: 'noclient' }; let s = null; try { s = await lcuRead(info, '/lol-champ-select/v1/session'); } catch (e) { return { state: 'noclient', note: String(e && e.message || e) }; } if (!s) return { state: 'idle' };
          const m = mapSession(s, byKeyMap()); if (!m) return { state: 'idle' };
          /* şampiyon seçiminde hat tahmini: 5 kişi tamamsa 120 atamayla, değilse kişi başına en olası hat (KABA; büyü/konum bilgisi yok) */
          const by = new Map(roster.map((c) => [c.id, c])); const guess = (list) => { const L = list.map((x) => Object.assign({}, x)); const open = L.filter((x) => !x.role);
            if (L.length === 5 && open.length === 5) { const a = assignRoles(L.map((x) => roleWeights(by.get(x.id) || null, null))); if (a) L.forEach((x, i) => { x.guess = { role: a[i].role, conf: a[i].conf, full: true }; }); }
            else for (const x of open) { const w = roleWeights(by.get(x.id) || null, null); const tot = ROLE_ORDER.reduce((s2, r) => s2 + w[r], 0); const br = ROLE_ORDER.reduce((b, r) => (w[r] > w[b] ? r : b), 'top'); x.guess = { role: br, conf: Math.round((1000 * w[br]) / tot) / 1000, full: false }; }
            return L; };
          return Object.assign({ state: 'champselect' }, m, { allies: guess(m.allies), enemies: guess(m.enemies) });
        } catch (e) { return errE(String(e && e.message || e)); }
      }
    };
    return { handlers, _state: () => state, _roster: () => roster };
  }
  /* ---- Tab'a basinca altin farki: tablodaki esya degerleri (tahmin; harcanmamis altin dahil degil). Yalnizca oyunun kendi Tab tablosunda
     zaten gorunen bilgilerin (esya, kill) toplami/farki; dusman buyu/yetenek bekleme sayaci ya da durum tetikli uyari YOK. ---- */
  function goldCompare(a, nameOf) {
    if (!a || !a.me) return { state: 'nogame' }; const nf = nameOf || ((x) => x); const sum = (L, f) => L.reduce((s, x) => s + (Number(x[f]) || 0), 0);
    const m = { gold: sum(a.allies, 'gold'), kills: sum(a.allies, 'k') }; const e = { gold: sum(a.enemies, 'gold'), kills: sum(a.enemies, 'k') };
    const pl = (x) => ({ champ: x.champ, name: String(nf(x.champ)).slice(0, 24), gold: Number(x.gold) || 0, me: !!x.me }); const lanes = []; let guessed = false;
    if (a.classic) for (const r of ['top', 'jungle', 'mid', 'bot', 'support']) { const x = a.allies.find((p) => p.role === r); const y = a.enemies.find((p) => p.role === r); if (!x || !y) continue; lanes.push({ role: r, mine: pl(x), enemy: pl(y), diff: (Number(x.gold) || 0) - (Number(y.gold) || 0) }); if (!x.known || !y.known) guessed = true; }
    return { state: 'ok', time: a.time, classic: !!a.classic, mine: m, enemy: e, diff: m.gold - e.gold, lanes, guessed, partial: a.allies.concat(a.enemies).some((p) => !p.gold) };
  }
  function lolGoldHtml() {
    const js = '(function(){var H=window.statscanHost,$=function(i){return document.getElementById(i)};'
      + 'function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=String(x);return e}'
      + 'var RN={top:"Üst",jungle:"Orman",mid:"Orta",bot:"Alt",support:"Destek"};'
      + 'function n(v){return String(Math.round(v)).replace(/\\B(?=(\\d{3})+(?!\\d))/g,".")}'
      + 'function sg(v){return(v>0?"+":v<0?"−":"")+n(Math.abs(v))}'
      + 'function cl(v){return v>0?"up":v<0?"dn":"eq"}'
      + 'function draw(g){if(!g||g.state!=="ok"){$("top").className="off";return}$("top").className="";'
      + '$("gl").textContent=n(g.mine.gold);$("gr").textContent=n(g.enemy.gold);var d=$("df");d.textContent=n(Math.abs(g.diff));d.className=cl(g.diff);$("ar").textContent=g.diff>0?"◀":g.diff<0?"▶":"•";'
      + '$("kl").textContent=g.mine.kills;$("kr").textContent=g.enemy.kills;var L=$("lanes");L.textContent="";'
      + '(g.lanes||[]).forEach(function(r){var w=el("div","ln"+(r.mine.me?" me":""));w.appendChild(el("span","c l",r.mine.name+" "+n(r.mine.gold)));var m=el("span","c m "+cl(r.diff),sg(r.diff));w.appendChild(m);w.appendChild(el("span","c r",n(r.enemy.gold)+" "+r.enemy.name));w.title=RN[r.role]||r.role;L.appendChild(w)});'
      + '$("ft").textContent="Eşya değeri toplamı (tahmin) · cepteki altın dahil değil"+(g.guessed?" · hat eşleşmesi tahmin":"")}'
      + 'var busy=false;function refresh(){if(busy||!H||!H.lolGold)return;busy=true;H.lolGold().then(draw).catch(function(){draw(null)}).then(function(){busy=false})}'
      + 'document.addEventListener("visibilitychange",function(){if(!document.hidden)refresh()});setInterval(function(){if(!document.hidden)refresh()},1500);refresh();})();';
    const css = 'html,body{margin:0;background:transparent;color:#e8ecf3;font:13px/1.35 system-ui,sans-serif;user-select:none}body{padding:8px 12px;background:rgba(8,12,20,.88);border:1px solid #c8aa6e;border-radius:10px;box-sizing:border-box;min-height:100vh}'
      + '#top{display:flex;align-items:center;justify-content:space-between;gap:10px;font-weight:700;font-size:16px}#top.off{opacity:.4}#gl{color:#e6c35c}#gr{color:#e6c35c}#df{font-size:15px;padding:2px 8px;border-radius:6px;background:#1b2434}'
      + '#df.up,.m.up{color:#5be08a}#df.dn,.m.dn{color:#ff6b6b}#df.eq,.m.eq{color:#aab}#ar{color:#c8aa6e;font-size:11px;margin:0 4px}.k{display:flex;justify-content:space-between;margin:4px 0 6px;color:#cfd6e6;font-weight:700}.k i{color:#c8aa6e;font-style:normal}'
      + '.ln{display:grid;grid-template-columns:1fr auto 1fr;gap:8px;padding:2px 0;border-top:1px solid rgba(200,170,110,.18);font-size:12px}.ln.me{background:rgba(200,170,110,.10)}.c.l{text-align:left}.c.r{text-align:right}.c.m{font-weight:700;min-width:54px;text-align:center}'
      + '.fine{margin:6px 0 0;color:#8f98ab;font-size:10.5px}';
    const csp = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'";
    return '<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="' + csp + '"><title>Altın farkı</title><style>' + css + '</style></head><body>'
      + '<div id="top" class="off"><span id="gl">0</span><span><span id="ar">•</span><span id="df" class="eq">0</span></span><span id="gr">0</span></div>'
      + '<div class="k"><span id="kl">0</span><i>⚔ kill</i><span id="kr">0</span></div><div id="lanes"></div><p class="fine" id="ft"></p><script>' + js + '</script></body></html>';
  }
  /* Tab tusu durumu: tek, sabit bir PowerShell sureci GetAsyncKeyState(0x09)'u yoklar (yalniz tus basili/birakildi; tus vurusu kaydedilmez, hicbir yere yazilmaz).
     Yalniz Windows. Betik sabit; disaridan gelen hicbir deger icine girmez. */
  const TAB_PS = "Add-Type -Namespace K -Name U -MemberDefinition '[DllImport(\"user32.dll\")] public static extern short GetAsyncKeyState(int v);'; $p = $false; while ($true) { $d = (([K.U]::GetAsyncKeyState(9) -band 0x8000) -ne 0); if ($d -ne $p) { $p = $d; if ($d) { [Console]::Out.WriteLine('D') } else { [Console]::Out.WriteLine('U') }; [Console]::Out.Flush() }; Start-Sleep -Milliseconds 40 }";
  function createTabWatcher(o) {
    o = o || {}; const spawnFn = o.spawn || cp.spawn; let child = null; let down = false; let buf = '';
    const set = (v) => { if (v !== down) { down = v; try { if (o.onChange) o.onChange(v); } catch (e) { /* dinleyici hatasi */ } } };
    return {
      start() {
        if (child) return true; if ((o.platform || process.platform) !== 'win32') return false;
        try { child = spawnFn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-EncodedCommand', Buffer.from(TAB_PS, 'utf16le').toString('base64')], { shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] }); } catch (e) { child = null; return false; }
        const me = child; buf = '';
        if (me.stdout) me.stdout.on('data', (d) => { buf = (buf + String(d)).slice(-256); const parts = buf.split(/\r?\n/); buf = parts.pop(); for (const ln of parts) { const t = ln.trim(); if (t === 'D') set(true); else if (t === 'U') set(false); } });
        const gone = () => { if (child === me) { child = null; set(false); } }; me.on('error', gone); me.on('exit', gone); return true;
      },
      stop() { const c = child; child = null; set(false); if (c) { try { c.kill(); } catch (e) { /* zaten bitti */ } } },
      running() { return !!child; }, isDown() { return down; }
    };
  }
  /* ---- mac acilis bindirmesi: yalniz STATIK mac oncesi bilgi (build/not). Dusman buyu/yetenek bekleme sayaci,
     ulti sayaci ve durum tetikli "simdi sunu yap" uyarisi YOK (Riot politikasi). Pencereyi app.js acar. ---- */
  function overlayDecide(prevIn, cfg, live) {
    const inGame = !!(live && live.state === 'ingame' && live.classic !== false && live.me && live.me.champ && live.matchup && live.matchup.enemy);
    return { inGame, open: !!(cfg && cfg.on) && inGame && !prevIn };
  }
  function lolOverlayHtml(secs) {
    const s = Math.max(8, Math.min(60, Math.round(Number(secs)) || 20));
    const js = '(function(){var H=window.statscanHost,SECS=' + s + ',$=function(i){return document.getElementById(i)};'
      + 'function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=String(x);return e}'
      + 'var RK=["all","iron","bronze","silver","gold","platinum","emerald","diamond","master","grandmaster","challenger"],ri=0,ctx=null,left=SECS,paused=false,pinned=false;'
      + 'function close(){try{window.close()}catch(e){}}'
      + 'function draw(m){var b=$("body");b.textContent="";if(!m||m.error||m.state!=="ok"){b.appendChild(el("p","dim",m&&m.state==="norank"?"Bu rank için veri yok.":"Bu eşleşme için kaynak veri yok."));if(m&&m.note)b.appendChild(el("p","note",m.note));return}'
      + 'b.appendChild(el("p","sum",(m.wr!=null?"%"+Number(m.wr).toFixed(1)+" kazanma · ":"")+(m.games!=null?m.games+" oyun":"")+(m.patch?" · yama "+m.patch:"")));'
      + 'var names={start:"Başlangıç",boots:"Ayakkabı",core:"Çekirdek",slot4:"4. eşya",slot5:"5. eşya",slot6:"6. eşya"};'
      + 'Object.keys(names).forEach(function(k){var a=m.items&&m.items[k];if(!a||!a.length)return;var r=el("div","sec");r.appendChild(el("b","",names[k]));a.slice(0,4).forEach(function(it){var c=el("span","it");var im=el("img");im.width=28;im.height=28;im.alt="";c.appendChild(im);c.appendChild(el("small","",(it.name||("#"+it.id))+" · "+it.games));r.appendChild(c);if(H.lolIcon)H.lolIcon("item",it.id).then(function(x){if(x&&x.data)im.src=x.data}).catch(function(){})});b.appendChild(r)});'
      + 'if(m.note){var n=el("div","note");n.appendChild(el("b","","Notun"));n.appendChild(el("div","",m.note));b.appendChild(n)}}'
      + 'function load(){if(!ctx)return;$("rk").textContent=RK[ri]==="all"?"Tüm ranklar (Emerald+)":RK[ri];H.lolMu({me:ctx.me,enemy:ctx.enemy,role:ctx.role,rank:RK[ri]}).then(draw).catch(function(){draw(null)})}'
      + 'function tick(){if(pinned||paused)return;left--;$("cd").textContent=left+" sn";if(left<=0)close()}'
      + '$("prev").onclick=function(){ri=(ri+RK.length-1)%RK.length;load()};$("next").onclick=function(){ri=(ri+1)%RK.length;load()};'
      + '$("pin").onclick=function(){pinned=!pinned;$("pin").textContent=pinned?"Sabit":"Sabitle";if(!pinned){left=SECS}};$("x").onclick=close;'
      + 'document.body.onmouseenter=function(){paused=true};document.body.onmouseleave=function(){paused=false};setInterval(tick,1000);'
      + 'Promise.all([H.lolLive(),H.lolChamps(false)]).then(function(r){var L=r[0],C=r[1];if(!L||L.state!=="ingame"||!L.matchup){$("t").textContent="Maç bilgisi yok";return}'
      + 'var nm={};((C&&C.champs)||[]).forEach(function(c){nm[c.id]=c.name});ctx={me:L.me.champ,enemy:L.matchup.enemy,role:L.matchup.role};'
      + '$("t").textContent=(nm[ctx.me]||ctx.me)+" vs "+(nm[ctx.enemy]||ctx.enemy);load()}).catch(function(){$("t").textContent="Veri alınamadı"});})();';
    const css = 'html,body{margin:0;background:rgba(14,18,26,.92);color:#e8ecf3;font:13px/1.4 system-ui,sans-serif}body{padding:10px;border:1px solid #c8aa6e;border-radius:10px;box-sizing:border-box;min-height:100vh}'
      + 'header{display:flex;gap:6px;align-items:center}header b{flex:1;font-size:15px}button{background:#1e2635;color:#e8ecf3;border:1px solid #3a4560;border-radius:6px;padding:3px 8px;cursor:pointer}'
      + '.rows{display:flex;gap:6px;align-items:center;margin:8px 0}.rows span{flex:1;text-align:center}.sec{margin:6px 0}.sec b{display:block;color:#c8aa6e}.it{display:inline-flex;align-items:center;gap:4px;margin:2px 8px 2px 0}.it small{color:#aab}.dim{color:#99a}.sum{color:#c8aa6e;font-weight:600}.note{margin-top:8px;padding:6px;border-radius:6px;background:rgba(200,170,110,.12);white-space:pre-wrap}';
    const csp = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'";
    return '<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="' + csp + '"><title>Blitz</title><style>' + css + '</style></head><body>'
      + '<header><b id="t">Blitz</b><span id="cd" class="dim">' + s + ' sn</span><button id="pin">Sabitle</button><button id="x">×</button></header>'
      + '<div class="rows"><button id="prev">‹</button><span id="rk">Tüm ranklar (Emerald+)</span><button id="next">›</button></div><div id="body"></div><script>' + js + '</script></body></html>';
  }
  return { createLolHost, overlayDecide, lolOverlayHtml, lolGoldHtml, goldCompare, goldOf, createTabWatcher, TAB_PS, parseRoles, ROLE_HOST, normChamp, parseChampions, heuristic, adv, rank, rosterZ, roleFit, wilson, personal, personalAll, parseStats, parseLcuCmd, mapSession, ROLES, LIM, DD_HOST, absLp, parseRanked, assignRoles, roleWeights, validateRunePage, parsePlayerQuery, parseFriends, histRunes, buildRuneNames, cpRunesFromText, LCU_WRITE_OK, parseCpMatchup, parseCpCounters, cpKebab, parseLive, analyzeLive, parseRunes, LIVE_OK, normRank, addSnap, lpSeries, lpEvents, todayLp, normMatch, overview, champStats, roleStats, partnerStats, attrLp, banPicks, compAnalysis, mkFilter, laneRole, LCU_OK, parseItems, buildItemAdvice, SUSTAIN, parseMu, aggMu, muRankSet, MU_RANKS, MU_ALL, MU_SLOTS };
})();

/* --- Uygulama Akisi (Kovan 'Uygulama Akisi' v0.0.1) ---
 * Kovan'in sag kenarindaki akan sutunun uygulama listesi. Kullanici Discord, Steam, Medal, League, tarayici gibi uygulamalari ekler; sutundan tiklayinca acilir.
 * Guvenlik: dosya yolunu/adresi arayuz GONDEREMEZ. Uygulama yalniz host dialogundan (kullanicinin kendi secimi) veya Baslat menusu taramasindan (arayuz yalniz
 * kimlik "sid" gonderir) eklenir; acma yalniz kayitli kimlikle olur. Yalniz .exe/.lnk/.url, UNC/ag yolu reddedilir, web girisi yalniz https. Komut satiri/arguman YOK,
 * shell YOK: dosya isletim sistemine openPath ile (cift tiklamayla ayni) acilir. Oyuna/belleğe/baska sürece dokunmaz, ag istegi yapmaz. */
/* Saf JS .lnk hedef okuyucu (MS-SHLLINK). Electron'un yerel shell.readShortcutLink'i toplu cagrida butun uygulamayi kapatabiliyordu; bu hicbir yerel kod cagirmaz, bozuk dosyada null doner. */
function readLnkTarget(file) {
  try {
    const fs = require('fs'); const st = fs.statSync(file); if (!st.isFile() || st.size < 0x4c || st.size > 262144) return null;
    const b = fs.readFileSync(file); if (b.readUInt32LE(0) !== 0x4c) return null;
    const flags = b.readUInt32LE(0x14); let o = 0x4c;
    if (flags & 1) { if (o + 2 > b.length) return null; o += 2 + b.readUInt16LE(o); }
    if (!(flags & 2) || o + 28 > b.length) return null;
    const size = b.readUInt32LE(o), hdr = b.readUInt32LE(o + 4), lf = b.readUInt32LE(o + 8);
    if (size < 28 || o + size > b.length || !(lf & 1)) return null;
    const rd = (off, uni) => { let e = off; if (uni) { while (e + 1 < o + size && (b[e] || b[e + 1])) e += 2; return b.toString('utf16le', off, e); } while (e < o + size && b[e]) e++; return b.toString('latin1', off, e); };
    const baseOff = b.readUInt32LE(o + 16), sufOff = b.readUInt32LE(o + 24);
    let base = '', suf = '';
    if (hdr >= 0x24 && o + 36 <= b.length) { const bu = b.readUInt32LE(o + 28), su = b.readUInt32LE(o + 32); if (bu) base = rd(o + bu, true); if (su) suf = rd(o + su, true); }
    if (!base && baseOff) base = rd(o + baseOff, false);
    if (!suf && sufOff) suf = rd(o + sufOff, false);
    const t = (base + suf).trim(); return t && t.length < 1024 ? { target: t } : null;
  } catch (e) { return null; }
}
const FLOWMOD = (() => {
  const fs = require('fs'); const path = require('path'); const crypto = require('crypto');
  const MAX_APPS = 24; const APP_EXT = /\.(exe|lnk|url)$/i; const ID_RE = /^[0-9a-f]{12}$/; const SID_RE = /^[0-9a-f]{10}$/;
  /* Baslat menusu taramasinda aranan tanidik uygulama adlari (yalniz kisayol adi eslesmesi; baska hicbir sey okunmaz) */
  const KNOWN = [/^discord/i, /^steam$/i, /^medal/i, /league of legends/i, /^riot client/i, /^google chrome$/i, /^firefox/i, /^microsoft edge$/i, /^brave/i, /^opera/i, /^spotify/i, /^obs studio/i, /^epic games launcher$/i, /battle\.net/i, /^whatsapp/i, /^telegram/i, /^visual studio code$/i, /^notepad\+\+$/i];
  const SKIP_SM = /(uninstall|kald[ıi]r|readme|release notes|documentation|dok[uü]man|help\b|yard[ıi]m|web ?site|web sitesi|license|lisans|manual|k[ıi]lavuz)/i;
  const cleanName = (s) => { if (typeof s !== 'string') return null; const v = s.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 40); return v || null; };
  const isUnc = (p) => /^[\\/]{2}/.test(p);
  function validWeb(u) {
    if (typeof u !== 'string' || u.length > 300) return null; let x; try { x = new URL(u.trim()); } catch (e) { return null; }
    if (x.protocol !== 'https:' || x.username || x.password || !x.hostname || !/\./.test(x.hostname)) return null; return x.href;
  }
  function createFlowHost(deps) {
    deps = deps || {}; const isWin = () => (deps.platform || process.platform) === 'win32'; const now = deps.now || (() => Date.now());
    const stateFile = deps.dataDir ? path.join(deps.dataDir, 'uygulamaakisi.json') : null;
    const errE = (message, extra) => Object.assign({ error: 'flow', message }, extra || {});
    let state = { v: 1, apps: [] };
    if (stateFile) { try { const o = JSON.parse(fs.readFileSync(stateFile, 'utf8')); if (o && Array.isArray(o.apps)) state.apps = o.apps.filter((a) => a && ID_RE.test(String(a.id)) && cleanName(a.name) && ((a.kind === 'app' && typeof a.path === 'string') || (a.kind === 'web' && validWeb(a.url)))).slice(0, MAX_APPS).map((a) => (a.kind === 'app' ? { id: a.id, name: cleanName(a.name), kind: 'app', path: a.path } : { id: a.id, name: cleanName(a.name), kind: 'web', url: validWeb(a.url) })); } catch (e) { /* ilk kullanim */ } }
    const save = () => { if (!stateFile) return; try { fs.mkdirSync(path.dirname(stateFile), { recursive: true }); const t = stateFile + '.tmp'; fs.writeFileSync(t, JSON.stringify(state)); fs.renameSync(t, stateFile); } catch (e) { /* bellekte kalir */ } };
    const iconCache = new Map(); const sugg = new Map(); const lastOpen = new Map();
    const norm = (p) => (isWin() ? path.normalize(p).toLowerCase() : path.normalize(p));
    function okPath(p) { if (typeof p !== 'string' || p.length > 1024 || p.indexOf('\0') >= 0) return 'Geçersiz yol.'; if (!path.isAbsolute(p) || isUnc(p)) return 'Yalnızca bu bilgisayardaki dosyalar eklenebilir.'; if (!APP_EXT.test(p)) return 'Yalnızca .exe, .lnk veya .url dosyası eklenebilir.'; let st; try { st = fs.statSync(p); } catch (e) { return 'Dosya bulunamadı.'; } return st.isFile() ? '' : 'Bir dosya seçmelisin.'; }
    const newId = () => { let id; do { id = crypto.randomBytes(6).toString('hex'); } while (state.apps.some((a) => a.id === id)); return id; };
    async function iconOf(p) {
      if (!deps.fileIcon) return null; if (iconCache.has(p)) return iconCache.get(p);
      let v = null; try { const r = await deps.fileIcon(p); if (typeof r === 'string' && /^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(r) && r.length <= 200000) v = r; } catch (e) { v = null; }
      iconCache.set(p, v); return v;
    }
    async function pub() {
      const out = []; for (const a of state.apps) { if (a.kind === 'web') { out.push({ id: a.id, name: a.name, kind: 'web', host: new URL(a.url).hostname.replace(/^www\./, ''), icon: null, missing: false }); continue; } const miss = !!okPath(a.path); out.push({ id: a.id, name: a.name, kind: 'app', icon: miss ? null : await iconOf(a.path), missing: miss }); }
      return { apps: out, max: MAX_APPS, windows: isWin() };
    }
    const find = (id) => (typeof id === 'string' && ID_RE.test(id) ? state.apps.find((a) => a.id === id) : null);
    function addApp(p, name) {
      if (state.apps.length >= MAX_APPS) return errE('En fazla ' + MAX_APPS + ' uygulama eklenebilir.');
      const e = okPath(p); if (e) return errE(e); if (state.apps.some((a) => a.kind === 'app' && norm(a.path) === norm(p))) return errE('Bu uygulama zaten listede.');
      const nm = cleanName(name) || cleanName(path.basename(p).replace(APP_EXT, '')) || 'Uygulama'; state.apps.push({ id: newId(), name: nm, kind: 'app', path: path.normalize(p) }); save(); return null;
    }
    function scanStart() {
      const dirs = deps.startMenuDirs || (isWin() ? [process.env.ProgramData && path.join(process.env.ProgramData, 'Microsoft', 'Windows', 'Start Menu', 'Programs'), process.env.APPDATA && path.join(process.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs')].filter(Boolean) : []);
      const found = new Map(); let budget = 3000;
      const walk = (d, depth) => { if (depth > 3 || budget <= 0) return; let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { return; }
        for (const en of ents) { if (budget-- <= 0) return; const full = path.join(d, en.name); if (en.isDirectory()) walk(full, depth + 1); else if (en.isFile() && /\.lnk$/i.test(en.name)) { const nm = cleanName(en.name.replace(/\.lnk$/i, '')); if (nm && !SKIP_SM.test(nm) && !found.has(nm.toLowerCase())) found.set(nm.toLowerCase(), { name: nm, path: full, known: KNOWN.some((re) => re.test(nm)) }); } } };
      for (const d of dirs) walk(d, 0); /* tanidik uygulamalar (Discord, Steam...) once, sonra alfabetik; tum Baslat menusu aranabilir */ return [...found.values()].sort((a, b) => (a.known === b.known ? a.name.localeCompare(b.name) : a.known ? -1 : 1)).slice(0, 400);
    }
    const handlers = {
      'flow:list': async () => { try { return await pub(); } catch (e) { return errE(String(e && e.message || e)); } },
      'flow:add': async () => {
        try { if (!deps.chooseApp) return errE('Dosya seçimi kullanılamıyor.'); const p = await deps.chooseApp(); if (!p) return { canceled: true }; const e = addApp(String(p), null); if (e) return e; return await pub(); } catch (e) { return errE(String(e && e.message || e)); }
      },
      'flow:addWeb': async (_e, name, url) => {
        try { if (state.apps.length >= MAX_APPS) return errE('En fazla ' + MAX_APPS + ' uygulama eklenebilir.'); const u = validWeb(url); if (!u) return errE('Geçerli bir https:// adresi gir (ör. https://ornek.com).'); if (state.apps.some((a) => a.kind === 'web' && a.url === u)) return errE('Bu adres zaten listede.');
          const nm = cleanName(name) || new URL(u).hostname.replace(/^www\./, ''); state.apps.push({ id: newId(), name: nm, kind: 'web', url: u }); save(); return await pub(); } catch (e) { return errE(String(e && e.message || e)); }
      },
      'flow:suggest': async () => {
        try { sugg.clear(); const items = []; if (isWin() || deps.startMenuDirs) for (const f of scanStart()) { const sid = crypto.randomBytes(5).toString('hex'); sugg.set(sid, f.path); let loc = ''; try { const r = (deps.readShortcut || readLnkTarget)(f.path); if (r && typeof r.target === 'string' && r.target) loc = path.dirname(r.target); } catch (e) { loc = ''; } items.push({ sid, name: f.name, location: loc, known: !!f.known, already: state.apps.some((a) => a.kind === 'app' && norm(a.path) === norm(f.path)) }); }
          return { items, windows: isWin() || !!deps.startMenuDirs }; } catch (e) { return errE(String(e && e.message || e)); }
      },
      'flow:addSuggested': async (_e, sid) => {
        try { const p = typeof sid === 'string' && SID_RE.test(sid) ? sugg.get(sid) : null; if (!p) return errE('Öneri bulunamadı; listeyi yenile.'); const nm = cleanName(path.basename(p).replace(APP_EXT, '')); const e = addApp(p, nm); if (e) return e; return await pub(); } catch (e) { return errE(String(e && e.message || e)); }
      },
      'flow:rename': async (_e, id, name) => { try { const a = find(id); if (!a) return errE('Uygulama bulunamadı.'); const nm = cleanName(name); if (!nm) return errE('Ad boş olamaz.'); a.name = nm; save(); return await pub(); } catch (e) { return errE(String(e && e.message || e)); } },
      'flow:remove': async (_e, id) => { try { const a = find(id); if (!a) return errE('Uygulama bulunamadı.'); state.apps = state.apps.filter((x) => x !== a); save(); return await pub(); } catch (e) { return errE(String(e && e.message || e)); } },
      'flow:order': async (_e, ids) => {
        try { if (!Array.isArray(ids)) return errE('Geçersiz sıra.'); const seen = new Set(); const next = []; for (const id of ids.slice(0, MAX_APPS)) { const a = find(id); if (a && !seen.has(a.id)) { seen.add(a.id); next.push(a); } } for (const a of state.apps) if (!seen.has(a.id)) next.push(a); state.apps = next; save(); return await pub(); } catch (e) { return errE(String(e && e.message || e)); }
      },
      'flow:open': async (_e, id) => {
        try {
          const a = find(id); if (!a) return errE('Uygulama bulunamadı.'); const t = now(); if (t - (lastOpen.get(a.id) || 0) < 800) return { ok: true, name: a.name, skipped: true }; lastOpen.set(a.id, t);
          if (a.kind === 'web') { const u = validWeb(a.url); if (!u || !deps.openExternal) return errE('Adres açılamadı.'); await deps.openExternal(u); return { ok: true, name: a.name }; }
          const e = okPath(a.path); if (e) return errE(a.name + ': ' + e, { missing: true }); if (!deps.openPath) return errE('Uygulama açma kullanılamıyor.');
          const r = await deps.openPath(a.path); if (typeof r === 'string' && r) return errE(a.name + ' açılamadı: ' + r.slice(0, 200)); return { ok: true, name: a.name };
        } catch (e) { return errE(String(e && e.message || e)); }
      }
    };
    return { handlers, _state: () => state };
  }
  return { createFlowHost, cleanName, validWeb, KNOWN, MAX_APPS };
})();

/* --- Otomatik Guncelleyici (Kovan 'upd'): kullanicinin sectigi uygulamalar icin winget ile guncelleme kontrolu + onayli guncelleme ---
 * Uygulamalari KENDISI bulur: Baslat menusundeki tum kisayollar taranir, her kisayolun hedefinden uygulamanin kurulu klasoru okunur (exe aramak gerekmez).
 * Guncelleme kontrolu 'winget upgrade' / 'winget list' ciktisini okur (yalniz okuma). Guncelleme 'winget upgrade --id <kimlik> -e --silent' ile yapilir:
 * kabuk YOK (execFile), kimlik yalniz bu hostun kendi kontrolunden gelir (arayuz kimlik/yol/komut gonderemez), her guncelleme arayuzde onaydan sonra baslar.
 * winget bilmeyen uygulamalar (kendi kendini guncelleyenler: Roblox, bazen Discord) icin durust 'bilinmiyor' doner; uydurma sonuc yok. */
const UPDMOD = (() => {
  const fs = require('fs'); const path = require('path'); const crypto = require('crypto'); const cp = require('child_process');
  const MAX_APPS = 30; const ID_RE = /^[0-9a-f]{12}$/; const SID_RE = /^[0-9a-f]{10}$/; const WID_RE = /^[A-Za-z0-9][A-Za-z0-9._+\-]{1,100}$/; const APP_EXT = /\.(exe|lnk)$/i;
  const SKIP = /(uninstall|kald[ıi]r|readme|release notes|documentation|dok[uü]man|help\b|yard[ıi]m|web ?site|web sitesi|license|lisans|manual|k[ıi]lavuz)/i;
  const NOT_APPLICABLE = -1978335189; /* 0x8A15002B: uygulanabilir guncelleme yok */
  const cleanName = (s) => { if (typeof s !== 'string') return null; const v = s.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 40); return v || null; };
  const nrm = (s) => String(s || '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, '');
  /* winget tablosu: baslik sutun konumlari (dil bagimsiz) + tire satiri; ilerleme/spinner satirlari atilir */
  function parseTable(text) {
    const lines = String(text || '').split(/\r?\n/).map((l) => { const i = l.lastIndexOf('\r'); return (i >= 0 ? l.slice(i + 1) : l).replace(/\s+$/, ''); });
    const di = lines.findIndex((l, i) => i > 0 && /^-{8,}$/.test(l.trim()) && lines[i - 1].trim()); if (di < 0) return [];
    const head = lines[di - 1]; let pos = [...head.matchAll(/\S+/g)].map((m) => m.index);
    if (pos.length < 3 || pos.length > 5) pos = [...head.matchAll(/\S+(?: \S+)*/g)].map((m) => m.index); if (pos.length < 3) return [];
    const cut = (l, k) => (l.slice(pos[k], k + 1 < pos.length ? pos[k + 1] : undefined) || '').trim(); const rows = [];
    for (let i = di + 1; i < lines.length; i++) { const l = lines[i]; if (!l.trim()) { if (rows.length) break; continue; } if (l.length <= pos[1]) continue;
      const c3 = pos.length >= 4 ? cut(l, 3) : ''; const hasAv = pos.length >= 5 || /\d/.test(c3); const r = { name: cut(l, 0), id: cut(l, 1), version: cut(l, 2), available: hasAv ? c3 : '', source: pos.length >= 5 ? cut(l, 4) : (hasAv ? '' : c3) };
      if (r.name && WID_RE.test(r.id) && /\d/.test(r.version)) rows.push(r); }
    return rows;
  }
  function pickRow(rows, app) {
    if (app.wid) { const r = rows.find((x) => x.id.toLowerCase() === app.wid.toLowerCase()); if (r) return r; }
    const exact = rows.filter((r) => nrm(r.name) === nrm(app.name)); if (exact.length) return exact[0];
    const n = nrm(app.name); if (n.length < 4) return null; const pre = rows.filter((r) => { const m = nrm(r.name); return m.length >= 4 && (m.startsWith(n) || n.startsWith(m)); }); return pre.length === 1 ? pre[0] : null;
  }
  const dirOf = (p) => { try { return path.dirname(p); } catch (e) { return ''; } };
  function createUpdHost(deps) {
    deps = deps || {}; const isWin = () => (deps.platform || process.platform) === 'win32'; const now = deps.now || (() => Date.now());
    const stateFile = deps.dataDir ? path.join(deps.dataDir, 'guncelleyici.json') : null; const errE = (message, extra) => Object.assign({ error: 'upd', message }, extra || {});
    let state = { v: 1, apps: [] };
    if (stateFile) { try { const o = JSON.parse(fs.readFileSync(stateFile, 'utf8')); if (o && Array.isArray(o.apps)) state.apps = o.apps.filter((a) => a && ID_RE.test(String(a.id)) && cleanName(a.name) && typeof a.path === 'string').slice(0, MAX_APPS).map((a) => ({ id: a.id, name: cleanName(a.name), path: a.path, wid: typeof a.wid === 'string' && WID_RE.test(a.wid) ? a.wid : null })); } catch (e) { /* ilk calistirma */ } }
    const save = () => { if (!stateFile) return; try { fs.mkdirSync(path.dirname(stateFile), { recursive: true }); const t = stateFile + '.tmp'; fs.writeFileSync(t, JSON.stringify(state)); fs.renameSync(t, stateFile); } catch (e) { /* bellekte kalir */ } };
    const find = (id) => (typeof id === 'string' && ID_RE.test(id) ? state.apps.find((a) => a.id === id) : null);
    const newId = () => { let id; do { id = crypto.randomBytes(6).toString('hex'); } while (state.apps.some((a) => a.id === id)); return id; };
    const norm = (p) => (isWin() ? path.normalize(p).toLowerCase() : path.normalize(p));
    const iconCache = new Map(); const sugg = new Map(); const pending = new Map(); let upCache = null; let busy = false;
    const run = deps.run || ((args, timeout) => new Promise((resolve) => { cp.execFile('winget', args, { windowsHide: true, timeout: timeout || 60000, maxBuffer: 4 * 1024 * 1024, encoding: 'utf8' }, (err, stdout, stderr) => resolve({ code: err ? (typeof err.code === 'number' ? err.code : (err.code === 'ENOENT' ? 'ENOENT' : -1)) : 0, stdout: String(stdout || ''), stderr: String(stderr || ''), killed: !!(err && err.killed) })); }));
    async function iconOf(p) { if (!deps.fileIcon) return null; if (iconCache.has(p)) return iconCache.get(p); let v = null; try { const r = await deps.fileIcon(p); if (typeof r === 'string' && /^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(r) && r.length <= 200000) v = r; } catch (e) { v = null; } iconCache.set(p, v); return v; }
    const exists = (p) => { try { return fs.statSync(p).isFile(); } catch (e) { return false; } };
    async function pub() { const out = []; for (const a of state.apps) { const miss = !exists(a.path); out.push({ id: a.id, name: a.name, icon: miss ? null : await iconOf(a.path), missing: miss }); } return { apps: out, max: MAX_APPS, windows: isWin() }; }
    function scanStart() {
      const dirs = deps.startMenuDirs || (isWin() ? [process.env.ProgramData && path.join(process.env.ProgramData, 'Microsoft', 'Windows', 'Start Menu', 'Programs'), process.env.APPDATA && path.join(process.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs')].filter(Boolean) : []);
      const found = new Map(); let budget = 5000;
      const walk = (d, depth) => { if (depth > 3 || budget <= 0) return; let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { return; }
        for (const en of ents) { if (budget-- <= 0) return; const full = path.join(d, en.name); if (en.isDirectory()) walk(full, depth + 1); else if (en.isFile() && /\.lnk$/i.test(en.name)) { const nm = cleanName(en.name.replace(/\.lnk$/i, '')); if (nm && !SKIP.test(nm) && !found.has(nm.toLowerCase())) found.set(nm.toLowerCase(), { name: nm, path: full }); } } };
      for (const d of dirs) walk(d, 0); return [...found.values()].sort((a, b) => a.name.localeCompare(b.name)).slice(0, 400);
    }
    function locationOf(lnk) { let t = null; try { const r = (deps.readShortcut || readLnkTarget)(lnk); if (r && typeof r.target === 'string' && r.target) t = r.target; } catch (e) { t = null; } if (!t) return { loc: '', target: null }; return { loc: dirOf(t), target: t }; }
    async function upgrades() { if (upCache && now() - upCache.t < 60000) return upCache.r; const r = await run(['upgrade', '--accept-source-agreements', '--disable-interactivity'], 90000); if (r.code === 'ENOENT') return { nowinget: true }; const v = { rows: parseTable(r.stdout), code: r.code }; upCache = { t: now(), r: v }; return v; }
    const handlers = {
      'upd:list': async () => { try { return await pub(); } catch (e) { return errE(String(e && e.message || e)); } },
      'upd:discover': async () => {
        try { sugg.clear(); const items = []; const t0 = Date.now(); let k = 0;
          if (isWin() || deps.startMenuDirs) for (const f of scanStart()) {
            const sid = crypto.randomBytes(5).toString('hex'); sugg.set(sid, f.path);
            /* kurulu klasor: kisayol hedefi okunur; ana surec donmasin diye araya soluk verilir ve 3 sn'yi asarsa kalanlarda klasor bos kalir */
            let lc = { loc: '' }; if (Date.now() - t0 < 3000) { lc = locationOf(f.path); if (++k % 20 === 0) await new Promise((r) => setImmediate(r)); }
            items.push({ sid, name: f.name, location: lc.loc, already: state.apps.some((a) => norm(a.path) === norm(f.path) || a.name.toLowerCase() === f.name.toLowerCase()) }); }
          return { items, windows: isWin() || !!deps.startMenuDirs }; } catch (e) { return errE(String(e && e.message || e)); }
      },
      'upd:add': async (_e, sid) => {
        try { const p = typeof sid === 'string' && SID_RE.test(sid) ? sugg.get(sid) : null; if (!p) return errE('Öneri bulunamadı; listeyi yenile.'); if (state.apps.length >= MAX_APPS) return errE('En fazla ' + MAX_APPS + ' uygulama eklenebilir.');
          if (state.apps.some((a) => norm(a.path) === norm(p))) return errE('Bu uygulama zaten listede.'); state.apps.push({ id: newId(), name: cleanName(path.basename(p).replace(APP_EXT, '')) || 'Uygulama', path: path.normalize(p), wid: null }); save(); return await pub(); } catch (e) { return errE(String(e && e.message || e)); }
      },
      'upd:addFile': async () => {
        try { if (!deps.chooseApp) return errE('Dosya seçimi kullanılamıyor.'); const p0 = await deps.chooseApp(); if (!p0) return { canceled: true }; const p = String(p0);
          if (typeof p !== 'string' || p.length > 1024 || !path.isAbsolute(p) || /^[\\/]{2}/.test(p) || !APP_EXT.test(p) || !exists(p)) return errE('Yalnızca bu bilgisayardaki .exe veya .lnk dosyası eklenebilir.');
          if (state.apps.length >= MAX_APPS) return errE('En fazla ' + MAX_APPS + ' uygulama eklenebilir.'); if (state.apps.some((a) => norm(a.path) === norm(p))) return errE('Bu uygulama zaten listede.');
          state.apps.push({ id: newId(), name: cleanName(path.basename(p).replace(APP_EXT, '')) || 'Uygulama', path: path.normalize(p), wid: null }); save(); return await pub(); } catch (e) { return errE(String(e && e.message || e)); }
      },
      'upd:remove': async (_e, id) => { try { const a = find(id); if (!a) return errE('Uygulama bulunamadı.'); state.apps = state.apps.filter((x) => x !== a); pending.delete(a.id); save(); return await pub(); } catch (e) { return errE(String(e && e.message || e)); } },
      'upd:check': async (_e, id) => {
        try {
          const a = find(id); if (!a) return errE('Uygulama bulunamadı.'); if (!isWin() && !deps.run) return { status: 'unsupported', name: a.name }; if (busy) return errE('Bir güncelleme sürüyor; bitmesini bekle.');
          pending.delete(a.id); const up = await upgrades(); if (up.nowinget) return { status: 'nowinget', name: a.name };
          const hit = pickRow(up.rows || [], a);
          if (hit) { if (a.wid !== hit.id) { a.wid = hit.id; save(); } pending.set(a.id, { wid: hit.id, t: now() }); return { status: 'available', name: a.name, current: hit.version, available: hit.available }; }
          const q = a.name.replace(/^-+/, '').trim(); const lr = await run(['list', '-q', q, '--accept-source-agreements', '--disable-interactivity'], 60000); if (lr.code === 'ENOENT') return { status: 'nowinget', name: a.name };
          const row = pickRow(parseTable(lr.stdout), a);
          if (row) { if (a.wid !== row.id) { a.wid = row.id; save(); } return { status: 'current', name: a.name, current: row.version }; }
          return { status: 'unknown', name: a.name };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'upd:apply': async (_e, id) => {
        try {
          const a = find(id); if (!a) return errE('Uygulama bulunamadı.'); const p = pending.get(a.id); if (!p || now() - p.t > 30 * 60 * 1000) return errE('Önce güncelleme kontrolü yap.'); if (!WID_RE.test(p.wid)) return errE('Geçersiz paket kimliği.'); if (busy) return errE('Bir güncelleme zaten sürüyor.');
          busy = true; let r; try { r = await run(['upgrade', '--id', p.wid, '-e', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity'], 15 * 60 * 1000); } finally { busy = false; }
          upCache = null; if (r.code === 'ENOENT') return { status: 'nowinget', name: a.name };
          if (r.code === 0) { pending.delete(a.id); return { status: 'updated', name: a.name }; }
          if (r.code === NOT_APPLICABLE) { pending.delete(a.id); return { status: 'current', name: a.name }; }
          const tail = String(r.stdout || r.stderr || '').split(/\r?\n/).map((l) => { const i = l.lastIndexOf('\r'); return (i >= 0 ? l.slice(i + 1) : l).trim(); }).filter((l) => l && !/^[-\\|/ ]+$/.test(l)).slice(-2).join(' ').slice(0, 200);
          return { status: 'failed', name: a.name, code: typeof r.code === 'number' ? r.code : null, killed: !!r.killed, detail: tail };
        } catch (e) { busy = false; return errE(String(e && e.message || e)); }
      }
    };
    return { handlers, _state: () => state };
  }
  return { createUpdHost, parseTable, pickRow, cleanName, MAX_APPS };
})();

/* --- Depodan dogrudan guncelleme (REPOMOD; latest.json/.ssu YERINE) ---
 * GitHub'daki yigido213/StatScan main dalinin `app/` klasorunu dogrudan bilgisayara indirir (userData/kovan-repo/builds/<agac>), sonraki acilista
 * app.js oradan calistirir. Surum kimligi = `app` klasorunun git agac sha'si (yalniz app/ degisince guncelleme sayilir). Ag: yalniz api.github.com +
 * raw.githubusercontent.com (commit'e sabitli adres). Her dosya git blob sha1'i agac listesiyle ESLESMEDEN yazilmaz; yol/uzanti/boyut/mod denetimi;
 * .js ve HTML icindeki betikler yalniz DERLENIR (calistirilmaz) — bozuk push kimsenin uygulamasini bozmasin. Acilista dosyalar yeniden dogrulanir;
 * iki basarisiz acilistan sonra onceki yapiya (yoksa uygulamayla gelene) donulur. KABUK/EXEC YOK. UYARI: imza yok; guven kokü = GitHub hesabi/main dali. */
const REPOMOD = (() => {
  const fs = require('fs'); const path = require('path'); const crypto = require('crypto'); const https = require('https'); const vm = require('vm');
  const SRC = { owner: 'yigido213', repo: 'StatScan', branch: 'main', dir: 'app' };
  const LIM = { files: 60, file: 8 * 1024 * 1024, total: 32 * 1024 * 1024, json: 4 * 1024 * 1024, ms: 20000, tries: 2, bad: 20 };
  const REQUIRED = ['StatScan.html', 'desktop/app.js', 'desktop/host.js', 'desktop/preload.js', 'dyn/statscan-dyn.js'];
  const EXT_OK = /\.(js|cjs|mjs|html|json|md|ps1|png|ico|css|svg|txt)$/i; const SEG_OK = /^[A-Za-z0-9_\-][A-Za-z0-9._\-]*$/; const SHA_RE = /^[0-9a-f]{40}$/;
  const HOSTS = new Set(['api.github.com', 'raw.githubusercontent.com']); const API = 'https://api.github.com'; const META = '.kovan-build.json';
  const sha1Blob = (buf) => crypto.createHash('sha1').update('blob ' + buf.length + '\0').update(buf).digest('hex');
  const rootOf = (dataDir) => path.join(dataDir, 'kovan-repo'); const buildsOf = (dataDir) => path.join(rootOf(dataDir), 'builds'); const stateFile = (dataDir) => path.join(rootOf(dataDir), 'state.json');
  const emptyState = () => ({ v: 1, current: null, previous: null, checked: null, boot: null, bad: [], lastRollback: null });
  function readState(dataDir) {
    try { const s = JSON.parse(fs.readFileSync(stateFile(dataDir), 'utf8')); if (!s || typeof s !== 'object' || s.v !== 1) return emptyState();
      const ok = (e) => e && typeof e === 'object' && SHA_RE.test(e.tree) && SHA_RE.test(e.commit) && /^[0-9a-f]{12}$/.test(e.dir);
      return { v: 1, current: ok(s.current) ? s.current : null, previous: ok(s.previous) ? s.previous : null, checked: s.checked && SHA_RE.test(s.checked.commit) && SHA_RE.test(s.checked.tree) ? s.checked : null, boot: s.boot && SHA_RE.test(s.boot.tree) && Number.isInteger(s.boot.tries) ? s.boot : null, bad: Array.isArray(s.bad) ? s.bad.filter((x) => SHA_RE.test(x)).slice(-LIM.bad) : [], lastRollback: s.lastRollback && typeof s.lastRollback === 'object' ? { tree: String(s.lastRollback.tree || ''), why: String(s.lastRollback.why || '').slice(0, 200), at: Number(s.lastRollback.at) || 0 } : null };
    } catch (e) { return emptyState(); }
  }
  function writeState(dataDir, st) { fs.mkdirSync(rootOf(dataDir), { recursive: true }); const f = stateFile(dataDir); const t = f + '.tmp'; fs.writeFileSync(t, JSON.stringify(st, null, 1)); fs.renameSync(t, f); }
  /* Yapi dosyalarini meta ile yeniden dogrular (boyut + sha1); bozuk/eksik/fazla dosya = false */
  function buildOk(dataDir, entry) {
    try { const dir = path.join(buildsOf(dataDir), entry.dir); const meta = JSON.parse(fs.readFileSync(path.join(dir, META), 'utf8'));
      if (!meta || meta.tree !== entry.tree || !meta.files || typeof meta.files !== 'object') return false; const rels = Object.keys(meta.files); if (!REQUIRED.every((r) => rels.includes(r))) return false;
      for (const r of rels) { const m = meta.files[r]; const buf = fs.readFileSync(path.join(dir, ...r.split('/'))); if (buf.length !== m.size || sha1Blob(buf) !== m.sha) return false; } return true;
    } catch (e) { return false; }
  }
  function rollbackState(st, why) {
    if (st.current) { st.bad = st.bad.concat(st.current.tree).filter((x, i, a) => a.indexOf(x) === i).slice(-LIM.bad); st.lastRollback = { tree: st.current.tree, why: String(why || '').slice(0, 200), at: Date.now() }; }
    st.current = st.previous && !st.bad.includes(st.previous.tree) ? st.previous : null; st.previous = null; st.boot = null; return st;
  }
  function pruneBuilds(dataDir, st) {
    try { const keep = new Set([st.current && st.current.dir, st.previous && st.previous.dir].filter(Boolean)); const b = buildsOf(dataDir); for (const n of fs.readdirSync(b)) if (!keep.has(n)) fs.rmSync(path.join(b, n), { recursive: true, force: true }); } catch (e) { /* klasor yok: sorun degil */ }
  }
  /* Acilista: gecerli yapi varsa {root, info}; yoksa null (uygulamayla gelen calisir). Her acilista sayac artar; markGood sifirlar. */
  function pickBoot(o) {
    const dataDir = o && o.dataDir; if (!dataDir) return null;
    try { let st = readState(dataDir);
      for (let i = 0; i < 3; i++) {
        const cur = st.current; if (!cur) return null;
        if (!buildOk(dataDir, cur)) { st = rollbackState(st, 'dosyalar dogrulanamadi'); writeState(dataDir, st); continue; }
        const same = st.boot && st.boot.tree === cur.tree; const tries = same ? st.boot.tries : 0;
        if (tries >= LIM.tries) { st = rollbackState(st, 'arka arkaya ' + tries + ' acilis tamamlanamadi'); writeState(dataDir, st); continue; }
        st.boot = { tree: cur.tree, tries: tries + 1 }; writeState(dataDir, st); return { root: path.join(buildsOf(dataDir), cur.dir), info: { tree: cur.tree, commit: cur.commit, msg: cur.msg || '' } };
      } return null;
    } catch (e) { return null; }
  }
  function markGood(dataDir, tree) { try { const st = readState(dataDir); if (st.boot && st.boot.tree === tree) { st.boot.tries = 0; writeState(dataDir, st); } } catch (e) { /* yoksay */ } }
  function rollback(dataDir, why) { try { const st = rollbackState(readState(dataDir), why); writeState(dataDir, st); pruneBuilds(dataDir, st); return st.current ? { tree: st.current.tree } : null; } catch (e) { return null; } }
  function reset(dataDir) { try { fs.rmSync(rootOf(dataDir), { recursive: true, force: true }); return true; } catch (e) { return false; } }
  function status(dataDir) { const st = readState(dataDir); return { current: st.current ? { tree: st.current.tree, commit: st.current.commit, msg: st.current.msg || '', at: st.current.at || 0 } : null, hasPrevious: !!st.previous, bad: st.bad.length, lastRollback: st.lastRollback }; }

  /* Agac listesini dogrular; gecerli dosya listesi doner, sorun varsa Error firlatir (mesajda yol yok). */
  function validateTree(entries) {
    if (!Array.isArray(entries)) throw new Error('Depo agaci anlasilamadi.'); const files = []; const seen = new Set(); let total = 0;
    for (const e of entries) {
      if (!e || typeof e.path !== 'string') throw new Error('Depo agacinda gecersiz girdi.'); if (e.type === 'tree') continue;
      if (e.type !== 'blob' || (e.mode !== '100644' && e.mode !== '100755')) throw new Error('Depoda desteklenmeyen girdi turu (sembolik baglanti/alt modul).');
      const segs = e.path.split('/'); if (!segs.every((s) => SEG_OK.test(s) && s !== '.' && s !== '..')) throw new Error('Depoda gecersiz dosya yolu.');
      if (!EXT_OK.test(e.path)) throw new Error('Depoda izin verilmeyen dosya turu: .' + (/\.([^./]+)$/.exec(e.path) || [, '?'])[1].slice(0, 12));
      if (!SHA_RE.test(e.sha) || !Number.isInteger(e.size) || e.size < 0 || e.size > LIM.file) throw new Error('Depoda gecersiz veya cok buyuk dosya.');
      const low = e.path.toLowerCase(); if (seen.has(low)) throw new Error('Depoda ayni adli (buyuk/kucuk harf) dosyalar var.'); seen.add(low);
      total += e.size; if (files.length + 1 > LIM.files || total > LIM.total) throw new Error('Depo app/ klasoru beklenenden buyuk.'); files.push({ path: e.path, sha: e.sha, size: e.size });
    }
    for (const r of REQUIRED) if (!files.some((f) => f.path === r)) throw new Error('Depoda gerekli dosya eksik: ' + r); return files;
  }
  /* Yalniz DERLER (calistirmaz): .js/.cjs, HTML icindeki betikler, .json */
  function syntaxCheck(rel, buf) {
    const txt = buf.toString('utf8').replace(/^\uFEFF/, ''); /* BOM */
    if (/\.(js|cjs)$/i.test(rel)) { const t2 = txt.replace(/^#![^\n]*/, ''); /* shebang: Node'un kendi yukleyicisi de atar */ try { new vm.Script('(function (exports, require, module, __filename, __dirname) {' + t2 + '\n})', { filename: rel }); } catch (e) { throw new Error(rel + ' sozdizimi bozuk: ' + String(e && e.message || e).slice(0, 120)); } }
    else if (/\.json$/i.test(rel)) { try { JSON.parse(txt); } catch (e) { throw new Error(rel + ' gecerli JSON degil.'); } }
    else if (/\.html$/i.test(rel)) { const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi; let m; let i = 0;
      while ((m = re.exec(txt))) { i++; const at = m[1]; if (/\bsrc\s*=/i.test(at)) continue; const ty = /\btype\s*=\s*["']?([^"'\s>]+)/i.exec(at); if (ty && !/^(text|application)\/(javascript|ecmascript)$/i.test(ty[1])) continue;
        try { new vm.Script(m[2], { filename: rel + '#betik' + i }); } catch (e) { throw new Error(rel + ' icindeki betik #' + i + ' sozdizimi bozuk: ' + String(e && e.message || e).slice(0, 120)); } } }
  }
  function netGet(url, accept, max, hops) {
    return new Promise((resolve, reject) => {
      let u; try { u = new URL(url); } catch (e) { return reject(new Error('Gecersiz adres.')); } if (u.protocol !== 'https:' || !HOSTS.has(u.hostname)) return reject(new Error('Yalnizca GitHub adreslerine izin verilir.'));
      const req = https.get(u, { headers: { 'User-Agent': 'Kovan-Updater', Accept: accept }, timeout: LIM.ms }, (res) => {
        const sc = res.statusCode;
        if ([301, 302, 307, 308].includes(sc) && res.headers.location) { res.resume(); if ((hops || 0) >= 3) return reject(new Error('Cok fazla yonlendirme.')); let nu; try { nu = new URL(res.headers.location, u).toString(); } catch (e) { return reject(new Error('Yonlendirme gecersiz.')); } return resolve(netGet(nu, accept, max, (hops || 0) + 1)); }
        if (sc === 403 || sc === 429) { res.resume(); return reject(new Error(sc === 429 || res.headers['x-ratelimit-remaining'] === '0' ? 'GitHub istek siniri doldu; biraz sonra tekrar dene.' : 'GitHub erisimi reddetti (HTTP ' + sc + ').')); }
        if (sc !== 200) { res.resume(); return reject(new Error('GitHub yaniti: HTTP ' + sc)); }
        let n = 0; const ch = []; res.on('data', (c) => { n += c.length; if (n > max) { req.destroy(new Error('Yanit cok buyuk.')); return; } ch.push(c); }); res.on('end', () => resolve(Buffer.concat(ch))); res.on('error', reject);
      }); req.on('timeout', () => req.destroy(new Error('Zaman asimi.'))); req.on('error', reject);
    });
  }
  const enc = (rel) => rel.split('/').map(encodeURIComponent).join('/');
  /* Guncelleme denetimi + gerekirse indirme/hazirlama. Doner: {status:'current'|'staged'|'blocked', commit, tree, msg}. Hata = Error (mesaj kullaniciya gosterilebilir). */
  async function check(deps) {
    deps = deps || {}; const dataDir = deps.dataDir; if (!dataDir) throw new Error('dataDir gerekli');
    const getJson = deps.getJson || (async (u) => JSON.parse((await netGet(u, 'application/vnd.github+json', LIM.json)).toString('utf8')));
    const getBuf = deps.getBuf || ((u, max) => netGet(u, 'application/octet-stream', max)); const now = deps.now || (() => Date.now());
    const R = '/repos/' + SRC.owner + '/' + SRC.repo; const st = readState(dataDir);
    const ref = await getJson(API + R + '/git/ref/heads/' + SRC.branch); const commit = ref && ref.object && ref.object.sha; if (!SHA_RE.test(commit || '')) throw new Error('GitHub yaniti anlasilamadi (dal).');
    if (st.checked && st.checked.commit === commit) { if (st.bad.includes(st.checked.tree)) return { status: 'blocked', commit, tree: st.checked.tree }; if (st.current && st.current.tree === st.checked.tree && buildOk(dataDir, st.current)) return { status: 'current', commit, tree: st.current.tree }; }
    const cm = await getJson(API + R + '/git/commits/' + commit); const rt = cm && cm.tree && cm.tree.sha; if (!SHA_RE.test(rt || '')) throw new Error('GitHub yaniti anlasilamadi (commit).');
    const msg = String(cm.message || '').split('\n')[0].slice(0, 160);
    const root = await getJson(API + R + '/git/trees/' + rt); if (!root || !Array.isArray(root.tree) || root.truncated) throw new Error('Depo kok agaci okunamadi.');
    const ent = root.tree.find((e) => e && e.path === SRC.dir && e.type === 'tree' && e.mode === '040000'); if (!ent || !SHA_RE.test(ent.sha)) throw new Error('Depoda "' + SRC.dir + '" klasoru bulunamadi.'); const tree = ent.sha;
    st.checked = { commit, tree };
    if (st.bad.includes(tree)) { writeState(dataDir, st); return { status: 'blocked', commit, tree, msg }; }
    if (st.current && st.current.tree === tree && buildOk(dataDir, st.current)) { writeState(dataDir, st); return { status: 'current', commit, tree, msg }; }
    const t = await getJson(API + R + '/git/trees/' + tree + '?recursive=1'); if (!t || t.truncated) throw new Error('Depo app/ agaci okunamadi.'); const files = validateTree(t.tree);
    const got = [];
    for (const f of files) {
      const buf = await getBuf('https://raw.githubusercontent.com/' + SRC.owner + '/' + SRC.repo + '/' + commit + '/' + SRC.dir + '/' + enc(f.path), f.size + 16);
      if (!Buffer.isBuffer(buf) || buf.length !== f.size || sha1Blob(buf) !== f.sha) throw new Error('Indirilen dosya depo listesiyle eslesmedi: ' + f.path);
      syntaxCheck(f.path, buf); got.push({ f, buf });
    }
    const dirName = tree.slice(0, 12); const builds = buildsOf(dataDir); const stage = path.join(builds, 'staging-' + crypto.randomBytes(4).toString('hex')); const final = path.join(builds, dirName);
    try {
      fs.mkdirSync(stage, { recursive: true }); const meta = { v: 1, tree, commit, files: {} };
      for (const { f, buf } of got) { const dest = path.join(stage, ...f.path.split('/')); if (!dest.startsWith(stage + path.sep)) throw new Error('Gecersiz yol.'); fs.mkdirSync(path.dirname(dest), { recursive: true }); fs.writeFileSync(dest, buf); meta.files[f.path] = { sha: f.sha, size: f.size }; }
      fs.writeFileSync(path.join(stage, META), JSON.stringify(meta)); fs.rmSync(final, { recursive: true, force: true }); fs.renameSync(stage, final);
    } catch (e) { try { fs.rmSync(stage, { recursive: true, force: true }); } catch (e2) { /* yoksay */ } throw new Error('Yeni surum diske yazilamadi: ' + String(e && e.message || e).slice(0, 120)); }
    if (st.current && st.current.tree !== tree) st.previous = st.current; st.current = { tree, commit, dir: dirName, at: now(), msg }; st.boot = { tree, tries: 0 };
    writeState(dataDir, st); pruneBuilds(dataDir, st); return { status: 'staged', commit, tree, msg };
  }
  return { check, pickBoot, markGood, rollback, reset, status, validateTree, syntaxCheck, sha1Blob, buildOk, readState, LIM, SRC, REQUIRED };
})();

/* --- Oyun Ayarlayici (Kovan 'oyunayar' v0.0.1) ---
 * Steam + Epic kutuphanelerini ve calisan oyunu algilar; anti-cheat'li oyunlara ASLA dokunmaz; bir oyunun metin ayar dosyasini (.ini/.cfg/.conf)
 * ayar oncesi YEDEKLEYEREK degistirir; FPS'i PresentMon ile olcup hedef FPS'e gore ayar onerir. Oyunu calistirmaz, oyuna kod enjekte etmez, bellegine bakmaz.
 * Anahtar adlari UYDURULMAZ: "ogrenen profil" — kullanici oyunda Dusuk/Orta/Yuksek/Ultra secip "kaydet" der, ayar dosyalari arasindaki FARK ogrenilir.
 * Dosya yolunu arayuz GONDEREMEZ (yalniz oyun kimligi + sabit kanallar); ayar dosyasi host tarafinda dialogla secilir. Yalnizca MEVCUT anahtarlar yazilir (yeni anahtar eklenmez).
 * PresentMon GOMULMEZ/INDIRILMEZ: kullanicinin kendi kurulumu bulunur. Windows hedefli; hesaplama kisimlari saf fonksiyon olarak test edilir. */
const GAMEMOD = (() => {
  const fs = require('fs'); const fsp = fs.promises; const path = require('path'); const os = require('os'); const cp = require('child_process'); const crypto = require('crypto');
  let platOverride = null; const isWin = () => (platOverride || process.platform) === 'win32';
  const PRESETS = ['low', 'medium', 'high', 'ultra']; const PRESET_TR = { low: 'Düşük', medium: 'Orta', high: 'Yüksek', ultra: 'Ultra' };
  const LIM = { cfgBytes: 2 * 1024 * 1024, scanEntries: 3000, backups: 30, frames: 400000, minFrames: 120, seconds: [10, 120], defSeconds: 30, fps: [20, 360], games: 500, hist: 20, planRows: 400 };
  const ID_RE = /^(steam|epic|riot):[\w.\-]{1,100}$/;
  const isFile = (p) => { try { return fs.statSync(p).isFile(); } catch (e) { return false; } };
  const isDir = (p) => { try { return fs.statSync(p).isDirectory(); } catch (e) { return false; } };
  const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
  const lc = (p) => String(p || '').replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase();
  const errE = (message, extra) => Object.assign({ error: 'game', message }, extra || {});

  /* ---------- anti-cheat algilama (liste TAM DEGILDIR; bilinmeyen anti-cheat'i yakalamayabilir) ---------- */
  const AC_NAMES = [
    [/^easyanticheat/i, 'Easy Anti-Cheat'], [/^eac(launcher|_?eos|_?setup|_?client)/i, 'Easy Anti-Cheat'], [/^battleye$/i, 'BattlEye'], [/^be(service|client)/i, 'BattlEye'],
    [/^(vgc\.exe|vgk\.sys|riot ?vanguard)/i, 'Riot Vanguard'], [/^xigncode/i, 'XIGNCODE3'], [/^(npggnt|npgamemon|gameguard)/i, 'nProtect GameGuard'], [/^(pbsvc|pbsetup|punkbuster|pnkbstr)/i, 'PunkBuster'],
    [/^faceit/i, 'FACEIT'], [/^ricochet/i, 'Ricochet'], [/^javelin/i, 'Javelin Anti-Cheat'], [/^(mhyprot|hoyoprotect)/i, 'HoYoverse Protect'], [/^anticheatexpert/i, 'AntiCheatExpert'], [/^(anticheat|anti-cheat)/i, 'Anti-cheat']
  ];
  const AC_TITLES = [
    [/valorant/i, 'Riot Vanguard'], [/league of legends/i, 'Riot Vanguard'], [/rocket league/i, 'Easy Anti-Cheat'], [/fortnite/i, 'Easy Anti-Cheat / BattlEye'], [/apex legends/i, 'Easy Anti-Cheat'],
    [/counter-?strike|\bcs2\b|\bcsgo\b/i, 'VAC'], [/rainbow six/i, 'BattlEye'], [/pubg|battlegrounds/i, 'BattlEye'], [/call of duty|warzone/i, 'Ricochet'], [/destiny 2/i, 'BattlEye'],
    [/dead by daylight/i, 'Easy Anti-Cheat'], [/^rust$/i, 'Easy Anti-Cheat'], [/the finals/i, 'Easy Anti-Cheat'], [/marvel rivals/i, 'Anti-cheat']
  ];
  /* calisan surec adindan (Riot/Epic kutuphanesinde gorunmeyebilir) */
  const AC_PROCS = { 'valorant-win64-shipping.exe': 'Riot Vanguard', 'league of legends.exe': 'Riot Vanguard', 'leagueclient.exe': 'Riot Vanguard', 'rocketleague.exe': 'Easy Anti-Cheat', 'fortniteclient-win64-shipping.exe': 'Easy Anti-Cheat / BattlEye', 'r5apex.exe': 'Easy Anti-Cheat', 'cs2.exe': 'VAC', 'csgo.exe': 'VAC' };
  function detectAntiCheat(title, names) {
    const out = new Map();
    for (const n of names || []) for (const [re, label] of AC_NAMES) if (re.test(n)) { if (!out.has(label)) out.set(label, 'dosya: ' + n); break; }
    for (const [re, label] of AC_TITLES) if (re.test(title || '')) { if (!out.has(label)) out.set(label, 'oyun adı'); }
    return [...out].map(([name, why]) => ({ name, why }));
  }

  /* ---------- Valve KeyValues (libraryfolders.vdf / appmanifest_*.acf) ---------- */
  function parseVdf(text) {
    const re = /"((?:[^"\\]|\\.)*)"|([{}])|\/\/[^\n]*/g; const root = Object.create(null); const st = [root]; let key = null; let m;
    const un = (s) => s.replace(/\\(.)/g, (_, c) => (c === 'n' ? '\n' : c === 't' ? '\t' : c));
    while ((m = re.exec(String(text)))) {
      if (m[2] === '{') { const o = Object.create(null); if (key !== null) st[st.length - 1][key] = o; st.push(o); key = null; } else if (m[2] === '}') { if (st.length > 1) st.pop(); key = null; } else if (m[1] !== undefined) { const s = un(m[1]); if (key === null) key = s; else { st[st.length - 1][key] = s; key = null; } }
    }
    return root;
  }
  const SKIP_STEAM = /^(steamworks common|steam linux runtime|proton|steamvr|steam controller|wallpaper engine|source sdk)/i;

  /* ---------- INI/CFG: satir koruyan okuma-yazma ---------- */
  function iniParse(text) {
    text = String(text); const bom = text.charCodeAt(0) === 0xfeff; const body = bom ? text.slice(1) : text; const eol = body.includes('\r\n') ? '\r\n' : '\n'; const lines = body.split(/\r?\n/); const entries = []; const seen = new Map(); let sec = '';
    lines.forEach((ln, i) => {
      const t = ln.trim(); if (!t || t[0] === ';' || t[0] === '#' || t.startsWith('//')) return; const ms = /^\[(.*)\]$/.exec(t); if (ms) { sec = ms[1]; return; }
      const eq = ln.indexOf('='); if (eq < 1) return; const key = ln.slice(0, eq).trim(); if (!key) return; let id = sec + '/' + key; const n = (seen.get(id) || 0) + 1; seen.set(id, n); if (n > 1) id += '#' + n;
      entries.push({ i, sec, key, id, value: ln.slice(eq + 1).trim() });
    });
    return { lines, eol, bom, entries, byId: new Map(entries.map((e) => [e.id, e])) };
  }
  /* changes: Map id -> yeni deger. YALNIZCA var olan anahtarlar yazilir; olmayanlar missing'e gider. */
  function iniApply(parsed, changes) {
    const lines = parsed.lines.slice(); const applied = []; const missing = [];
    for (const [id, to] of changes) {
      const e = parsed.byId.get(id); if (!e) { missing.push(id); continue; } if (e.value === String(to)) continue;
      const ln = lines[e.i]; const eq = ln.indexOf('='); const rest = ln.slice(eq + 1); const lead = /^\s*/.exec(rest)[0]; lines[e.i] = ln.slice(0, eq + 1) + lead + String(to); applied.push({ id, key: e.key, sec: e.sec, from: e.value, to: String(to) });
    }
    return { text: (parsed.bom ? '\ufeff' : '') + lines.join(parsed.eol), applied, missing };
  }
  const snapOf = (parsed) => { const o = {}; for (const e of parsed.entries) o[e.id] = e.value; return o; };

  /* ---------- Unreal Engine yerlesik profil (ScalabilityGroups olcegi: 0 Dusuk, 1 Orta, 2 Yuksek, 3 Epic, 4 Sinematik) ---------- */
  const UE_KEYS = /^sg\.(ViewDistance|AntiAliasing|Shadow|GlobalIllumination|Reflection|PostProcess|Texture|Effects|Foliage|Shading)Quality$/i;
  const UE_LEVEL = { low: 0, medium: 1, high: 2, ultra: 3 };
  const ueScan = (parsed) => parsed.entries.filter((e) => UE_KEYS.test(e.key) && /^[0-4]$/.test(e.value));
  const isUe = (parsed) => ueScan(parsed).length >= 3;
  function ueChanges(parsed, preset) { const m = new Map(); for (const e of ueScan(parsed)) m.set(e.id, String(UE_LEVEL[preset])); return m; }
  /* ---------- cozunurluk ---------- */
  const RES_RE = /^(\s*)(\d{3,5})(\s*[x×*,\/ ]\s*)(\d{3,5})(\s*)$/;
  const RES_PAIRS = [['resolutionsizex', 'resolutionsizey'], ['lastuserconfirmedresolutionsizex', 'lastuserconfirmedresolutionsizey'], ['desiredscreenwidth', 'desiredscreenheight'], ['lastuserconfirmeddesiredscreenwidth', 'lastuserconfirmeddesiredscreenheight'], ['resolutionx', 'resolutiony'], ['resolutionwidth', 'resolutionheight'], ['screenwidth', 'screenheight'], ['windowwidth', 'windowheight'], ['displaywidth', 'displayheight'], ['resx', 'resy'], ['sizex', 'sizey'], ['width', 'height']];
  const okWH = (w, h) => w >= 320 && w <= 16384 && h >= 200 && h <= 16384;
  function findResolution(parsed) {
    const out = []; const ents = parsed.entries;
    for (const e of ents) { const m = RES_RE.exec(e.value); if (m && /res|size|screen|display|window|video|mode/i.test(e.key) && okWH(+m[2], +m[4])) out.push({ kind: 'combined', id: e.id, w: +m[2], h: +m[4] }); }
    const by = new Map(ents.map((e) => [e.sec + '\u0000' + e.key.toLowerCase(), e])); const secs = [...new Set(ents.map((e) => e.sec))];
    for (const [a, b] of RES_PAIRS) for (const sec of secs) { const ea = by.get(sec + '\u0000' + a); const eb = by.get(sec + '\u0000' + b); if (ea && eb && /^\d{3,5}$/.test(ea.value) && /^\d{3,5}$/.test(eb.value) && okWH(+ea.value, +eb.value)) out.push({ kind: 'pair', wId: ea.id, hId: eb.id, w: +ea.value, h: +eb.value }); }
    return out;
  }
  function resChanges(descs, w, h) {
    const ch = new Map();
    for (const d of descs) { if (d.kind === 'combined') { ch.set(d.id, { fn: (v) => { const m = RES_RE.exec(v); return m ? m[1] + w + m[3] + h + m[5] : v; } }); } else { ch.set(d.wId, String(w)); ch.set(d.hId, String(h)); } }
    return ch;
  }
  const STD_RES = [[3840, 2160], [2560, 1440], [1920, 1080], [1600, 900], [1280, 720], [960, 540]];
  function resLadder(w, h) {
    if (Math.abs(w / h - 16 / 9) < 0.02) { const l = STD_RES.filter(([x]) => x <= w); if (!l.length || l[0][0] !== w) l.unshift([w, h]); return l.map(([x, y]) => ({ w: x, h: y })); }
    return [1, 0.833, 0.667, 0.5].map((f) => ({ w: Math.round((w * f) / 2) * 2, h: Math.round((h * f) / 2) * 2 }));
  }

  /* ---------- ogrenen profil: snapshot farkindan on-ayar anahtarlari ---------- */
  const NOISE = /(date|time|stamp|guid|uuid|hash|session|token|lastplayed|playtime|count|seed|version|build|user|name|path|dir|folder|volume|sens|fov|language|locale|bind|key$|mouse|gamepad|subtitle|brightness|gamma)/i;
  function deriveLearned(snaps) {
    const have = PRESETS.filter((p) => snaps && snaps[p]); if (have.length < 2) return { presets: have, keys: [], skipped: [] };
    const ids = new Set(); for (const p of have) for (const id of Object.keys(snaps[p])) ids.add(id); const keys = []; const skipped = [];
    for (const id of ids) {
      if (!have.every((p) => id in snaps[p])) continue; const vals = {}; for (const p of have) vals[p] = snaps[p][id]; if (new Set(Object.values(vals)).size < 2) continue;
      if (Object.values(vals).some((v) => RES_RE.test(v))) { skipped.push({ id, why: 'çözünürlük (ayrı yönetilir)' }); continue; } if (NOISE.test(id.split('/').pop())) { skipped.push({ id, why: 'kalite ayarına benzemiyor' }); continue; }
      keys.push({ id, values: vals });
    }
    return { presets: have, keys, skipped };
  }

  /* ---------- hedef FPS karar mantigi (saf) ---------- */
  /* o: { preset, resIdx, avg, p1, target, allowRes, available:[presets], ladderLen, hist:[{preset,resIdx,avg}] } */
  function tuneStep(o) {
    const ps = (o.available && o.available.length ? PRESETS.filter((p) => o.available.includes(p)) : PRESETS); let idx = ps.indexOf(o.preset); if (idx < 0) idx = 0; const tol = 0.05; const tgt = o.target; const eff = Math.min(o.avg, (o.p1 || o.avg) * 1.6); const hist = o.hist || []; const lastRes = Math.max(0, (o.ladderLen || 1) - 1);
    const bad = (p, r) => hist.some((h) => h.preset === p && h.resIdx === r && h.avg < tgt * (1 - tol));
    if (eff < tgt * (1 - tol)) {
      if (idx > 0) return { action: 'down', preset: ps[idx - 1], resIdx: o.resIdx, reason: 'Ortalama ' + Math.round(o.avg) + ' FPS (%1 düşük ' + Math.round(o.p1 || 0) + '), hedef ' + tgt + ' altında: bir ön ayar düşürülüyor.' };
      if (o.allowRes && o.resIdx < lastRes) return { action: 'res-down', preset: ps[idx], resIdx: o.resIdx + 1, reason: 'En düşük ön ayarda bile hedefin altında: çözünürlük bir basamak düşürülüyor.' };
      return { action: 'floor', preset: ps[idx], resIdx: o.resIdx, reason: 'En düşük ayarda' + (o.allowRes ? ' ve çözünürlükte' : '') + ' hedefe ulaşılamadı; donanım sınırına yakın.' };
    }
    if (o.avg > tgt * 1.35) {
      if (o.allowRes && o.resIdx > 0 && !bad(ps[idx], o.resIdx - 1)) return { action: 'res-up', preset: ps[idx], resIdx: o.resIdx - 1, reason: 'Hedefin rahat üstünde (' + Math.round(o.avg) + ' FPS): çözünürlük bir basamak yükseltiliyor.' };
      if (idx < ps.length - 1 && !bad(ps[idx + 1], o.resIdx)) return { action: 'up', preset: ps[idx + 1], resIdx: o.resIdx, reason: 'Hedefin rahat üstünde (' + Math.round(o.avg) + ' FPS): bir ön ayar yükseltiliyor.' };
      return { action: 'done', preset: ps[idx], resIdx: o.resIdx, reason: 'Daha yükseği denendi/yok; mevcut ayar en iyisi.' };
    }
    return { action: 'done', preset: ps[idx], resIdx: o.resIdx, reason: 'Hedefe uygun: ortalama ' + Math.round(o.avg) + ' FPS, %1 düşük ' + Math.round(o.p1 || 0) + ' FPS.' };
  }

  /* ---------- donanima gore KABA on-ayar tahmini (RTX 4060 = 100) ---------- */
  const GPU_PERF = [
    [/rtx\s*5090/, 400], [/rtx\s*5080/, 300], [/rtx\s*5070\s*ti/, 270], [/rtx\s*5070/, 215], [/rtx\s*5060\s*ti/, 135], [/rtx\s*5060/, 115], [/rtx\s*4090/, 360], [/rtx\s*4080/, 290], [/rtx\s*4070\s*ti\s*super/, 250], [/rtx\s*4070\s*ti/, 230], [/rtx\s*4070\s*super/, 210], [/rtx\s*4070/, 190], [/rtx\s*4060\s*ti/, 125], [/rtx\s*4060/, 100], [/rtx\s*4050/, 80],
    [/rtx\s*3090/, 230], [/rtx\s*3080/, 200], [/rtx\s*3070/, 150], [/rtx\s*3060\s*ti/, 135], [/rtx\s*3060/, 100], [/rtx\s*3050/, 70], [/rtx\s*2080/, 125], [/rtx\s*2070/, 105], [/rtx\s*2060/, 78], [/gtx\s*1660/, 60], [/gtx\s*1650/, 42], [/gtx\s*1080/, 85], [/gtx\s*1070/, 68], [/gtx\s*1060/, 50], [/gtx\s*1050/, 32],
    [/rx\s*9070\s*xt/, 260], [/rx\s*9070/, 235], [/rx\s*9060/, 130], [/rx\s*7900\s*xtx/, 290], [/rx\s*7900/, 250], [/rx\s*7800/, 200], [/rx\s*7700/, 165], [/rx\s*7600/, 105], [/rx\s*6950|rx\s*6900/, 190], [/rx\s*6800/, 170], [/rx\s*6750|rx\s*6700/, 140], [/rx\s*6650|rx\s*6600/, 95], [/rx\s*6500/, 45], [/rx\s*5700/, 85], [/rx\s*5600/, 65], [/rx\s*(580|590)/, 50], [/rx\s*(570|480)/, 42],
    [/arc\s*b580/, 120], [/arc\s*b570/, 105], [/arc\s*a770/, 110], [/arc\s*a750/, 100], [/arc\s*a580/, 80], [/arc\s*a380/, 35],
    [/iris\s*xe|uhd\s*graphics|intel\(r\)\s*graphics|hd graphics/, 18], [/radeon\(tm\)\s*graphics|radeon\s*graphics|vega\s*\d/, 25]
  ];
  const VIRTUAL_GPU = /(microsoft basic|remote|virtual|parsec|vmware|hyper-v|citrix|displaylink|idd)/i;
  function gpuPerf(name) { const n = String(name || '').toLowerCase().replace(/nvidia|geforce|amd|radeon(?!\()/g, ' ').replace(/\s+/g, ' '); if (!n.trim() || VIRTUAL_GPU.test(name || '')) return null; for (const [re, v] of GPU_PERF) if (re.test(n)) return /laptop|mobile|max-q/i.test(name) ? Math.round(v * 0.75) : v; return null; }
  function estimatePreset(hw, target, w, h) {
    const reasons = []; const perf = hw && hw.gpuPerf; if (perf == null) return { preset: 'medium', confident: false, reasons: ['Ekran kartı tanınmadığı için tahmin yapılamadı; “Orta” ile başlayıp FPS ölçümüyle düzeltmen önerilir.'] };
    const demand = Math.pow((w * h) / (1920 * 1080), 0.9) * Math.pow(Math.max(20, target) / 60, 0.9); const eff = perf / demand; let preset = eff >= 170 ? 'ultra' : eff >= 100 ? 'high' : eff >= 55 ? 'medium' : 'low';
    reasons.push('Ekran kartı (' + hw.gpu + ') + ' + w + '×' + h + ' @ ' + target + ' FPS hedefi için kaba skor ' + Math.round(eff) + '.');
    const capTo = (p, why) => { if (PRESETS.indexOf(preset) > PRESETS.indexOf(p)) { preset = p; reasons.push(why); } };
    if (hw.cores && hw.cores < 6 && target > 90) capTo('high', 'İşlemci çekirdek sayısı az (' + hw.cores + ') ve hedef yüksek: “Yüksek” ile sınırlandı.'); if (hw.ramGB && hw.ramGB < 12) capTo('medium', 'RAM az (' + hw.ramGB + ' GB): “Orta” ile sınırlandı.');
    return { preset, confident: true, reasons };
  }

  /* ---------- FPS olcumu: PresentMon CSV akisi ---------- */
  class FrameParser {
    constructor(cap) { this.buf = ''; this.col = -1; this.ms = []; this.cap = cap || LIM.frames; this.headerSeen = false; }
    feed(chunk) {
      this.buf += chunk; let i; while ((i = this.buf.indexOf('\n')) >= 0) { const ln = this.buf.slice(0, i).replace(/\r$/, ''); this.buf = this.buf.slice(i + 1); this.line(ln); } if (this.buf.length > 100000) this.buf = '';
    }
    line(ln) {
      if (!ln) return; const f = ln.split(','); if (this.col < 0) { const names = f.map((x) => x.trim().toLowerCase()); let c = names.indexOf('frametime'); if (c < 0) c = names.indexOf('msbetweenpresents'); if (c >= 0) { this.col = c; this.headerSeen = true; } return; }
      if (f.length <= this.col || this.ms.length >= this.cap) return; const v = parseFloat(f[this.col]); if (v > 0 && v < 2000) this.ms.push(v);
    }
    end() { if (this.buf) { this.line(this.buf.replace(/\r$/, '')); this.buf = ''; } }
  }
  function frameStats(ms) {
    const n = ms.length; if (!n) return null; const a = Float64Array.from(ms).sort(); const mean = a.reduce((s, x) => s + x, 0) / n; const med = a[Math.floor((n - 1) / 2)];
    /* "%1 dusuk": en yavas %1'lik karelerin ortalama FPS'i (en az 1 kare) */
    const slow = (frac) => { const k = Math.max(1, Math.ceil(n * frac)); let t = 0; for (let i = n - k; i < n; i++) t += a[i]; return 1000 / (t / k); };
    return { frames: n, avg: 1000 / mean, p1: slow(0.01), p01: slow(0.001), min: 1000 / a[n - 1], max: 1000 / a[0], medianMs: med, stutters: a.filter((x) => x > med * 3).length };
  }

  /* ---------- PresentMon bulma (kullanicinin kendi kurulumu) ---------- */
  function findPresentMon(o) {
    o = o || {}; const cand = []; const seen = new Set(); const add = (p) => { const k = lc(p); if (!seen.has(k) && isFile(p)) { seen.add(k); cand.push(p); } };
    if (o.userPath && path.isAbsolute(o.userPath)) add(o.userPath);
    for (const d of o.dirs || []) { let ents = []; try { ents = fs.readdirSync(d); } catch (e) { continue; } ents.sort().reverse(); for (const n of ents) if (/^presentmon/i.test(n) && (!isWin() || /\.exe$/i.test(n))) add(path.join(d, n)); }
    const tried = [];
    for (const p of cand) { const r = cp.spawnSync(p, ['--help'], { encoding: 'utf8', timeout: o.probeMs || 10000, windowsHide: true, shell: false, maxBuffer: 2 * 1024 * 1024 }); const txt = String(r.stdout || '') + String(r.stderr || ''); const ok = /presentmon/i.test(txt); tried.push({ path: p, ok }); if (ok) return { found: true, path: p, tried }; }
    return { found: false, path: '', tried };
  }
  const PM_HELP = ['PresentMon bu uygulamayla gelmez (Intel’in açık kaynak aracıdır); kendin indirip kur:', '1) github.com/GameTechDev/PresentMon → Releases bölümünden “PresentMon Console Application” (.exe) dosyasını indir.', '2) Bu sayfada “Yol seç” ile PresentMon .exe dosyasını göster.', '3) Ölçüm için PresentMon ETW izlemesi kullanır: StatScan’i yönetici olarak aç veya kullanıcını “Performance Log Users” grubuna ekle.'];

  /* ---------- host ---------- */
  function createGameHost(deps) {
    deps = deps || {}; const plat = () => deps.platform || process.platform; const winMode = () => (deps.platform ? deps.platform === 'win32' : isWin());
    const dataDir = deps.dataDir || null; const stateFile = dataDir ? path.join(dataDir, 'oyunayar.json') : null; const backDir = dataDir ? path.join(dataDir, 'oyunayar-yedek') : null;
    const now = deps.now || (() => Date.now()); const run = deps.run || ((cmd, args, ms) => new Promise((resolve, reject) => { cp.execFile(cmd, args, { timeout: ms || 20000, windowsHide: true, maxBuffer: 16 * 1024 * 1024, encoding: 'utf8' }, (e, so) => (e && !so ? reject(e) : resolve(String(so || '')))); }));
    let state = { v: 1, games: {}, pm: null }; if (stateFile) { try { const o = JSON.parse(fs.readFileSync(stateFile, 'utf8')); if (o && typeof o === 'object' && o.games && typeof o.games === 'object') state = Object.assign(state, o); } catch (e) { /* ilk kullanim */ } }
    const saveState = () => { if (!stateFile) return; try { fs.mkdirSync(path.dirname(stateFile), { recursive: true }); const t = stateFile + '.tmp'; fs.writeFileSync(t, JSON.stringify(state)); fs.renameSync(t, stateFile); } catch (e) { /* bellekte kalir */ } };
    const gs = (id) => { if (!Object.prototype.hasOwnProperty.call(state.games, id)) state.games[id] = { config: null, snaps: {}, target: 60, last: null, hist: [], res: null }; return state.games[id]; };
    let cache = { t: 0, list: [], libs: {} }; let jobSeq = 0; let activeJob = null; const jobs = new Map(); let hwCache = null; let pmCache = null;

    /* --- kutuphane tarama --- */
    async function steamRoots() {
      if (deps.steamRoots) return deps.steamRoots.slice(); const out = [];
      if (winMode()) { for (const [k, v] of [['HKCU\\Software\\Valve\\Steam', 'SteamPath'], ['HKLM\\SOFTWARE\\WOW6432Node\\Valve\\Steam', 'InstallPath']]) { try { const o = await run('reg', ['query', k, '/v', v], 8000); const m = new RegExp(v + '\\s+REG_SZ\\s+(.+)$', 'mi').exec(o); if (m) out.push(path.normalize(m[1].trim())); } catch (e) { /* kayit yok */ } } const pf = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)'; out.push(path.join(pf, 'Steam')); }
      return [...new Set(out.filter((d) => isDir(d)))];
    }
    async function scanSteam() {
      const games = []; const roots = await steamRoots(); const libs = new Set();
      for (const r of roots) { libs.add(r); try { const v = parseVdf(await fsp.readFile(path.join(r, 'steamapps', 'libraryfolders.vdf'), 'utf8')); const lf = v.libraryfolders || v.LibraryFolders || {}; for (const k of Object.keys(lf)) { const e = lf[k]; const p = typeof e === 'string' ? e : e && e.path; if (typeof p === 'string' && /^\d+$/.test(k) && path.isAbsolute(p)) libs.add(path.normalize(p)); } } catch (e) { /* kutuphane listesi yok */ } }
      for (const lib of libs) { const sa = path.join(lib, 'steamapps'); let ents = []; try { ents = await fsp.readdir(sa); } catch (e) { continue; }
        for (const f of ents) { if (!/^appmanifest_\d+\.acf$/i.test(f)) continue; try { const a = parseVdf(await fsp.readFile(path.join(sa, f), 'utf8')).AppState; if (!a || !a.appid || !a.name || !a.installdir || SKIP_STEAM.test(a.name)) continue; const dir = path.join(sa, 'common', a.installdir); if (!isDir(dir)) continue; games.push({ id: 'steam:' + String(a.appid).replace(/\W/g, ''), store: 'steam', appId: String(a.appid), name: String(a.name), dir }); } catch (e) { /* bozuk manifest */ } } }
      return { games, roots, libs: [...libs] };
    }
    async function scanEpic() {
      const games = []; const dir = deps.epicManifestDir || (winMode() ? path.join(process.env.ProgramData || 'C:\\ProgramData', 'Epic', 'EpicGamesLauncher', 'Data', 'Manifests') : null); if (!dir) return { games, dir: null };
      let ents = []; try { ents = await fsp.readdir(dir); } catch (e) { return { games, dir }; }
      for (const f of ents) { if (!/\.item$/i.test(f)) continue; try { const j = JSON.parse(await fsp.readFile(path.join(dir, f), 'utf8')); if (!j || !j.DisplayName || !j.InstallLocation || !j.AppName) continue; if (Array.isArray(j.AppCategories) && !j.AppCategories.includes('games')) continue; if (j.MainGameAppName && j.MainGameAppName !== j.AppName) continue; if (!isDir(j.InstallLocation)) continue; games.push({ id: 'epic:' + String(j.AppName).replace(/[^\w.\-]/g, '_').slice(0, 90), store: 'epic', appId: String(j.AppName), name: String(j.DisplayName), dir: path.normalize(j.InstallLocation), exe: typeof j.LaunchExecutable === 'string' ? path.basename(j.LaunchExecutable) : '' }); } catch (e) { /* bozuk manifest */ } }
      return { games, dir };
    }
    async function scanRiot() {
      const games = []; const roots = deps.riotRoots || (winMode() ? ['C:\\Riot Games'] : []);
      for (const r of roots) { let ents = []; try { ents = await fsp.readdir(r, { withFileTypes: true }); } catch (e) { continue; } for (const e of ents) if (e.isDirectory() && !/^riot client$/i.test(e.name)) games.push({ id: 'riot:' + e.name.replace(/[^\w.\-]/g, '_').slice(0, 90), store: 'riot', appId: e.name, name: e.name, dir: path.join(r, e.name), forceAc: 'Riot Vanguard' }); }
      return { games };
    }
    async function scan(force) {
      if (!force && cache.t && now() - cache.t < 20000) return cache;
      const [st, ep, ri] = await Promise.all([scanSteam().catch(() => ({ games: [], roots: [], libs: [] })), scanEpic().catch(() => ({ games: [], dir: null })), scanRiot().catch(() => ({ games: [] }))]); const seen = new Set(); const list = [];
      for (const g of [...st.games, ...ep.games, ...ri.games]) { const k = lc(g.dir); if (seen.has(k) || list.length >= LIM.games) continue; seen.add(k); list.push(g); }
      await Promise.all(list.map(async (g) => { const names = await listNames(g.dir); g.anticheat = detectAntiCheat(g.name, names); if (g.forceAc && !g.anticheat.length) g.anticheat.push({ name: g.forceAc, why: 'Riot oyunu' }); g.blocked = g.anticheat.length > 0; g.reEngine = /resident evil/i.test(g.name); }));
      list.sort((a, b) => a.name.localeCompare(b.name, 'tr')); cache = { t: now(), list, libs: { steam: st.roots, steamLibs: st.libs, epic: ep.dir } }; return cache;
    }
    async function listNames(dir, depth = 2) {
      const out = []; async function rec(d, k) { if (out.length >= LIM.scanEntries) return; let ents; try { ents = await fsp.readdir(d, { withFileTypes: true }); } catch (e) { return; } for (const e of ents) { if (out.length >= LIM.scanEntries) return; out.push(e.name); if (e.isDirectory() && !e.isSymbolicLink() && k < depth) await rec(path.join(d, e.name), k + 1); } } await rec(dir, 0); return out;
    }
    async function getGame(id) { if (typeof id !== 'string' || !ID_RE.test(id)) return null; let c = await scan(false); let g = c.list.find((x) => x.id === id); if (!g && now() - c.t > 3000) { c = await scan(true); g = c.list.find((x) => x.id === id); } return g || null; }

    /* --- calisan oyun --- */
    async function procList() {
      if (deps.listProcs) return deps.listProcs();
      if (winMode()) { const o = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference="SilentlyContinue";ConvertTo-Json -InputObject @(Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath) -Compress'], 20000); let v = []; try { v = JSON.parse(String(o).replace(/^\ufeff/, '') || '[]'); } catch (e) { v = []; } return (Array.isArray(v) ? v : [v]).map((r) => ({ pid: +r.ProcessId || 0, name: String(r.Name || ''), path: String(r.ExecutablePath || '') })); }
      const out = []; try { for (const d of fs.readdirSync('/proc')) { if (!/^\d+$/.test(d)) continue; try { out.push({ pid: +d, name: fs.readFileSync('/proc/' + d + '/comm', 'utf8').trim(), path: fs.readlinkSync('/proc/' + d + '/exe') }); } catch (e) { /* surec bitti */ } } } catch (e) { /* proc yok */ } return out;
    }
    let runCache = { t: 0, v: [] };
    async function running() {
      if (runCache.t && now() - runCache.t < 1500) return runCache.v; const r = await runningRaw(); runCache = { t: now(), v: r }; return r;
    }
    async function runningRaw() {
      const c = await scan(false); const procs = await procList(); const out = []; const seen = new Set();
      for (const p of procs) {
        const nm = String(p.name || '').toLowerCase(); const pp = lc(p.path); let g = null; if (pp) for (const x of c.list) { const d = lc(x.dir) + '\\'; if (pp.startsWith(d) && (!g || d.length > lc(g.dir).length)) g = x; }
        if (g) { const k = g.id; if (seen.has(k)) continue; if (/(crashhandler|crashreport|unins|setup|launcher|redist|vc_redist|dxsetup|easyanticheat|beservice|overlay|helper)/i.test(nm)) continue; seen.add(k); out.push({ gameId: g.id, name: g.name, exe: p.name, pid: p.pid, blocked: g.blocked, anticheat: g.anticheat }); }
        else if (AC_PROCS[nm]) { const k = 'ac:' + nm; if (seen.has(k)) continue; seen.add(k); out.push({ gameId: null, name: p.name, exe: p.name, pid: p.pid, blocked: true, anticheat: [{ name: AC_PROCS[nm], why: 'süreç adı' }] }); }
      }
      return out;
    }

    /* --- ayar dosyasi --- */
    const SETTINGS_NAME = /^(config|settings|graphics|video|gameusersettings|options|engine|display)[\w .\-]*\.(ini|cfg|conf)$/i;
    /* ---- ayar dosyasi bulma: cok katmanli arama + puanlama (bkz. scoreCfg) ---- */
    const GENERIC_DIR = new Set(['microsoft', 'windows', 'nvidia', 'nvidiacorporation', 'packages', 'temp', 'crashdumps', 'unitycache', 'google', 'mozilla', 'discord', 'steam', 'epicgameslauncher', 'programs', 'apple', 'adobe', 'intel', 'amd', 'packagecache', 'd3dscache', 'cache', 'logs', 'tempstate', 'connecteddevicesplatform', 'comms', 'publishers', 'virtualstore', 'jetbrains', 'slack', 'spotify', 'riotgames', 'electron']);
    const SKIP_IN_GAME = /^(engine|content|plugins|redist|_commonredist|paks|movies|localization|shaders?|streamingassets|managed|mono|il2cpp_data|resources|logs?|crashes|\.git|node_modules|natives|streaming|sounds?|audio|videos?|movie|fonts?|dlc|_redist|redistributable|directx|vcredist|dotnet|bink|wwise)$/i;
    const BAD_CFG = /(input|bind|control|crash|launcher|eos|account|install|manifest|cache|dedicated|server|steam_appid|uninst|telemetry|analytics|plugin)/i;
    const GFX_KEY = /(shadow|texture|quality|resolution|fullscreen|windowmode|vsync|antialias|anti_alias|\baa\b|graphic|fov|displaymode|screenmode|framerate|fps|ssao|bloom|motionblur|raytrac|upscal|dlss|fsr|gamma|brightness|vegetation|foliage|reflection|lighting)/i;
    const cdir = (p) => path.dirname(p);
    let docsCache = null;
    async function docsDirs() {
      if (docsCache) return docsCache; const set = new Set(); const home = deps.home || os.homedir();
      if (deps.docsDir) set.add(deps.docsDir); else {
        set.add(path.join(home, 'Documents')); if (process.env.OneDrive) set.add(path.join(process.env.OneDrive, 'Documents'));
        if (winMode()) { try { const o = await run('reg', ['query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders', '/v', 'Personal'], 8000); const m = /Personal\s+REG_(?:EXPAND_)?SZ\s+(.+)$/mi.exec(o); if (m) { const v = m[1].trim().replace(/%([^%]+)%/g, (_, k) => process.env[k] || ''); if (v && path.isAbsolute(v)) set.add(v); } } catch (e) { /* kayit yok */ } }
      }
      docsCache = [...set].filter((d) => isDir(d)); return docsCache;
    }
    /* yalnizca ayar dosyasi adayi ekler: where = 'named' (oyun adina uyan klasor) > 'game' (kurulum klasoru) > 'userdata' (Steam bulut) */
    async function findRaw(g) {
      const found = new Map(); const rank = { named: 3, game: 2, userdata: 1 };
      const add = (where) => async (p) => { const k = lc(p); try { const st = await fsp.stat(p); if (!(st.isFile() && st.size > 0 && st.size <= LIM.cfgBytes && /\.(ini|cfg|conf)$/i.test(p))) return; const o = found.get(k); if (!o || rank[where] > rank[o.where]) found.set(k, { path: p, where, size: st.size, mtime: st.mtimeMs }); } catch (e) { /* yok */ } };
      const bud = () => ({ n: 700 });
      await add('game')(path.join(g.dir, 'config.ini'));
      await walkIni(g.dir, 6, add('game'), { n: 8000 }, SKIP_IN_GAME, true);
      const names = new Set(); const exact = new Set(); const addName = (s) => { const n = norm(s); if (n.length >= 5) names.add(n); };
      addName(g.name); addName(path.basename(g.dir)); addName(String(g.name).replace(/\(.*?\)/g, '')); addName(String(g.name).split(/[:\-–]/)[0]); if (g.exe) addName(String(g.exe).replace(/\.exe$/i, ''));
      for (const pr of await ueProjects(g.dir)) { const n = norm(pr); if (n.length >= 3) exact.add(n); addName(pr); }
      const mt = (sn) => { if (exact.has(sn)) return true; if (sn.length < 5) return false; for (const n of names) if (n.includes(sn) || sn.includes(n)) return true; return false; };
      const home = deps.home || os.homedir(); const local = deps.localAppData || process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'); const roaming = deps.roamingAppData || process.env.APPDATA || path.join(cdir(local), 'Roaming');
      const bases = []; for (const d of await docsDirs()) { bases.push([d, true]); bases.push([path.join(d, 'My Games'), false]); } bases.push([local, true], [path.join(cdir(local), 'LocalLow'), true], [roaming, true], [path.join(home, 'Saved Games'), false]);
      const seenB = new Set();
      for (const [b, peek] of bases) {
        if (seenB.has(lc(b))) continue; seenB.add(lc(b)); let subs; try { subs = await fsp.readdir(b, { withFileTypes: true }); } catch (e) { continue; } let peeked = 0;
        for (const s of subs) {
          if (!s.isDirectory() || s.isSymbolicLink()) continue; const sn = norm(s.name); if (GENERIC_DIR.has(sn)) continue;
          if (mt(sn)) { await walkIni(path.join(b, s.name), 4, add('named'), bud()); continue; }
          if (peek && peeked < 200) { peeked++; let inner; try { inner = await fsp.readdir(path.join(b, s.name), { withFileTypes: true }); } catch (e) { continue; } for (const t of inner) if (t.isDirectory() && !t.isSymbolicLink() && mt(norm(t.name))) await walkIni(path.join(b, s.name, t.name), 4, add('named'), bud()); }
        }
      }
      if (g.store === 'steam' && g.appId && cache.libs && cache.libs.steam) for (const r of cache.libs.steam) { let us = []; try { us = await fsp.readdir(path.join(r, 'userdata')); } catch (e) { continue; } for (const u of us.slice(0, 20)) await walkIni(path.join(r, 'userdata', u, String(g.appId).replace(/\W/g, ''), 'remote'), 3, add('userdata'), bud()); }
      return [...found.values()];
    }
    async function ueProjects(dir) {
      const out = []; let ents = []; try { ents = await fsp.readdir(dir, { withFileTypes: true }); } catch (e) { return out; }
      for (const e of ents) { if (!e.isDirectory() || e.isSymbolicLink()) continue; const d = path.join(dir, e.name); if ((isDir(path.join(d, 'Binaries', 'Win64')) || isDir(path.join(d, 'Binaries', 'WinGDK'))) && isDir(path.join(d, 'Content'))) out.push(e.name); } return out.slice(0, 4);
    }
    /* aday puani: dosya adi + konum + icerik (grafik anahtari sayisi; Unreal GameUserSettings). -99 = aday degil */
    function scoreCfg(c) {
      const base = path.basename(c.path).toLowerCase(); if (BAD_CFG.test(base)) return { score: -99 };
      let s = /^gameusersettings\.ini$/.test(base) ? 6 : /^(graphics|video|display)/.test(base) ? 4 : /^(config|settings|options)/.test(base) ? 3 : 1;
      s += c.where === 'named' ? 2 : c.where === 'game' ? 1 : c.where === 'userdata' ? 1 : 0;
      const r = readCfg(c.path); if (r.error) return { score: -99 }; const p = iniParse(r.text); if (!p.entries.length) return { score: -99 };
      const gk = p.entries.filter((e) => GFX_KEY.test(e.key)).length; s += gk === 0 ? -3 : Math.min(4, Math.floor(gk / 2) + 1);
      const ue = isUe(p); if (ue) s += 3; return { score: s, kind: ue ? 'ue' : '', keys: p.entries.length };
    }
    const candCache = new Map();
    async function configCandidates(g) {
      const hit = candCache.get(g.id); if (hit && now() - hit.t < 30000) return hit.list;
      const raw = await findRaw(g); const list = [];
      for (const c of raw.slice().sort((x, y) => x.path.split(/[\\/]/).length - y.path.split(/[\\/]/).length).slice(0, 80)) { const sc = scoreCfg(c); if (sc.score >= 1) list.push(Object.assign({}, c, { score: sc.score, kind: sc.kind })); }
      list.sort((a, b) => b.score - a.score || a.path.length - b.path.length); const out = list.slice(0, 12); candCache.set(g.id, { t: now(), list: out }); return out;
    }
    /* genis (BFS) tarama: once yakin klasorler; anyName=true ise oyun klasorunde HER .ini/.cfg/.conf aday (puanlama eler) */
    async function walkIni(d, depth, add, budget, skip, anyName) {
      const rx = anyName ? /\.(ini|cfg|conf)$/i : SETTINGS_NAME; let level = [d];
      for (let lv = 0; lv <= depth && level.length; lv++) {
        const next = [];
        for (const dir of level) {
          if (budget.n <= 0) return; let ents; try { ents = await fsp.readdir(dir, { withFileTypes: true }); } catch (e) { continue; }
          for (const e of ents) { if (budget.n-- <= 0) return; const p = path.join(dir, e.name); if (e.isDirectory() && !e.isSymbolicLink()) { if (lv < depth && !(skip && skip.test(e.name))) next.push(p); } else if (e.isFile() && rx.test(e.name)) await add(p); }
        }
        level = next;
      }
    }
    function setConfig(s, p, auto) { if (s.config !== p) { s.config = p; s.snaps = {}; s.last = null; s.hist = []; } s.auto = !!auto; const r = readCfg(p); s.kind = !r.error && isUe(iniParse(r.text)) ? 'ue' : ''; }
    /* tum oyunlar icin ayar dosyasini otomatik bul; net kazanan varsa SEC (dosyaya yazmaz). Kullanicinin elle sectigini degistirmez. */
    async function detectAll(force) {
      const c = await scan(false); if (force) candCache.clear(); const out = []; const queue = c.list.slice(); let changed = false;
      const one = async (g) => {
        if (g.blocked) { out.push({ id: g.id, name: g.name, status: 'blocked' }); return; } const s = gs(g.id);
        const have = s.config && isFile(s.config); if (have && !s.auto) { out.push({ id: g.id, name: g.name, status: 'kept', path: s.config, kind: s.kind || '' }); return; }
        if (have && s.auto && !force) { out.push({ id: g.id, name: g.name, status: 'auto', path: s.config, kind: s.kind || '' }); return; }
        const cands = await configCandidates(g); s.found = cands.length; const top = cands[0]; const second = cands[1];
        if (top && top.score >= 4 && (!second || top.score - second.score >= 2)) { setConfig(s, top.path, true); changed = true; out.push({ id: g.id, name: g.name, status: 'auto', path: top.path, kind: s.kind, found: cands.length }); }
        else { if (s.config && !have) { s.config = null; s.auto = false; s.kind = ''; changed = true; } out.push({ id: g.id, name: g.name, status: cands.length ? 'choose' : 'none', found: cands.length }); }
      };
      const workers = Array.from({ length: 4 }, async () => { while (queue.length) await one(queue.shift()); }); await Promise.all(workers); if (changed) saveState();
      const n = (k) => out.filter((x) => x.status === k).length; out.sort((a, b) => a.name.localeCompare(b.name, 'tr'));
      return { games: out, counts: { total: out.length, auto: n('auto'), kept: n('kept'), choose: n('choose'), none: n('none'), blocked: n('blocked'), ue: out.filter((x) => x.kind === 'ue').length } };
    }
    function readCfg(p) {
      let st; try { st = fs.statSync(p); } catch (e) { return { error: 'Ayar dosyası okunamadı.' } } if (!st.isFile() || st.size > LIM.cfgBytes || st.size === 0) return { error: 'Ayar dosyası geçersiz (boş ya da çok büyük).' };
      const buf = fs.readFileSync(p); if (buf.includes(0)) return { error: 'Bu dosya UTF-16/ikili görünüyor; yalnızca metin (UTF-8) ayar dosyaları desteklenir.' }; return { text: buf.toString('utf8'), size: st.size };
    }
    function validPick(p) { if (typeof p !== 'string' || !path.isAbsolute(p)) return 'Geçersiz yol.'; if (!/\.(ini|cfg|conf)$/i.test(p)) return 'Yalnızca .ini / .cfg / .conf dosyaları desteklenir.'; if (winMode() && /^[a-z]:\\windows(\\|$)/i.test(p)) return 'Windows klasöründeki dosyalar seçilemez.'; return ''; }
    const editable = (g) => (g.blocked ? errE('Bu oyunda anti-cheat algılandı (' + g.anticheat.map((a) => a.name).join(', ') + '). Çevrimiçi/anti-cheat’li oyunların ayar dosyasına dokunulmaz.', { code: 'anticheat', anticheat: g.anticheat }) : null);
    async function ensureClosed(g) { const r = await running().catch(() => []); const hit = r.find((x) => x.gameId === g.id); return hit ? errE('Oyun şu an çalışıyor (' + hit.exe + '). Ayar dosyası oyun kapalıyken değiştirilir; oyunu tamamen kapatıp tekrar dene.', { code: 'running' }) : null; }

    /* --- yedek --- */
    const safeId = (id) => id.replace(/[^\w.\-]/g, '_');
    function indexOf(id) { try { const o = JSON.parse(fs.readFileSync(path.join(backDir, safeId(id), 'index.json'), 'utf8')); return Array.isArray(o) ? o : []; } catch (e) { return []; } }
    function backup(id, cfgPath, reason) {
      if (!backDir) return { error: 'Yedek klasörü yok.' }; const d = path.join(backDir, safeId(id)); fs.mkdirSync(d, { recursive: true }); const idx = indexOf(id); const buf = fs.readFileSync(cfgPath); const sha = crypto.createHash('sha256').update(buf).digest('hex'); const base = path.basename(cfgPath);
      const isFirst = !idx.some((x) => x.orig && lc(x.path) === lc(cfgPath)); const ts = new Date(now()).toISOString().replace(/[:.]/g, '-'); const tag = crypto.createHash('sha1').update(lc(cfgPath)).digest('hex').slice(0, 6); const file = (isFirst ? 'orijinal-' : ts + '-') + tag + '-' + base; fs.writeFileSync(path.join(d, file), buf);
      idx.push({ file, path: cfgPath, time: now(), sha, reason, orig: isFirst, size: buf.length }); const keep = idx.filter((x) => x.orig).concat(idx.filter((x) => !x.orig).slice(-LIM.backups)); for (const x of idx) if (!keep.includes(x)) { try { fs.unlinkSync(path.join(d, x.file)); } catch (e) { /* silinmis */ } }
      fs.writeFileSync(path.join(d, 'index.json'), JSON.stringify(keep)); return { ok: true, file, orig: isFirst };
    }
    function writeAtomic(p, text) { const t = p + '.kovan-tmp'; try { fs.writeFileSync(t, text, 'utf8'); fs.renameSync(t, p); } catch (e) { try { fs.unlinkSync(t); } catch (e2) { /* yok */ } throw Object.assign(new Error(e.code === 'EPERM' || e.code === 'EACCES' ? 'Dosya salt okunur ya da yazma izni yok; değiştirilmedi.' : String(e.message || e)), { code: e.code }); } }

    /* --- degisiklik plani --- */
    function learnedOf(id) { return deriveLearned(gs(id).snaps); }
    function buildChanges(id, parsed, req) {
      const ch = new Map(); const notes = []; const L = learnedOf(id);
      if (req.preset) { if (L.presets.includes(req.preset)) { for (const k of L.keys) ch.set(k.id, k.values[req.preset]); if (L.keys.length === 0 && L.presets.length >= 2) notes.push('Kaydettiğin ayarlar arasında fark bulunamadı.'); } else if (isUe(parsed)) { for (const [k, v] of ueChanges(parsed, req.preset)) ch.set(k, v); notes.push('Unreal Engine ölçeği kullanıldı (0=Düşük, 1=Orta, 2=Yüksek, 3=Epic); oyun menüsü adları farklı eşleyebilir. Oyunda kendi ön ayarını kaydedersen o öncelikli olur.'); } else notes.push('“' + PRESET_TR[req.preset] + '” için kaydedilmiş ayar yok: önce oyunda bu ön ayarı seçip “Kaydet” de.'); }
      if (req.resolution) { const d = findResolution(parsed); if (!d.length) notes.push('Bu ayar dosyasında çözünürlük anahtarı bulunamadı; çözünürlüğü oyunun içinden ayarla.'); else for (const [k, v] of resChanges(d, req.resolution.w, req.resolution.h)) { const e = parsed.byId.get(k); ch.set(k, typeof v === 'object' ? v.fn(e.value) : v); } }
      return { ch, notes };
    }
    function validReq(req) {
      if (!req || typeof req !== 'object') return { error: 'Geçersiz istek.' }; const o = {}; if (req.preset !== undefined && req.preset !== null) { if (!PRESETS.includes(req.preset)) return { error: 'Geçersiz ön ayar.' }; o.preset = req.preset; }
      if (req.resolution) { const w = Math.round(+req.resolution.w), h = Math.round(+req.resolution.h); if (!Number.isFinite(w) || !Number.isFinite(h) || w < 640 || w > 7680 || h < 360 || h > 4320) return { error: 'Geçersiz çözünürlük.' }; o.resolution = { w, h }; }
      if (!o.preset && !o.resolution) return { error: 'Ön ayar veya çözünürlük seç.' }; return { o };
    }

    /* --- donanim --- */
    async function hardware(force) {
      if (hwCache && !force) return hwCache; const hw = { gpu: '', gpus: [], gpuPerf: null, cpu: '', cores: 0, threads: 0, ramGB: Math.round(os.totalmem() / 1073741824), screen: null, platform: plat() };
      const cpus = os.cpus() || []; hw.cpu = (cpus[0] && cpus[0].model) || ''; hw.threads = cpus.length;
      if (winMode()) {
        try { const o = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference="SilentlyContinue";ConvertTo-Json -Compress -Depth 3 ([pscustomobject]@{g=@(Get-CimInstance Win32_VideoController|Select-Object Name,AdapterRAM,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate);c=@(Get-CimInstance Win32_Processor|Select-Object Name,NumberOfCores,NumberOfLogicalProcessors)})'], 25000); const j = JSON.parse(String(o).replace(/^\ufeff/, '')); const gl = (Array.isArray(j.g) ? j.g : [j.g]).filter(Boolean); hw.gpus = gl.map((x) => ({ name: String(x.Name || ''), perf: gpuPerf(x.Name), w: +x.CurrentHorizontalResolution || 0, h: +x.CurrentVerticalResolution || 0, hz: +x.CurrentRefreshRate || 0 })).filter((x) => x.name && !VIRTUAL_GPU.test(x.name)); const best = hw.gpus.slice().sort((a, b) => (b.perf || 0) - (a.perf || 0))[0] || hw.gpus[0]; if (best) { hw.gpu = best.name; hw.gpuPerf = best.perf; if (best.w && best.h) hw.screen = { w: best.w, h: best.h, hz: best.hz }; } const cl = (Array.isArray(j.c) ? j.c : [j.c]).filter(Boolean); if (cl[0]) { hw.cpu = String(cl[0].Name || hw.cpu).trim(); hw.cores = +cl[0].NumberOfCores || 0; hw.threads = +cl[0].NumberOfLogicalProcessors || hw.threads; } } catch (e) { hw.error = 'Donanım bilgisi okunamadı.'; }
      }
      hwCache = hw; return hw;
    }

    /* --- PresentMon --- */
    function pmDirs() { const d = []; for (const x of String(process.env.PATH || '').split(path.delimiter)) if (x && path.isAbsolute(x)) d.push(x); for (const k of ['ProgramFiles', 'ProgramFiles(x86)']) if (process.env[k]) d.push(path.join(process.env[k], 'Intel', 'PresentMon'), path.join(process.env[k], 'PresentMon')); if (dataDir) d.push(path.join(dataDir, 'tools')); return [...new Set(d)]; }
    function locatePm(force) { if (pmCache && !force) return pmCache; pmCache = findPresentMon({ userPath: state.pm, dirs: deps.pmDirs || pmDirs(), probeMs: deps.probeMs }); return pmCache; }
    function exec(job, file, args, seconds) {
      return new Promise((resolve) => {
        const parser = new FrameParser(); let errs = ''; let done = false; let timer; const fin = (r) => { if (done) return; done = true; clearTimeout(timer); job.child = null; parser.end(); resolve(Object.assign({ parser, err: errs }, r)); };
        let c; try { c = cp.spawn(file, args, { windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return fin({ code: -1, err: String(e && e.message || e) }); }
        job.child = c; c.stdout.setEncoding('utf8'); c.stdout.on('data', (d) => parser.feed(d)); c.stderr.on('data', (d) => { errs += d; if (errs.length > 20000) errs = errs.slice(-10000); });
        timer = setTimeout(() => { job.timedOut = true; try { c.kill(); } catch (e) { /* bitmis */ } fin({ code: -2 }); }, seconds * 1000 + (deps.graceMs !== undefined ? deps.graceMs : 25000)); c.on('error', (e) => fin({ code: -1, err: errs + String(e && e.message || e) })); c.on('close', (code) => fin({ code }));
      });
    }
    async function measure(job, pm, target, seconds) {
      try {
        let r = await exec(job, pm, ['--process_name', target.exe, '--timed', String(seconds), '--terminate_after_timed', '--output_stdout', '--no_console_stats', '--stop_existing_session'], seconds);
        if (!job.canceled && !job.timedOut && !r.parser.ms.length && !r.parser.headerSeen && /unknown|invalid|unrecogni|usage/i.test(r.err)) r = await exec(job, pm, ['-process_name', target.exe, '-timed', String(seconds), '-terminate_after_timed', '-output_stdout', '-no_top', '-stop_existing_session'], seconds);
        if (job.canceled) { job.state = 'canceled'; return; }
        const st = frameStats(r.parser.ms);
        if (!st || st.frames < LIM.minFrames) { job.state = 'failed'; job.error = /access|denied|administrator|elevat|privilege|performance log/i.test(r.err) ? 'PresentMon yetki istiyor: StatScan’i yönetici olarak aç ya da kullanıcını “Performance Log Users” grubuna ekle.' : (st ? 'Yetersiz örnek (' + st.frames + ' kare): oyun menüde/duraklatılmış olabilir; oyun içinde hareket ederken tekrar ölç.' : 'Hiç kare ölçülemedi. Oyun penceresi gerçekten çalışıyor ve süreç adı doğru mu? ' + String(r.err).trim().split(/\r?\n/).slice(-2).join(' ')); return; }
        const res = Object.assign({ seconds, exe: target.exe, game: target.name }, st); const g = target.gameId ? gs(target.gameId) : null; let advice = null;
        if (g) { const L = learnedOf(target.gameId); const ladderBase = g.res && g.res.native ? g.res.native : null; const ladder = ladderBase ? resLadder(ladderBase.w, ladderBase.h) : [null]; const cur = g.last || null;
          if (cur && cur.preset) { const entry = { preset: cur.preset, resIdx: cur.resIdx || 0, avg: st.avg, t: now() }; g.hist = (g.hist || []).concat([entry]).slice(-LIM.hist); advice = tuneStep({ preset: cur.preset, resIdx: cur.resIdx || 0, avg: st.avg, p1: st.p1, target: g.target || 60, allowRes: !!(g.res && g.res.allow && ladderBase), available: L.presets, ladderLen: ladder.length, hist: g.hist }); if (ladderBase && ladder[advice.resIdx]) advice.resolution = ladder[advice.resIdx]; } else advice = { action: 'baseline', reason: 'Ölçüm kaydedildi. Tavsiye için önce bir ön ayar uygula (“Uygula”); sonra oyunu yeniden başlatıp tekrar ölç.' }; saveState(); }
        job.result = { stats: res, advice }; job.state = 'done'; if (deps.notify) { try { deps.notify('Kovan Oyun Ayarlayıcı', 'Ölçüm bitti: ' + Math.round(st.avg) + ' FPS ort.'); } catch (e) { /* bildirim yok */ } }
      } catch (e) { job.state = 'failed'; job.error = String(e && e.message || e); } finally { if (job.state === 'running') job.state = 'failed'; job.endedAt = now(); }
    }

    const pubGame = (g) => { const s = Object.prototype.hasOwnProperty.call(state.games, g.id) ? state.games[g.id] : null; const L = s ? deriveLearned(s.snaps) : { presets: [], keys: [] }; return { id: g.id, store: g.store, name: g.name, dir: g.dir, blocked: g.blocked, anticheat: g.anticheat, reEngine: g.reEngine, config: s && s.config ? s.config : null, kind: s && s.kind ? s.kind : '', auto: !!(s && s.auto), found: s && s.found !== undefined ? s.found : null, learned: L.presets, keys: L.keys.length, target: s ? s.target : 60, last: s ? s.last : null }; };
    const handlers = {
      'game:scan': async (_e, force) => { try { const c = await scan(force === true); return { games: c.list.map(pubGame), libs: c.libs, platform: plat(), windows: winMode(), note: winMode() ? '' : 'Oyun kütüphaneleri yalnızca Windows’ta aranır.' }; } catch (e) { return errE(String(e && e.message || e)); } },
      'game:running': async () => { try { return { running: await running() }; } catch (e) { return errE(String(e && e.message || e)); } },
      'game:config': async (_e, id) => {
        try { const g = await getGame(id); if (!g) return errE('Oyun bulunamadı.'); const s = gs(g.id); const cands = await configCandidates(g); let info = null; let ue = null; if (s.config) { const r = readCfg(s.config); if (r.error) info = { error: r.error }; else { const p = iniParse(r.text); if (isUe(p)) ue = { kind: 'ue', keys: ueChanges(p, 'low').size }; const res = findResolution(p); info = { keys: p.entries.length, resolution: res.length ? { w: res[0].w, h: res[0].h, count: res.length } : null, size: r.size }; } }
          const L = deriveLearned(s.snaps); return { game: pubGame(g), candidates: cands, config: s.config, auto: !!s.auto, builtin: ue, info, presets: PRESETS.map((p) => ({ id: p, label: PRESET_TR[p], saved: !!s.snaps[p], builtin: !!ue })), learned: { presets: L.presets, keys: L.keys.slice(0, 200).map((k) => ({ id: k.id, values: k.values })), skipped: L.skipped.slice(0, 100) }, res: s.res || null, backups: backDir ? indexOf(g.id).map((x) => ({ file: x.file, time: x.time, orig: !!x.orig, reason: x.reason })) : [] }; } catch (e) { return errE(String(e && e.message || e)); }
      },
      'game:detectAll': async (_e, force) => { try { return await detectAll(force === true); } catch (e) { return errE(String(e && e.message || e)); } },
      'game:useConfig': async (_e, id, idx) => { try { const g = await getGame(id); if (!g) return errE('Oyun bulunamadı.'); const b = editable(g); if (b) return b; const cands = await configCandidates(g); const c = cands[Math.floor(Number(idx))]; if (!c) return errE('Aday bulunamadı.'); const r = readCfg(c.path); if (r.error) return errE(r.error); const s = gs(g.id); setConfig(s, c.path, false); saveState(); return { ok: true, path: c.path }; } catch (e) { return errE(String(e && e.message || e)); } },
      'game:chooseConfig': async (_e, id) => { try { const g = await getGame(id); if (!g) return errE('Oyun bulunamadı.'); const b = editable(g); if (b) return b; if (!deps.chooseConfig) return errE('Dosya seçimi yok.'); const f = await deps.chooseConfig(g.name); if (!f) return { canceled: true }; const bad = validPick(f); if (bad) return errE(bad); const r = readCfg(f); if (r.error) return errE(r.error); const s = gs(g.id); setConfig(s, f, false); saveState(); return { ok: true, path: f }; } catch (e) { return errE(String(e && e.message || e)); } },
      'game:snap': async (_e, id, preset) => {
        try { if (!PRESETS.includes(preset)) return errE('Geçersiz ön ayar.'); const g = await getGame(id); if (!g) return errE('Oyun bulunamadı.'); const b = editable(g); if (b) return b; const s = gs(g.id); if (!s.config) return errE('Önce ayar dosyasını seç.'); const r = readCfg(s.config); if (r.error) return errE(r.error); const p = iniParse(r.text); if (!p.entries.length) return errE('Dosyada “anahtar=değer” satırı bulunamadı; bu biçim desteklenmiyor.'); s.snaps[preset] = snapOf(p); const res = findResolution(p); if (res.length && !(s.res && s.res.native)) s.res = Object.assign({ allow: false }, s.res, { native: { w: res[0].w, h: res[0].h } }); saveState(); const L = deriveLearned(s.snaps); return { ok: true, saved: PRESETS.filter((x) => s.snaps[x]), keys: L.keys.length, skipped: L.skipped.length }; } catch (e) { return errE(String(e && e.message || e)); }
      },
      'game:snapClear': async (_e, id, preset) => { try { const g = await getGame(id); if (!g) return errE('Oyun bulunamadı.'); const s = gs(g.id); if (preset === 'all') s.snaps = {}; else if (PRESETS.includes(preset)) delete s.snaps[preset]; else return errE('Geçersiz ön ayar.'); saveState(); return { ok: true }; } catch (e) { return errE(String(e && e.message || e)); } },
      'game:plan': async (_e, id, req) => {
        try { const g = await getGame(id); if (!g) return errE('Oyun bulunamadı.'); const b = editable(g); if (b) return b; const v = validReq(req); if (v.error) return errE(v.error); const s = gs(g.id); if (!s.config) return errE('Önce ayar dosyasını seç.'); const r = readCfg(s.config); if (r.error) return errE(r.error); const p = iniParse(r.text); const { ch, notes } = buildChanges(g.id, p, v.o); const out = iniApply(p, ch); return { changes: out.applied.slice(0, LIM.planRows), total: out.applied.length, missing: out.missing.length, notes }; } catch (e) { return errE(String(e && e.message || e)); }
      },
      'game:apply': async (_e, id, req) => {
        try { const g = await getGame(id); if (!g) return errE('Oyun bulunamadı.'); const b = editable(g); if (b) return b; const v = validReq(req); if (v.error) return errE(v.error); const s = gs(g.id); if (!s.config) return errE('Önce ayar dosyasını seç.'); const run1 = await ensureClosed(g); if (run1) return run1;
          const r = readCfg(s.config); if (r.error) return errE(r.error); const p = iniParse(r.text); const { ch, notes } = buildChanges(g.id, p, v.o); const out = iniApply(p, ch); if (!out.applied.length) { if (!notes.length) { s.last = { preset: v.o.preset || (s.last && s.last.preset) || null, resIdx: s.last ? s.last.resIdx || 0 : 0, res: v.o.resolution || (s.last && s.last.res) || null, time: now() }; saveState(); } return { ok: true, nothing: true, notes, message: notes.length ? notes.join(' ') : 'Ayar dosyası zaten bu değerlerde; değişiklik yok (geçerli ayar olarak kaydedildi).' }; }
          if (!deps.confirm) return errE('Onay penceresi yok; değişiklik yapılmadı.'); const lines = out.applied.slice(0, 12).map((c) => '• ' + c.key + ': ' + c.from + ' → ' + c.to); const okc = await deps.confirm({ title: 'Oyun ayarları değiştirilsin mi?', message: g.name + '\n' + (v.o.preset ? 'Ön ayar: ' + PRESET_TR[v.o.preset] + '\n' : '') + (v.o.resolution ? 'Çözünürlük: ' + v.o.resolution.w + '×' + v.o.resolution.h + '\n' : '') + '\n' + out.applied.length + ' satır değişecek:\n' + lines.join('\n') + (out.applied.length > 12 ? '\n… (+' + (out.applied.length - 12) + ')' : '') + '\n\nDosya: ' + s.config + '\nDeğiştirmeden önce yedeği alınır; “Geri yükle” ile döndürebilirsin.', ok: 'Uygula', cancel: 'Vazgeç' }); if (!okc) return { error: 'declined', message: 'İptal edildi; hiçbir şey değiştirilmedi.', status: 400 };
          const bk = backup(g.id, s.config, (v.o.preset ? PRESET_TR[v.o.preset] : '') + (v.o.resolution ? ' ' + v.o.resolution.w + '×' + v.o.resolution.h : '')); if (bk.error) return errE(bk.error);
          writeAtomic(s.config, out.text); const chk = readCfg(s.config); let stuck = 0; if (!chk.error) { const p2 = iniParse(chk.text); for (const c of out.applied) { const e = p2.byId.get(c.id); if (e && e.value === c.to) stuck++; } }
          s.last = { preset: v.o.preset || (s.last && s.last.preset) || null, resIdx: s.last ? s.last.resIdx || 0 : 0, res: v.o.resolution || (s.last && s.last.res) || null, time: now() };
          if (v.o.resolution) { const base = s.res && s.res.native ? s.res.native : null; if (base) { const lad = resLadder(base.w, base.h); const i = lad.findIndex((x) => x.w === v.o.resolution.w && x.h === v.o.resolution.h); s.last.resIdx = i >= 0 ? i : 0; } } else if (req && Number.isInteger(req.resIdx)) s.last.resIdx = Math.max(0, req.resIdx);
          saveState(); return { ok: true, applied: out.applied.length, verified: stuck, notes, backup: bk.file, firstBackup: bk.orig };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'game:restore': async (_e, id, which) => {
        try { const g = await getGame(id); if (!g) return errE('Oyun bulunamadı.'); const run1 = await ensureClosed(g); if (run1) return run1; const idx = indexOf(g.id); if (!idx.length) return errE('Bu oyun için yedek yok.'); const s = gs(g.id); if (!s.config) return errE('Önce ayar dosyasını seç.'); const mine = idx.filter((x) => lc(x.path) === lc(s.config)); const pick = which === 'orig' ? mine.find((x) => x.orig) : mine.filter((x) => !x.orig).slice(-1)[0] || mine.find((x) => x.orig); if (!pick) return errE('Bu ayar dosyası için yedek bulunamadı.'); const src = path.join(backDir, safeId(g.id), pick.file); if (!isFile(src)) return errE('Yedek dosyası bulunamadı.');
          if (!deps.confirm) return errE('Onay penceresi yok; geri yüklenmedi.'); const okc = await deps.confirm({ title: 'Yedek geri yüklensin mi?', message: g.name + '\n\n' + (pick.orig ? 'ORİJİNAL (ilk) ayar dosyası' : 'Son yedek (' + new Date(pick.time).toLocaleString('tr-TR') + ')') + ' geri yüklenecek.\nŞu anki dosya önce yedeklenir.\n\n' + s.config, ok: 'Geri yükle', cancel: 'Vazgeç' }); if (!okc) return { error: 'declined', message: 'İptal edildi.', status: 400 };
          const cur = readCfg(s.config); if (!cur.error) backup(g.id, s.config, 'geri yükleme öncesi'); writeAtomic(s.config, fs.readFileSync(src, 'utf8')); s.last = null; saveState(); return { ok: true, restored: pick.orig ? 'orijinal' : 'son yedek' };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'game:target': async (_e, id, fps, allowRes) => { try { const g = await getGame(id); if (!g) return errE('Oyun bulunamadı.'); const n = Math.round(Number(fps)); if (!Number.isFinite(n) || n < LIM.fps[0] || n > LIM.fps[1]) return errE('Hedef FPS ' + LIM.fps[0] + '–' + LIM.fps[1] + ' arasında olmalı.'); const s = gs(g.id); s.target = n; if (typeof allowRes === 'boolean') s.res = Object.assign({ native: null }, s.res, { allow: allowRes }); saveState(); return { ok: true, target: n }; } catch (e) { return errE(String(e && e.message || e)); } },
      'game:hw': async (_e, force) => { try { return await hardware(force === true); } catch (e) { return errE(String(e && e.message || e)); } },
      'game:estimate': async (_e, fps, w, h) => { try { const t = Math.round(Number(fps)); const W = Math.round(Number(w)), H = Math.round(Number(h)); if (!(t >= LIM.fps[0] && t <= LIM.fps[1]) || !(W >= 640 && W <= 7680 && H >= 360 && H <= 4320)) return errE('Geçersiz hedef FPS veya çözünürlük.'); const hw = await hardware(false); return Object.assign({ hw: { gpu: hw.gpu, cpu: hw.cpu, cores: hw.cores, threads: hw.threads, ramGB: hw.ramGB, screen: hw.screen } }, estimatePreset(hw, t, W, H), { ladder: resLadder(W, H) }); } catch (e) { return errE(String(e && e.message || e)); } },
      'game:pm': async (_e, force) => { try { const r = locatePm(force === true); return { found: r.found, path: r.path, tried: r.tried, help: PM_HELP, windows: winMode() }; } catch (e) { return errE(String(e && e.message || e)); } },
      'game:choosePm': async () => { try { if (!deps.choosePm) return errE('Dosya seçimi yok.'); const f = await deps.choosePm(); if (!f) return { canceled: true }; if (typeof f !== 'string' || !path.isAbsolute(f)) return errE('Geçersiz yol.'); state.pm = f; const r = locatePm(true); if (!r.found || lc(r.path) !== lc(f)) { state.pm = null; pmCache = null; return errE('Seçilen dosya PresentMon olarak doğrulanamadı.', { help: PM_HELP }); } saveState(); return { ok: true, path: r.path }; } catch (e) { return errE(String(e && e.message || e)); } },
      'game:measure:start': async (_e, req) => {
        try { if (activeJob) return errE('Başka bir ölçüm sürüyor.'); const run1 = await running(); const t = run1.find((x) => x.gameId && !x.blocked); if (!t) { const blocked = run1.find((x) => x.blocked); return errE(blocked ? 'Çalışan oyunda anti-cheat algılandı (' + blocked.anticheat.map((a) => a.name).join(', ') + '); ölçüm yapılmaz.' : 'Kütüphanende çalışan bir oyun bulunamadı. Oyunu başlat ve oyun içinde hareket ederken tekrar dene.'); }
          const pm = locatePm(false); if (!pm.found) return errE('PresentMon bulunamadı.', { needPm: true, help: PM_HELP }); let sec = Math.round(Number(req && req.seconds)); if (!Number.isFinite(sec)) sec = LIM.defSeconds; sec = Math.min(LIM.seconds[1], Math.max(LIM.seconds[0], sec));
          const id = String(++jobSeq); const job = { id, state: 'running', startedAt: now(), seconds: sec, game: t.name, exe: t.exe, gameId: t.gameId, result: null, error: null, canceled: false, timedOut: false, child: null }; jobs.set(id, job); activeJob = job; if (jobs.size > 6) { const k = jobs.keys().next().value; if (jobs.get(k) !== job) jobs.delete(k); }
          measure(job, pm.path, { exe: t.exe, name: t.name, gameId: t.gameId }, sec).finally(() => { activeJob = null; }); return { id, game: t.name, exe: t.exe, seconds: sec };
        } catch (e) { return errE(String(e && e.message || e)); }
      },
      'game:measure:job': async (_e, id) => { const j = jobs.get(String(id)); if (!j) return errE('İş bulunamadı.'); return { id: j.id, state: j.state, game: j.game, exe: j.exe, seconds: j.seconds, elapsed: (j.endedAt || now()) - j.startedAt, result: j.result, error: j.error }; },
      'game:measure:cancel': async (_e, id) => { const j = jobs.get(String(id)); if (!j) return errE('İş bulunamadı.'); j.canceled = true; try { j.child && j.child.kill(); } catch (e) { /* bitmis */ } return { ok: true }; }
    };
    return { handlers, _scan: scan, _state: () => state };
  }
  return { createGameHost, isUe, ueChanges, detectAntiCheat, parseVdf, iniParse, iniApply, findResolution, resChanges, resLadder, deriveLearned, tuneStep, estimatePreset, gpuPerf, FrameParser, frameStats, findPresentMon, PRESETS, LIM, AC_PROCS, _setPlatform: (p) => { platOverride = p; } };
})();

/* --- RAM Analizi (Volatility 3 koprusu; Kovan 'ramanaliz' v0.0.1) ---
 * Volatility GOMULMEZ/INDIRILMEZ: kullanicinin kendi kurulumu bulunur (PATH'te vol / vol.py, Python + volatility3, ya da kullanicinin sectigi dosya).
 * Dokum dosyasinin yolunu arayuz GONDEREMEZ: dosya burada dialog ile secilir (deps.chooseDump); dokum yalnizca OKUNUR (Volatility'ye -f ile verilir), asla calistirilmaz/degistirilmez/tasinmaz.
 * Komutlar: sabit eklenti beyaz listesi, "-r json", arguman DIZISI, shell YOK. Varsayilan AG KAPALI (--offline); Windows sembol (PDB) indirmesi yalnizca acik onayla.
 * Is modeli: start/job/cancel, tek eszamanli is, zaman asimi (varsayilan 10 dk, asilirsa kismi rapor), cikti boyut siniri + sayfalama. Bulgu motoru: src/engine/102-memscan.js (deps.engine.ramScan). */
const MEMMOD = (() => {
  const fs = require('fs'); const path = require('path'); const os = require('os'); const cp = require('child_process');
  let platOverride = null; const isWin = () => (platOverride || process.platform) === 'win32';
  const EXTS = ['.raw', '.mem', '.dmp', '.vmem', '.lime'];
  /* id, eklenti adaylari (ilk calisan), baslik, agir mi (istege bagli) */
  const LAYERS = [
    { id: 'info', names: ['windows.info'], title: 'Sistem bilgisi', heavy: false }, { id: 'pslist', names: ['windows.pslist'], title: 'Süreç listesi', heavy: false }, { id: 'psscan', names: ['windows.psscan'], title: 'Süreç taraması (havuz)', heavy: false },
    { id: 'pstree', names: ['windows.pstree'], title: 'Süreç ağacı', heavy: false }, { id: 'cmdline', names: ['windows.cmdline'], title: 'Komut satırları', heavy: false }, { id: 'dlllist', names: ['windows.dlllist'], title: 'Yüklü DLL’ler', heavy: false },
    { id: 'ldrmodules', names: ['windows.malware.ldrmodules', 'windows.ldrmodules'], title: 'Modül listeleri (ldrmodules)', heavy: false }, { id: 'malfind', names: ['windows.malware.malfind', 'windows.malfind'], title: 'Enjekte kod (malfind)', heavy: false },
    { id: 'netscan', names: ['windows.netscan'], title: 'Ağ bağlantıları', heavy: false }, { id: 'svcscan', names: ['windows.svcscan'], title: 'Hizmetler', heavy: false }, { id: 'modules', names: ['windows.modules'], title: 'Çekirdek modülleri', heavy: false },
    { id: 'driverscan', names: ['windows.driverscan'], title: 'Sürücü taraması', heavy: false }, { id: 'filescan', names: ['windows.filescan'], title: 'Dosya nesneleri (ağır)', heavy: true }, { id: 'handles', names: ['windows.handles'], title: 'Tutamaçlar (ağır)', heavy: true }
  ];
  const LAYER = Object.create(null); for (const l of LAYERS) LAYER[l.id] = l;
  const DEFAULT_IDS = LAYERS.filter((l) => !l.heavy).map((l) => l.id);
  const LIM = { out: 96 * 1024 * 1024, rows: 300000, page: 200, find: 600, procs: 600, log: 12000, timeoutMin: [1, 120], defMin: 10, q: 120 };
  const PYCODE = 'from volatility3.cli import main; main()'; /* "python -m volatility3" 2.x'te yok (__main__ eksik): giris noktasi dogrudan cagrilir */
  const isFile = (p) => { try { return fs.statSync(p).isFile(); } catch (e) { return false; } };
  const cleanEnv = (base) => { const e = Object.assign({}, base || process.env); for (const k of ['PYTHONSTARTUP', 'PYTHONINSPECT', 'PYTHONBREAKPOINT', 'PYTHONHOME']) delete e[k]; e.PYTHONIOENCODING = 'utf-8'; e.PYTHONUTF8 = '1'; return e; };
  function runSync(file, args, env, ms) { const r = cp.spawnSync(file, args, { env, encoding: 'utf8', timeout: ms || 30000, windowsHide: true, shell: false, maxBuffer: 4 * 1024 * 1024 }); return { code: r.status, out: String(r.stdout || '') + String(r.stderr || ''), err: r.error }; }
  const exeNames = (b) => (isWin() ? [b + '.exe'] : [b]);
  function pathDirs(env, only) { if (only) return only.slice(); const out = []; for (const d of String(env.PATH || env.Path || '').split(path.delimiter)) if (d && path.isAbsolute(d) && !out.includes(d)) out.push(d); return out; }
  function whichIn(dirs, names) { for (const d of dirs) for (const n of names) { const p = path.join(d, n); if (isFile(p)) return p; } return null; }
  const verOf = (txt) => { const m = /Volatility 3 Framework\s+(\S+)/i.exec(String(txt)); return m ? m[1] : ''; };
  function findPython(env, dirs) { for (const nm of isWin() ? ['py', 'python', 'python3'] : ['python3', 'python']) { const p = whichIn(dirs, exeNames(nm)); if (p) return { exe: p, pre: nm === 'py' ? ['-3'] : [] }; } return null; }
  /* Kullanicinin Volatility kurulumunu bul. extra: kullanicinin sectigi dosya (vol, vol.exe, vol.py). Bulunan her aday '-h' ile dogrulanir. */
  function findVol(o) {
    o = o || {}; const env = cleanEnv(o.env); const dirs = pathDirs(env, o.onlyDirs); const cand = []; const seen = new Set(); const add = (c) => { const k = c.exe + '\u0000' + c.pre.join(' '); if (!seen.has(k)) { seen.add(k); cand.push(c); } };
    if (o.userPath && path.isAbsolute(o.userPath) && isFile(o.userPath)) { const ext = path.extname(o.userPath).toLowerCase(); if (ext === '.py') { const py = findPython(env, dirs); if (py) add({ kind: 'user-py', label: 'Seçilen: ' + o.userPath, exe: py.exe, pre: [...py.pre, o.userPath] }); } else if (ext === '' || ext === '.exe') add({ kind: 'user', label: 'Seçilen: ' + o.userPath, exe: o.userPath, pre: [] }); }
    const v = whichIn(dirs, exeNames('vol')); if (v) add({ kind: 'path', label: 'PATH: ' + v, exe: v, pre: [] });
    const vp = whichIn(dirs, ['vol.py']); const py = findPython(env, dirs); if (vp && py) add({ kind: 'path-py', label: 'PATH: ' + vp + ' (Python ile)', exe: py.exe, pre: [...py.pre, vp] });
    if (py) add({ kind: 'module', label: 'Python modülü: volatility3 (' + py.exe + ')', exe: py.exe, pre: [...py.pre, '-c', PYCODE] });
    const tried = []; let best = null;
    for (const c of cand) { const r = runSync(c.exe, [...c.pre, '-h'], env, o.probeMs || 40000); const ver = verOf(r.out); const ok = !!ver; tried.push({ label: c.label, ok, version: ver, why: ok ? '' : (r.err && r.err.code === 'ENOENT' ? 'bulunamadı' : /No module named/i.test(r.out) ? 'volatility3 Python paketi kurulu değil' : 'Volatility 3 olarak doğrulanamadı') }); if (ok && !best) best = Object.assign({}, c, { version: ver }); }
    return { found: !!best, best, tried, python: !!py };
  }
  const INSTALL = ['Volatility 3 bu uygulamayla gelmez; kendi bilgisayarına kur:', '1) Python 3.8+ kur (python.org).', '2) Komut satırında: pip install volatility3', '3) Bu sayfada “Yeniden ara”ya bas; bulunamazsa “vol” dosyasını (Scripts klasöründeki vol.exe veya vol.py) “Yol seç” ile göster.'];
  function validDump(p) {
    if (typeof p !== 'string' || !path.isAbsolute(p)) return { error: 'Geçersiz dosya yolu.' }; let st; try { st = fs.statSync(p); } catch (e) { return { error: 'Dosya okunamadı.' } } if (!st.isFile()) return { error: 'Bu bir dosya değil.' };
    const ext = path.extname(p).toLowerCase(); if (!EXTS.includes(ext)) return { error: 'Desteklenmeyen uzantı (' + (ext || 'yok') + '). Beklenen: ' + EXTS.join(' ') }; if (!st.size) return { error: 'Dosya boş.' };
    try { fs.accessSync(p, fs.constants.R_OK); } catch (e) { return { error: 'Dosya okunamıyor (izin yok).' } } return { ok: true, size: st.size, name: path.basename(p), ext };
  }
  function classify(out, offline) {
    const s = String(out); if (/Unsatisfied requirement[\s\S]*symbol_table_name|symbol table requirement|Unable to validate the plugin requirements/i.test(s) && /symbol/i.test(s)) return { code: 'symbols', message: offline ? 'Bu dökümün Windows sembolleri (PDB/ISF) çevrimdışı önbellekte yok. Ağ kapalı olduğu için indirilemedi. İzin verirsen Microsoft sembol sunucusundan indirilir; ya da sembolü Volatility’nin sembol klasörüne kendin koy.' : 'Windows sembolleri bulunamadı veya indirilemedi (ağ/sunucu hatası ya da bu sürüm için sembol yok).' };
    if (/translation layer requirement was not fulfilled|valid memory image/i.test(s)) return { code: 'layer', message: 'Dosya geçerli bir Windows bellek dökümü olarak tanınmadı (biçim/boyut bozuk ya da Windows dışı bir döküm olabilir).' };
    if (/No such file|cannot find the file/i.test(s)) return { code: 'file', message: 'Döküm dosyası bulunamadı.' }; return { code: 'plugin', message: 'Eklenti başarısız oldu.' };
  }
  function parseJson(txt) { const s = String(txt); const i = s.search(/[\[{]/); if (i < 0) return null; try { const v = JSON.parse(s.slice(i)); return Array.isArray(v) ? v : (v && typeof v === 'object' ? [v] : null); } catch (e) { return null; } }
  function flat(rows, depth) { const out = []; for (const r of Array.isArray(rows) ? rows : []) { if (!r || typeof r !== 'object') continue; const rest = Object.assign({}, r); const ch = rest.__children; delete rest.__children; rest.__depth = depth || 0; out.push(rest); if (Array.isArray(ch) && ch.length) for (const c of flat(ch, (depth || 0) + 1)) out.push(c); } return out; }
  const confirmText = () => 'Windows bellek dökümlerini çözmek için Volatility, çekirdeğin sembol (PDB) dosyasını Microsoft sembol sunucusundan (msdl.microsoft.com, HTTP) indirmek ister.\n\n• Giden bilgi: yalnızca çekirdek dosya adı ve sürüm kimliği (GUID/yaş) ile bağlantı bilgin (IP). Döküm içeriği GÖNDERİLMEZ.\n• İnen: sembol dosyaları (onlarca MB’a kadar); Volatility’nin kendi önbellek klasörüne yazılır. Hiçbir şey çalıştırılmaz.\n• Reddedersen ağ KULLANILMAZ; yalnızca çevrimdışı önbellekteki semboller kullanılır ve yoksa bunu net söyleriz.';
  function createMemHost(deps) {
    deps = deps || {}; const jobs = new Map(); let seq = 0; let active = null; let picked = null; let userVol = null; let volCache = null;
    const errE = (message, extra) => Object.assign({ error: 'mem', message }, extra || {});
    const eng = deps.engine || null; const stateFile = deps.dataDir ? path.join(deps.dataDir, 'ramanaliz.json') : null;
    if (stateFile) { try { const o = JSON.parse(fs.readFileSync(stateFile, 'utf8')); if (o && typeof o.vol === 'string' && path.isAbsolute(o.vol)) userVol = o.vol; } catch (e) { /* ilk kullanim */ } }
    const saveState = () => { if (!stateFile) return; try { fs.mkdirSync(path.dirname(stateFile), { recursive: true }); const t = stateFile + '.tmp'; fs.writeFileSync(t, JSON.stringify({ vol: userVol })); fs.renameSync(t, stateFile); } catch (e) { /* yazilamazsa bellekte kalir */ } };
    const locate = (force) => { if (volCache && !force) return volCache; volCache = findVol({ env: deps.env, onlyDirs: deps.onlyDirs, userPath: userVol, probeMs: deps.probeMs }); return volCache; };
    const pub = (r) => ({ found: r.found, version: r.best ? r.best.version : '', label: r.best ? r.best.label : '', tried: r.tried, python: r.python, install: INSTALL });
    function exec(job, file, args, cwd, ms) {
      return new Promise((resolve) => {
        const env = cleanEnv(deps.env); let out = ''; let errs = ''; let size = 0; let over = false; let done = false; let timer; const chunks = [];
        const fin = (r) => { if (done) return; done = true; clearTimeout(timer); job.child = null; resolve(Object.assign({ out: Buffer.concat(chunks).toString('utf8'), err: errs, over }, r)); };
        let c; try { c = cp.spawn(file, args, { cwd, env, windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return fin({ code: -1, err: String(e && e.message || e) }); }
        job.child = c; c.stdout.on('data', (d) => { size += d.length; if (size > LIM.out) { if (!over) { over = true; try { c.kill(); } catch (e) { /* bitmis */ } } return; } chunks.push(d); });
        c.stderr.on('data', (d) => { errs += d; if (errs.length > 200000) errs = errs.slice(-100000); });
        timer = setTimeout(() => { job.timedOut = true; try { c.kill(); } catch (e) { /* bitmis */ } fin({ code: -2 }); }, Math.max(1000, ms));
        c.on('error', (e) => fin({ code: -1, err: errs + String(e && e.message || e) })); c.on('close', (code) => fin({ code }));
      });
    }
    async function run(job, req, vol, allowNet) {
      const work = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-ram-')); const logp = (t) => { job.log += t + '\n'; if (job.log.length > 60000) job.log = job.log.slice(-40000); };
      const S = (id) => job.steps.find((s) => s.id === id); const step = (id, st, d) => { const s = S(id); if (!s) return; s.status = st; if (d !== undefined) s.detail = d; };
      try {
        for (const id of req.layers) {
          if (job.canceled || job.timedOut) break; const L = LAYER[id]; step(id, 'run'); let got = null; let lastErr = '';
          for (const nm of L.names) {
            const left = job.deadline - Date.now(); if (left < 1000) { job.timedOut = true; break; }
            const args = [...vol.pre, '-q', ...(allowNet ? [] : ['--offline']), '-o', work, '-f', req.file, '-r', 'json', nm]; if (deps.logArgs) deps.logArgs(vol.exe, args);
            const r = await exec(job, vol.exe, args, work, left); if (job.canceled || job.timedOut) break;
            if (r.over) { lastErr = 'Çıktı boyut sınırını aştı (' + Math.round(LIM.out / 1048576) + ' MB).'; logp('[' + nm + '] ' + lastErr); got = { truncated: true, rows: [] }; break; }
            const rows = r.code === 0 ? parseJson(r.out) : null;
            if (rows) { let f = flat(rows); let tr = false; if (f.length > LIM.rows) { f = f.slice(0, LIM.rows); tr = true; } got = { rows: f, truncated: tr }; break; }
            const c = classify(r.err + '\n' + r.out.slice(0, 4000), !allowNet); lastErr = c.message; logp('[' + nm + '] ' + String(r.err).trim().split(/\r?\n/).slice(-6).join('\n')); if (/invalid choice|unrecognized|No plugin|not a valid plugin/i.test(r.err) && L.names.length > 1) { lastErr = ''; continue; } if (c.code === 'symbols' || c.code === 'layer' || c.code === 'file') { job.fatal = job.fatal || c; break; } break;
          }
          if (got && got.rows.length >= 0 && !lastErr) { job.data[id] = got.rows; job.layerInfo[id] = { rows: got.rows.length, truncated: got.truncated, error: '' }; step(id, 'ok', got.rows.length + ' satır' + (got.truncated ? ' (kesildi)' : '')); }
          else if (got && got.truncated) { job.layerInfo[id] = { rows: 0, truncated: true, error: lastErr }; step(id, 'fail', lastErr); }
          else if (!job.canceled && !job.timedOut) { job.layerInfo[id] = { rows: 0, truncated: false, error: lastErr || 'Eklenti çalışmadı.' }; step(id, 'fail', lastErr || 'Eklenti çalışmadı.'); if (job.fatal && (id === 'info' || id === 'pslist' || Object.keys(job.data).length === 0)) { for (const x of job.steps) if (x.status === 'wait') { x.status = 'skip'; x.detail = 'Atlandı (döküm çözülemedi)'; } break; } }
        }
        for (const x of job.steps) if (x.status === 'run') { x.status = 'fail'; x.detail = job.canceled ? 'İptal edildi' : job.timedOut ? 'Zaman aşımı' : x.detail; } else if (x.status === 'wait' && (job.canceled || job.timedOut)) { x.status = 'skip'; x.detail = job.canceled ? 'İptal edildi' : 'Zaman aşımı'; }
        const have = Object.keys(job.data).length;
        if (job.canceled) { job.state = 'canceled'; return; }
        if (!have) { job.state = 'failed'; job.error = job.fatal ? job.fatal.message : (job.timedOut ? 'Zaman aşımı: hiçbir katman tamamlanmadı.' : 'Hiçbir katman çalıştırılamadı. Ayrıntı için günlüğe bak.'); job.errorCode = job.fatal ? job.fatal.code : (job.timedOut ? 'timeout' : 'plugin'); return; }
        const partial = job.timedOut || req.layers.some((id) => !job.data[id]); const scan = eng && eng.ramScan ? eng.ramScan(job.data) : null;
        job.result = { partial, timedOut: !!job.timedOut, scan: scan ? { version: scan.version, score: scan.score, level: scan.level, headline: scan.headline, counts: scan.counts, coverage: scan.coverage, notes: scan.notes, os: scan.os, caveats: scan.caveats, procs: scan.procs.slice(0, LIM.procs), findings: scan.findings.slice(0, LIM.find), moreFindings: Math.max(0, scan.findings.length - LIM.find) } : null, layers: job.layerInfo, meta: job.meta };
        job.scan = scan; job.state = partial ? 'partial' : 'done'; if (job.timedOut) job.error = 'Zaman aşımı (' + job.timeoutMin + ' dk): kısmi rapor üretildi.';
        if (deps.notify) { try { deps.notify('Kovan RAM Analizi', scan ? 'Bitti: puan ' + scan.score + '/100 (' + (partial ? 'kısmi' : 'tam') + ')' : 'Bitti') } catch (e) { /* bildirim yok */ } }
      } finally { try { fs.rmSync(work, { recursive: true, force: true }); } catch (e) { /* gecici klasor */ } if (job.state === 'running') job.state = 'failed'; job.endedAt = Date.now(); }
    }
    const handlers = {
      'mem:tools': async (_e, force) => { try { const r = locate(force === true); return Object.assign(pub(r), { layers: LAYERS.map((l) => ({ id: l.id, title: l.title, heavy: l.heavy })), exts: EXTS, windows: isWin() }); } catch (e) { return errE(String(e && e.message || e)); } },
      'mem:chooseVol': async () => { if (!deps.chooseVol) return errE('Dosya seçimi yok.'); const f = await deps.chooseVol(); if (!f) return { canceled: true }; if (typeof f !== 'string' || !path.isAbsolute(f)) return errE('Geçersiz yol.'); userVol = f; const r = locate(true); if (!r.found) { userVol = null; volCache = null; return Object.assign(errE('Seçilen dosya Volatility 3 olarak doğrulanamadı.'), pub(r)); } saveState(); return Object.assign({ ok: true }, pub(r)); },
      'mem:chooseDump': async () => { if (!deps.chooseDump) return errE('Dosya seçimi yok.'); const f = await deps.chooseDump(); if (!f) return { canceled: true }; const v = validDump(f); if (v.error) { picked = null; return errE(v.error); } picked = { path: f, size: v.size, name: v.name, ext: v.ext }; return { ok: true, name: v.name, size: v.size, ext: v.ext }; },
      'mem:start': async (_e, req) => {
        if (!req || typeof req !== 'object') return errE('Geçersiz istek.'); if (active) return errE('Başka bir analiz sürüyor.'); if (!picked) return errE('Önce bir bellek dökümü seç.');
        const v = validDump(picked.path); if (v.error) return errE(v.error); if (req.layers !== undefined && !Array.isArray(req.layers)) return errE('Katman seçimi geçersiz.'); const ids = Array.isArray(req.layers) ? req.layers : DEFAULT_IDS; if (!ids.length || ids.length > LAYERS.length || ids.some((x) => typeof x !== 'string' || !LAYER[x]) || new Set(ids).size !== ids.length) return errE('Katman seçimi geçersiz.');
        const order = LAYERS.map((l) => l.id).filter((x) => ids.includes(x)); const sym = req.symbols === 'allow' ? 'allow' : 'offline'; let tmo = Number(req.timeoutMin); if (!Number.isFinite(tmo)) tmo = LIM.defMin; tmo = Math.min(LIM.timeoutMin[1], Math.max(LIM.timeoutMin[0], Math.round(tmo)));
        const vr = locate(false); if (!vr.found) return errE('Volatility 3 bulunamadı.', { needVol: true, install: INSTALL, tried: vr.tried });
        let allowNet = false; if (sym === 'allow') { if (!deps.confirm) return errE('Onay penceresi yok; ağ kullanılamaz (çevrimdışı devam için “çevrimdışı” seç).'); allowNet = !!(await deps.confirm({ title: 'Sembol indirmeye izin verilsin mi?', message: confirmText(), ok: 'İndirmeye izin ver', cancel: 'Çevrimdışı devam et' })); }
        const id = String(++seq); const job = { id, state: 'running', steps: order.map((x) => ({ id: x, label: LAYER[x].title, status: 'wait', detail: '' })), log: '', result: null, scan: null, error: null, errorCode: '', data: {}, layerInfo: {}, startedAt: Date.now(), deadline: Date.now() + tmo * (deps.msPerMin || 60000), timeoutMin: tmo, net: allowNet, netAsked: sym === 'allow', canceled: false, timedOut: false, fatal: null, child: null, meta: { name: picked.name, size: picked.size, vol: vr.best.version, date: new Date().toISOString(), network: allowNet ? 'izinli' : 'kapalı (--offline)' } };
        jobs.set(id, job); active = job; if (jobs.size > 6) { const k = jobs.keys().next().value; if (jobs.get(k) !== job) jobs.delete(k); }
        run(job, Object.assign({ layers: order, file: picked.path }), vr.best, allowNet).catch((e) => { job.state = 'failed'; job.error = String(e && e.message || e); }).finally(() => { active = null; });
        return { id, network: allowNet, declined: sym === 'allow' && !allowNet };
      },
      'mem:job': async (_e, id) => { const j = jobs.get(String(id)); if (!j) return errE('İş bulunamadı.'); return { id: j.id, state: j.state, steps: j.steps, log: j.log.slice(-LIM.log), result: j.result, error: j.error, errorCode: j.errorCode, network: j.net, elapsed: (j.endedAt || Date.now()) - j.startedAt, timeoutMin: j.timeoutMin }; },
      'mem:cancel': async (_e, id) => { const j = jobs.get(String(id)); if (!j) return errE('İş bulunamadı.'); j.canceled = true; try { j.child && j.child.kill(); } catch (e) { /* bitmis */ } return { ok: true }; },
      'mem:rows': async (_e, id, layer, offset, limit, q) => {
        const j = jobs.get(String(id)); if (!j) return errE('İş bulunamadı.'); if (typeof layer !== 'string' || !LAYER[layer]) return errE('Katman geçersiz.'); const rows = j.data[layer]; if (!rows) return errE('Bu katman çalışmadı.');
        let off = Math.max(0, Math.floor(Number(offset)) || 0); const lim = Math.min(LIM.page, Math.max(1, Math.floor(Number(limit)) || 100)); const needle = String(q || '').toLowerCase().slice(0, LIM.q); let list = rows;
        if (needle) list = rows.filter((r) => { try { return JSON.stringify(r).toLowerCase().includes(needle); } catch (e) { return false; } });
        const cols = []; for (const r of list.slice(0, 50)) for (const k of Object.keys(r)) if (k !== '__depth' && !cols.includes(k)) cols.push(k); if (off >= list.length) off = Math.max(0, list.length - lim);
        return { layer, total: list.length, all: rows.length, offset: off, columns: cols.slice(0, 24), rows: list.slice(off, off + lim), truncated: !!(j.layerInfo[layer] && j.layerInfo[layer].truncated) };
      },
      'mem:report': async (_e, id, kind) => {
        const j = jobs.get(String(id)); if (!j || !j.scan) return errE('Rapor yok (analiz bitmemiş).'); const meta = Object.assign({}, j.meta, { partial: j.state === 'partial' });
        if (kind === 'json') return { ok: true, name: 'kovan-ram-analizi.json', mime: 'application/json', text: JSON.stringify({ meta, result: j.scan }, null, 2) };
        return { ok: true, name: 'kovan-ram-analizi.md', mime: 'text/markdown', text: eng && eng.ramReportText ? eng.ramReportText(j.scan, meta) : '' };
      }
    };
    return { handlers, _locate: locate, _pick: (p) => { const v = validDump(p); if (v.error) return v; picked = { path: p, size: v.size, name: v.name, ext: v.ext }; return v; } };
  }
  return { createMemHost, findVol, validDump, classify, parseJson, flat, LAYERS, EXTS, LIM, DEFAULT_IDS, PYCODE, _setPlatform: (p) => { platOverride = p; } };
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
  /* Kalici tarama gecmisi + ICERIK (SHA-256) tekillestirme: ayni icerik yeniden taranmaz/bildirilmez, her tarama burada gorunur.
     Tek satir = tek icerik (sayac artar). Yalnizca ozet saklanir (ad, klasor, boyut, skor, karar, ilk 3 bulgu basligi); dosya icerigi saklanmaz. */
  const HMAX = deps.historyMax || 2000; const hist = { rows: [], by: new Map() }; let hTimer = null, hDirty = false, hSeq = 0;
  const HS = (v, n) => String(v == null ? '' : v).slice(0, n); const isSha = (x) => typeof x === 'string' && /^[0-9a-f]{64}$/.test(x);
  const hKey = (r) => (isSha(r.sha256) ? r.sha256 : 'x:' + r.name + ':' + (r.size | 0));
  function hClean(r) {
    if (!r || typeof r !== 'object') return null; const first = HS(r.first || r.last, 40); const last = HS(r.last || r.first, 40); if (!first || isNaN(Date.parse(first)) || isNaN(Date.parse(last))) return null;
    const sc = r.score === null || r.score === undefined || r.score === '' ? null : Number(r.score);
    return { id: r.id | 0, src: r.src === 'watch' ? 'watch' : 'manual', name: HS(r.name, 200), dir: HS(r.dir, 500), size: Math.max(0, Number(r.size) || 0), sha256: isSha(r.sha256) ? r.sha256 : '', score: sc === null || !isFinite(sc) ? null : Math.max(0, Math.min(100, Math.round(sc))), verdict: HS(r.verdict, 60), partial: !!r.partial, mode: HS(r.mode, 20), alert: !!r.alert, notified: !!r.notified, top: Array.isArray(r.top) ? r.top.slice(0, 3).map((x) => HS(x, 90)) : [], count: Math.max(1, r.count | 0), first, last };
  }
  function hFlush() {
    if (hTimer) { clearTimeout(hTimer); hTimer = null; } if (!hDirty || !deps.historyPath) return; hDirty = false;
    try { fs.mkdirSync(path.dirname(deps.historyPath), { recursive: true }); const tmp = deps.historyPath + '.tmp'; fs.writeFileSync(tmp, JSON.stringify({ v: 1, rows: hist.rows }), { mode: 0o600 }); fs.renameSync(tmp, deps.historyPath); } catch (e) { addLog('error', 'Tarama geçmişi yazılamadı: ' + e.message); }
  }
  function hSave(now) { hDirty = true; if (!deps.historyPath) return; if (now) { hFlush(); return; } if (!hTimer) hTimer = setTimeout(hFlush, 400); }
  const hFront = (r) => { const i = hist.rows.indexOf(r); if (i > 0) { hist.rows.splice(i, 1); hist.rows.unshift(r); } };
  function hLoad() {
    if (!deps.historyPath) return; let o = null; try { o = JSON.parse(fs.readFileSync(deps.historyPath, 'utf8')); } catch (e) { return; } if (!o || !Array.isArray(o.rows)) return;
    for (const raw of o.rows.slice(0, HMAX)) { const c = hClean(raw); if (c && !hist.by.has(hKey(c))) { hist.rows.push(c); hist.by.set(hKey(c), c); } }
    hist.rows.sort((a, b) => Date.parse(b.last) - Date.parse(a.last)); hSeq = hist.rows.reduce((m, r) => Math.max(m, r.id), 0);
  }
  function historyAdd(e) {
    if (!e || typeof e !== 'object') return null; const now = new Date().toISOString(); const c = hClean(Object.assign({}, e, { id: 0, first: now, last: now, count: 1 })); if (!c) return null; const old = hist.by.get(hKey(c));
    if (old) { Object.assign(old, { src: c.src, name: c.name, dir: c.dir || old.dir, size: c.size, score: c.score, verdict: c.verdict, partial: c.partial, mode: c.mode, alert: c.alert, notified: old.notified || c.notified, top: c.top, count: old.count + 1, last: now }); hFront(old); hSave(); return old; }
    c.id = ++hSeq; hist.rows.unshift(c); hist.by.set(hKey(c), c);
    while (hist.rows.length > HMAX) { const x = hist.rows.pop(); if (hist.by.get(hKey(x)) === x) hist.by.delete(hKey(x)); } hSave(); return c;
  }
  function historyList(o) {
    o = o || {}; const q = HS(o.q, 100).toLowerCase(); let rows = hist.rows;
    if (o.filter === 'alert') rows = rows.filter((r) => r.alert); else if (o.filter === 'watch') rows = rows.filter((r) => r.src === 'watch'); else if (o.filter === 'manual') rows = rows.filter((r) => r.src === 'manual');
    if (q) rows = rows.filter((r) => (r.name + ' ' + r.dir + ' ' + r.sha256 + ' ' + r.verdict).toLowerCase().includes(q));
    const off = Math.max(0, Number(o.offset) | 0); const lim = Math.min(200, Math.max(1, Number(o.limit) | 0 || 50));
    return { total: hist.rows.length, alerts: hist.rows.filter((r) => r.alert).length, matched: rows.length, rows: rows.slice(off, off + lim).map((r) => Object.assign({}, r, { top: r.top.slice() })) };
  }
  function historyClear() { hist.rows.length = 0; hist.by.clear(); hSave(true); }
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
    try {
      const buf = fs.readFileSync(it.full); const sha256 = require('crypto').createHash('sha256').update(buf).digest('hex'); const prev = hist.by.get(sha256);
      if (prev && prev.score !== null) { /* ayni icerik zaten taranmis: yeniden tarama ve bildirim YOK (mtime/yol degisse de) */
        prev.count++; prev.last = new Date().toISOString(); prev.name = it.name; prev.dir = it.dir; prev.size = buf.length; hFront(prev); hSave();
        addLog('info', it.name + ' — içerik daha önce taranmış (aynı SHA-256, ' + prev.count + '. görülme); tekrar taranmadı, bildirim gönderilmedi', { name: it.name });
        return { item: { id: it.id, name: it.name, dir: it.dir, size: buf.length, sha256, dup: true, prev: { score: prev.score, verdict: prev.verdict, last: prev.last } } };
      }
      return { item: { id: it.id, name: it.name, dir: it.dir, size: buf.length, sha256, bytes: new Uint8Array(buf.buffer, buf.byteOffset, buf.length) } };
    } catch (e) { addLog('error', it.name + ' okunamadı: ' + e.message, { name: it.name }); return { item: { id: it.id, name: it.name, dir: it.dir, size: it.size, error: 'Okunamadı: ' + e.message } }; }
  }
  hLoad();
  return { validate, setFolders, take, stop, log: () => log.slice(0, 100), addLog, folders: () => [...folders.keys()], historyAdd, historyList, historyClear, flush: hFlush, _tick: tick, _consider: consider };
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
  /* RAM Analizi: kullanicinin kendi Volatility 3 kurulumu (bkz. MEMMOD); dosya secimi + ag onayi host tarafinda */
  if (deps.mem !== false) { const mh = MEMMOD.createMemHost(Object.assign({ confirm: deps.confirm, notify: deps.notify }, deps.mem || {})); Object.assign(handlers, mh.handlers); }
  /* Uygulama Akisi: sagdaki akan sutun; yalniz kullanicinin sectigi uygulamalar, yol arayuzden gelmez (bkz. FLOWMOD) */
  if (deps.flow !== false) { const fh = FLOWMOD.createFlowHost(Object.assign({ openExternal: deps.openExternal }, deps.flow || {})); Object.assign(handlers, fh.handlers); }
  /* Otomatik Guncelleyici: winget ile kontrol/onayli guncelleme (bkz. UPDMOD) */
  if (deps.upd !== false) { const uh = UPDMOD.createUpdHost(Object.assign({}, deps.flow ? { dataDir: deps.flow.dataDir, fileIcon: deps.flow.fileIcon, chooseApp: deps.flow.chooseApp, readShortcut: deps.flow.readShortcut, startMenuDirs: deps.flow.startMenuDirs, platform: deps.flow.platform } : {}, deps.upd || {})); Object.assign(handlers, uh.handlers); }
  /* Oyun Ayarlayici: oyun algilama + anti-cheat filtresi + yedekli ayar dosyasi + FPS olcumu (bkz. GAMEMOD) */
  if (deps.game !== false) { const gh = GAMEMOD.createGameHost(Object.assign({ confirm: deps.confirm, notify: deps.notify }, deps.game || {})); Object.assign(handlers, gh.handlers); }
  /* Karsi Secim (LoL counter): Data Dragon + kisisel kayit + salt-okunur LCU (bkz. LOLMOD) */
  if (deps.lol !== false) { const lh = LOLMOD.createLolHost(Object.assign({ confirm: deps.confirm }, deps.lol || {})); Object.assign(handlers, lh.handlers); }
  /* harici decompiler koprusu (yalnizca onayli, yalnizca yerel; bkz. OBFMOD) */
  const obf = OBFMOD.createObfHost({ outputRoot: deps.obfOutputRoot, userToolsDir: deps.obfToolsDir, showItemInFolder: deps.showItemInFolder, confirm: deps.confirm, spawn: deps.obfSpawn, env: deps.obfEnv });
  if (deps.obfOutputRoot) Object.assign(handlers, obf.handlers);
  const watcher = createWatcher({ excludeDir: deps.obfOutputRoot, maxBytes: deps.watchMaxBytes, tickMs: deps.watchTickMs, historyPath: deps.historyPath, historyMax: deps.historyMax }); const recentNotes = new Map();
  Object.assign(handlers, {
    'watch:suggest': async () => { const out = []; const add = (label, p) => { try { if (p && fs.statSync(p).isDirectory()) out.push({ label, path: p }); } catch (e) { /* yok */ } }; if (deps.downloadsDir) add('İndirilenler', deps.downloadsDir); if (deps.modsDirs) deps.modsDirs.forEach((m) => add(m.label, m.path)); return { suggestions: out }; },
    'watch:choose': async () => { if (!deps.chooseFolder) return { error: 'na', message: 'Klasör seçimi yok.' }; const d = await deps.chooseFolder(); if (!d) return { canceled: true }; const e = watcher.validate(d); return e ? { error: 'bad', message: e } : { path: d }; },
    'watch:set': async (_e, list) => watcher.setFolders(list),
    'watch:take': async () => watcher.take(),
    'watch:log': async () => ({ log: watcher.log(), folders: watcher.folders() }),
    'watch:note': async (_e, kind, text, name) => { const k = ['scan', 'alert', 'info', 'error'].includes(kind) ? kind : 'info'; watcher.addLog(k, String(text || '').slice(0, 400), { name: String(name || '').slice(0, 200) }); return { ok: true }; },
    /* ayni metinli bildirim 10 dk icinde yeniden gosterilmez (arayuz tarafindan tekrarlansa bile) */
    'watch:notify': async (_e, title, body) => { const t = String(title || '').slice(0, 100); const b = String(body || '').slice(0, 300); const k = t + '\n' + b; const now = Date.now(); const last = recentNotes.get(k); if (last !== undefined && now - last < 600000) return { ok: true, suppressed: true }; recentNotes.set(k, now); if (recentNotes.size > 200) for (const [kk, v] of recentNotes) if (now - v >= 600000) recentNotes.delete(kk); if (deps.notify) deps.notify(t, b); return { ok: true }; },
    'history:add': async (_e, entry) => { const r = watcher.historyAdd(entry); return r ? { ok: true, id: r.id, count: r.count } : { error: 'bad', message: 'Geçersiz kayıt.' }; },
    'history:list': async (_e, o) => watcher.historyList(o),
    'history:clear': async () => { if (deps.confirm) { const ok = await deps.confirm({ title: 'Tarama geçmişi silinsin mi?', message: 'Listelenen tüm tarama kayıtları silinir. Dosyalara dokunulmaz. Silinen içerikler klasör izlemede yeniden görülürse bir kez daha taranır ve bildirilebilir.', ok: 'Geçmişi sil', cancel: 'Vazgeç' }); if (!ok) return { canceled: true }; } watcher.historyClear(); return { ok: true }; }
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

module.exports = { createHost, createWatcher, readLnkTarget, updModule: UPDMOD, repoModule: REPOMOD, riskyList, VT_RE, obfModule: OBFMOD, compileModule: COMPMOD, accessModule: ACCESSMOD, sysModule: SYSMOD, memModule: MEMMOD, gameModule: GAMEMOD, lolModule: LOLMOD, flowModule: FLOWMOD };
