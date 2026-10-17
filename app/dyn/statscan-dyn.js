#!/usr/bin/env node
/*
 * StatScan dinamik analiz yardimcisi (Windows Sandbox)
 * ----------------------------------------------------
 * - Ornegi ASLA ana sistemde calistirmaz; yalnizca Windows Sandbox icinde calistirir.
 * - Yalnizca Windows 10 Pro ve Windows 11 Pro'da acilir; kosullar karsilanmiyorsa nedenini soyler.
 * - Bagimlilik yok (yalniz Node.js >= 18). StatScan.html icindeki statik motoru aynen kullanir.
 *
 * Kullanim:
 *   node statscan-dyn.js check                 kosullari denetler
 *   node statscan-dyn.js scan <dosya>          once statik tarar; anlamli bulgu yoksa dinamik analizi sorar
 *   node statscan-dyn.js dry-run <dosya>       .wsb ve calisma klasorunu uretir, Sandbox'i BASLATMAZ
 *   node statscan-dyn.js serve                 StatScan.html'i yerel (127.0.0.1) olarak sunar; arayuzden dinamik analiz
 *   node statscan-dyn.js help
 */
'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const cp = require('child_process');
const http = require('http');
const crypto = require('crypto');
const readline = require('readline');

const VERSION = '1.0.0';
const GUEST_HOME = 'C:\\Users\\WDAGUtilityAccount';
const GUEST_IN = GUEST_HOME + '\\Desktop\\in';
const GUEST_OUT = GUEST_HOME + '\\Desktop\\out';
const GUEST_JRE = GUEST_HOME + '\\Desktop\\jre';
const SANDBOX_PROCS = ['WindowsSandbox.exe', 'WindowsSandboxClient.exe', 'WindowsSandboxRemoteSession.exe', 'WindowsSandboxServer.exe'];
const SEV_RANK = { info: 0, low: 1, med: 2, high: 3, crit: 4 };

/* ======================================================================
 * Yardimcilar
 * ==================================================================== */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const xmlEsc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
const xmlUnesc = (s) => String(s).replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
const clone = (o) => JSON.parse(JSON.stringify(o));
const extOf = (n) => { const b = String(n || '').split(/[\\/]/).pop(); const i = b.lastIndexOf('.'); return i > 0 ? b.slice(i + 1).toLowerCase() : ''; };
const baseOf = (n) => String(n || '').split(/[\\/]/).pop();
const isObj = (o) => o && typeof o === 'object' && !Array.isArray(o);

class DynError extends Error {
  constructor(code, message, extra) { super(message); this.code = code; this.extra = extra || null; }
}

/* ======================================================================
 * Yapilandirma
 * ==================================================================== */
const DEFAULTS = {
  sandbox: {
    clipboard: 'Disable',      // ClipboardRedirection: pano
    networking: 'Disable',     // Networking: ag
    printer: 'Disable',        // PrinterRedirection: yazici
    audioInput: 'Disable',     // AudioInput: mikrofon
    videoInput: 'Disable',     // VideoInput: kamera
    vGPU: 'Disable',           // vGPU: sanal GPU
    protectedClient: 'Default', // ProtectedClient (AppContainer yalitimi)
    memoryMB: 4096,
    mappedFolders: []          // yalnizca gerekli ek klasorler; varsayilan salt okunur
  },
  analysis: {
    durationSec: 60,
    stopWhenIdle: true,        // surec bitti ve sessizlik olduysa erken bitir
    idleSec: 10,
    defender: 'keep',          // keep: Sandbox icindeki Defender acik kalir (tespitleri raporlanir) | disable: davranisi gormek icin kapatilir
    screenshot: true,
    hkcuDiff: true,
    bait: true,                // sahte kimlik/cuzdan dosyalari + pano tuzagi (stealer/clipper tespiti)
    firewallLanBlock: true,    // ag acikken yerel agi engelle (en iyi caba)
    maxDropped: 20,
    maxDroppedMB: 20,
    javaHome: '',              // .jar icin tasinabilir JRE/JDK klasoru (icinde bin\java.exe)
    dllExport: 'DllMain',
    launch: {},                // {"exe":{"program":"{sample}","args":["--x"]}} gibi uzanti/tur bazli komut
    preSteps: [],              // Sandbox icinde ornekten once calisacak PowerShell satirlari
    postSteps: [],             // ornek bittikten sonra calisacak PowerShell satirlari
    watchExtra: []             // izlenecek ek Sandbox klasorleri
  },
  host: {
    stagingRoot: '',
    keepArtifacts: false,
    maxSampleMB: 150,
    startupTimeoutSec: 240,
    collectTimeoutSec: 180,
    minimizeWindow: true,
    showGuestConsole: false,
    scanDropped: true,
    scanDroppedMode: 'normal',
    port: 0
  }
};

const ENABLE_VALUES = ['Enable', 'Disable', 'Default'];
const SYN_ON = new Set(['true', 'on', 'ac', 'aç', 'acik', 'açık', 'evet', 'enable', 'enabled']);
const SYN_OFF = new Set(['false', 'off', 'kapat', 'kapali', 'kapalı', 'hayir', 'hayır', 'disable', 'disabled']);

function normEnable(v, name, def, errors) {
  if (v === undefined || v === null || v === '') return def;
  const s = String(v).trim().toLowerCase();
  const exact = ENABLE_VALUES.find((x) => x.toLowerCase() === s);
  if (exact) return exact;
  if (v === true || SYN_ON.has(s)) return 'Enable';
  if (v === false || SYN_OFF.has(s)) return 'Disable';
  if (s === 'varsayilan' || s === 'varsayılan') return 'Default';
  errors.push(name + ': "' + v + '" geçersiz. Enable, Disable veya Default olmalı.');
  return def;
}
function normInt(v, name, def, min, max, errors) {
  if (v === undefined || v === null || v === '') return def;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) { errors.push(name + ': ' + min + ' ile ' + max + ' arasında bir tam sayı olmalı (verilen: ' + v + ').'); return def; }
  return n;
}
function normBool(v, name, def, errors) {
  if (v === undefined || v === null || v === '') return def;
  if (typeof v === 'boolean') return v;
  const s = String(v).toLowerCase();
  if (SYN_ON.has(s)) return true; if (SYN_OFF.has(s)) return false;
  errors.push(name + ': true veya false olmalı.'); return def;
}
function normStrList(v, name, max, maxLen, errors) {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) { errors.push(name + ': liste olmalı.'); return []; }
  const out = [];
  for (const x of v.slice(0, max)) { if (typeof x !== 'string' || x.length > maxLen || /[\u0000]/.test(x)) { errors.push(name + ': geçersiz öğe.'); continue; } out.push(x); }
  if (v.length > max) errors.push(name + ': en çok ' + max + ' öğe kabul edilir.');
  return out;
}

/* Gecerli bir Windows mutlak yolu mu? (surucu harfi sart; UNC, goreli yol, "..", joker karakter yok) */
function winPathProblem(p) {
  if (typeof p !== 'string' || !p) return 'boş';
  if (p.length > 240) return 'çok uzun';
  if (/[\u0000-\u001f<>"|?*]/.test(p)) return 'geçersiz karakter içeriyor';
  if (!/^[A-Za-z]:\\/.test(p)) return 'sürücü harfiyle başlayan mutlak bir yol olmalı (ör. C:\\klasor)';
  if (p.split('\\').some((s) => s === '..' || s === '.')) return '"." veya ".." parçası içeremez';
  return null;
}
const TOO_BROAD = /^[A-Za-z]:\\?$|^[A-Za-z]:\\(?:Windows|Program Files(?: \(x86\))?|ProgramData|Users)\\?$/i;
const RESERVED_GUEST = [GUEST_IN.toLowerCase(), GUEST_OUT.toLowerCase(), GUEST_JRE.toLowerCase()];

function validateConfig(input, deps) {
  const d = Object.assign({ exists: fs.existsSync }, deps || {});
  const errors = [], warnings = [];
  const inp = isObj(input) ? input : {};
  const sb = isObj(inp.sandbox) ? inp.sandbox : {}, an = isObj(inp.analysis) ? inp.analysis : {}, ho = isObj(inp.host) ? inp.host : {};
  const D = DEFAULTS;
  const v = { sandbox: {}, analysis: {}, host: {} };
  v.sandbox.clipboard = normEnable(sb.clipboard, 'sandbox.clipboard', D.sandbox.clipboard, errors);
  v.sandbox.networking = normEnable(sb.networking, 'sandbox.networking', D.sandbox.networking, errors);
  v.sandbox.printer = normEnable(sb.printer, 'sandbox.printer', D.sandbox.printer, errors);
  v.sandbox.audioInput = normEnable(sb.audioInput, 'sandbox.audioInput', D.sandbox.audioInput, errors);
  v.sandbox.videoInput = normEnable(sb.videoInput, 'sandbox.videoInput', D.sandbox.videoInput, errors);
  v.sandbox.vGPU = normEnable(sb.vGPU, 'sandbox.vGPU', D.sandbox.vGPU, errors);
  v.sandbox.protectedClient = normEnable(sb.protectedClient, 'sandbox.protectedClient', D.sandbox.protectedClient, errors);
  v.sandbox.memoryMB = normInt(sb.memoryMB, 'sandbox.memoryMB', D.sandbox.memoryMB, 2048, 65536, errors);
  v.sandbox.mappedFolders = [];
  if (sb.mappedFolders !== undefined && !Array.isArray(sb.mappedFolders)) errors.push('sandbox.mappedFolders: liste olmalı.');
  const mf = Array.isArray(sb.mappedFolders) ? sb.mappedFolders : [];
  if (mf.length > 4) errors.push('sandbox.mappedFolders: en çok 4 ek klasör eşlenebilir (yalnızca gerekenleri eşle).');
  mf.slice(0, 4).forEach((f, i) => {
    const nm = 'sandbox.mappedFolders[' + i + ']';
    if (!isObj(f)) { errors.push(nm + ': nesne olmalı.'); return; }
    const hp = winPathProblem(f.hostFolder);
    if (hp) { errors.push(nm + '.hostFolder: ' + hp + '.'); return; }
    if (TOO_BROAD.test(f.hostFolder)) { errors.push(nm + '.hostFolder: "' + f.hostFolder + '" çok geniş; yalnızca gereken alt klasörü eşle.'); return; }
    if (!d.exists(f.hostFolder)) { errors.push(nm + '.hostFolder: klasör bulunamadı (' + f.hostFolder + '); olmayan klasör Sandbox\'ın hiç açılmamasına yol açar.'); return; }
    const gf = f.sandboxFolder || (GUEST_HOME + '\\Desktop\\' + baseOf(f.hostFolder).replace(/[^\w.-]/g, '_'));
    const gp = winPathProblem(gf);
    if (gp) { errors.push(nm + '.sandboxFolder: ' + gp + '.'); return; }
    if (RESERVED_GUEST.some((r) => gf.toLowerCase() === r || gf.toLowerCase().startsWith(r + '\\'))) { errors.push(nm + '.sandboxFolder: StatScan\'in ayırdığı klasörlerle çakışıyor.'); return; }
    const ro = f.readOnly === undefined ? true : normBool(f.readOnly, nm + '.readOnly', true, errors);
    if (!ro) warnings.push(nm + ': yazılabilir eşleme. Sandbox içindeki zararlı bu klasöre yazabilir; yalnızca gerçekten gerekiyorsa kullan.');
    v.sandbox.mappedFolders.push({ hostFolder: f.hostFolder, sandboxFolder: gf, readOnly: ro });
  });
  v.analysis.durationSec = normInt(an.durationSec, 'analysis.durationSec', D.analysis.durationSec, 10, 900, errors);
  v.analysis.stopWhenIdle = normBool(an.stopWhenIdle, 'analysis.stopWhenIdle', D.analysis.stopWhenIdle, errors);
  v.analysis.idleSec = normInt(an.idleSec, 'analysis.idleSec', D.analysis.idleSec, 3, 120, errors);
  const df = String(an.defender === undefined ? D.analysis.defender : an.defender).toLowerCase();
  if (df === 'keep' || df === 'disable') v.analysis.defender = df; else { errors.push('analysis.defender: keep veya disable olmalı.'); v.analysis.defender = D.analysis.defender; }
  v.analysis.screenshot = normBool(an.screenshot, 'analysis.screenshot', D.analysis.screenshot, errors);
  v.analysis.hkcuDiff = normBool(an.hkcuDiff, 'analysis.hkcuDiff', D.analysis.hkcuDiff, errors);
  v.analysis.bait = normBool(an.bait, 'analysis.bait', D.analysis.bait, errors);
  v.analysis.firewallLanBlock = normBool(an.firewallLanBlock, 'analysis.firewallLanBlock', D.analysis.firewallLanBlock, errors);
  v.analysis.maxDropped = normInt(an.maxDropped, 'analysis.maxDropped', D.analysis.maxDropped, 0, 100, errors);
  v.analysis.maxDroppedMB = normInt(an.maxDroppedMB, 'analysis.maxDroppedMB', D.analysis.maxDroppedMB, 1, 200, errors);
  v.analysis.javaHome = '';
  if (an.javaHome) {
    const jp = winPathProblem(an.javaHome);
    if (jp) errors.push('analysis.javaHome: ' + jp + '.');
    else if (!d.exists(path.win32.join(an.javaHome, 'bin', 'java.exe'))) errors.push('analysis.javaHome: ' + an.javaHome + '\\bin\\java.exe bulunamadı.');
    else v.analysis.javaHome = an.javaHome;
  }
  const ex = String(an.dllExport === undefined ? D.analysis.dllExport : an.dllExport);
  if (/^[A-Za-z_#][\w@#?$]{0,63}$/.test(ex)) v.analysis.dllExport = ex; else { errors.push('analysis.dllExport: geçersiz dışa aktarım adı.'); v.analysis.dllExport = D.analysis.dllExport; }
  v.analysis.launch = {};
  if (an.launch !== undefined && !isObj(an.launch)) errors.push('analysis.launch: nesne olmalı.');
  if (isObj(an.launch)) {
    for (const [k, o] of Object.entries(an.launch)) {
      if (!/^[a-z0-9]{1,8}$/i.test(k) || !isObj(o) || typeof o.program !== 'string' || !o.program || o.program.length > 300) { errors.push('analysis.launch.' + k + ': {"program":"...","args":[...]} biçiminde olmalı.'); continue; }
      v.analysis.launch[k.toLowerCase()] = { program: o.program, args: normStrList(o.args, 'analysis.launch.' + k + '.args', 20, 300, errors) };
    }
  }
  v.analysis.preSteps = normStrList(an.preSteps, 'analysis.preSteps', 20, 2000, errors);
  v.analysis.postSteps = normStrList(an.postSteps, 'analysis.postSteps', 20, 2000, errors);
  v.analysis.watchExtra = normStrList(an.watchExtra, 'analysis.watchExtra', 10, 240, errors).filter((p) => { const pr = winPathProblem(p); if (pr) { errors.push('analysis.watchExtra: "' + p + '" ' + pr + '.'); return false; } return true; });
  v.host.stagingRoot = typeof ho.stagingRoot === 'string' ? ho.stagingRoot : '';
  if (v.host.stagingRoot) { const sp = winPathProblem(v.host.stagingRoot); if (sp && process.platform === 'win32') { errors.push('host.stagingRoot: ' + sp + '.'); v.host.stagingRoot = ''; } }
  v.host.keepArtifacts = normBool(ho.keepArtifacts, 'host.keepArtifacts', D.host.keepArtifacts, errors);
  v.host.maxSampleMB = normInt(ho.maxSampleMB, 'host.maxSampleMB', D.host.maxSampleMB, 1, 700, errors);
  v.host.startupTimeoutSec = normInt(ho.startupTimeoutSec, 'host.startupTimeoutSec', D.host.startupTimeoutSec, 30, 900, errors);
  v.host.collectTimeoutSec = normInt(ho.collectTimeoutSec, 'host.collectTimeoutSec', D.host.collectTimeoutSec, 30, 900, errors);
  v.host.minimizeWindow = normBool(ho.minimizeWindow, 'host.minimizeWindow', D.host.minimizeWindow, errors);
  v.host.showGuestConsole = normBool(ho.showGuestConsole, 'host.showGuestConsole', D.host.showGuestConsole, errors);
  v.host.scanDropped = normBool(ho.scanDropped, 'host.scanDropped', D.host.scanDropped, errors);
  const sm = String(ho.scanDroppedMode || D.host.scanDroppedMode);
  if (['quick', 'normal', 'deep'].includes(sm)) v.host.scanDroppedMode = sm; else { errors.push('host.scanDroppedMode: quick, normal veya deep olmalı.'); v.host.scanDroppedMode = D.host.scanDroppedMode; }
  v.host.port = normInt(ho.port, 'host.port', D.host.port, 0, 65535, errors);
  if (v.sandbox.networking !== 'Disable') warnings.push('Ağ açık: Sandbox, ana bilgisayarın ağına bağlanabilir. Örnek internete ve (engellenmezse) yerel ağa erişebilir. Varsayılan "Disable" önerilir.');
  if (v.sandbox.clipboard !== 'Disable') warnings.push('Pano paylaşımı açık: Sandbox ile ana sistem panosu arasında veri akabilir.');
  if (v.sandbox.vGPU !== 'Disable') warnings.push('vGPU açık: Microsoft, saldırı yüzeyini artırabileceğini belirtir.');
  if (v.sandbox.audioInput === 'Enable' || v.sandbox.videoInput === 'Enable') warnings.push('Mikrofon/kamera açık: ana bilgisayarın giriş aygıtları Sandbox\'a açılır.');
  return { ok: errors.length === 0, errors, warnings, value: v };
}

function mergeDeep(a, b) {
  const out = clone(a);
  for (const k of Object.keys(b || {})) { if (isObj(b[k]) && isObj(out[k])) out[k] = mergeDeep(out[k], b[k]); else out[k] = b[k]; }
  return out;
}
function loadConfig(file) {
  let user = {};
  if (file) {
    let txt;
    try { txt = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''); } catch (e) { throw new DynError('config-read', 'Yapılandırma dosyası okunamadı: ' + file + ' (' + e.message + ')'); }
    try { user = JSON.parse(txt); } catch (e) { throw new DynError('config-json', 'Yapılandırma dosyası geçerli JSON değil: ' + file + ' (' + e.message + ')'); }
  }
  return mergeDeep(DEFAULTS, user);
}
/* Arayuzden gelen istek: yalniz beyaz listedeki ayarlar degistirilebilir (komut/klasor degil). */
const UI_ENUMS = ['clipboard', 'networking', 'printer', 'audioInput', 'videoInput', 'vGPU'];
function applyUiOverrides(cfg, ui) {
  const c = clone(cfg); const u = isObj(ui) ? ui : {};
  const errors = [];
  for (const k of UI_ENUMS) if (u[k] !== undefined) c.sandbox[k] = normEnable(u[k], k, c.sandbox[k], errors);
  if (u.durationSec !== undefined) c.analysis.durationSec = normInt(u.durationSec, 'durationSec', c.analysis.durationSec, 10, 900, errors);
  if (u.defender !== undefined) { const s = String(u.defender).toLowerCase(); if (s === 'keep' || s === 'disable') c.analysis.defender = s; else errors.push('defender geçersiz.'); }
  if (u.screenshot !== undefined) c.analysis.screenshot = normBool(u.screenshot, 'screenshot', c.analysis.screenshot, errors);
  if (u.stopWhenIdle !== undefined) c.analysis.stopWhenIdle = normBool(u.stopWhenIdle, 'stopWhenIdle', c.analysis.stopWhenIdle, errors);
  if (u.bait !== undefined) c.analysis.bait = normBool(u.bait, 'bait', c.analysis.bait, errors);
  if (u.keepArtifacts !== undefined) c.host.keepArtifacts = normBool(u.keepArtifacts, 'keepArtifacts', c.host.keepArtifacts, errors);
  return { cfg: c, errors };
}

/* ======================================================================
 * Sistem kosullari: Windows 10 Pro / Windows 11 Pro + Windows Sandbox
 * ==================================================================== */
const EDITION_NAMES = {
  Professional: 'Pro', ProfessionalN: 'Pro N', ProfessionalWorkstation: 'Pro for Workstations', ProfessionalEducation: 'Pro Education',
  Core: 'Home', CoreN: 'Home N', CoreSingleLanguage: 'Home Single Language', CoreCountrySpecific: 'Home China',
  Enterprise: 'Enterprise', EnterpriseN: 'Enterprise N', EnterpriseS: 'Enterprise LTSC', IoTEnterprise: 'IoT Enterprise', IoTEnterpriseS: 'IoT Enterprise LTSC',
  Education: 'Education', EducationN: 'Education N', Cloud: 'S (Cloud)', CloudN: 'S N (Cloud)', Starter: 'Starter'
};
const MIN_WIN10_BUILD = 18362; // 1903: Windows Sandbox'in ilk surumu

function parseRegQuery(text) {
  const o = {};
  for (const line of String(text || '').split(/\r?\n/)) { const m = /^\s{2,}(\S+)\s+REG_\w+\s+(.*)$/.exec(line); if (m) o[m[1]] = m[2].trim(); }
  return o;
}
function defaultRegQuery() {
  return cp.execFileSync('reg', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'], { encoding: 'utf8', windowsHide: true, timeout: 10000 });
}
function defaultTaskList() {
  try { return cp.execFileSync('tasklist', ['/FO', 'CSV', '/NH'], { encoding: 'utf8', windowsHide: true, timeout: 10000 }); } catch (e) { return ''; }
}
function runningSandboxProcs(taskListText) {
  const names = new Set(String(taskListText || '').split(/\r?\n/).map((l) => (/^"([^"]+)"/.exec(l) || [])[1]).filter(Boolean).map((s) => s.toLowerCase()));
  return SANDBOX_PROCS.filter((p) => names.has(p.toLowerCase()));
}
function defaultHypervisor() {
  try {
    const out = cp.execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '(Get-CimInstance Win32_ComputerSystem).HypervisorPresent'], { encoding: 'utf8', windowsHide: true, timeout: 12000 }).trim().toLowerCase();
    return out === 'true' ? true : out === 'false' ? false : null;
  } catch (e) { return null; }
}

function checkPrerequisites(deps) {
  const d = Object.assign({ platform: process.platform, regQuery: defaultRegQuery, exists: fs.existsSync, windir: process.env.SystemRoot || process.env.windir || 'C:\\Windows', taskList: defaultTaskList, hypervisor: defaultHypervisor }, deps || {});
  const res = { available: false, busy: false, state: '', os: { platform: d.platform }, reasons: [], warnings: [] };
  const fail = (state, title, detail, fix) => { res.state = state; res.reasons.push({ code: state, title, detail, fix: fix || [] }); return res; };
  if (d.platform !== 'win32') {
    return fail('not-windows', 'Bu bilgisayar Windows değil', 'Dinamik analiz Windows Sandbox kullanır ve yalnızca Windows 10 Pro ile Windows 11 Pro\'da açılır. Şu anki sistem: ' + d.platform + '. Statik tarama her sistemde çalışmaya devam eder.');
  }
  let reg = {};
  try { reg = parseRegQuery(d.regQuery()); } catch (e) { return fail('os-unknown', 'Windows sürümü okunamadı', 'Kayıt defterinden sürüm bilgisi alınamadı (' + (e && e.message ? e.message.split('\n')[0] : e) + '). Sürüm doğrulanamadığı için dinamik analiz açılmadı.'); }
  const build = parseInt(reg.CurrentBuildNumber || reg.CurrentBuild || '0', 10) || 0;
  const edition = reg.EditionID || '';
  const win11 = build >= 22000;
  const friendly = EDITION_NAMES[edition] || edition || 'bilinmiyor';
  res.os = { platform: 'win32', edition, editionName: friendly, build, windows: win11 ? '11' : '10', display: 'Windows ' + (win11 ? '11' : '10') + ' ' + friendly + (reg.DisplayVersion ? ' ' + reg.DisplayVersion : '') + ' (build ' + build + ')' };
  if (!build || !edition) return fail('os-unknown', 'Windows sürümü belirlenemedi', 'Sürüm ve sürüm sınıfı (edition) okunamadı; güvenli tarafta kalıp dinamik analiz açılmadı.');
  if (edition !== 'Professional') {
    const isHome = /^Core/.test(edition);
    const detail = isHome
      ? 'Bu bilgisayar ' + res.os.display + ' çalıştırıyor. Windows Home sürümünde Windows Sandbox özelliği hiç bulunmaz; Microsoft bunu yalnızca Pro, Enterprise ve Education sürümlerinde sunar. StatScan dinamik analizi yalnızca Windows 10 Pro ve Windows 11 Pro için açılır.'
      : 'Bu bilgisayar ' + res.os.display + ' çalıştırıyor. StatScan dinamik analizi yalnızca Windows 10 Pro ve Windows 11 Pro için açık tutuldu; bu sürümde Windows Sandbox bulunabilir olsa da özellik burada kullanıma açılmadı.';
    return fail('unsupported-edition', 'Bu Windows sürümünde dinamik analiz kullanılamaz', detail, isHome ? ['Pro sürümüne yükseltmek (Ayarlar > Sistem > Etkinleştirme) Windows Sandbox\'ı kullanılabilir yapar.', 'Bunun dışında dinamik analizi Pro sürümü olan başka bir bilgisayarda ya da bir sanal makinede çalıştırabilirsin.'] : []);
  }
  if (!win11 && build < MIN_WIN10_BUILD) {
    return fail('old-build', 'Windows 10 sürümün çok eski', 'Windows Sandbox için Windows 10 sürüm 1903 (build ' + MIN_WIN10_BUILD + ') veya üstü gerekir; bu bilgisayarda build ' + build + ' var.', ['Windows Update ile Windows 10\'u güncelle.']);
  }
  const exe = path.win32.join(d.windir, 'System32', 'WindowsSandbox.exe');
  if (!d.exists(exe)) {
    return fail('feature-missing', 'Windows Sandbox özelliği kurulu / etkin değil', 'Bu bilgisayar desteklenen bir sürüm (' + res.os.display + ') ama "Windows Sandbox" isteğe bağlı özelliği etkin değil (WindowsSandbox.exe bulunamadı).', [
      'Başlat menüsünde "Windows özelliklerini aç veya kapat" yaz, açılan pencerede "Windows Sandbox" kutusunu işaretle, Tamam\'a bas ve bilgisayarı yeniden başlat.',
      'Ya da yönetici PowerShell\'de şunu çalıştırıp yeniden başlat: Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All',
      'Özellik listede görünmüyorsa veya yeniden başlatmadan sonra açılmıyorsa BIOS/UEFI\'de sanallaştırmanın (Intel VT-x / AMD-V, SVM) açık olduğunu kontrol et.'
    ]);
  }
  res.state = 'ok'; res.available = true; res.sandboxExe = exe;
  let hv = null; try { hv = d.hypervisor(); } catch (e) { hv = null; }
  if (hv === false) res.warnings.push('Hypervisor çalışmıyor görünüyor: sanallaştırma BIOS/UEFI\'de kapalı olabilir ya da Windows Sandbox kurulduktan sonra yeniden başlatılmamış olabilir. Sandbox açılmazsa önce bunları kontrol et.');
  const running = runningSandboxProcs(d.taskList());
  if (running.length) { res.busy = true; res.warnings.push('Windows Sandbox şu anda açık (' + running.join(', ') + '). Aynı anda yalnızca bir Sandbox çalışabilir; dinamik analiz için önce mevcut Sandbox\'ı kapat.'); }
  return res;
}

/* Windows Sandbox ozelligini etkinlestirme (yonetici izni ister, kullanici UAC penceresinde onaylar).
 * Yalnizca desteklenen surumde ve ozellik kapaliyken calisir; komut sabittir, disaridan metin alinmaz. */
const ENABLE_PS = 'Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart';
function enableSandboxFeature(depsIn) {
  const d = Object.assign({ prereq: null, spawn: cp.spawn }, depsIn || {});
  const pre = d.prereq || checkPrerequisites();
  if (pre.state !== 'feature-missing') throw new DynError('not-applicable', pre.available ? 'Windows Sandbox zaten etkin.' : 'Bu sistemde özellik etkinleştirilemez: ' + ((pre.reasons[0] && pre.reasons[0].title) || pre.state));
  const inner = ENABLE_PS + '; Write-Host ""; Write-Host "Tamamlandi. Degisikligin gecerli olmasi icin bilgisayari yeniden baslat."; Read-Host "Kapatmak icin Enter"';
  const outer = "Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList '-NoProfile','-Command','" + inner.replace(/'/g, "''") + "'";
  const child = d.spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', outer], { windowsHide: true, stdio: 'ignore', detached: true });
  if (child && child.unref) child.unref();
  return { started: true, command: ENABLE_PS };
}

/* ======================================================================
 * .wsb uretimi ve dogrulama (Microsoft belgesindeki sema)
 * ==================================================================== */
const WSB_TOP = ['vGPU', 'Networking', 'MappedFolders', 'LogonCommand', 'AudioInput', 'VideoInput', 'ProtectedClient', 'PrinterRedirection', 'ClipboardRedirection', 'MemoryInMB'];
const WSB_ENUMS = ['vGPU', 'Networking', 'AudioInput', 'VideoInput', 'ProtectedClient', 'PrinterRedirection', 'ClipboardRedirection'];

function buildWsb(sb, folders, command) {
  const L = ['<Configuration>'];
  L.push('  <vGPU>' + sb.vGPU + '</vGPU>');
  L.push('  <Networking>' + sb.networking + '</Networking>');
  L.push('  <MappedFolders>');
  for (const f of folders) {
    L.push('    <MappedFolder>');
    L.push('      <HostFolder>' + xmlEsc(f.host) + '</HostFolder>');
    L.push('      <SandboxFolder>' + xmlEsc(f.guest) + '</SandboxFolder>');
    L.push('      <ReadOnly>' + (f.readOnly ? 'true' : 'false') + '</ReadOnly>');
    L.push('    </MappedFolder>');
  }
  L.push('  </MappedFolders>');
  L.push('  <LogonCommand>');
  L.push('    <Command>' + xmlEsc(command) + '</Command>');
  L.push('  </LogonCommand>');
  L.push('  <AudioInput>' + sb.audioInput + '</AudioInput>');
  L.push('  <VideoInput>' + sb.videoInput + '</VideoInput>');
  L.push('  <ProtectedClient>' + sb.protectedClient + '</ProtectedClient>');
  L.push('  <PrinterRedirection>' + sb.printer + '</PrinterRedirection>');
  L.push('  <ClipboardRedirection>' + sb.clipboard + '</ClipboardRedirection>');
  L.push('  <MemoryInMB>' + sb.memoryMB + '</MemoryInMB>');
  L.push('</Configuration>');
  return L.join('\r\n') + '\r\n';
}

/* Kucuk, katı bir yapı denetleyicisi: yalnızca belgelenmiş öğeleri ve değerleri kabul eder. */
function validateWsb(xml, opts) {
  const relaxHost = !!(opts && opts.relaxHost);
  const errors = [];
  const tokRe = /<(\/?)([A-Za-z][A-Za-z0-9]*)\s*>|([^<]+)|(<[^>]*>)/g;
  const root = { name: '#root', kids: [], text: '' }; const stack = [root]; let m;
  const text = String(xml).replace(/^\uFEFF/, '');
  while ((m = tokRe.exec(text))) {
    if (m[4]) { errors.push('Beklenmeyen işaretleme: ' + m[4].slice(0, 40)); continue; }
    if (m[3] !== undefined) { const top = stack[stack.length - 1]; top.text += m[3]; continue; }
    if (m[1] === '/') { const top = stack.pop(); if (!top || top.name !== m[2]) { errors.push('Kapanış etiketi uyuşmuyor: </' + m[2] + '>'); return errors; } if (!stack.length) { errors.push('Fazladan kapanış etiketi'); return errors; } }
    else { const n = { name: m[2], kids: [], text: '' }; stack[stack.length - 1].kids.push(n); stack.push(n); }
  }
  if (stack.length !== 1) { errors.push('Kapatılmamış etiket var: <' + stack[stack.length - 1].name + '>'); return errors; }
  if (root.kids.length !== 1 || root.kids[0].name !== 'Configuration') { errors.push('Kök öğe tek bir <Configuration> olmalı.'); return errors; }
  const cfg = root.kids[0];
  if (cfg.text.trim()) errors.push('<Configuration> içinde serbest metin olamaz.');
  const seen = new Set();
  for (const k of cfg.kids) {
    if (!WSB_TOP.includes(k.name)) { errors.push('Tanınmayan öğe: <' + k.name + '>'); continue; }
    if (seen.has(k.name)) errors.push('<' + k.name + '> birden fazla kez tanımlı.');
    seen.add(k.name);
    const val = xmlUnesc(k.text).trim();
    if (WSB_ENUMS.includes(k.name)) { if (k.kids.length || !ENABLE_VALUES.includes(val)) errors.push('<' + k.name + '> değeri Enable, Disable veya Default olmalı (bulunan: "' + val + '").'); }
    else if (k.name === 'MemoryInMB') { if (!/^\d+$/.test(val) || Number(val) < 2048) errors.push('<MemoryInMB> en az 2048 olan bir tam sayı olmalı.'); }
    else if (k.name === 'MappedFolders') {
      if (k.text.trim()) errors.push('<MappedFolders> içinde serbest metin olamaz.');
      for (const f of k.kids) {
        if (f.name !== 'MappedFolder') { errors.push('<MappedFolders> içinde yalnızca <MappedFolder> olabilir (bulunan: <' + f.name + '>).'); continue; }
        const fseen = new Set();
        for (const c of f.kids) {
          if (!['HostFolder', 'SandboxFolder', 'ReadOnly'].includes(c.name)) { errors.push('<MappedFolder> içinde tanınmayan öğe: <' + c.name + '>'); continue; }
          if (fseen.has(c.name)) errors.push('<' + c.name + '> birden fazla kez tanımlı.'); fseen.add(c.name);
          const cv = xmlUnesc(c.text).trim();
          if (c.name === 'ReadOnly') { if (cv !== 'true' && cv !== 'false') errors.push('<ReadOnly> true veya false olmalı.'); }
          else if (!(relaxHost && c.name === 'HostFolder')) { const pp = winPathProblem(cv); if (pp) errors.push('<' + c.name + '> geçersiz: ' + pp + '.'); }
        }
        if (!fseen.has('HostFolder')) errors.push('<MappedFolder> için <HostFolder> zorunlu.');
        if (!fseen.has('SandboxFolder')) errors.push('<MappedFolder> için <SandboxFolder> zorunlu.');
      }
    } else if (k.name === 'LogonCommand') {
      const cs = k.kids.filter((c) => c.name === 'Command');
      if (cs.length !== 1 || k.kids.length !== 1 || !xmlUnesc(cs[0].text).trim()) errors.push('<LogonCommand> tam olarak bir dolu <Command> içermeli.');
    }
  }
  return errors;
}

/* ======================================================================
 * Ornek turu ve baslatma plani
 * ==================================================================== */
const KIND_BY_EXT = { exe: 'exe', scr: 'exe', com: 'exe', pif: 'exe', dll: 'dll', ocx: 'dll', cpl: 'dll', jar: 'jar', ps1: 'ps1', bat: 'bat', cmd: 'bat', vbs: 'wsh', vbe: 'wsh', js: 'wsh', jse: 'wsh', wsf: 'wsh', hta: 'hta', lnk: 'lnk', msi: 'msi' };
const RUNNABLE_EXT = new Set(Object.keys(KIND_BY_EXT));

function sanitizeSampleName(name, kind, buf) {
  let b = baseOf(name).replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '').slice(0, 80);
  if (!b || /^(?:con|prn|aux|nul|com\d|lpt\d)(?:\.|$)/i.test(b)) b = 'sample' + (b ? '_' + b : '');
  const ext = extOf(b);
  const mz = buf && buf.length > 1 && buf[0] === 0x4d && buf[1] === 0x5a;
  if (!KIND_BY_EXT[ext] && mz) b += '.exe';
  if (!KIND_BY_EXT[extOf(b)] && buf && buf.length > 3 && buf[0] === 0x50 && buf[1] === 0x4b && kind === 'jar') b += '.jar';
  return b;
}
function detectKind(name, buf) {
  const ext = extOf(name); let kind = KIND_BY_EXT[ext] || '';
  const mz = buf && buf.length > 1 && buf[0] === 0x4d && buf[1] === 0x5a;
  const pk = buf && buf.length > 3 && buf[0] === 0x50 && buf[1] === 0x4b;
  if (!kind && mz) kind = 'exe';
  if ((kind === 'exe' || kind === 'dll') && !mz) kind = '';
  if (kind === 'jar' && !pk) kind = '';
  return kind;
}
function launchPlan(kind, ext, an, javaMapped) {
  const o = an.launch && (an.launch[ext] || an.launch[kind]);
  if (o) return { program: o.program, args: o.args || [], source: 'config' };
  switch (kind) {
    case 'exe': return { program: '{sample}', args: [] };
    case 'dll': return { program: 'rundll32.exe', args: ['{sample},' + an.dllExport] };
    case 'jar': return javaMapped ? { program: '{java}', args: ['-jar', '{sample}'] } : { skip: true, skipReason: 'Sandbox\'ta Java yok; .jar çalıştırılamadı. Yapılandırmada analysis.javaHome ile taşınabilir bir JRE/JDK klasörü ver (bin\\java.exe içermeli).' };
    case 'ps1': return { program: 'powershell.exe', args: ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '{sample}'] };
    case 'bat': return { program: 'cmd.exe', args: ['/c', '{sample}'] };
    case 'wsh': return { program: 'wscript.exe', args: ['//B', '//Nologo', '{sample}'] };
    case 'hta': return { program: 'mshta.exe', args: ['{sample}'] };
    case 'lnk': return { program: '{sample}', args: [] };
    case 'msi': return { program: 'msiexec.exe', args: ['/i', '{sample}', '/qn'] };
    default: return { skip: true, skipReason: 'Bu dosya türü çalıştırılabilir değil (exe, dll, jar, betik, hta, lnk, msi desteklenir).' };
  }
}

/* ======================================================================
 * Hazirlik: calisma klasoru, run.json, .wsb
 * ==================================================================== */
function defaultStagingRoot(cfg) {
  if (cfg.host.stagingRoot) return cfg.host.stagingRoot;
  const base = process.env.LOCALAPPDATA || os.tmpdir();
  return path.join(base, 'StatScan', 'dyn');
}
function guestCommand(showConsole) {
  return 'powershell.exe -NoProfile -ExecutionPolicy Bypass' + (showConsole ? '' : ' -WindowStyle Hidden') + ' -File "' + GUEST_IN + '\\collector.ps1"';
}
function planJob(cfg, sample, jobId, root, deps) {
  const d = Object.assign({ collectorPath: path.join(__dirname, 'collector.ps1') }, deps || {});
  const kind = detectKind(sample.name, sample.data);
  const stagedName = sanitizeSampleName(sample.name, kind, sample.data);
  const stagedExt = extOf(stagedName);
  const javaMapped = !!cfg.analysis.javaHome;
  const lp = launchPlan(kind || KIND_BY_EXT[stagedExt] || '', stagedExt, cfg.analysis, javaMapped);
  const jobDir = path.join(root, jobId);
  const inDir = path.join(jobDir, 'in'), outDir = path.join(jobDir, 'out');
  const folders = [{ host: inDir, guest: GUEST_IN, readOnly: true }, { host: outDir, guest: GUEST_OUT, readOnly: false }];
  if (javaMapped && kind === 'jar') folders.push({ host: cfg.analysis.javaHome, guest: GUEST_JRE, readOnly: true });
  for (const f of cfg.sandbox.mappedFolders) folders.push({ host: f.hostFolder, guest: f.sandboxFolder, readOnly: f.readOnly });
  const wsb = buildWsb(cfg.sandbox, folders, guestCommand(cfg.host.showGuestConsole));
  const wsbErrors = validateWsb(wsb, { relaxHost: process.platform !== 'win32' });
  if (wsbErrors.length) throw new DynError('wsb-invalid', 'Üretilen .wsb yapılandırması geçersiz: ' + wsbErrors.join(' '));
  const run = {
    schema: 1, jobId, sampleName: stagedName, displayName: baseOf(sample.name), sampleSha256: sha256(sample.data), sampleSize: sample.data.length, kind: kind || 'unknown',
    durationSec: cfg.analysis.durationSec, stopWhenIdle: cfg.analysis.stopWhenIdle, idleSec: cfg.analysis.idleSec, defender: cfg.analysis.defender,
    screenshot: cfg.analysis.screenshot, hkcuDiff: cfg.analysis.hkcuDiff, bait: cfg.analysis.bait, firewallLanBlock: cfg.analysis.firewallLanBlock,
    networking: cfg.sandbox.networking, maxDropped: cfg.analysis.maxDropped, maxDroppedMB: cfg.analysis.maxDroppedMB,
    launch: lp, preSteps: cfg.analysis.preSteps, postSteps: cfg.analysis.postSteps, watchExtra: cfg.analysis.watchExtra
  };
  return { kind, stagedName, jobDir, inDir, outDir, folders, wsb, run, collectorPath: d.collectorPath, wsbPath: path.join(jobDir, 'job.wsb') };
}
function stageJob(plan, sample) {
  fs.mkdirSync(plan.inDir, { recursive: true }); fs.mkdirSync(plan.outDir, { recursive: true });
  fs.writeFileSync(path.join(plan.inDir, 'sample.dat'), sample.data);       // ana sistemde "sample.dat": cift tiklansa bile calismaz
  fs.copyFileSync(plan.collectorPath, path.join(plan.inDir, 'collector.ps1'));
  fs.writeFileSync(path.join(plan.inDir, 'run.json'), JSON.stringify(plan.run, null, 2), 'utf8');
  fs.writeFileSync(plan.wsbPath, '\uFEFF' + plan.wsb, 'utf8');
}
function rmDir(dir) { try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 6, retryDelay: 400 }); } catch (e) { /* kilitli dosya: sonra silinir */ } }

/* ======================================================================
 * Sandbox surecleri (baslat / kapat / kucult)
 * ==================================================================== */
function realDeps() {
  const win = process.platform === 'win32';
  return {
    launch(wsbPath) {
      const exe = path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsSandbox.exe');
      const child = cp.spawn(exe, [wsbPath], { detached: true, stdio: 'ignore', windowsHide: true });
      child.on('error', () => { });
      child.unref();
    },
    running() { return win ? runningSandboxProcs(defaultTaskList()).length > 0 : false; },
    kill() {
      if (!win) return;
      for (const p of SANDBOX_PROCS) { try { cp.execFileSync('taskkill', ['/F', '/IM', p], { windowsHide: true, stdio: 'ignore', timeout: 10000 }); } catch (e) { /* calismiyor olabilir */ } }
    },
    minimize() {
      if (!win) return;
      const ps = "Add-Type -Namespace SS -Name U -MemberDefinition '[DllImport(\"user32.dll\")] public static extern bool ShowWindow(System.IntPtr h, int c);'; " +
        "foreach($n in 'WindowsSandboxClient','WindowsSandboxRemoteSession'){ foreach($p in @(Get-Process -Name $n -ErrorAction SilentlyContinue)){ if($p.MainWindowHandle -ne [System.IntPtr]::Zero){ [void][SS.U]::ShowWindow($p.MainWindowHandle,6) } } }";
      try { cp.execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', ps], { windowsHide: true, timeout: 15000 }, () => { }); } catch (e) { /* en iyi caba */ }
    },
    sleep
  };
}

/* ======================================================================
 * Gozlem verisi: dogrulama / temizleme (Sandbox'tan gelen veri GUVENILMEZ)
 * ==================================================================== */
const CTRL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g;
const str = (v, max) => { if (v === null || v === undefined) return ''; let s = typeof v === 'string' ? v : (typeof v === 'number' || typeof v === 'boolean' ? String(v) : ''); s = s.replace(CTRL, '�'); return s.length > (max || 500) ? s.slice(0, max || 500) + '…' : s; };
const num = (v, def) => { const n = Number(v); return Number.isFinite(n) ? n : (def === undefined ? 0 : def); };
const arr = (v, max) => (Array.isArray(v) ? v.slice(0, max) : (isObj(v) ? [v] : []));
const bool = (v) => v === true;

function sanitizeTrace(raw) {
  const t = { ok: false, fatal: '', plannedSec: 0, elapsedSec: 0, stoppedEarly: false, guest: {}, sample: {}, collectorPid: 0, processes: [], files: { events: [], items: [], eventCap: false }, registry: { persistence: [], hkcu: [] }, tasks: [], services: [], wmi: [], network: { dns: [], connections: [] }, defender: { detections: [], threats: [] }, bait: { enabled: false, auditOk: false, mouse: false, files: [], reads: [], clipboard: [] }, windows: [], screenshot: null, errors: [], notes: [] };
  if (!isObj(raw)) { t.fatal = 'Toplayıcı çıktısı geçerli bir nesne değil.'; return t; }
  if (raw.fatal) { t.fatal = str(raw.fatal, 300); return t; }
  t.ok = true;
  t.plannedSec = num(raw.plannedSec); t.elapsedSec = num(raw.elapsedSec); t.stoppedEarly = bool(raw.stoppedEarly); t.collectorPid = num(raw.collectorPid);
  const g = isObj(raw.guest) ? raw.guest : {};
  t.guest = { os: str(g.os, 120), build: str(g.build, 20), networking: str(g.networking, 20), defender: str(g.defender, 20), firewallLanBlock: bool(g.firewallLanBlock) };
  const s = isObj(raw.sample) ? raw.sample : {};
  t.sample = { name: str(s.name, 120), sha256: str(s.sha256, 64), existedAfterCopy: s.existedAfterCopy !== false, existsAfter: s.existsAfter !== false, launchError: str(s.launchError, 400), program: str(s.program, 300), args: str(s.args, 400), rootPid: num(s.rootPid), exited: bool(s.exited), exitCode: s.exitCode === null || s.exitCode === undefined ? null : num(s.exitCode), aliveAtEnd: bool(s.aliveAtEnd), cpuSec: s.cpuSec === null || s.cpuSec === undefined ? null : num(s.cpuSec) };
  const p = isObj(raw.processes) ? raw.processes : {};
  const mkp = (x, src) => ({ pid: num(x.pid), ppid: num(x.ppid), name: str(baseOf(x.path || x.name), 80), path: str(x.path, 300), cmd: str(x.cmd, 1500), start: str(x.start, 40), src });
  const merged = new Map();
  for (const x of arr(p.poll, 1500)) if (isObj(x)) { const q = mkp(x, 'poll'); merged.set(q.pid + '|' + q.name.toLowerCase(), q); }
  for (const x of arr(p.audit, 1500)) if (isObj(x)) { const q = mkp(x, 'audit'); const k = q.pid + '|' + q.name.toLowerCase(); const o = merged.get(k); if (o) { merged.set(k, Object.assign(o, { cmd: q.cmd || o.cmd, path: q.path || o.path, ppid: q.ppid || o.ppid, src: 'audit' })); } else merged.set(k, q); }
  t.processes = [...merged.values()].filter((q) => q.pid > 0);
  const f = isObj(raw.files) ? raw.files : {};
  t.files.events = arr(f.events, 6000).filter(isObj).map((e) => ({ k: str(e.k, 12), p: str(e.p, 400), o: str(e.o, 400), t: str(e.t, 40) }));
  t.files.items = arr(f.items, 200).filter(isObj).map((e) => ({ path: str(e.path, 400), size: num(e.size), sha256: str(e.sha256, 64).toLowerCase(), mz: bool(e.mz), zip: bool(e.zip), sameAsSample: bool(e.sameAsSample), copied: bool(e.copied) }));
  t.files.eventCap = bool(f.eventCap);
  const r = isObj(raw.registry) ? raw.registry : {};
  t.registry.persistence = arr(r.persistence, 400).filter(isObj).map((e) => ({ c: str(e.c, 10), k: str(e.k, 400), v: str(e.v, 600), old: str(e.old, 600) }));
  t.registry.hkcu = arr(r.hkcu, 800).filter(isObj).map((e) => ({ key: str(e.key, 300), line: str(e.line, 500) }));
  t.tasks = arr(raw.tasks, 100).filter(isObj).map((e) => ({ name: str(e.name, 300), action: str(e.action, 600) }));
  t.services = arr(raw.services, 100).filter(isObj).map((e) => ({ c: str(e.c, 10), name: str(e.name, 120), v: str(e.v, 500), old: str(e.old, 500) }));
  t.wmi = arr(raw.wmi, 40).filter(isObj).map((e) => ({ cls: str(e.cls, 60), name: str(e.name, 120), detail: str(e.detail, 500) }));
  const n = isObj(raw.network) ? raw.network : {};
  t.network.dns = arr(n.dns, 400).filter(isObj).map((e) => ({ name: str(e.name, 253).toLowerCase() })).filter((e) => e.name);
  t.network.connections = arr(n.connections, 400).filter(isObj).map((e) => ({ remote: str(e.remote, 64), port: num(e.port), state: str(e.state, 20), pid: num(e.pid) })).filter((e) => e.remote);
  const dr = isObj(raw.defenderResult) ? raw.defenderResult : {};
  t.defender.detections = arr(dr.detections, 40).filter(isObj).map((e) => ({ id: str(e.id, 40), proc: str(e.proc, 120), res: str(e.res, 400) }));
  t.defender.threats = arr(dr.threats, 40).filter(isObj).map((e) => ({ id: str(e.id, 40), name: str(e.name, 160), sev: str(e.sev, 10) }));
  const bt = isObj(raw.bait) ? raw.bait : {};
  const KINDS = ['browser', 'token', 'wallet', 'cred'];
  const kd = (v) => (KINDS.includes(v) ? v : 'cred');
  t.bait = {
    enabled: bool(bt.enabled), auditOk: bool(bt.auditOk), mouse: bool(bt.mouse),
    files: arr(bt.files, 60).filter(isObj).map((e) => ({ path: str(e.path, 300), kind: kd(e.kind) })),
    reads: arr(bt.reads, 150).filter(isObj).map((e) => ({ pid: num(e.pid), proc: str(e.proc, 260), path: str(e.path, 300), kind: kd(e.kind), t: str(e.t, 40) })),
    clipboard: arr(bt.clipboard, 10).filter(isObj).map((e) => ({ type: str(e.type, 8), set: str(e.set, 100), seen: str(e.seen, 200), changed: bool(e.changed) }))
  };
  t.windows = arr(raw.windows, 40).filter(isObj).map((e) => ({ pid: num(e.pid), name: str(e.name, 80), title: str(e.title, 200) }));
  t.screenshot = isObj(raw.screenshot) ? { file: 'screen.png', w: num(raw.screenshot.w), h: num(raw.screenshot.h) } : null;
  t.errors = arr(raw.errors, 60).map((e) => str(e, 300)); t.notes = arr(raw.notes, 60).map((e) => str(e, 300));
  return t;
}

/* ======================================================================
 * Bulgu uretimi
 * ==================================================================== */
/* Dinamik bulgular Sandbox'ta GOZLENEN olaylara dayanir (basis: fact); ATT&CK etiketi siniflandirmadir, kanit degildir. */
const DYN_MITRE = [[/^dyn_persist_run|^dyn_persist_startup/, ['T1547.001']], [/^dyn_persist_task/, ['T1053.005']], [/^dyn_persist_service|^dyn_service_changed/, ['T1543.003']], [/^dyn_persist_wmi/, ['T1546.003']], [/^dyn_persist_reg/, ['T1547', 'T1546.012']], [/^dyn_defender/, ['T1562.001']], [/^dyn_uac_reg|^dyn_hijack_reg/, ['T1548.002']], [/^dyn_ransom/, ['T1486']], [/^dyn_stealer_browser/, ['T1555.003']], [/^dyn_stealer_tokens|^dyn_stealer_creds/, ['T1552.001']], [/^dyn_stealer_wallet/, ['T1005']], [/^dyn_clipper/, ['T1115']], [/^dyn_dns|^dyn_net/, ['T1071']], [/^dyn_selfdelete/, ['T1070.004']], [/^dyn_selfcopy|^dyn_dropped|^dyn_drop_system/, ['T1105']], [/^dyn_lolbin|^dyn_certutil|^dyn_mshta|^dyn_regsvr|^dyn_rundll|^dyn_bitsadmin|^dyn_wmic/, ['T1218']], [/^dyn_masq/, ['T1036.005']], [/^dyn_shadow/, ['T1490']]];
const F = (id, sev, w, title, why, act, ev, fp, cat) => { const m = DYN_MITRE.find(([re]) => re.test(id)); return { id, sev, w, title, why, act, ev: (ev || []).slice(0, 8).map((x) => String(x).slice(0, 320)), fp: fp || '', cat: cat || 'dyn', dyn: true, basis: 'fact', mitre: m ? m[1] : [] }; };

const NOISE_PROC = new Set(['conhost.exe', 'wmiprvse.exe', 'backgroundtaskhost.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe', 'searchindexer.exe', 'mpcmdrun.exe', 'mpdlpcmd.exe', 'smartscreen.exe', 'taskhostw.exe', 'runtimebroker.exe', 'sihost.exe', 'audiodg.exe', 'werfault.exe', 'wermgr.exe', 'tiworker.exe', 'trustedinstaller.exe', 'compattelrunner.exe', 'usocoreworker.exe', 'musnotification.exe', 'wuauclt.exe', 'svchost.exe', 'dwm.exe', 'fontdrvhost.exe', 'ctfmon.exe', 'dllhost.exe', 'wsqmcons.exe', 'defrag.exe', 'sppsvc.exe', 'vm3dservice.exe', 'wudfhost.exe', 'securityhealthsystray.exe', 'securityhealthservice.exe']);
const OWN_PROC = /collector\.ps1|\\ssrun\\hkcu_|ss-lan-block|wevtutil\.exe\s+(?:sl|cl)\s+"?Microsoft-Windows-DNS-Client|auditpol|ProcessCreationIncludeCmdLine|Get-CimInstance|Get-WinEvent|Get-ScheduledTask|shutdown\.exe/i;
const FILE_NOISE = [
  /\\AppData\\Local\\Microsoft\\(?:Windows|Edge|WindowsApps|OneDrive|Office|Teams|Credentials|Vault)\\/i,
  /\\AppData\\Local\\(?:Packages|D3DSCache|CrashDumps|Temp\\(?:MpCmdRun|__PSScriptPolicyTest|PSRunspace|chrome_|edge_|Low\\)|Microsoft\\)/i,
  /\\AppData\\Roaming\\Microsoft\\(?:Windows\\(?:Recent|Network Shortcuts|Printer Shortcuts|SendTo|Templates|Libraries|Start Menu\\Programs\\(?:Accessories|Windows PowerShell|System Tools|Administrative Tools|Maintenance))|Crypto|SystemCertificates|Spelling)/i,
  /\\ProgramData\\Microsoft\\(?:Windows Defender|Windows\\(?:WER|Caches|DeviceMetadataCache|AppRepository|ClipSVC|SystemData|Start Menu\\Programs\\(?!StartUp))|Diagnosis|Network|Crypto|Search|Device Stage|NetFramework|DeviceSync|User Account Pictures|Windows Security Health|Windows Defender Advanced Threat Protection)/i,
  /\\Windows\\(?:Temp\\(?:MpCmdRun|CVR|wct|\{)|Logs|Prefetch|ServiceProfiles|System32\\(?:winevt|LogFiles|config|catroot2|sru|wbem\\Repository|Tasks|DriverStore|spool)|SoftwareDistribution|Installer|Fonts|Microsoft\.NET|WinSxS|assembly|servicing|AppCompat|Performance|Panther|INF|Minidump|LiveKernelReports)/i,
  /\\ssrun\\hkcu_(?:before|after)\.reg$/i, /\\NTUSER\.DAT|\\UsrClass\.dat/i, /\.(?:etl|pf|regtrans-ms|blf|jfm|edb|chk|sqm)$/i
];
const isNoisePath = (p) => FILE_NOISE.some((re) => re.test(p));
const REG_NOISE = /\\(?:UserAssist|RecentDocs|ComDlg32|BagMRU|Bags|MuiCache|FeatureUsage|Search\\RecentApps|Explorer\\(?:StreamMRU|TypedPaths|Streams|ShellFolders|FileExts|Discardable)|CloudStore|TaskBar|Notifications|Cache|Telemetry|Diagnostics|ContentDeliveryManager|Lock Screen|AppModel|Windows Error Reporting|InputPersonalization|Input\\|Console\\|Control Panel\\(?:Desktop|International|Colors|Cursors)|Software\\Microsoft\\(?:Edge|Office|OneDrive|Windows\\CurrentVersion\\(?:Explorer|Search|Notifications|PushNotifications|Group Policy|Policies\\Explorer))|Printers\\|Network\\|SessionInfo|DWM|Accessibility)/i;
const BENIGN_DNS = /(?:^|\.)(?:microsoft\.com|windows\.com|windowsupdate\.com|msftconnecttest\.com|msftncsi\.com|live\.com|office\.com|office365\.com|office\.net|azure\.com|azureedge\.net|msedge\.net|bing\.com|bing\.net|digicert\.com|trafficmanager\.net|akadns\.net|akamaiedge\.net|akamai\.net|windows\.net|s-microsoft\.com|msauth\.net|microsoftonline\.com|skype\.com|events\.data\.microsoft\.com|gvt1\.com|localhost|local|internal|lan|home|wpad)$/i;
const SUSP_HOSTS = [
  { re: /(?:^|\.)(?:discord(?:app)?\.com|discord\.gg|discordapp\.net)$/i, sev: 'high', w: 16, why: 'Discord adresine erişim denendi. Webhook ile veri sızdırma stealer\'lar için en yaygın yöntemdir.' },
  { re: /(?:^|\.)api\.telegram\.org$|(?:^|\.)t\.me$/i, sev: 'high', w: 16, why: 'Telegram bot API\'sine erişim denendi; veri sızdırma ya da komut alma için sık kullanılır.' },
  { re: /(?:^|\.)(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w+|rentry\.co|transfer\.sh|anonfiles\.com|gofile\.io|file\.io|0x0\.st|catbox\.moe)$/i, sev: 'med', w: 10, why: 'Paste/dosya paylaşım servisine erişim denendi; ikinci aşama yük indirme ya da veri bırakma için kullanılabilir.' },
  { re: /(?:^|\.)(?:ipify\.org|ip-api\.com|ipinfo\.io|checkip\.amazonaws\.com|icanhazip\.com|ifconfig\.me|myexternalip\.com|whatismyip\.\w+|ipapi\.co|ipecho\.net|ident\.me|ipwho\.is)$/i, sev: 'med', w: 8, why: 'Dış IP adresi öğrenen bir servise erişim denendi. Stealer ve RAT\'ler kurbanın IP\'sini bu şekilde öğrenir; ama birçok meşru uygulama da yapar.' },
  { re: /(?:^|\.)(?:duckdns\.org|no-ip\.\w+|ddns\.net|dyndns\.\w+|hopto\.org|zapto\.org|serveo\.net|ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|webhook\.site|requestbin\.\w+|pipedream\.net|portmap\.io)$/i, sev: 'high', w: 14, why: 'Dinamik DNS / tünel servisine erişim denendi. RAT\'ler komut sunucusunu sabit adres olmadan bu servislerle gizler.' },
  { re: /(?:^|\.)(?:grabify\.link|iplogger\.\w+|2no\.co|leakix\.net|blasze\.\w+|yip\.su)$/i, sev: 'crit', w: 25, why: 'IP kaydedici (IP logger) adresine erişim denendi.' },
  { re: /\.onion$/i, sev: 'high', w: 12, why: 'Tor (.onion) adresi çözülmeye çalışıldı.' },
  { re: /(?:^|\.)(?:raw\.githubusercontent\.com|gist\.githubusercontent\.com)$/i, sev: 'low', w: 3, why: 'GitHub ham içerik adresine erişim denendi. Meşru kullanımlar çok yaygın; yük indirme için de kullanılır.' }
];
const RISKY_PORT = new Map([[4444, 'Metasploit varsayılanı'], [1337, 'sık kullanılan arka kapı portu'], [31337, 'klasik arka kapı portu'], [6667, 'IRC (botnet)'], [6697, 'IRC (botnet)'], [5555, 'ADB / sık kullanılan RAT portu'], [9001, 'Tor'], [3389, 'RDP'], [445, 'SMB'], [23, 'Telnet']]);
const DYN_RULE_SKIP = new Set(['tg_link', 'long_b64', 'js_obf', 'bat_obf', 'addr_regex', 'lnk_cmd', 'vbs_exec', 'antivm', 'office_macro', 'known_artifacts', 'silentnet_strings', 'hardcoded_ip', 'chain_c2', 'mc_logfile', 'dl_exe_url_static']);
const ML_NAME = /!ml\b|wacatac|sabsik|zpevdo|tiggre|fuerboos|bitrep|occamy|ursu|casdet|phonzy|egairigl|cloud|gen$|generic|agent\.\w+!|!rfn\b|!mtb/i;

function isPrivateIp(ip) {
  if (/:/.test(ip)) return /^(?:fe80|fc|fd|::1)/i.test(ip);
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip); if (!m) return false; const a = +m[1], b = +m[2];
  return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
}
const short = (s, n) => { s = String(s); return s.length > (n || 200) ? s.slice(0, n || 200) + '…' : s; };

function buildDynamic(trace, ctx) {
  const engine = ctx.engine; const findings = []; const info = { tree: [], counts: {} };
  const root = trace.sample.rootPid;
  const own = trace.collectorPid;
  const net = ctx.networking || trace.guest.networking || 'Disable';
  /* --- surec agaci --- */
  const procs = trace.processes.filter((q) => !(q.cmd && OWN_PROC.test(q.cmd)));
  const byPid = new Map(procs.map((q) => [q.pid, q]));
  const inTree = new Set(); if (root) inTree.add(root);
  for (let i = 0; i < 6; i++) for (const q of procs) if (inTree.has(q.ppid) && !inTree.has(q.pid)) inTree.add(q.pid);
  const relevant = procs.filter((q) => q.pid !== own && q.ppid !== own || q.pid === root).filter((q) => !NOISE_PROC.has(q.name.toLowerCase()) || inTree.has(q.pid));
  relevant.sort((a, b) => String(a.start).localeCompare(String(b.start)));
  const kids = (pid) => relevant.filter((q) => q.ppid === pid && q.pid !== pid);
  const walk = (q, depth, out) => { if (depth > 6 || out.length > 80) return; out.push({ depth, pid: q.pid, name: q.name, cmd: q.cmd }); for (const c of kids(q.pid)) walk(c, depth + 1, out); };
  const rootProc = byPid.get(root);
  if (rootProc) walk(rootProc, 0, info.tree);
  const outsiders = relevant.filter((q) => q.pid !== root && !inTree.has(q.pid));
  const spawned = relevant.filter((q) => q.pid !== root);
  info.counts.processes = spawned.length;
  /* --- komut satirlari: StatScan'in statik kural kataligiyla --- */
  const lines = [];
  const addLine = (text, where) => { if (text && text.length > 3) lines.push({ text, where }); };
  for (const q of spawned) addLine(q.cmd || q.path, 'süreç: ' + q.name);
  for (const e of trace.files.events) if (!isNoisePath(e.p)) addLine(e.p, 'dosya: ' + e.k);
  for (const e of trace.registry.persistence) addLine(e.k + ' = ' + e.v, 'kayıt defteri');
  for (const e of trace.registry.hkcu) if (!REG_NOISE.test(e.key + e.line)) addLine(e.key + ' ' + e.line, 'HKCU');
  for (const e of trace.tasks) addLine(e.name + ' ' + e.action, 'görev');
  for (const e of trace.services) addLine(e.name + ' ' + e.v, 'hizmet');
  for (const e of trace.wmi) addLine(e.name + ' ' + e.detail, 'WMI');
  for (const e of trace.network.dns) addLine(e.name, 'DNS');
  for (const e of trace.windows) addLine(e.title, 'pencere: ' + e.name);
  const hits = new Map();
  if (engine && engine.STR_RULES) {
    for (const r of engine.STR_RULES) {
      if (DYN_RULE_SKIP.has(r.id) || !r.re) continue;
      const re = new RegExp(r.re.source, (r.re.flags || '').replace(/[gy]/g, ''));
      for (const ln of lines) { if (re.test(ln.text)) { let h = hits.get(r.id); if (!h) { h = { r, ev: [] }; hits.set(r.id, h); } if (h.ev.length < 4) h.ev.push('[' + ln.where + '] ' + short(ln.text, 240)); } }
    }
  }
  let ruleW = 0;
  for (const { r, ev } of hits.values()) {
    if (r.sev === 'info' || !(r.w > 0)) continue;
    const w = Math.min(r.w, Math.max(0, 55 - ruleW)); ruleW += w;
    findings.push(F('dyn_' + r.id, r.sev, w, 'Çalışma anında gözlendi: ' + r.t, (r.why || '') + ' Bu davranış örnek Sandbox\'ta çalışırken gözlendi (statik eşleşmeden daha güçlü kanıt).', r.act || 'Davranışın kaynağını incele.', ev, 'Meşru kurulum ve güncelleme araçları da benzer komutlar çalıştırabilir; kanıt satırındaki komutun neyi hedeflediğine bak.', r.cat));
  }
  /* --- surec davranisi: LOLBin kotuye kullanimi, taklit, golge kopya silme, surec firtinasi --- */
  { const LOL = [[/certutil(?:\.exe)?"?\s.*(?:-urlcache|-decode|-verifyctl|-encode)/i, 'certutil ile indirme/çözme'], [/bitsadmin(?:\.exe)?"?\s.*\/(?:transfer|addfile)/i, 'bitsadmin ile indirme'], [/mshta(?:\.exe)?"?\s+(?:https?:|javascript:|vbscript:)/i, 'mshta ile uzak/satır içi betik'], [/regsvr32(?:\.exe)?"?\s.*(?:\/i:\s*https?:|scrobj\.dll)/i, 'regsvr32 “Squiblydoo”'], [/rundll32(?:\.exe)?"?\s+(?:javascript:|.*\bmshtml\b)/i, 'rundll32 ile betik çalıştırma'], [/wmic(?:\.exe)?"?\s.*process\s+call\s+create/i, 'wmic ile süreç oluşturma'], [/msiexec(?:\.exe)?"?\s.*\/[iq]\w*\s+https?:/i, 'msiexec ile uzak paket'], [/(?:installutil|regasm|regsvcs|msbuild|cmstp|odbcconf|ieexec)(?:\.exe)?"?\s/i, 'imzalı araçla kod çalıştırma (proxy execution)']];
    const lolHits = []; for (const q of spawned) { const c = q.cmd || ''; for (const [re, lab] of LOL) if (re.test(c)) { lolHits.push(lab + ' — ' + short(c, 200)); break; } }
    if (lolHits.length) findings.push(F('dyn_lolbin', 'med', 6, 'Sistem araçları kötüye kullanıldı (LOLBin): ' + lolHits.length + ' süreç', 'Örnek çalışırken Windows’un kendi imzalı araçlarını indirme, kod çalıştırma ya da savunma atlatma kalıplarıyla başlattı. Yönetim betikleri de bazılarını kullanır; kalıbın örnek tarafından başlatılmış olması gözlenmiştir, amacı tahmindir.', 'Komut satırlarını oku; indirilen adresi ve dosyayı incele.', lolHits, 'Kurulum programları ve yönetim araçları msiexec/regsvr32/certutil çağırabilir.', 'proc'));
    const SYSN = /^(?:svchost|lsass|csrss|winlogon|services|smss|explorer|taskhostw|spoolsv|dwm|wininit)\.exe$/i;
    const masq = spawned.filter((q) => SYSN.test(q.name) && q.path && !/^[A-Za-z]:\\Windows\\(?:System32|SysWOW64)\\|^[A-Za-z]:\\Windows\\explorer\.exe$/i.test(q.path)); if (masq.length) findings.push(F('dyn_masq', 'high', 20, 'Sistem süreci adını taklit eden süreç', 'Windows sistem sürecinin adını taşıyan bir süreç System32 dışındaki bir yoldan çalışıyor: kendini sıradan bir sistem sürecine benzetme (masquerading) yöntemi.', 'Yolu ve imzayı kontrol et.', masq.map((q) => q.name + ' (PID ' + q.pid + ') ← ' + short(q.path, 160)), '', 'proc'));
    if (spawned.length >= 40) findings.push(F('dyn_procstorm', 'low', 4, 'Çok sayıda alt süreç (' + spawned.length + ')', 'Örnek kısa sürede çok sayıda süreç başlattı. Derleyici/kurulum programları da yapar; tarama, patlatma ya da fidye hazırlığında da görülür.', 'Süreç ağacına bak.', spawned.slice(0, 5).map((q) => q.name), '', 'proc')); }
  /* --- Defender --- */
  const dets = trace.defender.threats.filter((x) => x.name);
  if (dets.length || trace.defender.detections.length) {
    const names = dets.map((x) => x.name);
    const mlOnly = names.length > 0 && names.every((n) => ML_NAME.test(n));
    findings.push(F('dyn_defender', mlOnly ? 'high' : 'crit', mlOnly ? 25 : 40, 'Sandbox içindeki Microsoft Defender zararlı algıladı', 'Örnek çalıştırılırken ya da kopyalanırken Windows Defender şu tehdidi bildirdi: ' + (names.join(', ') || 'ayrıntı alınamadı') + '.', 'Tespit adını Microsoft Security Intelligence\'ta ara; örneği yine yalnızca izole ortamda tut.', names.concat(trace.defender.detections.map((x) => x.res).filter(Boolean)).slice(0, 6), mlOnly ? 'Algılanan ad makine öğrenmesi/genel bir tespite benziyor (ör. ...!ml, Wacatac). Bunlar bazen paketlenmiş meşru yazılımlarda yanlış pozitif verir.' : 'İmza tabanlı tespitler genellikle güvenilirdir; yine de örnek bilinen bir araç (ör. pentest aracı) olabilir.', 'av'));
  }
  if (!trace.sample.existedAfterCopy) {
    findings.push(F('dyn_defender_removed', 'high', 22, 'Sandbox\'taki Defender örneği anında kaldırdı', 'Örnek Sandbox\'a kopyalandıktan hemen sonra dosya sistemi tarafından silindi/karantinaya alındı; bu yüzden hiç çalıştırılamadı. Bu genellikle imza tabanlı bir tespittir.', 'Davranışı görmek istiyorsan ayarlardan "Sandbox içi Defender: kapalı" seçip yeniden dene (yalnızca izole Sandbox içinde).', [], 'Yanlış pozitif mümkündür; Defender adı varsa yukarıdaki bulguya bak.', 'av'));
  }
  /* --- baslatma / etkinlik yok --- */
  if (trace.sample.launchError && trace.sample.existedAfterCopy) {
    findings.push(F('dyn_launch_failed', 'info', 0, 'Örnek çalıştırılamadı', trace.sample.launchError, 'Dosya türünü, mimariyi (32/64 bit) ve gerekli çalışma zamanlarını (ör. VC++, Java) kontrol et.', [], '', 'dyn'));
  }
  const ec = trace.sample.exitCode;
  if (ec === -1073741515 || ec === 3221225781) {
    findings.push(F('dyn_missing_dll', 'info', 0, 'Örnek eksik bir DLL yüzünden başlayamadı', 'Çıkış kodu 0xC0000135 (DLL bulunamadı). Temiz bir Sandbox\'ta VC++ çalışma zamanı gibi bileşenler yoktur; bu yüzden davranış gözlenemedi. Zararlılığın göstergesi değildir.', 'Gerekli çalışma zamanını Sandbox\'a eklemek için analysis.preSteps ile yükleyici çalıştırabilir veya klasör eşleyebilirsin.', ['çıkış kodu ' + ec], '', 'dyn'));
  }
  /* --- kalicilik: kayit defteri --- */
  const regRun = [], regCrit = [], regOther = [];
  for (const e of trace.registry.persistence) {
    if (e.c === 'removed') continue; const k = e.k;
    const line = e.k.replace(/::<anahtar var>$/, '') + (e.v ? ' = ' + short(e.v, 160) : '');
    if (/\\(?:Run|RunOnce)::/i.test(k) && !/::<anahtar var>$/.test(k)) regRun.push(line);
    else if (/Image File Execution Options/i.test(k) || /AppInit_DLLs/i.test(k) && e.v) regCrit.push(line);
    else if (/Winlogon::(?:Shell|Userinit|Taskman|AppSetup)/i.test(k)) { if (!/^(?:explorer\.exe|C:\\Windows\\system32\\userinit\.exe,?)$/i.test(e.v)) regCrit.push(line); }
    else if (/Defender\\Exclusions|Policies\\Microsoft\\Windows Defender/i.test(k) && !/::<anahtar var>$/.test(k)) regOther.push({ id: 'dyn_defender_reg', line });
    else if (/Policies\\System::(?:EnableLUA|ConsentPromptBehaviorAdmin|EnableLUA)/i.test(k)) regOther.push({ id: 'dyn_uac_reg', line });
    else if (/Classes\\(?:ms-settings|mscfile|exefile)\\/i.test(k) && !/::<anahtar var>$/.test(k)) regOther.push({ id: 'dyn_hijack_reg', line });
    else if (/Session Manager::BootExecute|Environment::UserInitMprLogonScript|NT\\CurrentVersion\\Windows::(?:Load|Run)/i.test(k)) regCrit.push(line);
  }
  if (regRun.length) findings.push(F('dyn_persist_run', 'high', 20, 'Başlangıçta çalışma (Run anahtarı) eklendi', 'Örnek, Windows her açıldığında kendini çalıştıracak bir kayıt defteri girdisi oluşturdu. Zararlıların kalıcılık için en çok kullandığı yöntemdir.', 'Girdinin gösterdiği dosyayı bul ve incele; gerçek sistemde varsa sil.', regRun, 'Meşru kurulum programları da Run girdisi ekler; girdinin hangi dosyayı çalıştırdığına bak.', 'persist'));
  if (regCrit.length) findings.push(F('dyn_persist_reg', 'crit', 30, 'Sistem başlatma/yükleme kayıt ayarları değiştirildi', 'Winlogon, AppInit_DLLs, Image File Execution Options gibi sistem açılışını ve süreç yüklemesini etkileyen kayıt defteri girdileri değişti. Bunlar ileri düzey kalıcılık ve ele geçirme teknikleridir.', 'Değişen girdileri ve işaret ettikleri dosyaları incele.', regCrit, 'Çok nadiren meşru yazılım (hata ayıklayıcı yapılandırması gibi) bu anahtarlara yazar.', 'persist'));
  const byId = new Map(); for (const o of regOther) { if (!byId.has(o.id)) byId.set(o.id, []); byId.get(o.id).push(o.line); }
  if (byId.has('dyn_defender_reg')) findings.push(F('dyn_defender_reg', 'high', 22, 'Defender ayarları/istisnaları kayıt defterinden değiştirildi', 'Windows Defender\'ın istisna listesi ya da ilkeleri değişti; zararlılar kendini korumak için bunu yapar.', 'İstisna olarak eklenen yolları incele.', byId.get('dyn_defender_reg'), '', 'evade'));
  if (byId.has('dyn_uac_reg')) findings.push(F('dyn_uac_reg', 'high', 15, 'UAC (kullanıcı hesabı denetimi) ayarı değiştirildi', 'UAC\'yi zayıflatan kayıt değerleri değişti.', 'Ayarı orijinal haline getir; değişikliği yapan kaynağı bul.', byId.get('dyn_uac_reg'), '', 'evade'));
  if (byId.has('dyn_hijack_reg')) findings.push(F('dyn_hijack_reg', 'high', 25, 'Dosya ilişkisi/UAC atlatma anahtarı yazıldı', 'ms-settings, mscfile veya exefile açma komutu kullanıcı kaydında değiştirildi; bu yaygın bir UAC atlatma ve yürütme ele geçirme yöntemidir.', 'Girdinin hangi komutu çalıştırdığını incele.', byId.get('dyn_hijack_reg'), '', 'evade'));
  /* --- kalicilik: gorev / hizmet / WMI / Startup --- */
  const tasks = trace.tasks.filter((x) => !/^\\Microsoft\\/i.test(x.name));
  if (tasks.length) findings.push(F('dyn_persist_task', 'high', 20, 'Zamanlanmış görev oluşturuldu', 'Örnek çalışırken yeni bir zamanlanmış görev eklendi. Görevler zararlılarda kalıcılık ve yetki yükseltme için sık kullanılır.', 'Görevin çalıştırdığı komutu incele.', tasks.map((x) => x.name + (x.action ? ' → ' + short(x.action, 160) : '')), 'Bazı yazılımlar kurulumda güncelleme görevi ekler.', 'persist'));
  const svcNew = trace.services.filter((x) => x.c === 'added');
  if (svcNew.length) findings.push(F('dyn_persist_service', 'high', 22, 'Yeni Windows hizmeti eklendi', 'Örnek çalışırken yeni bir hizmet kaydı oluşturuldu. Hizmetler SYSTEM yetkisiyle çalışabildiği için ciddi bir kalıcılık yöntemidir.', 'Hizmetin dosya yolunu incele.', svcNew.map((x) => x.name + ' → ' + short(x.v, 160)), 'Sürücü/servis kuran meşru yazılımlar da hizmet ekler.', 'persist'));
  const svcCh = trace.services.filter((x) => x.c === 'changed');
  if (svcCh.length) findings.push(F('dyn_service_changed', 'med', 10, 'Mevcut bir Windows hizmetinin yolu/başlangıç türü değişti', 'Var olan hizmet yapılandırması değiştirildi.', 'Değişikliği incele.', svcCh.map((x) => x.name + ' : ' + short(x.old, 90) + ' → ' + short(x.v, 90)), '', 'persist'));
  const wmi = trace.wmi.filter((x) => /CommandLineEventConsumer|ActiveScriptEventConsumer/.test(x.cls));
  if (wmi.length) findings.push(F('dyn_persist_wmi', 'crit', 30, 'WMI olay aboneliği (kalıcı arka kapı yöntemi) bulundu', 'Komut/betik çalıştıran bir WMI olay tüketicisi var. Bu, dosyasız kalıcılık için kullanılan gelişmiş bir tekniktir.', 'Tüketicinin komutunu ve filtresini incele.', wmi.map((x) => x.cls + ' ' + x.name + ' ' + short(x.detail, 160)), 'Çok nadir meşru yönetim araçları kullanır.', 'persist'));
  const startup = trace.files.events.filter((e) => e.k !== 'Deleted' && /\\Start Menu\\Programs\\Startup\\[^\\]+$/i.test(e.p));
  if (startup.length) findings.push(F('dyn_persist_startup', 'high', 18, 'Başlangıç klasörüne dosya bırakıldı', 'Startup klasörüne yazılan dosyalar her oturum açılışında çalışır.', 'Bırakılan dosyayı incele.', startup.map((e) => e.p), 'Bazı programlar kısayol bırakır.', 'persist'));
  /* --- dosya sistemi --- */
  const items = trace.files.items;
  const selfCopies = items.filter((x) => x.sameAsSample);
  if (selfCopies.length) {
    const persistLoc = selfCopies.filter((x) => /\\(?:AppData|ProgramData|Users\\Public|Start Menu)\\/i.test(x.path));
    findings.push(F('dyn_selfcopy', persistLoc.length ? 'high' : 'med', persistLoc.length ? 14 : 8, 'Örnek kendini başka bir yere kopyaladı', 'Çalışan dosya kendi aynısını başka bir konuma yazdı. Yerleşme (persistence) ve tespit atlatma için yaygın bir davranıştır.', 'Kopyanın konumunu ve onu başlatan girdileri incele.', selfCopies.map((x) => x.path), 'Kendini güncelleyen/kuran bazı programlar da yapar.', 'persist'));
  }
  const dropped = items.filter((x) => !x.sameAsSample && !isNoisePath(x.path) && (x.mz || x.zip || /\.(?:exe|dll|scr|sys|jar|bat|cmd|ps1|vbs|vbe|js|jse|hta|lnk|msi)$/i.test(x.path)));
  const sysDrop = dropped.filter((x) => /\\Windows\\(?:System32|SysWOW64)\\/i.test(x.path));
  if (sysDrop.length) findings.push(F('dyn_drop_system', 'crit', 30, 'Sistem klasörüne çalıştırılabilir dosya yazıldı', 'System32/SysWOW64 gibi korumalı sistem klasörlerine dosya yazıldı. Meşru yazılım bile bunu nadiren yapar.', 'Yazılan dosyaları incele.', sysDrop.map((x) => x.path), '', 'persist'));
  const execDrop = dropped.filter((x) => (x.mz || x.zip) || /\.(?:exe|dll|scr|jar)$/i.test(x.path)).filter((x) => !sysDrop.includes(x));
  if (execDrop.length) findings.push(F('dyn_dropped_exec', 'med', 12, 'Örnek çalışırken yeni çalıştırılabilir dosya(lar) bıraktı', 'Örnek diske ' + execDrop.length + ' çalıştırılabilir/arşiv dosyası yazdı (dropper davranışı). Bu dosyalar ayrıca statik olarak taranır.', 'Bırakılan dosyaların taramasına bak; her birini ayrıca incele.', execDrop.map((x) => x.path + ' (' + x.size + ' B, ' + (x.sha256 || '?').slice(0, 12) + '…)'), 'Meşru yükleyiciler/kurulumlar da dosya bırakır; içerik taramasına bak.', 'dl'));
  const scripts = dropped.filter((x) => /\.(?:bat|cmd|ps1|vbs|vbe|js|jse|hta|lnk|msi)$/i.test(x.path) && !(x.mz || x.zip));
  if (scripts.length) findings.push(F('dyn_dropped_script', 'low', 5, 'Örnek çalışırken betik/kısayol dosyası bıraktı', 'Yeni betik veya kısayol dosyaları yazıldı.', 'Dosyaları ayrıca incele.', scripts.map((x) => x.path), '', 'dl'));
  const ev = trace.files.events.filter((e) => !isNoisePath(e.p));
  const userDocs = ev.filter((e) => /\\(?:Documents|Desktop|Pictures|Downloads|Videos|Music)\\/i.test(e.p) && !/\\Desktop\\(?:in|out)(?:\\|$)/i.test(e.p));
  const renames = userDocs.filter((e) => e.k === 'Renamed' && e.o && extOf(e.o) !== extOf(e.p));
  const noteFiles = ev.filter((e) => e.k === 'Created' && /(?:^|\\)(?:readme|how[ _-]?to[ _-]?(?:decrypt|recover|restore)|decrypt[\w _-]*|restore[ _-]?(?:my[ _-])?files|recover[ _-]?(?:my[ _-])?files|!+[\w _-]*(?:readme|decrypt)[\w _-]*)\.(?:txt|html?|hta)$/i.test(e.p));
  if ((renames.length >= 10 && userDocs.length >= 25) || noteFiles.length || userDocs.filter((e) => e.k === 'Changed').length >= 60) {
    findings.push(F('dyn_ransom_like', 'crit', 45, 'Fidye yazılımı davranışı: çok sayıda kullanıcı dosyası değiştirildi / not dosyası bırakıldı', 'Belgeler, Masaüstü ve Resimler klasörlerinde çok sayıda dosya yeniden adlandırıldı veya değiştirildi' + (noteFiles.length ? ' ve fidye notuna benzer dosya(lar) oluşturuldu' : '') + '. Bu şifreleyici (ransomware) kalıbıdır.', 'Ana sisteminde çalıştırma; örneği hemen izole et.', renames.slice(0, 3).map((e) => baseOf(e.o) + ' → ' + baseOf(e.p)).concat(noteFiles.slice(0, 3).map((e) => e.p)), 'Toplu dosya düzenleyen/senkronize eden meşru araçlar benzer iz bırakabilir; ama bunlar nadiren not dosyası bırakır.', 'ransom'));
  }
  if (trace.sample.existedAfterCopy && !trace.sample.existsAfter && !trace.defender.threats.length && trace.sample.rootPid) {
    findings.push(F('dyn_selfdelete', 'med', 10, 'Örnek çalıştıktan sonra kendini sildi', 'Çalıştırılan dosya analiz sonunda diskte yok. Zararlılar iz bırakmamak için kendilerini siler; bazı kurulum programları da geçici dosyalarını siler.', 'Silinmeden önce ne yaptığını diğer bulgulardan oku.', [], 'Meşru kurulum/güncelleme programları kendini silebilir.', 'evade'));
  }
  const ransomWin = trace.windows.filter((w) => /(?:your files|decrypt|encrypted|bitcoin|ransom|payment|dosyalarınız|şifrelendi|fidye)/i.test(w.title));
  if (ransomWin.length) findings.push(F('dyn_ransom_window', 'crit', 35, 'Ekranda fidye notu benzeri pencere açıldı', 'Açılan pencerenin başlığı fidye/şifreleme ifadeleri içeriyor.', 'Ekran görüntüsüne bak.', ransomWin.map((w) => w.name + ': ' + w.title), 'Güvenlik eğitimi yazılımları benzer metin gösterebilir.', 'ransom'));
  /* --- ag --- */
  const dnsAll = trace.network.dns; const dnsExt = dnsAll.filter((x) => !BENIGN_DNS.test(x.name) && !/^[0-9.]+$/.test(x.name));
  info.counts.dns = dnsExt.length;
  const susp = new Map();
  for (const x of dnsExt) for (const s of SUSP_HOSTS) if (s.re.test(x.name)) { if (!susp.has(s.why)) susp.set(s.why, { s, names: [] }); susp.get(s.why).names.push(x.name); }
  let sidx = 0;
  for (const { s, names } of susp.values()) findings.push(F('dyn_dns_susp' + (++sidx), s.sev, s.w, 'Şüpheli adres çözümlendi: ' + names.slice(0, 2).join(', '), s.why + (net === 'Disable' ? ' (Ağ kapalıydı; örnek yine de bu adrese ulaşmaya çalıştı.)' : ''), 'Adresin kime ait olduğunu araştır; gerçek sistemde bu alan adlarına erişimi engelle.', names, 'Meşru uygulamalar da bu servisleri kullanabilir; bağlama bak.', 'net'));
  const plain = dnsExt.filter((x) => ![...susp.values()].some((v) => v.names.includes(x.name)));
  if (plain.length) findings.push(F('dyn_dns_external', 'med', 8, plain.length + ' dış alan adı çözümlenmeye çalışıldı', 'Örnek çalışırken Sandbox\'tan dışarıdaki alan adlarına DNS sorgusu yapıldı' + (net === 'Disable' ? ' (ağ kapalı olduğu halde: örnek internete çıkmaya çalışıyor)' : '') + '. Bunlar işletim sistemi/telemetri trafiği de olabilir; örnekle ilişki kesin değildir.', 'Adresleri araştır; beklenmeyen/anlamsız alan adları komut sunucusu olabilir.', plain.map((x) => x.name), 'Windows kendi hizmetleri için de sorgu yapar; Microsoft alan adları elenmiştir ama kalanlar işletim sistemine ait olabilir.', 'net'));
  const conns = trace.network.connections.filter((c) => !isPrivateIp(c.remote));
  const lan = trace.network.connections.filter((c) => isPrivateIp(c.remote) && !/^127\.|^::1$/.test(c.remote));
  info.counts.connections = conns.length;
  if (conns.length) {
    const risky = conns.filter((c) => RISKY_PORT.has(c.port));
    findings.push(F('dyn_net_conn', risky.length ? 'high' : 'med', risky.length ? 16 : 10, conns.length + ' dış IP adresine bağlantı denemesi', 'Örnek çalışırken genel (internet) IP adreslerine TCP bağlantısı kurulmaya çalışıldı' + (net === 'Disable' ? ' (ağ kapalıydı, bu yüzden bağlantı kurulamadı ama deneme görüldü)' : '') + '. Komut sunucusu (C2) ya da veri sızdırma kanalı olabilir.', 'IP adreslerinin kime ait olduğunu araştır (whois/ASN).', conns.slice(0, 8).map((c) => c.remote + ':' + c.port + ' (' + c.state + ')' + (RISKY_PORT.has(c.port) ? ' — ' + RISKY_PORT.get(c.port) : '')), 'Sürüm/lisans kontrolü yapan meşru yazılımlar da dışarı bağlanır.', 'net'));
  }
  if (new Set(lan.map((c) => c.remote)).size >= 5) findings.push(F('dyn_net_lan', 'med', 10, 'Yerel ağdaki çok sayıda adrese bağlantı denemesi', 'Örnek çok sayıda yerel ağ adresine bağlanmayı denedi (ağ taraması / yayılma davranışı olabilir).', 'Yerel ağ erişimini kapalı tut.', lan.slice(0, 6).map((c) => c.remote + ':' + c.port), 'Ağ keşfi yapan meşru yazılımlar da yapar.', 'net'));
  /* --- bekleme / etkinlik yok --- */
  /* --- tuzak veri: stealer / clipper --- */
  const bt = trace.bait || { enabled: false, files: [], reads: [], clipboard: [] };
  const BAIT_IGNORE = new Set([...NOISE_PROC, 'msmpeng.exe', 'nissrv.exe', 'system', 'searchhost.exe', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'taskmgr.exe', 'explorer.exe']);
  const procByPid = new Map(trace.processes.map((q) => [q.pid, q]));
  const baitReads = bt.reads.filter((r) => {
    const nm = baseOf(r.proc).toLowerCase();
    if (!nm || BAIT_IGNORE.has(nm)) return false;
    if (own && r.pid === own) return false;
    const q = procByPid.get(r.pid);
    if (q && q.cmd && OWN_PROC.test(q.cmd)) return false;
    if (/^powershell(_ise)?\.exe$/.test(nm) && (!q || !inTree.has(q.pid)) && r.pid !== root) return false;
    return true;
  });
  const BK = {
    browser: { id: 'dyn_stealer_browser', sev: 'crit', w: 40, title: 'Tarayıcı parola/çerez verisi okundu (bilgi hırsızı davranışı)', why: 'Sandbox\'a bırakılan SAHTE Chrome/Edge/Brave/Firefox parola, çerez ve şifreleme anahtarı dosyaları örnek çalışırken açıldı. Bilgi çalan (stealer) zararlıların ilk işi budur.', act: 'Gerçek sistemde çalıştırma; çalıştırdıysan tüm tarayıcı parolalarını değiştir, oturumları kapat.' },
    token: { id: 'dyn_stealer_tokens', sev: 'high', w: 30, title: 'Oturum belirteci dosyaları okundu (Discord/Telegram/Steam)', why: 'Sahte Discord token, Telegram tdata ve Steam oturum dosyaları okundu. Hesap ele geçirmek için kullanılan tipik davranıştır.', act: 'Çalıştırdıysan Discord/Telegram/Steam oturumlarını kapat, parolaları ve 2FA\'yı yenile.' },
    wallet: { id: 'dyn_stealer_wallet', sev: 'crit', w: 35, title: 'Kripto cüzdan dosyaları okundu', why: 'Sahte Exodus/Electrum/Bitcoin/MetaMask cüzdan ve seed dosyaları okundu. Cüzdan hırsızı davranışı.', act: 'Çalıştırdıysan fonları yeni bir cüzdana taşı; eski seed\'i kullanma.' },
    cred: { id: 'dyn_stealer_creds', sev: 'high', w: 28, title: 'SSH/bulut/parola dosyaları okundu', why: 'Sahte .ssh, .aws, FileZilla ve parola listesi dosyaları okundu. Sunucu ve bulut kimliklerini toplayan hırsızlar yapar.', act: 'Çalıştırdıysan anahtarları ve bulut kimliklerini iptal edip yenile.' }
  };
  const readKinds = new Set();
  for (const k of Object.keys(BK)) {
    const rs = baitReads.filter((r) => r.kind === k);
    if (!rs.length) continue;
    readKinds.add(k);
    const b = BK[k];
    findings.push(F(b.id, b.sev, b.w, b.title, b.why, b.act, rs.slice(0, 6).map((r) => baseOf(r.proc) + ' (PID ' + r.pid + ') → ' + baseOf(r.path)), 'Tarayıcı, yedekleme veya parola yöneticisi gibi meşru yazılımlar bu dosyaları açar; dosyayı hangi programın okuduğuna bak.', 'steal'));
  }
  if (readKinds.size >= 2) findings.push(F('dyn_stealer_multi', 'crit', 20, 'Birden fazla türde kimlik verisi toplandı', 'Örnek tarayıcı, oturum, cüzdan ve sunucu kimliklerinden en az ' + readKinds.size + ' farklı türü tarıyor; bu, kapsamlı bir bilgi hırsızı (infostealer) kalıbıdır.', 'Örneği hemen izole et; gerçek sistemde çalıştırdıysan tüm hesapları güvenli bir cihazdan yenile.', [...readKinds].map((k) => BK[k].title), '', 'steal'));
  const ADDR = /^(bc1[0-9a-z]{20,80}|[13][1-9A-HJ-NP-Za-km-z]{25,40}|0x[0-9a-fA-F]{40})$/;
  const clipHit = bt.clipboard.filter((c) => c.changed && ADDR.test(c.seen.trim()) && c.seen.trim() !== c.set);
  if (clipHit.length) findings.push(F('dyn_clipper', 'crit', 40, 'Pano kripto adresi değiştirildi (clipper zararlısı)', 'Sandbox panosuna konan sahte kripto adresi, örnek çalışırken başka bir adresle değiştirildi. Clipper zararlıları kopyalanan cüzdan adresini saldırganınkiyle değiştirip parayı çalar.', 'Çalıştırdıysan kripto transferlerinde adresi her seferinde elle doğrula.', clipHit.map((c) => c.type.toUpperCase() + ': ' + c.set.slice(0, 16) + '… → ' + c.seen.slice(0, 20) + '…'), 'Pano yöneticileri ve çeviri/biçimlendirme araçları panoyu değiştirir, ama bir kripto adresini başka bir adrese çevirmezler.', 'steal'));
  if (bt.enabled && !baitReads.length && !clipHit.length && trace.sample.rootPid && !trace.sample.launchError) {
    findings.push(F('dyn_bait_untouched', 'info', 0, bt.auditOk ? 'Tuzak kimlik dosyalarına dokunulmadı' : 'Tuzak dosyaları kuruldu ama okuma denetimi çalışmadı', bt.auditOk ? 'Sahte tarayıcı, cüzdan ve oturum dosyaları bu çalıştırmada okunmadı. Bu yalnızca bu çalıştırmayı anlatır: bir hırsız beklemeyi, belirli bir tetikleyiciyi ya da gerçek bir kullanıcı profilini bekliyor olabilir.' : 'Dosya okuma denetimi (Security 4663) Sandbox\'ta etkinleştirilemedi; bu yüzden hırsızlık davranışı ölçülemedi. Pano denetimi yine çalıştı.', 'Bunu "temiz" kanıtı sayma.', [], '', 'dyn'));
  }
  info.bait = { enabled: !!bt.enabled, auditOk: !!bt.auditOk, files: bt.files.length, reads: baitReads.length, kinds: [...readKinds], clipboard: bt.clipboard.map((c) => ({ type: c.type, changed: c.changed && ADDR.test(c.seen.trim()) })) };
  const activity = spawned.length + ev.length + dnsExt.length + conns.length + baitReads.length + clipHit.length + trace.registry.persistence.filter((x) => x.c !== 'removed').length;
  if (trace.sample.rootPid && trace.sample.aliveAtEnd && trace.sample.cpuSec !== null && trace.sample.cpuSec < 0.3 && trace.elapsedSec >= 20) {
    findings.push(F('dyn_idle_wait', 'low', 3, 'Örnek analiz boyunca çalışmadan bekledi', 'Süreç ' + trace.elapsedSec + ' sn boyunca neredeyse hiç işlemci kullanmadı. Kullanıcı girdisi bekliyor, zaman bombası ya da sandbox algılama ile bekleme yapıyor olabilir. Bu, zararsız olduğunu göstermez.', 'Daha uzun süreyle yeniden dene ya da statik bulgulara öncelik ver.', ['işlemci süresi ' + trace.sample.cpuSec + ' sn / geçen ' + trace.elapsedSec + ' sn'], '', 'evade'));
  }
  if (trace.sample.rootPid && trace.sample.exited && activity === 0 && trace.elapsedSec <= 5 && ec === 0) {
    findings.push(F('dyn_quick_exit', 'low', 3, 'Örnek hiçbir şey yapmadan hemen çıktı', 'Çıkış kodu 0 ile birkaç saniyede sonlandı ve gözlenebilir bir etkinlik yok. Bazı zararlılar sanal ortamı algılayınca sessizce kapanır; bazı programlar da argüman/girdi bekler.', 'Statik bulgularla birlikte değerlendir.', [], '', 'evade'));
  }
  if (!findings.some((x) => x.w > 0) && trace.sample.rootPid && !trace.sample.launchError) {
    findings.push(F('dyn_no_activity', 'info', 0, 'Dinamik analizde belirgin zararlı davranış gözlenmedi', 'Sandbox\'ta ' + trace.elapsedSec + ' sn çalışırken kurala uyan bir kalıcılık, ağ, dosya veya süreç davranışı görülmedi. Bu YALNIZCA bu çalıştırmada görülenleri anlatır: zararlı sanal ortamı algılayıp saklanabilir, belirli bir koşul/tarih/sunucu yanıtı bekleyebilir, ağ kapalıyken çalışmayabilir ya da eksik bir bileşen yüzünden hiç başlamamış olabilir.', 'Bunu "temiz" kanıtı sayma; statik bulgularla birlikte değerlendir.', [], '', 'dyn'));
  }
  info.counts.fileEvents = ev.length; info.counts.dropped = dropped.length;
  info.outsiders = outsiders.slice(0, 20).map((q) => ({ pid: q.pid, name: q.name, cmd: q.cmd }));
  return { findings, info };
}

const sevWeightCap = (list) => Math.min(100, Math.round(list.reduce((a, x) => a + (x.w || 0), 0)));
function combineScores(staticScore, dynScore) {
  const hi = Math.max(staticScore, dynScore), lo = Math.min(staticScore, dynScore);
  return Math.min(100, hi + Math.round(lo * 0.5));
}

/* ======================================================================
 * Sonuc okuma, dusen dosyalari tarama
 * ==================================================================== */
function readFileCapped(file, cap) {
  const st = fs.statSync(file);
  if (!st.isFile()) throw new Error('dosya değil');
  if (st.size > cap) throw new Error('çok büyük (' + st.size + ' bayt)');
  return fs.readFileSync(file);
}
function readScreenshot(outDir, cfg) {
  if (!cfg.analysis.screenshot) return null;
  try {
    const b = readFileCapped(path.join(outDir, 'screen.png'), 3 * 1024 * 1024);
    if (b.length < 60 || b.readUInt32BE(0) !== 0x89504e47 || b.readUInt32BE(4) !== 0x0d0a1a0a) return null;
    return 'data:image/png;base64,' + b.toString('base64');
  } catch (e) { return null; }
}
async function scanDropped(trace, outDir, cfg, engine, notes) {
  const results = [];
  if (!cfg.host.scanDropped || !engine) return results;
  const dir = path.join(outDir, 'dropped');
  let names = []; try { names = fs.readdirSync(dir); } catch (e) { return results; }
  const bySha = new Map(trace.files.items.filter((x) => x.sha256).map((x) => [x.sha256, x]));
  let n = 0;
  for (const nm of names) {
    if (n >= cfg.analysis.maxDropped) break;
    const m = /^([0-9a-f]{64})\.bin$/.exec(nm); if (!m) continue;
    try {
      const buf = readFileCapped(path.join(dir, nm), cfg.analysis.maxDroppedMB * 1024 * 1024);
      if (sha256(buf) !== m[1]) { notes.push('Düşen dosyanın özeti uyuşmadı, atlandı: ' + nm.slice(0, 16)); continue; }
      const meta = bySha.get(m[1]); const orig = meta ? meta.path : nm;
      const r = await engine.scanFile({ name: baseOf(orig) || nm, data: buf }, { mode: cfg.host.scanDroppedMode });
      if (r && r.info) { delete r.info.classView; delete r.info.classViewCapped; }
      r.name = 'Düşen dosya › ' + baseOf(orig); r.origPath = orig; r.dropped = true; n++;
      results.push(r);
    } catch (e) { notes.push('Düşen dosya taranamadı: ' + (e && e.message)); }
  }
  return results;
}

/* ======================================================================
 * Is akisi
 * ==================================================================== */
async function runDynamic(input, depsIn) {
  const deps = Object.assign(realDeps(), depsIn || {});
  const cfg = input.config; const engine = input.engine; const onPhase = input.onPhase || (() => { }); const signal = input.signal || { aborted: false };
  const pre = (depsIn && depsIn.prereq) ? depsIn.prereq : checkPrerequisites();
  if (!pre.available) { const r = pre.reasons[0] || {}; throw new DynError('unavailable', (r.title || 'Dinamik analiz kullanılamıyor') + '. ' + (r.detail || ''), { prereq: pre }); }
  if (pre.busy && !(depsIn && depsIn.ignoreBusy)) throw new DynError('busy', 'Windows Sandbox şu anda açık. Aynı anda yalnızca bir örnek çalışabilir; açık olanı kapatıp yeniden dene.', { prereq: pre });
  if (!input.data || !input.data.length) throw new DynError('empty', 'Örnek dosya boş.');
  if (input.data.length > cfg.host.maxSampleMB * 1024 * 1024) throw new DynError('too-big', 'Örnek ' + cfg.host.maxSampleMB + ' MB sınırını aşıyor (host.maxSampleMB).');
  const root = defaultStagingRoot(cfg); const jobId = (input.jobId || crypto.randomBytes(6).toString('hex'));
  const sample = { name: input.name || 'sample', data: input.data };
  onPhase({ phase: 'prepare', label: 'Hazırlanıyor: Sandbox yapılandırması ve çalışma klasörü' });
  const plan = planJob(cfg, sample, jobId, root, depsIn);
  stageJob(plan, sample);
  const warnings = [];
  const notes = [];
  const t0 = Date.now(); let killed = false;
  const kill = () => { if (!killed) { killed = true; try { deps.kill(); } catch (e) { /* yoksay */ } } };
  const finish = (fn) => { try { return fn(); } finally { if (!cfg.host.keepArtifacts) rmDir(plan.jobDir); } };
  try {
    if (depsIn && depsIn.dryRun) return { dryRun: true, plan };
    onPhase({ phase: 'boot', label: 'Windows Sandbox başlatılıyor' });
    await deps.launch(plan.wsbPath);
    let minTimer = null;
    if (cfg.host.minimizeWindow) { let n = 0; minTimer = setInterval(() => { try { deps.minimize(); } catch (e) { /* yoksay */ } if (++n > 20) clearInterval(minTimer); }, 1500); if (minTimer.unref) minTimer.unref(); }
    const startedFlag = path.join(plan.outDir, 'started.flag'), doneFlag = path.join(plan.outDir, 'done.flag');
    let started = false;
    while (!started) {
      if (signal.aborted) { kill(); throw new DynError('cancelled', 'Dinamik analiz iptal edildi.'); }
      if (fs.existsSync(startedFlag)) { started = true; break; }
      const waited = (Date.now() - t0) / 1000;
      if (waited > cfg.host.startupTimeoutSec) { kill(); throw new DynError('start-timeout', 'Windows Sandbox ' + cfg.host.startupTimeoutSec + ' sn içinde hazır olmadı. Sanallaştırmanın açık olduğunu, Sandbox özelliğinin kurulumdan sonra yeniden başlatıldığını ve başka bir Sandbox\'ın çalışmadığını kontrol et.'); }
      if (waited > 45 && !deps.running()) throw new DynError('sandbox-not-started', 'Windows Sandbox açılmadı. Olası nedenler: sanallaştırma BIOS/UEFI\'de kapalı, özellik kurulduktan sonra yeniden başlatılmadı, yetersiz bellek/disk, ya da .wsb yapılandırması (bellek/klasör) reddedildi.');
      await deps.sleep(1000);
    }
    const planned = cfg.analysis.durationSec; const tStart = Date.now();
    onPhase({ phase: 'run', label: 'Örnek Sandbox içinde çalışıyor', elapsed: 0, total: planned });
    const hardLimit = planned + cfg.host.collectTimeoutSec;
    let done = false;
    while (!done) {
      if (signal.aborted) { kill(); throw new DynError('cancelled', 'Dinamik analiz iptal edildi.'); }
      if (fs.existsSync(doneFlag)) { done = true; break; }
      const el = (Date.now() - tStart) / 1000;
      let st = null; try { st = JSON.parse(fs.readFileSync(path.join(plan.outDir, 'status.json'), 'utf8')); } catch (e) { /* yarım yazılmış olabilir */ }
      const phase = st && st.phase === 'collect' ? 'collect' : 'run';
      onPhase({ phase, label: phase === 'collect' ? 'Gözlem verisi toplanıyor' : 'Örnek Sandbox içinde çalışıyor', elapsed: Math.min(Math.round(el), planned), total: planned });
      if (el > hardLimit) { kill(); throw new DynError('collect-timeout', 'Analiz beklenen sürede bitmedi (' + hardLimit + ' sn); Sandbox kapatıldı. Yarım kalan veri kullanılamıyor.'); }
      if (el > 20 && !deps.running()) { await deps.sleep(1500); if (!fs.existsSync(doneFlag)) throw new DynError('sandbox-closed', 'Windows Sandbox analiz bitmeden kapandı (pencere elle kapatılmış olabilir).'); }
      await deps.sleep(1000);
    }
    if (minTimer) clearInterval(minTimer);
    onPhase({ phase: 'analyze', label: 'Gözlem verisi çözümleniyor' });
    for (let i = 0; i < 20 && deps.running(); i++) await deps.sleep(1000);
    kill();
    let raw = null;
    try { raw = JSON.parse(readFileCapped(path.join(plan.outDir, 'result.json'), 64 * 1024 * 1024).toString('utf8').replace(/^\uFEFF/, '')); } catch (e) { throw new DynError('result-unreadable', 'Toplayıcının sonuç dosyası okunamadı: ' + (e && e.message)); }
    const trace = sanitizeTrace(raw);
    if (!trace.ok) throw new DynError('collector-failed', 'Sandbox içindeki toplayıcı başarısız oldu: ' + (trace.fatal || 'bilinmeyen hata'));
    const { findings, info } = buildDynamic(trace, { engine, networking: cfg.sandbox.networking });
    const droppedResults = await scanDropped(trace, plan.outDir, cfg, engine, notes);
    const dscore = droppedResults.reduce((a, r) => Math.max(a, r.score || 0), 0);
    if (dscore >= 20) findings.push(F('dyn_dropped_scan', dscore >= 55 ? 'high' : 'med', Math.min(30, Math.round(dscore * 0.35)), 'Bırakılan dosyalar statik taramada riskli çıktı', 'Örneğin çalışırken diske bıraktığı dosyalardan en yüksek skor ' + dscore + '/100.', 'Alt dosyalar bölümünde ayrıntıya bak.', droppedResults.filter((r) => r.score >= 10).slice(0, 6).map((r) => r.name + ' → ' + r.score + '/100 (' + r.verdict + ')'), '', 'dl'));
    findings.sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev] || b.w - a.w);
    const dynScore = sevWeightCap(findings);
    const shot = readScreenshot(plan.outDir, cfg);
    const sandboxInfo = { networking: cfg.sandbox.networking, clipboard: cfg.sandbox.clipboard, printer: cfg.sandbox.printer, audioInput: cfg.sandbox.audioInput, videoInput: cfg.sandbox.videoInput, vGPU: cfg.sandbox.vGPU, protectedClient: cfg.sandbox.protectedClient, memoryMB: cfg.sandbox.memoryMB, mappedFolders: plan.folders.map((f) => ({ host: f.host === plan.inDir ? '(StatScan giriş klasörü)' : f.host === plan.outDir ? '(StatScan çıkış klasörü)' : f.host, guest: f.guest, readOnly: f.readOnly })) };
    if (cfg.host.keepArtifacts) notes.push('Çalışma klasörü silinmedi: ' + plan.jobDir + ' (zararlı dosyalar içerebilir).');
    const dyn = {
      version: VERSION, jobId, at: new Date().toISOString(), os: pre.os.display,
      sample: { name: input.name, stagedAs: plan.stagedName, kind: plan.kind || 'bilinmiyor', sha256: plan.run.sampleSha256, launch: trace.sample.program ? (trace.sample.program + (trace.sample.args ? ' ' + trace.sample.args : '')) : '', launchError: trace.sample.launchError, exitCode: trace.sample.exitCode, aliveAtEnd: trace.sample.aliveAtEnd, cpuSec: trace.sample.cpuSec, existsAfter: trace.sample.existsAfter },
      settings: { durationSec: cfg.analysis.durationSec, defender: cfg.analysis.defender, stopWhenIdle: cfg.analysis.stopWhenIdle, screenshot: cfg.analysis.screenshot },
      sandbox: sandboxInfo, elapsedSec: trace.elapsedSec, stoppedEarly: trace.stoppedEarly, lanBlock: trace.guest.firewallLanBlock,
      tree: info.tree, outsiders: info.outsiders, counts: info.counts, bait: info.bait,
      network: { dns: trace.network.dns.slice(0, 60).map((x) => x.name), connections: trace.network.connections.slice(0, 60) },
      files: { created: trace.files.events.filter((e) => e.k === 'Created' && !isNoisePath(e.p)).slice(0, 80).map((e) => e.p), dropped: trace.files.items.map((x) => ({ path: x.path, size: x.size, sha256: x.sha256, pe: x.mz, sameAsSample: x.sameAsSample })).slice(0, 60), eventCap: trace.files.eventCap },
      registry: trace.registry.persistence.filter((e) => e.c !== 'removed').slice(0, 40).map((e) => ({ c: e.c, k: e.k.replace(/::<anahtar var>$/, ''), v: e.v })),
      tasks: trace.tasks.map((x) => x.name), services: trace.services.map((x) => x.c + ' ' + x.name), defender: trace.defender.threats.map((x) => x.name),
      windows: trace.windows, errors: trace.errors, notes: trace.notes.concat(notes).concat(warnings),
      dynScore, screenshot: shot
    };
    return finish(() => ({ dynamic: dyn, findings, children: droppedResults, dynScore }));
  } catch (e) {
    kill();
    if (!cfg.host.keepArtifacts) rmDir(plan.jobDir);
    throw e;
  }
}

/* Statik sonuca dinamik sonucu isler (Node tarafi: CLI ve test). */
function mergeDynamic(res, out, engine) {
  const st = res.score || 0;
  res.staticScore = st; res.staticVerdict = res.verdict;
  res.dynamic = out.dynamic;
  res.findings = (res.findings || []).concat(out.findings);
  res.findings.sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev] || (b.w || 0) - (a.w || 0));
  res.children = (res.children || []).concat(out.children || []);
  res.dynScore = out.dynScore;
  res.score = combineScores(st, out.dynScore);
  res.verdict = engine && engine.verdict ? engine.verdict(res.score) : res.verdict;
  res.analyses = (res.analyses || []).filter((a) => a.id !== 'dyn').concat([{ id: 'dyn', label: 'Dinamik/davranış analizi (Windows Sandbox)', status: (out.dynamic && out.dynamic.ok === false) ? 'partial' : 'done', note: 'Örnek yalıtılmış geçici Sandbox’ta çalıştırıldı; süreç ağacı, dosya/kayıt defteri/görev/hizmet/WMI değişiklikleri, DNS/TCP, tuzak kimlik dosyaları ve pano gözlendi. Yalnızca gözlenen süre içindeki davranış görülür; sanal ortam algılayan ya da bekleyen örnekler eksik kalabilir. Şifreli ağ içeriği ve çekirdek düzeyi davranış izlenmez.' }]);
  res.notes = (res.notes || []).concat(['Dinamik analiz yapıldı (Windows Sandbox). Skor = statik ' + st + ' ve dinamik ' + out.dynScore + ' skorlarından yüksek olan + diğerinin yarısı (en çok 100).']);
  return res;
}

/* Statik tarama "anlamli bulgu yok" mu? (dinamik analiz onerisi icin) */
function isRunnableResult(res) {
  if (RUNNABLE_EXT.has(extOf(res.name))) return true;
  return /\bPE\b|EXE|DLL|\.NET|Java|JAR|betik|MSI|LNK|HTA/i.test(String(res.type || ''));
}
function hasMeaningfulFinding(res) {
  const walk = (r) => (r.findings || []).some((f) => f.w > 0 && SEV_RANK[f.sev] >= 2) || (r.children || []).some(walk);
  return (res.score || 0) >= 10 || walk(res);
}

/* ======================================================================
 * Motor (StatScan.html icindeki statik tarayici)
 * ==================================================================== */
let ENGINE = null;
function findHtml(explicit) {
  const cands = [explicit, path.join(__dirname, 'StatScan.html'), path.join(__dirname, '..', 'StatScan.html'), path.join(process.cwd(), 'StatScan.html')].filter(Boolean);
  for (const c of cands) { try { if (fs.statSync(c).isFile()) return path.resolve(c); } catch (e) { /* sonraki */ } }
  throw new DynError('html-missing', 'StatScan.html bulunamadı. Bu dosyanın yanına ya da bir üst klasöre koy, ya da --html <yol> ver.');
}
function loadEngine(htmlPath) {
  if (ENGINE) return ENGINE;
  const html = fs.readFileSync(htmlPath, 'utf8');
  const a = html.indexOf('<script>'); const b = html.indexOf('</script>', a);
  if (a < 0 || b < 0) throw new DynError('engine-missing', 'StatScan.html içinde motor betiği bulunamadı.');
  const m = { exports: {} };
  new Function('module', 'exports', html.slice(a + 8, b))(m, m.exports);
  if (typeof m.exports.scanFile !== 'function') throw new DynError('engine-missing', 'StatScan motoru yüklenemedi.');
  ENGINE = m.exports; return ENGINE;
}

/* ======================================================================
 * Yerel arayuz sunucusu (127.0.0.1) - StatScan.html ile dinamik analiz
 * ==================================================================== */
/* Hizmet cekirdegi: HTTP'den bagimsiz. Masaustu uygulamasi (Electron ana sureci) dogrudan bunu kullanir,
 * tarayici modu ise createServer uzerinden ayni cekirdege HTTP ile baglanir. */
function createService(opts) {
  const cfg0 = opts.config; const engine = opts.engine; const deps = opts.deps || {};
  const jobs = new Map(); let active = null;
  function statusObj() {
    let pre; try { pre = checkPrerequisites(deps.prereqDeps); } catch (e) { pre = { available: false, busy: false, state: 'error', os: {}, reasons: [{ code: 'error', title: 'Koşullar denetlenemedi', detail: String(e && e.message || e), fix: [] }], warnings: [] }; }
    const v = validateConfig(cfg0);
    return { companion: true, version: VERSION, available: pre.available, busy: pre.busy || !!active, state: pre.state, os: pre.os, reasons: pre.reasons, warnings: pre.warnings.concat(v.warnings), configErrors: v.errors, defaults: { sandbox: v.value.sandbox, analysis: { durationSec: v.value.analysis.durationSec, defender: v.value.analysis.defender, screenshot: v.value.analysis.screenshot, stopWhenIdle: v.value.analysis.stopWhenIdle, bait: v.value.analysis.bait }, maxSampleMB: v.value.host.maxSampleMB } };
  }
  const fail = (status, error, message, extra) => Object.assign(new DynError(error, message), { status, extra });
  function start(inp) {
    if (active) throw fail(409, 'busy', 'Başka bir dinamik analiz sürüyor.');
    const st = statusObj(); if (!st.available) throw fail(400, 'unavailable', (st.reasons[0] && st.reasons[0].title) || 'Kullanılamıyor', { reasons: st.reasons });
    if (st.busy) throw fail(409, 'busy', 'Windows Sandbox şu anda açık.');
    const cap = validateConfig(cfg0).value.host.maxSampleMB * 1024 * 1024;
    const data = Buffer.isBuffer(inp.data) ? inp.data : Buffer.from(inp.data || []);
    if (data.length > cap) throw fail(413, 'too-big', 'Dosya ' + (cap / 1048576) + ' MB sınırını aşıyor.');
    if (!data.length) throw fail(400, 'empty', 'Dosya boş.');
    const o = applyUiOverrides(cfg0, inp.ui || {}); if (o.errors.length) throw fail(400, 'opts', o.errors.join(' '));
    const v = validateConfig(o.cfg); if (!v.ok) throw fail(400, 'config', v.errors.join(' '));
    const staticScore = Math.max(0, Math.min(100, Number(inp.staticScore || 0) || 0));
    const job = { id: crypto.randomBytes(8).toString('hex'), state: 'running', phase: 'prepare', label: 'Hazırlanıyor', elapsed: 0, total: v.value.analysis.durationSec, signal: { aborted: false }, result: null, error: null, staticScore };
    jobs.set(job.id, job); active = job;
    (async () => {
      try {
        const out = await runDynamic({ name: inp.name || 'sample', data, config: v.value, engine, jobId: job.id, signal: job.signal, onPhase: (p) => { job.phase = p.phase; job.label = p.label; if (p.elapsed !== undefined) { job.elapsed = p.elapsed; job.total = p.total; } } }, deps.runDeps);
        const combined = combineScores(staticScore, out.dynScore);
        job.result = { dynamic: out.dynamic, findings: out.findings, children: out.children, dynScore: out.dynScore, staticScore, score: combined, verdict: engine.verdict(combined) };
        job.state = 'done';
      } catch (e) { job.state = e && e.code === 'cancelled' ? 'cancelled' : 'error'; job.error = { code: (e && e.code) || 'error', message: String(e && e.message || e) }; }
      finally { active = null; }
    })();
    return { id: job.id };
  }
  function job(id) {
    const j = jobs.get(String(id)); if (!j) throw fail(404, 'yok', 'İş bulunamadı.');
    const o = { id: j.id, state: j.state, phase: j.phase, label: j.label, elapsed: j.elapsed, total: j.total, error: j.error }; if (j.state === 'done') o.result = j.result; return o;
  }
  function cancel(id) { const j = jobs.get(String(id)); if (!j) throw fail(404, 'yok', 'İş bulunamadı.'); j.signal.aborted = true; return { ok: true }; }
  function closeAll() { for (const j of jobs.values()) j.signal.aborted = true; }
  return { status: statusObj, start, job, cancel, closeAll, jobs, maxBytes: () => validateConfig(cfg0).value.host.maxSampleMB * 1024 * 1024 };
}

function createServer(opts) {
  const html = opts.html; const token = opts.token || crypto.randomBytes(24).toString('hex');
  const svc = opts.service || createService(opts); const jobs = svc.jobs;
  let port = 0;
  const hostOk = (req) => { const h = String(req.headers.host || ''); return h === '127.0.0.1:' + port || h === 'localhost:' + port; };
  const originOk = (req) => { const o = req.headers.origin; return !o || o === 'http://127.0.0.1:' + port || o === 'http://localhost:' + port; };
  const send = (res, code, obj, extra) => { const b = Buffer.from(typeof obj === 'string' ? obj : JSON.stringify(obj)); res.writeHead(code, Object.assign({ 'Content-Type': typeof obj === 'string' ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8', 'Content-Length': b.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cross-Origin-Resource-Policy': 'same-origin' }, extra || {})); res.end(b); };
  const page = () => html.replace(/(<meta name="statscan-companion" content=")[^"]*(")/, '$1' + token + '$2');
  const readBody = (req, cap) => new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on('data', (c) => { n += c.length; if (n > cap) { reject(new DynError('too-big', 'Dosya çok büyük.')); req.destroy(); return; } chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks))); req.on('error', reject);
  });
  const server = http.createServer(async (req, res) => {
    try {
      if (!hostOk(req) || !originOk(req)) return send(res, 403, { error: 'forbidden' });
      const u = new URL(req.url, 'http://127.0.0.1:' + port); const p = u.pathname;
      if (req.method === 'GET' && (p === '/' || p === '/StatScan.html')) return send(res, 200, page());
      if (!p.startsWith('/api/')) return send(res, 404, { error: 'not found' });
      if (req.headers['x-statscan-token'] !== token) return send(res, 401, { error: 'token' });
      if (req.method === 'GET' && p === '/api/status') return send(res, 200, svc.status());
      if (req.method === 'POST' && p === '/api/dynamic') {
        if (Number(req.headers['content-length'] || 0) > svc.maxBytes()) return send(res, 413, { error: 'too-big', message: 'Dosya sınırı aşıyor.' });
        const data = await readBody(req, svc.maxBytes());
        let ui = {}; try { ui = JSON.parse(u.searchParams.get('opts') || '{}'); } catch (e) { return send(res, 400, { error: 'opts', message: 'Ayarlar çözümlenemedi.' }); }
        try { return send(res, 202, svc.start({ name: u.searchParams.get('name') || 'sample', data, ui, staticScore: u.searchParams.get('static') })); }
        catch (e) { if (e && e.status) return send(res, e.status, Object.assign({ error: e.code, message: e.message }, e.extra || {})); throw e; }
      }
      let m = /^\/api\/job\/([0-9a-f]{16})$/.exec(p);
      if (m && req.method === 'GET') { try { return send(res, 200, svc.job(m[1])); } catch (e) { if (e && e.status) return send(res, e.status, { error: e.code }); throw e; } }
      m = /^\/api\/job\/([0-9a-f]{16})\/cancel$/.exec(p);
      if (m && req.method === 'POST') { try { return send(res, 200, svc.cancel(m[1])); } catch (e) { if (e && e.status) return send(res, e.status, { error: e.code }); throw e; } }
      return send(res, 404, { error: 'not found' });
    } catch (e) {
      if (!res.headersSent) send(res, e && e.code === 'too-big' ? 413 : 500, { error: 'server', message: String(e && e.message || e) });
    }
  });
  return {
    server, token, jobs, service: svc,
    listen(p) { return new Promise((resolve, reject) => { server.once('error', reject); server.listen(p || 0, '127.0.0.1', () => { port = server.address().port; resolve(port); }); }); },
    close() { svc.closeAll(); return new Promise((r) => server.close(() => r())); }
  };
}

/* ======================================================================
 * Komut satiri
 * ==================================================================== */
function parseArgs(argv) {
  const a = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    if (x.startsWith('--')) { const k = x.slice(2); const eq = k.indexOf('='); if (eq > 0) a.flags[k.slice(0, eq)] = k.slice(eq + 1); else if (i + 1 < argv.length && !argv[i + 1].startsWith('--') && !['dinamik', 'dinamik-yok', 'evet', 'json', 'keep', 'no-open', 'yardim', 'help'].includes(k)) a.flags[k] = argv[++i]; else a.flags[k] = true; }
    else a._.push(x);
  }
  return a;
}
const HELP = `StatScan dinamik analiz yardımcısı v${VERSION}

Kullanım:
  node statscan-dyn.js check [--json]
  node statscan-dyn.js scan <dosya> [--mode quick|normal|deep] [--dinamik | --dinamik-yok | --evet] [seçenekler]
  node statscan-dyn.js dry-run <dosya>        .wsb ve çalışma klasörünü üretir, Sandbox'ı BAŞLATMAZ
  node statscan-dyn.js serve [--port N] [--no-open]
  node statscan-dyn.js config                 geçerli yapılandırmayı doğrulayıp yazdırır

Seçenekler:
  --config <yol>        yapılandırma dosyası (varsayılan: statscan-dyn.config.json, yanında varsa)
  --html <yol>          StatScan.html yolu
  --sure <sn>           analiz süresi (10-900)
  --ag Enable|Disable   Sandbox ağı (varsayılan Disable)
  --pano Enable|Disable pano paylaşımı (varsayılan Disable)
  --yazici, --mikrofon, --kamera, --vgpu  Enable|Disable|Default
  --defender keep|disable  Sandbox içindeki Defender
  --json <dosya>        sonucu JSON olarak kaydet
  --keep                çalışma klasörünü silme (zararlı dosya içerebilir)

Dinamik analiz yalnızca Windows 10 Pro ve Windows 11 Pro'da, Windows Sandbox etkinse çalışır.
Örnek dosya ana sistemde ASLA çalıştırılmaz.`;

function cliOverrides(flags) {
  const u = {};
  const map = { ag: 'networking', pano: 'clipboard', yazici: 'printer', mikrofon: 'audioInput', kamera: 'videoInput', vgpu: 'vGPU', sure: 'durationSec', defender: 'defender' };
  for (const [k, t] of Object.entries(map)) if (flags[k] !== undefined && flags[k] !== true) u[t] = flags[k];
  return u;
}
function resolveConfig(flags) {
  let file = flags.config; if (file === true) file = null;
  if (!file) { const d = path.join(__dirname, 'statscan-dyn.config.json'); if (fs.existsSync(d)) file = d; }
  const base = loadConfig(file);
  const o = applyUiOverrides(base, cliOverrides(flags));
  if (o.errors.length) throw new DynError('args', 'Komut satırı seçenekleri geçersiz: ' + o.errors.join(' '));
  if (flags.keep) o.cfg.host.keepArtifacts = true;
  const v = validateConfig(o.cfg);
  if (!v.ok) throw new DynError('config', 'Yapılandırma geçersiz:\n  - ' + v.errors.join('\n  - '));
  return { cfg: v.value, warnings: v.warnings, file };
}
function printPrereq(pre) {
  console.log('Sistem: ' + (pre.os && pre.os.display ? pre.os.display : (pre.os && pre.os.platform) || 'bilinmiyor'));
  if (pre.available) console.log('Durum : Dinamik analiz KULLANILABİLİR (Windows Sandbox etkin).' + (pre.busy ? ' Şu an bir Sandbox açık.' : ''));
  else console.log('Durum : Dinamik analiz KULLANILAMIYOR.');
  for (const r of pre.reasons) { console.log('\n' + r.title + '\n  ' + r.detail); for (const f of r.fix || []) console.log('  - ' + f); }
  for (const w of pre.warnings) console.log('\nUyarı: ' + w);
}
const ask = (q) => new Promise((resolve) => { const rl = readline.createInterface({ input: process.stdin, output: process.stdout }); rl.question(q, (a) => { rl.close(); resolve(a); }); rl.on('close', () => resolve('')); });
function printResult(r) {
  console.log('\n' + r.name + ' → skor ' + r.score + '/100 · ' + r.verdict + (r.partial ? ' (kısmi tarama)' : ''));
  if (r.dynamic) console.log('  statik ' + r.staticScore + ' · dinamik ' + r.dynScore);
  const top = (r.findings || []).filter((f) => f.w > 0 || SEV_RANK[f.sev] >= 2).slice(0, 12);
  if (!top.length) console.log('  Kural eşleşmesi yok. Bu "temiz" anlamına gelmez; araç her zararlıyı yakalayamaz.');
  for (const f of top) console.log('  [' + ({ crit: 'KRİTİK', high: 'YÜKSEK', med: 'ORTA', low: 'DÜŞÜK', info: 'BİLGİ' }[f.sev]) + '] ' + (f.dyn ? '(dinamik) ' : '') + f.title + (f.w ? '  +' + f.w : ''));
}

async function main(argv) {
  const a = parseArgs(argv); const cmd = a._[0] || 'help';
  if (cmd === 'help' || a.flags.help || a.flags.yardim) { console.log(HELP); return 0; }
  if (cmd === 'check') {
    const pre = checkPrerequisites();
    if (a.flags.json) console.log(JSON.stringify(pre, null, 2)); else printPrereq(pre);
    return pre.available ? 0 : 2;
  }
  if (cmd === 'config') { const { cfg, warnings, file } = resolveConfig(a.flags); console.log('Yapılandırma dosyası: ' + (file || '(yok, varsayılanlar)')); console.log(JSON.stringify(cfg, null, 2)); for (const w of warnings) console.log('Uyarı: ' + w); return 0; }
  const { cfg, warnings } = resolveConfig(a.flags);
  const htmlPath = findHtml(a.flags.html === true ? null : a.flags.html);
  const engine = loadEngine(htmlPath);
  if (cmd === 'serve') {
    const html = fs.readFileSync(htmlPath, 'utf8');
    if (!/<meta name="statscan-companion"/.test(html)) throw new DynError('html-old', 'Bu StatScan.html dinamik analiz arayüzünü içermiyor (statscan-companion etiketi yok). Güncel StatScan.html\'i kullan.');
    const srv = createServer({ config: cfg, engine, html });
    const port = await srv.listen(a.flags.port ? Number(a.flags.port) : cfg.host.port);
    const url = 'http://127.0.0.1:' + port + '/';
    const pre = checkPrerequisites();
    console.log('StatScan yerel hizmeti çalışıyor: ' + url + '\nBu pencereyi kapatma; durdurmak için Ctrl+C.\nYalnızca bu bilgisayardan erişilebilir (127.0.0.1). Dosyalar internete gönderilmez.');
    if (!pre.available) { console.log('\nNot: Dinamik analiz şu an kullanılamıyor:'); printPrereq(pre); }
    for (const w of warnings) console.log('Uyarı: ' + w);
    if (!a.flags['no-open'] && process.platform === 'win32') { try { cp.spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore', windowsHide: true }).unref(); } catch (e) { /* elle ac */ } }
    process.on('SIGINT', async () => { try { realDeps().kill(); } catch (e) { /* yoksay */ } await srv.close(); process.exit(0); });
    return new Promise(() => { });
  }
  const file = a._[1]; if (!file) { console.error('Dosya yolu gerekli.\n\n' + HELP); return 1; }
  let data; try { data = fs.readFileSync(file); } catch (e) { console.error('Dosya okunamadı: ' + e.message); return 1; }
  const name = path.basename(file);
  if (cmd === 'dry-run') {
    const o = await runDynamic({ name, data, config: cfg, engine }, { dryRun: true, prereq: { available: true, busy: false, os: { display: 'kuru çalıştırma' }, reasons: [], warnings: [] } });
    console.log('Kuru çalıştırma tamam (Sandbox başlatılmadı).\nÇalışma klasörü: ' + o.plan.jobDir + '\n.wsb: ' + o.plan.wsbPath + '\n\n' + o.plan.wsb + '\nBaşlatma planı: ' + JSON.stringify(o.plan.run.launch));
    console.log('Not: Klasör silinmedi; işin bitince elle sil.');
    return 0;
  }
  if (cmd !== 'scan') { console.error('Bilinmeyen komut: ' + cmd + '\n\n' + HELP); return 1; }
  const mode = ['quick', 'normal', 'deep'].includes(a.flags.mode) ? a.flags.mode : 'normal';
  console.log('Statik tarama (' + mode + ') yapılıyor; dosya çalıştırılmaz…');
  const res = await engine.scanFile({ name, data }, { mode });
  printResult(res);
  if (a.flags['dinamik-yok']) { finishCli(res, a, engine); return 0; }
  let want = false;
  const pre = checkPrerequisites();
  const runnable = isRunnableResult(res);
  const meaningful = hasMeaningfulFinding(res);
  if (a.flags.dinamik || a.flags.evet) {
    if (!pre.available) { console.log('\nDinamik analiz istendi ama kullanılamıyor:'); printPrereq(pre); finishCli(res, a, engine); return 2; }
    want = runnable;
    if (!runnable) console.log('\nBu dosya türü Sandbox\'ta çalıştırılabilir görünmüyor; dinamik analiz atlandı.');
  } else if (runnable && !meaningful) {
    if (!pre.available) { console.log('\nStatik analizde anlamlı bir bulgu çıkmadı. Dinamik analiz bu bilgisayarda kullanılamıyor:'); printPrereq(pre); }
    else {
      console.log('\nStatik analizde anlamlı bir bulgu çıkmadı. Bu "temiz" demek değildir.');
      if (!process.stdin.isTTY) console.log('Etkileşimli olmayan oturum: dinamik analiz için --dinamik ekle.');
      else { const ans = (await ask('Dinamik analize geçilsin mi? Dosya yalnızca Windows Sandbox içinde çalıştırılır. [e/H] ')).trim().toLowerCase(); want = ans === 'e' || ans === 'evet' || ans === 'y' || ans === 'yes'; if (!want) console.log('Dinamik analiz yapılmadı; mevcut rapor yukarıda.'); }
    }
  }
  if (want) {
    for (const w of warnings) console.log('Uyarı: ' + w);
    console.log('\nWindows Sandbox başlatılıyor (' + cfg.analysis.durationSec + ' sn’ye kadar sürer)…');
    let last = '';
    try {
      const out = await runDynamic({ name, data, config: cfg, engine, onPhase: (p) => { const s = p.label + (p.total ? ' (' + p.elapsed + '/' + p.total + ' sn)' : ''); if (s !== last && (p.elapsed === undefined || p.elapsed % 10 === 0)) { last = s; console.log('  · ' + s); } } });
      mergeDynamic(res, out, engine);
      console.log('\n--- Dinamik analiz sonucu ---'); printResult(res);
      for (const n of out.dynamic.notes) console.log('  not: ' + n);
    } catch (e) { console.log('\nDinamik analiz tamamlanamadı: ' + (e && e.message)); finishCli(res, a, engine); return 3; }
  }
  finishCli(res, a, engine); return 0;
}
function finishCli(res, a) {
  if (a.flags.json && a.flags.json !== true) {
    const copy = JSON.parse(JSON.stringify(res, (k, v) => (k === 'screenshot' ? undefined : v)));
    fs.writeFileSync(a.flags.json, JSON.stringify({ tool: 'StatScan', dynamicHelper: VERSION, generated: new Date().toISOString(), results: [copy] }, null, 2), 'utf8');
    console.log('\nJSON rapor: ' + a.flags.json);
  }
}

module.exports = {
  VERSION, DEFAULTS, DynError, validateConfig, loadConfig, mergeDeep, applyUiOverrides, checkPrerequisites, parseRegQuery, runningSandboxProcs,
  buildWsb, validateWsb, detectKind, sanitizeSampleName, launchPlan, planJob, stageJob, guestCommand, sanitizeTrace, buildDynamic, combineScores, mergeDynamic,
  runDynamic, enableSandboxFeature, ENABLE_PS, createService, createServer, isRunnableResult, hasMeaningfulFinding, loadEngine, findHtml, winPathProblem, isNoisePath, isPrivateIp, main, GUEST_IN, GUEST_OUT
};
if (require.main === module) {
  main(process.argv.slice(2)).then((c) => { if (typeof c === 'number') process.exitCode = c; }).catch((e) => { console.error('\nHata: ' + (e && e.message ? e.message : e)); process.exitCode = 1; });
}
