/* Kovan RAM Analizi: bulgu motoru (Volatility 3 "-r json" çıktıları üstünde sezgisel kurallar).
   SAF JS: dosya / ağ / süreç erişimi YOK; yalnızca verilen satırları okur. Aynı kod hem StatScan.html motorunda (inject.mjs) hem host tarafında çalışır.
   Girdi: { info, pslist, psscan, pstree, cmdline, dlllist, ldrmodules, malfind, netscan, svcscan, modules, driverscan, filescan, handles } — her biri
   Volatility satırlarının dizisi (verilmeyen katman = çalışmadı). Sütun adları büyük/küçük harf ve boşluk duyarsız okunur (Volatility sürümleri arası).
   ÖNEMLİ: Bu bir SEZGİSEL puanlamadır. Hiçbir döküm "sorunsuz" ilan edilmez; her bulguda yanlış pozitif açıklaması bulunur.
   Sistem süreci tabloları SYSMOD (host.js) ile aynı kalıptan KOPYALANDI (taşınmadı; SYSMOD'a dokunulmaz). */
const RAM_SCRIPT_HOSTS = new Set(['powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'msbuild.exe', 'installutil.exe', 'wmic.exe']);
const RAM_SUSP_ARGS = /(-enc(odedcommand)?\s|-e\s+[A-Za-z0-9+/=]{30,}|frombase64string|downloadstring|downloadfile|invoke-expression|\biex\b|net\.webclient|-w(indowstyle)?\s+hidden|-nop\b|-noni\b|-ep\s+bypass|executionpolicy\s+bypass|urlcache|scrobj\.dll|\/i:https?:|mshta(\.exe)?\s+(https?:|vbscript:|javascript:)|rundll32.*javascript:|bitsadmin.*\/transfer|wmic.*process\s+call\s+create)/i;
const RAM_BAD_DIRS = [/\\appdata\\local\\temp\\/i, /\\windows\\temp\\/i, /\\users\\public\\/i, /\\downloads\\/i, /\\\$recycle\.bin\\/i, /\\appdata\\roaming\\[^\\]+\.(exe|scr|dll)$/i, /\\programdata\\[^\\]+\.(exe|scr|dll)$/i];
const RAM_PORTS = { 4444: 'Metasploit varsayılanı', 1337: 'sık görülen arka kapı portu', 31337: 'klasik arka kapı portu', 6667: 'IRC (botnet C2)', 6697: 'IRC (TLS)', 5555: 'ADB/RAT portu', 9001: 'Tor yönlendirici', 9030: 'Tor dizin', 9050: 'Tor SOCKS', 3333: 'madencilik havuzu (stratum)', 14444: 'madencilik havuzu', 12345: 'NetBus' };
/* beklenen konum (system32 | windows), beklenen ebeveyn(ler); parentMayBeGone: ebeveyn normalde sonlanır; single: tek örnek olmalı */
const RAM_SYSTEM = {
  'smss.exe': { dir: 'system32', parents: ['system', 'smss.exe'], gone: true }, 'csrss.exe': { dir: 'system32', parents: ['smss.exe'], gone: true }, 'wininit.exe': { dir: 'system32', parents: ['smss.exe'], gone: true, single: true },
  'winlogon.exe': { dir: 'system32', parents: ['smss.exe'], gone: true }, 'services.exe': { dir: 'system32', parents: ['wininit.exe'], single: true }, 'lsass.exe': { dir: 'system32', parents: ['wininit.exe'], single: true },
  'lsm.exe': { dir: 'system32', parents: ['wininit.exe'] }, 'svchost.exe': { dir: 'system32', parents: ['services.exe'] }, 'taskhostw.exe': { dir: 'system32', parents: ['svchost.exe'] }, 'spoolsv.exe': { dir: 'system32', parents: ['services.exe'] },
  'dwm.exe': { dir: 'system32', parents: ['winlogon.exe'], gone: true }, 'explorer.exe': { dir: 'windows', parents: ['userinit.exe', 'winlogon.exe', 'explorer.exe'], gone: true }, 'runtimebroker.exe': { dir: 'system32', parents: ['svchost.exe'] },
  'sihost.exe': { dir: 'system32', parents: ['svchost.exe'] }, 'dllhost.exe': { dir: 'system32', parents: ['svchost.exe'] }, 'fontdrvhost.exe': { dir: 'system32', parents: ['wininit.exe', 'winlogon.exe'], gone: true }, 'ctfmon.exe': { dir: 'system32', parents: [] },
  'conhost.exe': { dir: 'system32', parents: [] }, 'searchindexer.exe': { dir: 'system32', parents: ['services.exe'] }
};
const RAM_JIT = new Set(['chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 'vivaldi.exe', 'java.exe', 'javaw.exe', 'dotnet.exe', 'powershell.exe', 'pwsh.exe', 'code.exe', 'node.exe', 'devenv.exe', 'teams.exe', 'slack.exe', 'discord.exe', 'spotify.exe', 'steam.exe', 'steamwebhelper.exe', 'msmpeng.exe', 'onedrive.exe', 'msedgewebview2.exe']);
const RAM_SKIP = new Set(['system', 'idle', 'registry', 'memory compression', 'secure system', 'system idle process']);
const RAM_FP = {
  hidden: 'Döküm alınırken sonlanan/oluşan süreçler, tutarsız (smear) bellek sayfaları ve bozuk EPROCESS kalıntıları pslist ile psscan arasında fark üretebilir. Adı, PID’i ve zamanları tutarlıysa gerçek bir gizlenmiş süreç olma ihtimali artar.',
  terminated: 'Sonlanmış süreçlerin kalıntıları psscan’de normal olarak durur; tek başına şüphe değildir.',
  inject: 'JIT derleyen programlar (tarayıcılar, .NET, Java, Electron uygulamaları), bazı DRM/anti-hile ve güvenlik yazılımları RWX özel bellek kullanır. MZ başlığı olmayan RWX bölgeleri en sık yanlış pozitiftir; MZ başlığı (PE) olanlar çok daha anlamlıdır.',
  unlink: 'Ana yürütülebilir dosya ve bazı sistem DLL’leri listelerden birinde bulunmayabilir; veri olarak eşlenen dosyalar da çıkabilir. Üç listeden de eksik olan, yürütülebilir uzantılı bir görüntü daha anlamlıdır.',
  parent: 'Windows 10/11’de bazı sistem süreçlerinin ebeveyni (smss, userinit) kısa sürede sonlandığı için pslist’te görünmez; sanallaştırma/güvenlik ürünleri de süreç ağacını değiştirebilir. Tek başına ebeveyn uyuşmazlığı kesin kanıt değildir.',
  single: 'Nadiren, döküm anında eski bir örneğin kalıntısı veya oturum yeniden başlatması ikinci bir örnek gösterebilir.',
  path: 'Konum bilgisi PEB/denetim kaydından okunur; bozuk veya bellekten atılmış sayfalar yanlış yol gösterebilir. Kurulu sistemde WinSxS ve yama sürümleri nadiren farklı konum kullanır.',
  lookalike: 'Güvenlik yazılımları, sanallaştırma ürünleri ve bazı üçüncü taraf araçlar sistem süreçlerine benzer adlar kullanabilir.',
  baddir: 'Bazı meşru kurulum programları, taşınabilir uygulamalar ve güncelleyiciler geçici/İndirilenler/AppData klasörlerinden çalışır.',
  cmdline: 'Yönetim betikleri, kurulum programları ve kurumsal araçlar (SCCM, Intune, Chocolatey) kodlanmış veya gizli pencereli PowerShell kullanabilir.',
  shellnet: 'Betik konakları yazılım kurulumu/güncellemesi sırasında meşru olarak internete bağlanabilir; netscan kapanmış/eski bağlantı artıklarını da gösterebilir.',
  sysnet: 'LSASS ve benzeri sistem süreçleri normalde genel internete bağlanmaz; ancak bağlantı artığı veya yanlış eşleşen PID/sahip bilgisi yanlış pozitif doğurabilir.',
  port: 'Bu portlar kötü amaçlı yazılımda sık görülür ama meşru uygulamalar da kullanabilir.',
  dll: 'Kullanıcı klasörlerinden DLL yüklemek bazı meşru uygulamalarda (Electron, taşınabilir araçlar) yaygındır.',
  service: 'Bazı meşru yazılımlar hizmet ikili dosyasını ProgramData veya kullanıcı profilinde tutar.',
  driver: 'Yüklemesi kaldırılmış sürücüler driverscan’de kalır; farklı adlandırılmış sürücüler karşılaştırmada eşleşmeyebilir.'
};
const RAM_LAYERS = ['info', 'pslist', 'psscan', 'pstree', 'cmdline', 'dlllist', 'ldrmodules', 'malfind', 'netscan', 'svcscan', 'modules', 'driverscan', 'filescan', 'handles'];
const ramKey = (k) => String(k).toLowerCase().replace(/[^a-z0-9]/g, '');
function ramGet(row, names) { if (!row || typeof row !== 'object') return undefined; const ks = Object.keys(row); for (const n of names) { const want = ramKey(n); for (const k of ks) if (ramKey(k) === want) { const v = row[k]; if (v !== null && v !== undefined) return v; } } return undefined; }
const ramInt = (v) => { if (v === undefined || v === null || v === '') return null; const n = typeof v === 'number' ? v : parseInt(String(v), /^0x/i.test(String(v)) ? 16 : 10); return Number.isFinite(n) ? n : null; };
const ramStr = (v) => (v === undefined || v === null ? '' : String(v));
const ramTime = (v) => { if (v === undefined || v === null) return null; const s = String(v).trim(); return !s || s === '-' || /^n\/?a$/i.test(s) || /^disabled$/i.test(s) || /^1601-/.test(s) ? null : s; };
const ramLow = (v) => ramStr(v).toLowerCase();
function ramPathNorm(p) { if (!p) return ''; let s = String(p).trim().replace(/^"|"$/g, '').replace(/\//g, '\\').toLowerCase(); s = s.replace(/^\\\?\?\\/, '').replace(/^\\\\\?\\/, '').replace(/^\\systemroot\\/, '\\windows\\').replace(/^\\device\\harddiskvolume\d+/, '').replace(/^[a-z]:/, ''); return s; }
function ramExePath(cmd) { const s = ramStr(cmd).trim(); if (!s) return ''; if (s[0] === '"') { const e = s.indexOf('"', 1); return e > 0 ? s.slice(1, e) : s.slice(1); } const m = /^(.*?\.(?:exe|sys|dll|scr|bat|cmd))(?:\s|$)/i.exec(s); return m ? m[1] : s.split(/\s+/)[0]; }
function ramLev(a, b) { const m = a.length, n = b.length; if (Math.abs(m - n) > 2) return 9; let p = Array.from({ length: n + 1 }, (_, i) => i); for (let i = 1; i <= m; i++) { const c = [i]; for (let j = 1; j <= n; j++) c[j] = Math.min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); p = c; } return p[n]; }
function ramSwapped(a, b) { if (a.length !== b.length) return false; for (let i = 0; i < a.length - 1; i++) { if (a[i] !== b[i]) return a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2); } return false; }
function ramIpClass(ip) {
  ip = String(ip || '').trim().toLowerCase(); if (!ip || ip === '*' || ip === '0.0.0.0' || ip === '::') return 'any';
  const m4 = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(ip); if (m4) ip = m4[1];
  if (ip.includes(':')) { if (ip === '::1') return 'loopback'; if (/^fe[89ab]/.test(ip)) return 'linklocal'; if (/^f[cd]/.test(ip)) return 'private'; if (/^ff/.test(ip)) return 'multicast'; return 'public'; }
  const p = ip.split('.').map(Number); if (p.length !== 4 || p.some((x) => !(x >= 0 && x <= 255))) return 'unknown';
  if (p[0] === 127) return 'loopback'; if (p[0] === 10) return 'private'; if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return 'private'; if (p[0] === 192 && p[1] === 168) return 'private';
  if (p[0] === 169 && p[1] === 254) return 'linklocal'; if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return 'cgnat'; if (p[0] >= 224 && p[0] <= 239) return 'multicast'; if (p[0] === 0 || p[0] >= 240) return 'unknown';
  return 'public';
}
const ramExternal = (ip) => { const c = ramIpClass(ip); return c === 'public' || c === 'cgnat'; };
/* Volatility "__children" ağacını (pstree) düz satırlara çevirir; her satıra __depth ekler */
function ramFlatten(rows, depth) { const out = []; for (const r of Array.isArray(rows) ? rows : []) { if (!r || typeof r !== 'object') continue; const { __children, ...rest } = r; rest.__depth = depth || 0; out.push(rest); if (Array.isArray(__children) && __children.length) for (const c of ramFlatten(__children, (depth || 0) + 1)) out.push(c); } return out; }
const RAM_LEVEL = (s) => (s >= 60 ? 'high' : s >= 30 ? 'mid' : 'low');
const RAM_SEV = (p) => (p >= 35 ? 'high' : p >= 15 ? 'mid' : p > 0 ? 'low' : 'info');

function ramScan(data, opts) {
  data = data || {}; opts = opts || {};
  const has = (k) => Array.isArray(data[k]); const rowsOf = (k) => (has(k) ? data[k] : []);
  const coverage = RAM_LAYERS.map((k) => ({ id: k, state: has(k) ? 'ok' : 'missing', rows: has(k) ? data[k].length : 0 }));
  const notes = []; const F = []; let seq = 0;
  const add = (rule, pts, pid, proc, title, detail, fp) => { F.push({ id: 'F' + (++seq), rule, sev: RAM_SEV(pts), pts, pid: pid === undefined ? null : pid, proc: proc || '', title, detail: detail || '', fp: fp || RAM_FP[rule] || '' }); };
  /* --- süreçler --- */
  const norm = (r, kind) => ({ kind, pid: ramInt(ramGet(r, ['PID'])), ppid: ramInt(ramGet(r, ['PPID'])), name: ramStr(ramGet(r, ['ImageFileName', 'Name', 'Process'])), created: ramTime(ramGet(r, ['CreateTime'])), exited: ramTime(ramGet(r, ['ExitTime'])), threads: ramInt(ramGet(r, ['Threads'])), handles: ramInt(ramGet(r, ['Handles'])), session: ramInt(ramGet(r, ['SessionId'])), path: ramStr(ramGet(r, ['Path'])), cmd: ramStr(ramGet(r, ['Cmd'])) });
  const pl = rowsOf('pslist').map((r) => norm(r, 'pslist')).filter((p) => p.pid !== null); const ps = rowsOf('psscan').map((r) => norm(r, 'psscan')).filter((p) => p.pid !== null); const pt = ramFlatten(rowsOf('pstree')).map((r) => norm(r, 'pstree')).filter((p) => p.pid !== null);
  const live = has('pslist') ? pl : ps.filter((p) => !p.exited); if (!has('pslist')) notes.push('pslist çalışmadı: süreç listesi psscan’den (ZamanBitişi olmayanlar) türetildi; gizli süreç karşılaştırması yapılamadı.');
  const byPid = new Map(); for (const p of [...ps, ...pt, ...pl]) byPid.set(p.pid, p);
  const procMap = new Map(); const P = (pid, name) => { let o = procMap.get(pid); if (!o) { o = { pid, name: name || '', ppid: null, path: '', cmd: '', created: null, exited: null, hidden: false, why: [] }; procMap.set(pid, o); } if (name && !o.name) o.name = name; return o; };
  for (const p of [...ps, ...pt, ...pl]) { const o = P(p.pid, p.name); if (p.ppid !== null) o.ppid = p.ppid; if (p.created) o.created = p.created; if (p.exited !== undefined && p.kind !== 'psscan') o.exited = p.exited; if (p.path && !o.path) o.path = p.path; if (p.cmd && !o.cmd) o.cmd = p.cmd; }
  const pathOf = (p) => { const o = procMap.get(p.pid); return o ? o.path : ''; };
  for (const r of rowsOf('cmdline')) { const pid = ramInt(ramGet(r, ['PID'])); const a = ramStr(ramGet(r, ['Args'])); if (pid === null || !a || /inaccessible|swapped/i.test(a)) continue; const o = P(pid, ramStr(ramGet(r, ['Process']))); o.cmd = a; }
  const dllBy = new Map(); for (const r of rowsOf('dlllist')) { const pid = ramInt(ramGet(r, ['PID'])); if (pid === null) continue; const d = { name: ramStr(ramGet(r, ['Name'])), path: ramStr(ramGet(r, ['Path'])) }; if (!dllBy.has(pid)) dllBy.set(pid, []); dllBy.get(pid).push(d); }
  for (const [pid, list] of dllBy) { const o = procMap.get(pid); if (o && !o.path && list[0] && ramLow(list[0].name) === ramLow(o.name)) o.path = list[0].path; }
  const nameOf = (pid, fb) => { const o = procMap.get(pid); return (o && o.name) || fb || ''; };
  /* R1: pslist ↔ psscan */
  if (has('pslist') && has('psscan')) {
    const seen = new Set(pl.map((p) => p.pid + '|' + (p.created || ''))); const seenPid = new Set(pl.map((p) => p.pid)); const gone = [];
    for (const p of ps) {
      if (seen.has(p.pid + '|' + (p.created || ''))) continue;
      if (p.exited) { gone.push(p); continue; }
      const o = P(p.pid, p.name); o.hidden = true;
      const odd = !p.created; const reuse = seenPid.has(p.pid);
      add('hidden', odd ? 15 : 45, p.pid, p.name, 'pslist’te yok, psscan’de duruyor (ExitTime yok)', (p.name || '?') + ' (PID ' + p.pid + ', PPID ' + (p.ppid === null ? '?' : p.ppid) + ') etkin süreç listesinde değil ama havuz taramasında bulundu' + (odd ? '; CreateTime yok → bozuk kalıntı olabilir' : '') + (reuse ? '; aynı PID başka bir süreç tarafından da kullanılıyor (PID yeniden kullanımı)' : '') + '.');
    }
    if (gone.length) add('terminated', 0, null, '', gone.length + ' sonlanmış süreç kalıntısı (psscan)', gone.slice(0, 12).map((p) => (p.name || '?') + ':' + p.pid).join(', ') + (gone.length > 12 ? ' …' : ''));
    const plOnly = pl.filter((p) => !ps.some((q) => q.pid === p.pid && (q.created || '') === (p.created || ''))); if (plOnly.length && plOnly.length <= 20) for (const p of plOnly) add('hidden', 8, p.pid, p.name, 'pslist’te var, psscan’de bulunamadı', (p.name || '?') + ' (PID ' + p.pid + ') havuz taramasında görünmüyor; havuz etiketi üzerine yazılmış veya sayfa bozuk olabilir.');
  } else if (has('pslist') !== has('psscan')) notes.push('pslist/psscan karşılaştırması için iki katman da gerekir.');
  /* R4: sistem süreci taklidi, yanlış yol, ebeveyn */
  const liveBy = new Map(); for (const p of live) { const k = ramLow(p.name); if (!liveBy.has(k)) liveBy.set(k, []); liveBy.get(k).push(p); }
  for (const p of live) {
    const ln = ramLow(p.name); if (!ln || RAM_SKIP.has(ln)) continue; const sys = RAM_SYSTEM[ln]; const pth = ramPathNorm(pathOf(p));
    if (sys) {
      if (pth) { const want = sys.dir === 'windows' ? ['\\windows\\' + ln] : ['\\windows\\system32\\' + ln, '\\windows\\syswow64\\' + ln]; if (!want.includes(pth)) add('path', 45, p.pid, p.name, 'Sistem süreci adı, beklenmeyen konumdan', p.name + ' (PID ' + p.pid + ') şu konumda: ' + pathOf(p) + ' — beklenen: ' + want[0] + ' (taklit olabilir).'); }
      if (p.ppid !== null && sys.parents) {
        const par = byPid.get(p.ppid);
        if (par) { const pn = ramLow(par.name); if (sys.parents.length && !sys.parents.includes(pn)) add('parent', 30, p.pid, p.name, 'Beklenmeyen ebeveyn süreç', p.name + ' (PID ' + p.pid + ') ebeveyni ' + (par.name || '?') + ' (PID ' + p.ppid + '); beklenen: ' + sys.parents.join(' / ') + '.'); }
        else if (!sys.gone && sys.parents.length) add('parent', 15, p.pid, p.name, 'Ebeveyn süreç listede yok', p.name + ' (PID ' + p.pid + ') için PPID ' + p.ppid + ' hiçbir listede bulunamadı; beklenen ebeveyn: ' + sys.parents.join(' / ') + '.');
      }
      if (sys.single) { const all = liveBy.get(ln) || []; if (all.length > 1) { const first = all.slice().sort((a, b) => String(a.created || '').localeCompare(String(b.created || '')))[0]; if (p !== first || all.some((q) => !q.created)) add('single', 30, p.pid, p.name, 'Tek olması gereken sistem süreğinden birden fazla var', all.length + ' adet ' + p.name + ' çalışıyor (PID: ' + all.map((q) => q.pid).join(', ') + ').'); } }
    } else if (ln.length >= 6 && !/^(taskhost|taskhostex)\.exe$/.test(ln)) {
      for (const k of Object.keys(RAM_SYSTEM)) if (ln !== k && k.length >= 6 && (ramLev(ln, k) <= 1 || ramSwapped(ln, k))) { add('lookalike', 40, p.pid, p.name, 'Adı sistem sürecine çok benziyor', p.name + ' (PID ' + p.pid + ') adı ' + k + ' ile neredeyse aynı.'); break; }
    }
    if (pth && RAM_BAD_DIRS.some((r) => r.test(pth))) add('baddir', 20, p.pid, p.name, 'Kullanıcının yazabildiği/geçici konumdan çalışıyor', p.name + ' (PID ' + p.pid + ') konumu: ' + pathOf(p));
  }
  /* R5: şüpheli komut satırı */
  for (const [pid, o] of procMap) {
    if (!o.cmd) continue; const ln = ramLow(o.name); let pts = 0; const why = [];
    if (RAM_SUSP_ARGS.test(o.cmd)) { pts += RAM_SCRIPT_HOSTS.has(ln) ? 30 : 20; why.push('kodlama/gizleme/indirme kalıpları'); }
    const b64 = /[A-Za-z0-9+/]{200,}={0,2}/.exec(o.cmd); if (b64) { pts += 15; why.push('çok uzun kodlanmış veri (' + b64[0].length + ' karakter)'); }
    if (pts) add('cmdline', pts, pid, o.name, 'Şüpheli komut satırı', (o.name || '?') + ' (PID ' + pid + '): ' + why.join('; ') + ' — ' + o.cmd.slice(0, 220) + (o.cmd.length > 220 ? ' …' : ''));
  }
  /* R2: malfind */
  const mfBy = new Map(); for (const r of rowsOf('malfind')) { const pid = ramInt(ramGet(r, ['PID'])); if (pid === null) continue; if (!mfBy.has(pid)) mfBy.set(pid, []); mfBy.get(pid).push(r); }
  for (const [pid, list] of mfBy) {
    const name = nameOf(pid, ramStr(ramGet(list[0], ['Process']))); const ln = ramLow(name);
    const reg = list.map((r) => { const hd = ramStr(ramGet(r, ['Hexdump'])).trim().toLowerCase(); const notes2 = ramStr(ramGet(r, ['Notes'])); const prot = ramStr(ramGet(r, ['Protection'])); return { start: ramGet(r, ['Start VPN']), end: ramGet(r, ['End VPN']), prot, rwx: /EXECUTE_READWRITE|EXECUTE_WRITECOPY/i.test(prot), mz: /^4d 5a/.test(hd) || /^4d5a/.test(hd) || /MZ header|PE header/i.test(notes2), tag: ramStr(ramGet(r, ['Tag'])) }; });
    const mz = reg.filter((x) => x.mz).length; const hx = (v) => (typeof v === 'number' ? '0x' + v.toString(16) : ramStr(v)); const extra = Math.min(10, 3 * (reg.length - 1));
    const pts = mz ? 35 + extra : (RAM_JIT.has(ln) ? 6 : 20) + Math.min(8, extra);
    add('inject', pts, pid, name, mz ? 'Bellekte PE (MZ) başlıklı yürütülebilir bölge: enjekte kod/yansıtmalı DLL olabilir' : 'RWX özel bellek bölgesi (enjekte kod olabilir)', reg.length + ' bölge: ' + reg.slice(0, 4).map((x) => hx(x.start) + '–' + hx(x.end) + ' ' + (x.prot || '?') + (x.mz ? ' [MZ]' : '')).join('; ') + (reg.length > 4 ? ' …' : '') + (!mz && RAM_JIT.has(ln) ? ' — ' + name + ' JIT kullanan bir program olabilir (puan düşürüldü).' : ''));
  }
  /* R3: ldrmodules */
  const ldBy = new Map(); for (const r of rowsOf('ldrmodules')) { const pid = ramInt(ramGet(r, ['Pid', 'PID'])); if (pid === null) continue; const flag = (n) => { const v = ramGet(r, [n]); return v === true || ramLow(v) === 'true'; }; if (flag('InLoad') || flag('InInit') || flag('InMem')) continue; const path = ramStr(ramGet(r, ['MappedPath'])); if (!ldBy.has(pid)) ldBy.set(pid, []); ldBy.get(pid).push({ base: ramGet(r, ['Base']), path }); }
  for (const [pid, list] of ldBy) {
    const exe = list.filter((x) => /\.(dll|exe|sys|ocx|cpl|drv)$/i.test(x.path)); const anon = list.filter((x) => !x.path);
    if (exe.length) add('unlink', Math.min(45, 30 + 4 * (exe.length - 1)), pid, nameOf(pid), 'Modül üç PEB listesinden de silinmiş (unlink)', exe.slice(0, 5).map((x) => x.path).join('; ') + (exe.length > 5 ? ' …' : ''));
    else if (anon.length) add('unlink', Math.min(25, 15 + 3 * (anon.length - 1)), pid, nameOf(pid), 'Yolu olmayan görüntü bölgesi üç listede de yok', anon.length + ' bölge (taban: ' + anon.slice(0, 3).map((x) => (typeof x.base === 'number' ? '0x' + x.base.toString(16) : ramStr(x.base))).join(', ') + ').');
  }
  /* dlllist: kullanıcı klasörlerinden DLL */
  for (const [pid, list] of dllBy) { const bad = list.filter((d) => RAM_BAD_DIRS.some((r) => r.test(ramPathNorm(d.path)))); if (bad.length) add('dll', Math.min(18, 6 * bad.length), pid, nameOf(pid), 'Kullanıcının yazabildiği/geçici konumdan DLL yüklü', bad.slice(0, 4).map((d) => d.path).join('; ') + (bad.length > 4 ? ' …' : '')); }
  /* R6: ağ */
  const netBy = new Map(); let netRows = 0;
  for (const r of rowsOf('netscan')) {
    const pid = ramInt(ramGet(r, ['PID'])); const fa = ramStr(ramGet(r, ['ForeignAddr'])); const fp = ramInt(ramGet(r, ['ForeignPort'])); const st = ramStr(ramGet(r, ['State'])).toUpperCase(); const owner = ramStr(ramGet(r, ['Owner']));
    if (!ramExternal(fa)) continue; netRows++; const name = nameOf(pid, owner); const ln = ramLow(name); const historic = /^(CLOSED|TIME_WAIT|)$/.test(st); let pts = 0; const why = [];
    if (RAM_SCRIPT_HOSTS.has(ln)) { pts += historic ? 18 : 30; why.push('betik/komut konağı internete bağlanıyor'); }
    else if (/^(lsass|services|winlogon|csrss|smss|wininit)\.exe$/.test(ln)) { pts += 25; why.push('sistem süreci genel internete bağlanıyor'); }
    if (RAM_PORTS[fp]) { pts += 10; why.push('port ' + fp + ' (' + RAM_PORTS[fp] + ')'); }
    if (!pts) continue; const key = pid === null ? 'x' : pid; if (!netBy.has(key)) netBy.set(key, { pid, name, pts: 0, items: [], sys: false }); const e = netBy.get(key); if (/^(lsass|services|winlogon|csrss|smss|wininit)\.exe$/.test(ln)) e.sys = true; e.pts = Math.min(40, Math.max(e.pts, pts) + (e.items.length ? 3 : 0)); e.items.push(fa + ':' + fp + ' ' + (st || '?') + ' — ' + why.join('; '));
  }
  for (const e of netBy.values()) { const isShell = RAM_SCRIPT_HOSTS.has(ramLow(e.name)); add(isShell ? 'shellnet' : e.sys ? 'sysnet' : 'port', e.pts, e.pid, e.name, isShell ? 'Betik/komut konağı genel internete bağlantılı' : e.sys ? 'Sistem süreci genel internete bağlantılı' : 'Şüpheli port bağlantısı', e.items.slice(0, 4).join(' | ') + (e.items.length > 4 ? ' …' : '')); }
  /* hizmetler */
  for (const r of rowsOf('svcscan')) {
    const bin = ramStr(ramGet(r, ['Binary', 'Binary (Registry)'])); if (!bin) continue; const exe = ramPathNorm(ramExePath(bin)); const nm = ramStr(ramGet(r, ['Name'])); const pid = ramInt(ramGet(r, ['PID']));
    if (RAM_BAD_DIRS.some((x) => x.test(exe))) add('service', 25, pid, nameOf(pid), 'Hizmet ikili dosyası kullanıcı/geçici klasöründe', 'Hizmet ' + nm + ': ' + bin);
    else if (RAM_SCRIPT_HOSTS.has(ramLow(ramExePath(bin)).split(/[\\/]/).pop())) add('service', 25, pid, nameOf(pid), 'Hizmet komut/betik konağı üzerinden başlatılıyor', 'Hizmet ' + nm + ': ' + bin);
  }
  /* sürücüler */
  const mods = rowsOf('modules'); const modNames = new Set(mods.map((r) => ramLow(ramGet(r, ['Name'])).replace(/\.(sys|dll|exe)$/, '')));
  for (const r of mods) { const pth = ramPathNorm(ramGet(r, ['Path'])); if (pth && RAM_BAD_DIRS.some((x) => x.test(pth))) add('driver', 30, null, '', 'Çekirdek modülü kullanıcı/geçici klasöründen yüklü', ramStr(ramGet(r, ['Name'])) + ' — ' + ramStr(ramGet(r, ['Path']))); }
  if (has('modules') && has('driverscan')) { const miss = rowsOf('driverscan').map((r) => ramStr(ramGet(r, ['Name', 'Driver Name']))).filter((n) => n && !modNames.has(ramLow(n).replace(/^\\driver\\/, '').replace(/\.(sys|dll|exe)$/, ''))); if (miss.length) add('driver', miss.length <= 5 ? 10 : 12, null, '', miss.length + ' sürücü driverscan’de var, modül listesinde yok', miss.slice(0, 10).join(', ') + (miss.length > 10 ? ' …' : '') + ' — yüklemesi kaldırılmış veya gizlenmiş olabilir.'); }
  /* --- puanlama --- */
  for (const f of F) if (f.pid !== null) P(f.pid, f.proc); /* bulgusu olup listelerde görünmeyen PID de süreç tablosunda yer alsın */
  const perPid = new Map(); let dumpPts = 0; for (const f of F) { if (f.pid === null) dumpPts += f.pts; else perPid.set(f.pid, (perPid.get(f.pid) || 0) + f.pts); }
  const procs = [...procMap.values()].map((o) => { const score = Math.min(100, perPid.get(o.pid) || 0); const why = F.filter((f) => f.pid === o.pid && f.pts > 0).map((f) => ({ id: f.id, pts: f.pts, text: f.title })); return { pid: o.pid, ppid: o.ppid, name: o.name, path: o.path, cmd: o.cmd.slice(0, 400), created: o.created, exited: o.exited, hidden: o.hidden, score, level: RAM_LEVEL(score), why }; }).filter((p) => p.score > 0 || (has('pslist') && live.some((l) => l.pid === p.pid)));
  procs.sort((a, b) => b.score - a.score || a.pid - b.pid);
  const top = procs.filter((p) => p.score > 0).map((p) => p.score); let score = (top[0] || 0) + 0.2 * (top.slice(1, 4).reduce((a, b) => a + b, 0)) + Math.min(30, dumpPts); score = Math.min(100, Math.round(score)); const level = RAM_LEVEL(score);
  const key = ['pslist', 'psscan', 'malfind', 'netscan', 'ldrmodules', 'cmdline']; const missing = key.filter((k) => !has(k)); if (missing.length) notes.push('Çalışmayan/eksik katmanlar: ' + missing.join(', ') + ' — bu katmanlara dayanan kurallar değerlendirilemedi; puan eksik veriye göre düşük kalmış olabilir.');
  const counts = { procs: live.length, findings: F.length, high: F.filter((f) => f.sev === 'high').length, mid: F.filter((f) => f.sev === 'mid').length, low: F.filter((f) => f.sev === 'low').length, info: F.filter((f) => f.sev === 'info').length };
  const headline = level === 'high' ? 'Güçlü şüphe bulguları var — ayrıntılı inceleme önerilir.' : level === 'mid' ? 'Dikkat gerektiren bulgular var.' : 'Belirgin bulgu yok (bu, dökümün zararsız olduğu anlamına gelmez).';
  const kv = {}; for (const r of rowsOf('info')) { const k = ramStr(ramGet(r, ['Variable'])); if (k) kv[k] = ramStr(ramGet(r, ['Value'])); }
  const findings = F.slice().sort((a, b) => b.pts - a.pts);
  return { version: 1, score, level, headline, counts, coverage, notes, os: kv, procs, findings, caveats: ['Sezgisel puandır; bir sınıflandırma veya “zararlı/zararsız” hükmü değildir.', 'Düşük puan, dökümün sorunsuz olduğunu göstermez: eksik katmanlar, bozuk sayfalar ve bilinmeyen teknikler bulunamaz.', 'Her bulgunun yanında olası yanlış pozitif açıklaması vardır; kesin yargı için kaynak katman çıktılarını ve Volatility’yi kendin doğrula.'] };
}
const RAM_LV_TR = { high: 'Yüksek', mid: 'Orta', low: 'Düşük', info: 'Bilgi' };
function ramReportText(res, meta) {
  meta = meta || {}; const L = []; const q = (s) => String(s === undefined || s === null ? '' : s).replace(/\r?\n/g, ' ');
  L.push('# Kovan RAM Analizi raporu', '');
  L.push('- Dosya: ' + q(meta.name || '?') + (meta.size ? ' (' + meta.size + ' bayt)' : ''), '- Volatility: ' + q(meta.vol || '?'), '- Tarih: ' + q(meta.date || ''), '- Durum: ' + (meta.partial ? 'KISMİ (zaman aşımı/iptal/hatalı katman)' : 'tamamlandı'), '');
  L.push('## Genel puan: ' + res.score + ' / 100 — ' + RAM_LV_TR[res.level], '', res.headline, '');
  L.push('> Bu rapor sezgiseldir; hiçbir dökümü “sorunsuz” ilan etmez. Her bulgu için olası yanlış pozitif açıklaması aşağıdadır.', '');
  L.push('## Katman kapsamı', '', '| Katman | Durum | Satır |', '|---|---|---|'); for (const c of res.coverage) L.push('| ' + c.id + ' | ' + (c.state === 'ok' ? 'çalıştı' : 'yok') + ' | ' + c.rows + ' |'); L.push('');
  if (res.notes.length) { L.push('## Notlar', ''); for (const n of res.notes) L.push('- ' + n); L.push(''); }
  const sp = res.procs.filter((p) => p.score > 0).slice(0, 25); L.push('## Süreç puanları (en şüpheliler)', ''); if (!sp.length) L.push('Puan alan süreç yok.', ''); else { L.push('| PID | Süreç | Puan | Düzey | Gerekçeler |', '|---|---|---|---|---|'); for (const p of sp) L.push('| ' + p.pid + ' | ' + q(p.name) + ' | ' + p.score + ' | ' + RAM_LV_TR[p.level] + ' | ' + q(p.why.map((w) => w.text + ' (+' + w.pts + ')').join('; ')) + ' |'); L.push(''); }
  L.push('## Bulgular', ''); if (!res.findings.length) L.push('Bulgu yok.', ''); for (const f of res.findings) { L.push('### [' + RAM_LV_TR[f.sev] + ', +' + f.pts + '] ' + q(f.title) + (f.pid !== null ? ' — ' + q(f.proc) + ' (PID ' + f.pid + ')' : ''), '', q(f.detail), '', '*Olası yanlış pozitif:* ' + q(f.fp), ''); }
  L.push('## Sınırlar', ''); for (const c of res.caveats) L.push('- ' + c); L.push('- Volatility GERÇEK bir Windows dökümünde bu uygulama tarafından henüz denenmemiştir (v0.0.1 beta).');
  return L.join('\n') + '\n';
}
