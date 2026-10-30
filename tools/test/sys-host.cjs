'use strict';
// Gorev Yoneticisi + Ag Izleyici host testi (SYSMOD). Calistir: node tools/test/sys-host.cjs
const path = require('path'); const net = require('net');
const { sysModule: S } = require(path.join(__dirname, '../../app/desktop/host.js'));
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };

(async () => {
  // --- saf fonksiyonlar ---
  const C = S.ipClass;
  ok(C('10.1.2.3') === 'private' && C('192.168.1.5') === 'private' && C('172.16.0.1') === 'private' && C('172.32.0.1') === 'public', 'ipClass: özel aralıklar (172.16-31 dahil, 172.32 hariç)');
  ok(C('127.0.0.1') === 'loopback' && C('::1') === 'loopback' && C('169.254.1.1') === 'linklocal' && C('8.8.8.8') === 'public' && C('100.64.0.1') === 'cgnat', 'ipClass: loopback/linklocal/public/cgnat');
  ok(C('::ffff:10.0.0.1') === 'private' && C('::ffff:1.1.1.1') === 'public' && C('fe80::1') === 'linklocal' && C('fd00::1') === 'private' && C('2606:4700::1') === 'public' && C('0.0.0.0') === 'any', 'ipClass: IPv6 ve eşlenmiş IPv4');
  ok(S.isExternal('8.8.8.8') && !S.isExternal('192.168.0.1') && !S.isExternal('') , 'isExternal');

  const t0 = 1e12; const reg = []; for (let i = 0; i < 10; i++) reg.push(t0 + i * 60000 + (i % 2 ? 800 : -800));
  ok(S.beaconScore(reg).beacon === true, 'beacon: ~60 sn düzenli aralık yakalanır (cv ' + S.beaconScore(reg).cv + ')');
  const rnd = [0, 3000, 90000, 100000, 400000, 410000, 900000, 2000000].map((x) => t0 + x);
  ok(S.beaconScore(rnd).beacon === false, 'beacon: düzensiz aralık yakalanmaz');
  ok(S.beaconScore([t0, t0 + 1000, t0 + 2000]).beacon === false && S.beaconScore(Array.from({ length: 10 }, (_, i) => t0 + i * 500)).beacon === false, 'beacon: az örnek / çok sık aralık (<4 sn) beacon sayılmaz');

  const sp = (o) => Object.assign({ pid: 500, ppid: 4, name: 'x.exe', path: 'C:\\Program Files\\App\\x.exe', cmd: '' }, o);
  ok(S.scoreProc(sp({ name: 'svchost.exe', path: 'C:\\Users\\a\\AppData\\Local\\Temp\\svchost.exe' }), null, [], {}).score >= 60, 'puan: svchost.exe Temp’ten → yüksek (taklit + geçici konum)');
  ok(S.scoreProc(sp({ name: 'svchost.exe', path: 'C:\\Windows\\System32\\svchost.exe' }), { status: 'Valid' }, [], {}).score === 0, 'puan: gerçek svchost.exe → 0');
  ok(S.scoreProc(sp({ name: 'scvhost.exe', path: 'C:\\Windows\\System32\\scvhost.exe' }), null, [], {}).score >= 40, 'puan: scvhost.exe (yazım taklidi) yakalanır');
  ok(S.scoreProc(sp({ name: 'powershell.exe', path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', cmd: 'powershell -w hidden -enc SQBFAFgA' }), { status: 'Valid' }, [], {}).score >= 25, 'puan: gizli/kodlu PowerShell komutu işaretlenir');
  ok(S.scoreProc(sp({ name: 'cmd.exe', path: 'C:\\Windows\\System32\\cmd.exe' }), { status: 'Valid' }, [], { parentName: 'winword.exe' }).score >= 25, 'puan: Word’ün başlattığı cmd.exe işaretlenir');
  const clean = S.scoreProc(sp({ name: 'notepad.exe', path: 'C:\\Windows\\System32\\notepad.exe' }), { status: 'Valid' }, [], {}); ok(clean.score === 0 && clean.level === 'low', 'puan: temiz imzalı süreç 0 / düşük (yanlış alarm yok)');
  ok(S.scoreProc(sp({ name: 'cheat.exe', path: 'C:\\Users\\a\\Downloads\\cheat.exe' }), { status: 'NotSigned' }, [{ state: 'Established', remote: '8.8.8.8', rport: 4444 }], {}).score >= 60, 'puan: Downloads + imzasız + internete bağlı + 4444 → yüksek');
  ok(S.scoreProc(sp({ pid: 4, name: 'System', path: '' }), null, [], {}).score === 0, 'puan: System süreci 0');

  const fl = S.flagConn({ state: 'Established', remote: '1.2.3.4', rport: 4444, proto: 'TCP', local: '10.0.0.2' }, sp({ name: 'powershell.exe' }), null);
  ok(fl.some((f) => /4444/.test(f.t)) && fl.some((f) => /Kabuk/.test(f.t)), 'bayrak: 4444 + PowerShell dışarı bağlantı');
  ok(S.flagConn({ state: 'Established', remote: '192.168.1.9', rport: 4444, proto: 'TCP', local: '192.168.1.2' }, sp({ name: 'powershell.exe' }), null).length === 0, 'bayrak: yerel ağdaki bağlantı işaretlenmez');
  ok(S.flagConn({ state: 'Established', remote: '93.184.216.34', rport: 443, proto: 'TCP', local: '10.0.0.2' }, sp({ name: 'chrome.exe' }), { status: 'Valid' }).length === 0, 'bayrak: imzalı tarayıcı :443 temiz');

  // --- gercek /proc verisi (Linux) ---
  if (process.platform === 'linux') {
    const h = S.createSysHost({ platform: 'linux', ownPid: process.pid }); const h2 = h.handlers;
    const r1 = await h2['sys:procs'](); ok(Array.isArray(r1.procs) && r1.procs.length > 0, 'sys:procs gerçek süreçleri okur (' + r1.procs.length + ')');
    const me = r1.procs.find((p) => p.pid === process.pid); ok(me && /node/.test(me.name) && me.mem > 0 && me.path, 'kendi süreci doğru okundu: ' + (me && me.name) + ' mem=' + (me && Math.round(me.mem / 1048576)) + 'MB');
    ok(r1.stats.memTotal > 0 && r1.stats.cores >= 1, 'sistem istatistikleri');
    const spin = Date.now() + 1500; while (Date.now() < spin) { /* CPU harca */ }
    await new Promise((r) => setTimeout(r, 1300)); const r2 = await h2['sys:procs'](); const me2 = r2.procs.find((p) => p.pid === process.pid); ok(me2 && me2.cpu >= 0 && me2.cpu <= 100, 'CPU% hesabı aralıkta (' + (me2 && me2.cpu.toFixed(1)) + ')');
    // gercek soket: yerel sunucu + istemci
    const srv = net.createServer((s) => s.on('data', () => {})); await new Promise((r) => srv.listen(0, '127.0.0.1', r)); const port = srv.address().port;
    const cl = net.connect(port, '127.0.0.1'); await new Promise((r) => cl.on('connect', r));
    const n = await h2['sys:net'](); const mine = n.conns.filter((c) => c.pid === process.pid);
    ok(mine.some((c) => c.state === 'Listen' && c.lport === port), 'sys:net: dinleyen soket süreçle eşleşti (port ' + port + ')');
    ok(mine.some((c) => c.state === 'Established' && c.rport === port && c.dir === 'local'), 'sys:net: kurulu bağlantı, yerel yön');
    ok(n.summary.total > 0 && typeof n.summary.since === 'number', 'sys:net: özet');
    const d = await h2['sys:detail'](null, process.pid); ok(d.pid === process.pid && d.sha256.length === 64 && d.size > 0 && Array.isArray(d.conns) && d.level, 'sys:detail: yol, SHA-256, bağlantılar, puan (' + d.score + ')');
    ok((await h2['sys:detail'](null, 'rm -rf')).error === 'bad' && (await h2['sys:detail'](null, -1)).error === 'bad' && (await h2['sys:detail'](null, '12;calc')).error === 'bad', 'sys:detail: sayı olmayan PID reddedilir (komut enjeksiyonu yok)');
    ok((await h2['sys:kill'](null, 4)).error === 'bad' && (await h2['sys:kill'](null, 0)).error === 'bad' && (await h2['sys:kill'](null, process.pid)).error === 'self', 'sys:kill: PID ≤4 ve kendi süreci korunur');
    cl.destroy(); srv.close();
  }

  // --- kill: onay + kritik surec korumasi (sahte) ---
  { let killed = null, asked = 0; const run = async (cmd, args) => JSON.stringify([{ ProcessId: 700, ParentProcessId: 4, Name: 'notepad.exe', ExecutablePath: 'C:\\Windows\\notepad.exe', CommandLine: 'notepad', ThreadCount: 2, HandleCount: 50, WorkingSetSize: 1000000, PrivateBytes: 100, KernelModeTime: 0, UserModeTime: 0, ReadTransferCount: 0, WriteTransferCount: 0, start: 1 }, { ProcessId: 701, ParentProcessId: 4, Name: 'lsass.exe', ExecutablePath: 'C:\\Windows\\System32\\lsass.exe', CommandLine: '', ThreadCount: 9, HandleCount: 900, WorkingSetSize: 5e6, PrivateBytes: 100, KernelModeTime: 0, UserModeTime: 0, ReadTransferCount: 0, WriteTransferCount: 0, start: 1 }]);
    for (const answer of [false, true]) { const h = S.createSysHost({ platform: 'win32', run, ownPid: 1, confirm: async () => { asked++; return answer; }, kill: (p) => { killed = p; } }); await h.handlers['sys:procs'](); const r = await h.handlers['sys:kill'](null, 700); if (!answer) ok(r.error === 'declined' && killed === null, 'kill: onay reddedilirse sonlandırılmaz'); else ok(r.ok && killed === 700, 'kill: onaylanınca yalnızca o PID sonlandırılır'); }
    const h = S.createSysHost({ platform: 'win32', run, ownPid: 1, confirm: async () => true, kill: () => { throw new Error('çağrılmamalı'); } }); await h.handlers['sys:procs'](); const rc = await h.handlers['sys:kill'](null, 701); ok(rc.error === 'critical', 'kill: lsass.exe gibi kritik süreç onay sorulmadan reddedilir'); }

  // --- Windows ag verisi (sahte PowerShell ciktisi) + beacon izleme ---
  { let tt = 1e12; const procsJson = JSON.stringify([{ ProcessId: 900, ParentProcessId: 4, Name: 'evil.exe', ExecutablePath: 'C:\\Users\\a\\AppData\\Local\\Temp\\evil.exe', CommandLine: '', ThreadCount: 1, HandleCount: 1, WorkingSetSize: 1, PrivateBytes: 1, KernelModeTime: 0, UserModeTime: 0, ReadTransferCount: 0, WriteTransferCount: 0, start: 1 }]); let tick = 0;
    const run = async (cmd, args) => { const sc = args[args.length - 1]; if (/Get-CimInstance Win32_Process/.test(sc)) return procsJson; if (/Get-NetTCPConnection/.test(sc)) { tick++; return JSON.stringify([{ LocalAddress: '10.0.0.2', LocalPort: 50000 + tick, RemoteAddress: '203.0.113.7', RemotePort: 4444, State: 'Established', OwningProcess: 900 }, { LocalAddress: '0.0.0.0', LocalPort: 8080, RemoteAddress: '0.0.0.0', RemotePort: 0, State: 'Listen', OwningProcess: 900 }]) + '@@UDP@@[]'; } if (/Get-AuthenticodeSignature/.test(sc)) return JSON.stringify([{ p: 'C:\\Users\\a\\AppData\\Local\\Temp\\evil.exe', st: 'NotSigned', who: '' }]); return '[]'; };
    const h = S.createSysHost({ platform: 'win32', run, now: () => tt, ownPid: 1 }); let last; for (let i = 0; i < 9; i++) { tt += 60000 + (i % 2 ? 500 : -500); last = await h.handlers['sys:net'](); }
    const c = last.conns.find((x) => x.state === 'Established'); ok(c && c.name === 'evil.exe' && c.dir === 'out' && c.sig === 'NotSigned', 'Windows ağ: süreç eşleşti, dış yön, imza durumu (' + (c && c.sig) + ')');
    ok(c.beacon && c.beacon.beacon, 'Windows ağ: her ~60 sn yeni yerel portla yeniden bağlanma beacon olarak yakalandı (' + c.beacon.n + ' örnek)');
    ok(c.flags.some((f) => /4444/.test(f.t)) && c.flags.some((f) => /beacon/.test(f.t)) && c.flags.some((f) => /İmzasız/.test(f.t)) && c.flags.some((f) => /Geçici/.test(f.t)), 'Windows ağ: 4 bayrak (port, beacon, imzasız, geçici klasör)');
    ok(last.conns.find((x) => x.state === 'Listen').flags.some((f) => /dinliyor/.test(f.t)), 'Windows ağ: 0.0.0.0 dinleyen alışılmadık süreç işaretlenir');
    const hi = await h.handlers['sys:nethist'](); ok(hi.hist.length === 1 && hi.hist[0].total === 9, 'geçmiş: tek uzak uç, 9 yeni bağlantı'); await h.handlers['sys:netreset'](); ok((await h.handlers['sys:nethist']()).hist.length === 0, 'geçmiş sıfırlanır');
    const p = (await h.handlers['sys:procs']()).procs[0]; const sc = S.scoreProc(p, { status: 'NotSigned' }, last.conns.filter((x) => x.pid === 900), {}); ok(sc.level === 'high', 'evil.exe Extended puanı yüksek: ' + sc.score); }

  // --- host kaydi ---
  const { createHost } = require(path.join(__dirname, '../../app/desktop/host.js')); const hh = createHost({ service: { closeAll() {} }, sys: { platform: 'linux' } });
  ok(['sys:procs', 'sys:sigs', 'sys:detail', 'sys:list', 'sys:net', 'sys:nethist', 'sys:netreset', 'sys:reveal', 'sys:kill'].every((k) => typeof hh.handlers[k] === 'function'), 'createHost: 9 sys kanalı kayıtlı');
  console.log(bad ? '\n' + bad + ' HATA' : '\nTÜMÜ GEÇTİ'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error('İSTİSNA', e); process.exit(2); });
