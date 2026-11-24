// Otomatik Guncelleyici (UPDMOD) host testi: sahte winget (run) + sahte Baslat menusu. Gercek winget/uygulama calismaz.
const fs = require('fs'); const os = require('os'); const path = require('path');
const { createHost, updModule } = require('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-upd-'));
const mkf = (n, body = 'x') => { const p = path.join(tmp, n); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, body); return p; };
const PNG = 'data:image/png;base64,iVBORw0KGgo=';
mkf('sm/Programs/Discord/Discord.lnk'); mkf('sm/Programs/Roblox/Roblox Player.lnk'); mkf('sm/Programs/Steam.lnk'); mkf('sm/Programs/Spotify.lnk'); mkf('sm/Programs/Discord/Uninstall Discord.lnk'); mkf('sm/Programs/Readme.lnk');
const pe = Buffer.alloc(70); pe.writeUInt16LE(0x5a4d); pe.writeUInt32LE(64, 60); pe.writeUInt32LE(0x4550, 64); pe.writeUInt16LE(0x8664, 68);
mkf('apps/Discord/app-1.0.8/Discord.exe', pe);
mkf('apps/Discord/app-1.0.9/Discord.exe', pe);
mkf('apps/Discord/app-1.0.99/Discord.exe');
const UP = 'Name            Id                 Version     Available   Source\r\n-----------------------------------------------------------------------\r\nDiscord         Discord.Discord    1.0.9100    1.0.9200    winget\r\nSpotify         Spotify.Spotify    1.2.30      1.2.31      winget\r\n2 upgrades available.\r\n';
const UP_TR = 'Ad              Kimlik             Sürüm       Kullanılabilir Kaynak\r\n-----------------------------------------------------------------------\r\nDiscord         Discord.Discord    1.0.9100    1.0.9200       winget\r\n';
const LIST_STEAM = '\r   - \r   \\ \r                                         \r\nName   Id             Version   Source\r\n----------------------------------------\r\nSteam  Valve.Steam    2.10.91   winget\r\n';
const LIST_SPOTIFY = 'Name      Id                Version   Available  Source\r\n-------------------------------------------------------\r\nSpotify   Spotify.Spotify   1.2.30    1.2.31     winget\r\n';
let calls = []; let upgradeOut = UP; let listSpotify = ''; let applyCode = 0; let applyOut = 'Successfully installed\r\n'; let noWinget = false; let gate = null;
const requests = []; const opened = [];
let manifest = [1, 0, 10];
const fetch = async (url, options) => { requests.push({ url, options }); return Response.json({ full: { host_version: manifest } }); };
const run = async (args) => { calls.push(args.join(' ')); if (noWinget) return { code: 'ENOENT', stdout: '', stderr: '' };
  if (args[0] === 'upgrade' && args[1] === '--id') { if (gate) await gate; return { code: applyCode, stdout: applyOut, stderr: '' }; }
  if (args[0] === 'upgrade') return { code: 0, stdout: upgradeOut, stderr: '' };
  if (args[0] === 'list') { const q = args[2].toLowerCase(); return { code: 0, stdout: /steam/.test(q) ? LIST_STEAM : /spotify/.test(q) ? listSpotify : 'No installed package found matching input criteria.\r\n', stderr: '' }; } return { code: 1, stdout: '', stderr: '' }; };
let t = 1000;
const mk = (dir, extra) => createHost({ service: { closeAll() {} }, flow: false, openExternal: async (url) => opened.push(url), upd: Object.assign({ dataDir: dir, platform: 'win32', now: () => (t += 10), startMenuDirs: [path.join(tmp, 'sm/Programs')], fileIcon: async (p) => (/Roblox/.test(p) ? null : PNG), readShortcut: (p) => (/Discord\.lnk$/.test(p) ? { target: path.join(tmp, 'apps/Discord/app-1.0.8/Discord.exe') } : null), localAppData: path.join(tmp, 'apps'), run, fetch, chooseApp: async () => null }, extra || {}) });

// --- tablo ayristirici ---
{ const r = updModule.parseTable(UP); ok(r.length === 2 && r[0].id === 'Discord.Discord' && r[0].version === '1.0.9100' && r[0].available === '1.0.9200' && r[1].name === 'Spotify', 'parseTable: 2 satir, altbilgi (2 upgrades available.) atildi');
  const r2 = updModule.parseTable(UP_TR); ok(r2.length === 1 && r2[0].id === 'Discord.Discord' && r2[0].available === '1.0.9200', 'parseTable: Turkce baslik (dil bagimsiz)');
  const r3 = updModule.parseTable(LIST_STEAM); ok(r3.length === 1 && r3[0].id === 'Valve.Steam' && r3[0].available === '', 'parseTable: spinner satirlari + Available sutunu olmayan list ciktisi');
  ok(updModule.parseTable('').length === 0 && updModule.parseTable('No installed package found matching input criteria.').length === 0, 'parseTable: bos/tablo yok -> []'); }

(async () => {
  const dir = path.join(tmp, 'data'); let h = mk(dir);
  // --- kesif ---
  let d = await h.handlers['upd:discover'](null);
  const names = d.items.map((i) => i.name);
  ok(d.windows && names.includes('Discord') && names.includes('Steam') && names.includes('Roblox Player'), 'discover: Baslat menusundeki tum uygulamalar bulunur (' + names.join(', ') + ')');
  ok(!names.some((n) => /uninstall|readme/i.test(n)), 'discover: Uninstall/Readme kisayollari elenir');
  const dis = d.items.find((i) => i.name === 'Discord'); ok(dis.location === path.join(tmp, 'apps/Discord/app-1.0.8'), 'discover: kisayol hedefinden kurulu klasor bulunur');
  ok(d.items.every((i) => /^[0-9a-f]{10}$/.test(i.sid)) && JSON.stringify(d).indexOf('Programs') < 0, 'discover: arayuze kisayol/Baslat yolu verilmez (yalniz kurulu klasor)');
  // --- ekleme ---
  let r = await h.handlers['upd:add'](null, dis.sid); ok(!r.error && r.apps.length === 1 && r.apps[0].name === 'Discord' && r.apps[0].icon === PNG, 'add: Discord eklendi, simge geldi');
  ok(JSON.stringify(r).indexOf(tmp) < 0, 'add/list: yanit hicbir yol icermez');
  r = await h.handlers['upd:add'](null, dis.sid); ok(r.error && /zaten/.test(r.message), 'add: ayni uygulama iki kez eklenmez');
  r = await h.handlers['upd:add'](null, 'ffffffffff'); ok(r.error, 'add: bilinmeyen sid reddedilir');
  r = await h.handlers['upd:add'](null, '../../x'); ok(r.error, 'add: bicimsiz sid reddedilir');
  d = await h.handlers['upd:discover'](null); ok(d.items.find((i) => i.name === 'Discord').already === true, 'discover: eklenmis uygulama "already"');
  for (const n of ['Roblox Player', 'Steam', 'Spotify']) { const it = d.items.find((i) => i.name === n); r = await h.handlers['upd:add'](null, it.sid); }
  r = await h.handlers['upd:list'](null); ok(r.apps.length === 4 && r.apps.find((a) => a.name === 'Roblox Player').icon === null, 'list: 4 uygulama; simgesiz olan icon=null (arayuz harf gosterir)');
  const ids = {}; for (const a of r.apps) ids[a.name] = a.id; const id = (n) => ids[n];
  // --- kontrol ---
  calls = []; let c = await h.handlers['upd:check'](null, id('Discord'));
  ok(c.status === 'available' && c.current === '1.0.9' && c.available === '1.0.10' && c.action === 'download', 'Discord: read newest valid installation and compare numerically');
  ok(calls.length === 0 && requests[0].url.endsWith('arch=x64') && requests[0].options.redirect === 'error', 'Discord: manifest uses installed executable architecture without invoking WinGet');
  manifest = [1, 0, 9];
  c = await h.handlers['upd:check'](null, id('Discord'), false, 5);
  ok(c.available === '1.0.10' && requests.length === 1, 'Discord: cache serves previous manifest within interval');
  c = await h.handlers['upd:check'](null, id('Discord'), true, 5);
  ok(c.status === 'current' && requests.length === 2, 'Discord: forced refresh bypasses cache');
  t += 5 * 60000; manifest = [1, 0, 8];
  c = await h.handlers['upd:check'](null, id('Discord'), false, 5);
  ok(c.status === 'current' && requests.length === 3, 'Discord: expired cache refreshes and older remote version is not an update');
  r = await h.handlers['upd:download'](null, id('Discord'));
  ok(r.ok && opened[0] === 'https://discord.com/download' && (await h.handlers['upd:download'](null, id('Steam'))).error, 'Discord: only Discord can open the fixed official URL');
  ok((await h.handlers['upd:apply'](null, id('Discord'))).error && calls.length === 0, 'Discord: install is rejected by the host');
  c = await h.handlers['upd:check'](null, id('Spotify')); ok(c.status === 'available', 'Spotify: WinGet upgrade remains available');
  c = await h.handlers['upd:check'](null, id('Steam')); ok(c.status === 'current' && c.current === '2.10.91', 'check: Steam winget list ile bulundu, guncelleme yok -> current');
  c = await h.handlers['upd:check'](null, id('Roblox Player')); ok(c.status === 'unknown', 'check: winget bilmeyen uygulama -> unknown (durust; uydurma sonuc yok)');
  ok(calls.filter((x) => x.startsWith('upgrade --accept')).length === 1, 'WinGet: multiple checks share the upgrade snapshot');
  upgradeOut = ''; listSpotify = LIST_SPOTIFY;
  c = await h.handlers['upd:check'](null, id('Spotify'), true, 5);
  ok(c.status === 'available' && c.available === '1.2.31', 'WinGet: list fallback preserves the Available column');
  upgradeOut = UP; listSpotify = ''; manifest = [1, 0, 10];
  let scan = await mk(dir).handlers['upd:scan'](null, 5);
  ok(scan.some((x) => x.id === id('Discord') && x.status === 'available') && scan.some((x) => x.id === id('Spotify') && x.status === 'available'), 'scan: combines Discord and WinGet updates');
  ok(calls.every((x) => !/;|&|\|/.test(x)), 'check: komutlarda kabuk metakarakteri yok');
  // --- kimlik kalicilik ---
  h = mk(dir); r = await h.handlers['upd:list'](null); ok(r.apps.length === 4, 'kalicilik: yeniden acilista 4 uygulama');
  ok(JSON.parse(fs.readFileSync(path.join(dir, 'guncelleyici.json'), 'utf8')).apps.find((a) => a.name === 'Spotify').wid === 'Spotify.Spotify', 'kalicilik: bulunan winget kimligi saklandi');
  const checkDiscord = (extra) => mk(dir, extra).handlers['upd:check'](null, id('Discord'));
  ok((await checkDiscord({ readShortcut: () => null, localAppData: path.join(tmp, 'missing') })).status === 'local_unreadable', 'Discord: missing installation is reported');
  ok((await checkDiscord({ fetch: async () => { throw new Error('offline'); } })).status === 'offline', 'Discord: network failure is reported');
  ok((await checkDiscord({ fetch: async () => { throw new DOMException('', 'TimeoutError'); } })).status === 'timeout', 'Discord: timeout is reported');
  ok((await checkDiscord({ fetch: async () => new Response('', { status: 503 }) })).code === 503, 'Discord: HTTP error is reported');
  ok((await checkDiscord({ fetch: async () => Response.json({ full: { host_version: ['1', '0', '10'] } }) })).status === 'invalid_response', 'Discord: unexpected response is reported');
  ok((await mk(dir, { run: async () => ({ code: 1, stdout: LIST_STEAM }) }).handlers['upd:check'](null, id('Steam'))).status === 'winget_error', 'WinGet: failed query never reports current');
  // --- uygulama ---
  calls = []; r = await h.handlers['upd:apply'](null, id('Spotify')); ok(r.error && /kontrol/.test(r.message), 'apply: once kontrol yapilmadan guncelleme REDDEDILIR');
  upgradeOut = UP; h = mk(dir); await h.handlers['upd:list'](null);
  c = await h.handlers['upd:check'](null, id('Spotify')); calls = [];
  r = await h.handlers['upd:apply'](null, id('Spotify'));
  ok(r.status === 'updated' && calls.length === 1 && calls[0] === 'upgrade --id Spotify.Spotify -e --silent --accept-package-agreements --accept-source-agreements --disable-interactivity', 'apply: tam komut dogru (kimlik, -e, sessiz, etkilesimsiz): ' + calls[0]);
  r = await h.handlers['upd:apply'](null, id('Spotify')); ok(r.error, 'apply: bir kez uygulanan bekleyen guncelleme tekrar uygulanmaz');
  // basarisiz
  c = await h.handlers['upd:check'](null, id('Spotify')); applyCode = 1603; applyOut = '\r\nInstaller failed with exit code: 1603\r\n';
  r = await h.handlers['upd:apply'](null, id('Spotify')); ok(r.status === 'failed' && r.code === 1603 && /1603/.test(r.detail), 'apply: basarisiz kurulum -> failed + kod + ozet');
  c = await h.handlers['upd:check'](null, id('Spotify')); applyCode = -1978335189; r = await h.handlers['upd:apply'](null, id('Spotify')); ok(r.status === 'current', 'apply: "uygulanabilir guncelleme yok" kodu -> current');
  applyCode = 0;
  // es zamanli
  c = await h.handlers['upd:check'](null, id('Spotify')); let rel; gate = new Promise((res) => { rel = res; });
  const p1 = h.handlers['upd:apply'](null, id('Spotify')); await new Promise((res) => setTimeout(res, 20)); const p2 = await h.handlers['upd:check'](null, id('Steam')); ok(p2.error && /sürüyor/.test(p2.message), 'es zamanli: guncelleme surerken kontrol/baska guncelleme reddedilir');
  rel(); gate = null; r = await p1; ok(r.status === 'updated', 'es zamanli: ilk guncelleme biter');
  // winget yok
  noWinget = true; upgradeOut = UP; h = mk(path.join(tmp, 'data2')); d = await h.handlers['upd:discover'](null); await h.handlers['upd:add'](null, d.items.find((i) => i.name === 'Steam').sid); r = await h.handlers['upd:list'](null);
  c = await h.handlers['upd:check'](null, r.apps[0].id); ok(c.status === 'nowinget', 'winget yok -> nowinget (durust mesaj arayuzde)'); noWinget = false;
  // kaldir
  h = mk(dir); r = await h.handlers['upd:list'](null); r = await h.handlers['upd:remove'](null, id('Steam')); ok(r.apps.length === 3 && !r.apps.some((a) => a.name === 'Steam'), 'remove: kaldirildi'); r = await h.handlers['upd:remove'](null, 'zzzz'); ok(r.error, 'remove: bicimsiz kimlik reddedilir');
  // dosyadan
  const exe = mkf('apps/Brave/brave.exe'); let pick = exe; h = mk(path.join(tmp, 'data3'), { chooseApp: async () => pick });
  r = await h.handlers['upd:addFile'](null); ok(!r.error && r.apps[0].name === 'brave', 'addFile: dialogla secilen exe eklenir'); pick = mkf('x/not.txt'); r = await h.handlers['upd:addFile'](null); ok(r.error, 'addFile: .txt reddedilir'); pick = '\\\\sunucu\\paylasim\\a.exe'; r = await h.handlers['upd:addFile'](null); ok(r.error, 'addFile: UNC/ag yolu reddedilir'); pick = null; r = await h.handlers['upd:addFile'](null); ok(r.canceled, 'addFile: iptal');
  // Windows disi
  h = createHost({ service: { closeAll() {} }, flow: false, upd: { dataDir: path.join(tmp, 'data4'), platform: 'linux' } }); d = await h.handlers['upd:discover'](null); ok(d.windows === false && d.items.length === 0, 'Windows disi: kesif bos, windows=false');
  // kaynak taramasi: kabuk yok
  const src = fs.readFileSync(path.join(__dirname, '../../app/desktop/host.js'), 'utf8'); const m = /const UPDMOD = \(\(\) => \{[\s\S]*?\n\}\)\(\);/.exec(src); ok(m && !/\bexec\(|shell:\s*true|spawn\(/.test(m[0]) && /execFile\('winget'/.test(m[0]), 'kaynak: UPDMOD yalniz execFile(winget) kullanir; exec/shell/spawn yok');
  console.log(bad ? '\n' + bad + ' HATA' : '\nTAMAM'); process.exit(bad ? 1 : 0);
})();
