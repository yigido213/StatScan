// Uygulama Akisi (FLOWMOD) host testi: sahte dialog/ikon/openPath ile. Gercek uygulama acilmaz.
const fs = require('fs'); const os = require('os'); const path = require('path');
const { createHost, flowModule } = require('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-flow-'));
const mkf = (n, body = 'x') => { const p = path.join(tmp, n); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, body); return p; };
const PNG = 'data:image/png;base64,iVBORw0KGgo=';
const opened = []; const ext = []; let next = null; let t = 1000; let openErr = '';
const mk = (dir, extra) => createHost(Object.assign({ service: { closeAll() {} }, openExternal: async (u) => { ext.push(u); }, flow: Object.assign({ dataDir: dir, platform: 'win32', now: () => (t += 5000), chooseApp: async () => next, fileIcon: async () => PNG, openPath: async (p) => { opened.push(p); return openErr; } }, extra || {}) }, {})).handlers;
(async () => {
  const dir = path.join(tmp, 'data'); let h = mk(dir);
  const discord = mkf('apps/Discord.exe'); const steam = mkf('apps/Steam.lnk'); const txt = mkf('apps/notlar.txt'); const sub = path.join(tmp, 'klasor.exe'); fs.mkdirSync(sub);
  let r = await h['flow:list'](null); ok(Array.isArray(r.apps) && r.apps.length === 0 && r.max === flowModule.MAX_APPS, 'baslangic: bos liste');
  next = null; r = await h['flow:add'](null); ok(r.canceled === true, 'dialog iptal -> canceled');
  next = discord; r = await h['flow:add'](null); ok(r.apps && r.apps.length === 1 && r.apps[0].name === 'Discord' && r.apps[0].kind === 'app' && r.apps[0].icon === PNG && !r.apps[0].missing, 'exe eklenir; ad dosya adindan; ikon gelir');
  ok(!JSON.stringify(r).includes(tmp), 'arayuze giden yanitta dosya yolu YOK');
  next = discord; r = await h['flow:add'](null); ok(r.error === 'flow' && /zaten/.test(r.message), 'ayni uygulama iki kez eklenmez');
  next = txt; r = await h['flow:add'](null); ok(r.error === 'flow' && /\.exe/.test(r.message), '.txt reddedilir (yalniz exe/lnk/url)');
  next = sub; r = await h['flow:add'](null); ok(r.error === 'flow', 'klasor reddedilir (.exe adli olsa bile)');
  next = path.join(tmp, 'yok.exe'); r = await h['flow:add'](null); ok(r.error === 'flow' && /bulunamad/.test(r.message), 'olmayan dosya reddedilir');
  for (const bp of ['\\\\sunucu\\paylasim\\x.exe', '//sunucu/p/x.exe', 'goreli/x.exe', 'x.exe']) { next = bp; r = await h['flow:add'](null); ok(r.error === 'flow', 'UNC/goreli yol reddedilir: ' + bp); }
  next = steam; r = await h['flow:add'](null); ok(r.apps.length === 2 && r.apps[1].name === 'Steam', '.lnk eklenir');
  // web
  r = await h['flow:addWeb'](null, 'Tarayıcı', 'http://ornek.com'); ok(r.error === 'flow', 'http adresi reddedilir');
  for (const u of ['javascript:alert(1)', 'file:///c:/x.exe', 'https://kullanici:sifre@ornek.com', 'https://localhost', 'ornek', 'steam://run/1']) { r = await h['flow:addWeb'](null, 'x', u); ok(r.error === 'flow', 'gecersiz adres reddedilir: ' + u); }
  r = await h['flow:addWeb'](null, '  Medal\u0007  ', 'https://medal.tv/'); ok(r.apps && r.apps.length === 3 && r.apps[2].kind === 'web' && r.apps[2].name === 'Medal' && r.apps[2].host === 'medal.tv', 'https adresi eklenir; ad temizlenir; host gorunur');
  r = await h['flow:addWeb'](null, '', 'https://www.ornek.com/a'); ok(r.apps[3].name === 'ornek.com', 'ad bossa host kullanilir');
  r = await h['flow:addWeb'](null, 'z', 'https://medal.tv/'); ok(r.error === 'flow', 'ayni adres iki kez eklenmez');
  ok(JSON.parse(fs.readFileSync(path.join(dir, 'uygulamaakisi.json'), 'utf8')).apps.length === 4, 'durum diske yazildi');
  // kalicilik + bozuk kayit
  h = mk(dir); r = await h['flow:list'](null); ok(r.apps.length === 4 && r.apps[0].name === 'Discord', 'yeniden acilinca liste korunur');
  fs.writeFileSync(path.join(dir, 'uygulamaakisi.json'), JSON.stringify({ v: 1, apps: [{ id: 'zzzz', name: 'k', kind: 'app', path: discord }, { id: 'aaaaaaaaaaaa', name: 'x', kind: 'web', url: 'http://kotu.com' }, { id: 'bbbbbbbbbbbb', name: 'Iyi', kind: 'web', url: 'https://iyi.com/' }, null] }));
  h = mk(dir); r = await h['flow:list'](null); ok(r.apps.length === 1 && r.apps[0].name === 'Iyi', 'bozuk/gecersiz kayitlar yuklenirken elenir');
  fs.writeFileSync(path.join(dir, 'uygulamaakisi.json'), '{bozuk'); h = mk(dir); r = await h['flow:list'](null); ok(r.apps.length === 0, 'bozuk JSON cokmez');
  // yeniden doldur
  h = mk(path.join(tmp, 'd2')); next = discord; await h['flow:add'](null); next = steam; await h['flow:add'](null); await h['flow:addWeb'](null, 'Medal', 'https://medal.tv/'); r = await h['flow:list'](null);
  const [a, b, c] = r.apps.map((x) => x.id);
  // acma
  opened.length = 0; ext.length = 0; r = await h['flow:open'](null, a); ok(r.ok === true && opened.length === 1 && opened[0] === discord, 'uygulama kimlikle acilir (kayitli yol)');
  r = await h['flow:open'](null, a); ok(r.ok && r.skipped !== true && opened.length === 2, 'zaman gectiyse tekrar acilir'); // now() her cagrida 5 sn ilerler
  const hh = mk(path.join(tmp, 'd2'), { now: () => 7 }); r = await hh['flow:open'](null, b); r = await hh['flow:open'](null, b); ok(r.skipped === true, 'ust uste hizli tiklama tek acilis sayilir');
  r = await h['flow:open'](null, c); ok(r.ok && ext.length === 1 && ext[0] === 'https://medal.tv/', 'web girisi https adresiyle acilir');
  for (const bad2 of ['../../etc/passwd', 'C:\\Windows\\system32\\cmd.exe', '', null, 123, 'aaaaaaaaaaaa', { id: a }]) { opened.length = 0; r = await h['flow:open'](null, bad2); ok(r.error === 'flow' && opened.length === 0, 'kayitsiz/sahte kimlik ACMAZ: ' + JSON.stringify(bad2)); }
  openErr = 'Erisim engellendi'; r = await h['flow:open'](null, b); ok(r.error === 'flow' && /Erisim/.test(r.message), 'isletim sistemi hatasi arayuze iletilir'); openErr = '';
  fs.unlinkSync(discord); r = await h['flow:list'](null); ok(r.apps[0].missing === true && r.apps[0].icon === null, 'silinen dosya "missing" olur'); opened.length = 0; r = await h['flow:open'](null, a); ok(r.error === 'flow' && r.missing === true && opened.length === 0, 'silinen dosya acilmaz');
  mkf('apps/Discord.exe');
  // yeniden adlandir / sirala / sil
  r = await h['flow:rename'](null, b, '  Steam   Oyun  '); ok(r.apps[1].name === 'Steam Oyun', 'yeniden adlandirma bosluk temizler');
  r = await h['flow:rename'](null, b, '   '); ok(r.error === 'flow', 'bos ad reddedilir');
  r = await h['flow:rename'](null, 'bbbbbbbbbbbb', 'x'); ok(r.error === 'flow', 'bilinmeyen kimlik reddedilir');
  r = await h['flow:order'](null, [c, a]); ok(r.apps.map((x) => x.id).join() === [c, a, b].join(), 'siralama: verilenler once, geri kalan sonda');
  r = await h['flow:order'](null, [c, c, 'sahte', b, a, a]); ok(r.apps.map((x) => x.id).join() === [c, b, a].join(), 'siralama: tekrar/sahte kimlik yok sayilir');
  r = await h['flow:order'](null, 'x'); ok(r.error === 'flow', 'siralama dizi olmali');
  r = await h['flow:remove'](null, b); ok(r.apps.length === 2 && !r.apps.some((x) => x.id === b), 'silme');
  r = await h['flow:remove'](null, b); ok(r.error === 'flow', 'ayni kaydi ikinci kez silme hatasi');
  // sinir
  const h3 = mk(path.join(tmp, 'd3')); for (let i = 0; i < flowModule.MAX_APPS; i++) r = await h3['flow:addWeb'](null, 'a' + i, 'https://s' + i + '.com/'); ok(r.apps && r.apps.length === flowModule.MAX_APPS, 'azami ' + flowModule.MAX_APPS + ' uygulama');
  r = await h3['flow:addWeb'](null, 'fazla', 'https://fazla.com/'); ok(r.error === 'flow' && /En fazla/.test(r.message), 'azami asilinca reddedilir');
  // ikon dogrulama
  const h4 = mk(path.join(tmp, 'd4'), { fileIcon: async () => 'javascript:alert(1)' }); next = steam; r = await h4['flow:add'](null); ok(r.apps[0].icon === null, 'data:image/png disi ikon reddedilir');
  const h5 = mk(path.join(tmp, 'd5'), { fileIcon: async () => { throw new Error('x'); } }); next = steam; r = await h5['flow:add'](null); ok(r.apps && r.apps[0].icon === null, 'ikon hatasi cokmez');
  // Baslat menusu onerileri
  const sm = path.join(tmp, 'startmenu'); mkf('startmenu/Programs/Discord Inc/Discord.lnk'); mkf('startmenu/Programs/Steam/Steam.lnk'); mkf('startmenu/Programs/Steam/Uninstall Steam.lnk'); mkf('startmenu/Programs/Medal.lnk'); mkf('startmenu/Programs/Rastgele Uygulama.lnk'); mkf('startmenu/Programs/League of Legends.lnk'); mkf('startmenu/Programs/Discord.txt');
  const h6 = mk(path.join(tmp, 'd6'), { startMenuDirs: [path.join(sm, 'Programs'), path.join(tmp, 'olmayan')] });
  r = await h6['flow:suggest'](null); const names = r.items.map((x) => x.name); ok(names.join() === ['Discord', 'League of Legends', 'Medal', 'Steam', 'Rastgele Uygulama'].join(), 'oneriler: tum Baslat menusu, tanidik adlar once, "Uninstall" yok -> ' + names.join('|'));
  ok(!JSON.stringify(r).includes(tmp) && r.items.every((x) => /^[0-9a-f]{10}$/.test(x.sid)), 'oneri yaniti yol icermez; yalniz sid');
  { const hl = mk(path.join(tmp, 'd6b'), { startMenuDirs: [path.join(sm, 'Programs')], readShortcut: (p) => (/Rastgele/.test(p) ? { target: path.join(tmp, 'apps/Rastgele/rast.exe') } : null) }); const rl = await hl['flow:suggest'](null); const rr = rl.items.find((x) => x.name === 'Rastgele Uygulama'); ok(rr && rr.location === path.join(tmp, 'apps/Rastgele') && rr.known === false, 'oneri: kisayol hedefinden kurulu klasor kendisi bulunur (location), tanidik degilse known=false'); }
  const d = r.items.find((x) => x.name === 'Discord'); r = await h6['flow:addSuggested'](null, d.sid); ok(r.apps && r.apps.length === 1 && r.apps[0].name === 'Discord', 'onerilen eklenir');
  r = await h6['flow:suggest'](null); ok(r.items.find((x) => x.name === 'Discord').already === true, 'eklenen oneride "already" isaretlenir');
  r = await h6['flow:addSuggested'](null, 'ffffffffff'); ok(r.error === 'flow', 'bilinmeyen sid reddedilir');
  r = await h6['flow:addSuggested'](null, '../../x'); ok(r.error === 'flow', 'bicimsiz sid reddedilir');
  const h7 = mk(path.join(tmp, 'd7'), { platform: 'linux' }); r = await h7['flow:suggest'](null); ok(r.items.length === 0 && r.windows === false, 'Windows disinda oneri bos');
  // ad temizligi
  ok(flowModule.cleanName('a\u0000b\n c') === 'a b c' && flowModule.cleanName('x'.repeat(100)).length === 40 && flowModule.cleanName(5) === null && flowModule.cleanName('  ') === null, 'cleanName: kontrol karakteri, uzunluk, tur');
  // erisim engeli sarmalayicisi: engelli kurulumda flow: da reddedilir
  const hb = createHost({ service: { closeAll() {} }, flow: { dataDir: path.join(tmp, 'd8'), platform: 'win32' }, access: { dataDir: path.join(tmp, 'acc'), publicKey: null } });
  ok(typeof hb.handlers['flow:open'] === 'function', 'erisim modulu varken flow: kanallari kayitli');
  // kaynak taramasi: FLOWMOD'da shell/exec/spawn/ag yok
  const src = fs.readFileSync(path.join(__dirname, '../../app/desktop/host.js'), 'utf8'); const a1 = src.indexOf('const FLOWMOD = (() => {'); const a2 = src.indexOf("/* --- Otomatik Guncelleyici (Kovan 'upd')"); const body = src.slice(a1, a2);
  ok(a1 > 0 && a2 > a1, 'FLOWMOD, GAMEMOD oncesinde (MEMMOD diliminin disinda)');
  ok(!/child_process|cp\.|spawn|exec\(|execFile|shell\s*:|require\('(https?|net|tls|dgram|dns)'\)|fetch\(|XMLHttpRequest|\bdeps\.(get|getBin|run)\b/.test(body.replace(/\/\*[\s\S]*?\*\//g, '')), 'FLOWMOD: komut calistirma/ag kodu YOK (yalniz openPath/openExternal enjekte)');
  console.log(bad ? '\n' + bad + ' BASARISIZ' : '\nHepsi gecti'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
