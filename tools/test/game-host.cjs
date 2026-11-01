'use strict';
// Oyun Ayarlayici host testi (GAMEMOD). Calistir: node tools/test/game-host.cjs
// Sahte Steam/Epic/Riot kutuphanesi, sahte surec listesi ve sahte PresentMon (node betigi) ile calisir; gercek oyuna/Windows'a dokunmaz.
const path = require('path'); const fs = require('fs'); const os = require('os');
const { gameModule: G } = require(path.join(__dirname, '../../app/desktop/host.js'));
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };

(async () => {
  // ---------- saf fonksiyonlar ----------
  const v = G.parseVdf('"libraryfolders"\n{\n\t"0"\n\t{\n\t\t"path"\t\t"D:\\\\SteamLibrary"\n\t\t"apps" { "1": "2" }\n\t}\n}\n');
  ok(v.libraryfolders['0'].path === 'D:\\SteamLibrary', 'vdf: kaçışlı yol okunur');
  ok(Object.getPrototypeOf(G.parseVdf('"__proto__" { "x" "1" }')) === null, 'vdf: prototip kirliliği yok (null prototip)');

  const ac = (t, n) => G.detectAntiCheat(t, n).map((x) => x.name);
  ok(ac('Rocket League', []).includes('Easy Anti-Cheat'), 'anti-cheat: Rocket League adı');
  ok(ac('VALORANT', []).includes('Riot Vanguard') && ac('League of Legends', []).includes('Riot Vanguard'), 'anti-cheat: Valorant ve LoL');
  ok(ac('Some Game', ['EasyAntiCheat', 'Game.exe']).includes('Easy Anti-Cheat'), 'anti-cheat: EasyAntiCheat klasörü');
  ok(ac('Some Game', ['BEService_x64.exe']).includes('BattlEye') && ac('X', ['xigncode']).includes('XIGNCODE3'), 'anti-cheat: BattlEye / XIGNCODE dosyaları');
  ok(ac('Resident Evil Requiem', ['config.ini', 're_chunk_000.pak', 'REQUIEM.exe']).length === 0, 'anti-cheat: Resident Evil (temiz klasör) engellenmez');
  ok(ac('Cities: Skylines', ['config.ini']).length === 0 && ac('Rusty Lake', []).length === 0, 'anti-cheat: sahte pozitif yok (“Rust” adı yalnız tam eşleşir)');

  // INI
  const raw = '\ufeff[Graphics]\r\nShadowQuality = 2 ; gölge\r\nTexture=3\r\n# yorum\r\nResolution=1920x1080\r\n[Misc]\r\nShadowQuality=9\r\nShadowQuality=10\r\nFOV=90\r\n';
  const p = G.iniParse(raw);
  ok(p.bom && p.eol === '\r\n' && p.entries.length === 6, 'ini: BOM + CRLF korunur, ' + p.entries.length + ' anahtar');
  ok(p.byId.has('Graphics/ShadowQuality') && p.byId.has('Misc/ShadowQuality') && p.byId.has('Misc/ShadowQuality#2'), 'ini: bölüm + tekrar eden anahtar kimlikleri');
  const out = G.iniApply(p, new Map([['Graphics/Texture', '1'], ['Misc/ShadowQuality#2', '4'], ['Graphics/Yok', '5'], ['Misc/FOV', '90']]));
  ok(out.applied.length === 2 && out.missing.length === 1 && out.missing[0] === 'Graphics/Yok', 'ini: yalnızca VAR olan ve değişen anahtarlar yazılır; olmayan eklenmez');
  ok(out.text.startsWith('\ufeff[Graphics]\r\n') && /Texture=1\r\n/.test(out.text) && /ShadowQuality = 2 ; gölge/.test(out.text) && /# yorum/.test(out.text), 'ini: yorumlar, boşluklar, BOM ve CRLF bozulmadı');
  ok(!/Yok/.test(out.text), 'ini: olmayan anahtar dosyaya eklenmedi');

  // cozunurluk
  let res = G.findResolution(G.iniParse('[A]\nResolution=1920x1080\n'));
  ok(res.length === 1 && res[0].kind === 'combined' && res[0].w === 1920 && res[0].h === 1080, 'çözünürlük: birleşik anahtar (1920x1080)');
  const ue = G.iniParse('[/Script/Engine.GameUserSettings]\nResolutionSizeX=2560\nResolutionSizeY=1440\nLastUserConfirmedResolutionSizeX=2560\nLastUserConfirmedResolutionSizeY=1440\nFOV=90\n');
  const r2 = G.findResolution(ue); ok(r2.length === 2 && r2.every((d) => d.kind === 'pair'), 'çözünürlük: UE tarzı X/Y çiftleri (2 çift)');
  const ch = G.resChanges(r2, 1600, 900); const o2 = G.iniApply(ue, ch); ok(/ResolutionSizeX=1600/.test(o2.text) && /ResolutionSizeY=900/.test(o2.text) && /LastUserConfirmedResolutionSizeX=1600/.test(o2.text) && /FOV=90/.test(o2.text), 'çözünürlük: çiftler birlikte yazılır, diğer anahtarlara dokunulmaz');
  const comb = G.iniParse('[A]\nResolution = 1920 x 1080\n'); const o3 = G.iniApply(comb, new Map([[G.findResolution(comb)[0].id, G.resChanges(G.findResolution(comb), 1280, 720).get('A/Resolution').fn('1920 x 1080')]])); ok(/Resolution = 1280 x 720/.test(o3.text), 'çözünürlük: ayraç biçimi korunur ("1280 x 720")');
  ok(G.findResolution(G.iniParse('[A]\nWidth=5\nHeight=7\n')).length === 0, 'çözünürlük: anlamsız küçük değerler çözünürlük sayılmaz');
  const lad = G.resLadder(1920, 1080); ok(lad[0].w === 1920 && lad[1].w === 1600 && lad[2].w === 1280 && lad.length === 4, 'merdiven: 1920x1080 → 1600x900 → 1280x720 → 960x540');
  ok(G.resLadder(3440, 1440)[0].w === 3440 && G.resLadder(3440, 1440).length === 4, 'merdiven: ultra geniş için oransal basamaklar');

  // ogrenen profil
  const snap = (o) => o;
  const L = G.deriveLearned({ low: snap({ 'G/Shadow': '0', 'G/Tex': '0', 'G/Res': '1280x720', 'G/LastPlayed': '111', 'G/Same': 'a', 'G/FOV': '80' }), ultra: snap({ 'G/Shadow': '3', 'G/Tex': '4', 'G/Res': '1920x1080', 'G/LastPlayed': '222', 'G/Same': 'a', 'G/FOV': '95' }) });
  ok(L.presets.join() === 'low,ultra' && L.keys.map((k) => k.id).sort().join() === 'G/Shadow,G/Tex', 'öğrenme: yalnız kalite anahtarları (Shadow, Tex)');
  ok(L.skipped.some((s) => s.id === 'G/Res') && L.skipped.some((s) => s.id === 'G/LastPlayed') && L.skipped.some((s) => s.id === 'G/FOV') && !L.keys.some((k) => k.id === 'G/Same'), 'öğrenme: çözünürlük/zaman damgası/FOV atlanır, değişmeyen anahtar yok');
  ok(G.deriveLearned({ low: { 'a/b': '1' } }).keys.length === 0, 'öğrenme: tek snapshot ile öğrenilmez');

  // hedef FPS karari
  const T = (o) => G.tuneStep(Object.assign({ preset: 'high', resIdx: 0, avg: 60, p1: 50, target: 60, allowRes: false, available: G.PRESETS, ladderLen: 4, hist: [] }, o));
  ok(T({ avg: 42, p1: 30 }).action === 'down' && T({ avg: 42, p1: 30 }).preset === 'medium', 'karar: hedefin altı → bir ön ayar düşür');
  ok(T({ avg: 62, p1: 55 }).action === 'done', 'karar: hedefe uygun → bitti');
  ok(T({ avg: 120, p1: 100 }).action === 'up' && T({ avg: 120, p1: 100 }).preset === 'ultra', 'karar: hedefin çok üstü → bir ön ayar yükselt');
  ok(T({ preset: 'low', avg: 30, p1: 20, allowRes: true }).action === 'res-down' && T({ preset: 'low', avg: 30, p1: 20, allowRes: true }).resIdx === 1, 'karar: en düşük ön ayarda çözünürlük düşürülür (izin varsa)');
  ok(T({ preset: 'low', avg: 30, p1: 20, allowRes: false }).action === 'floor', 'karar: izin yoksa en düşükte “donanım sınırı”');
  ok(T({ preset: 'high', avg: 130, p1: 100, hist: [{ preset: 'ultra', resIdx: 0, avg: 40 }] }).action === 'done', 'karar: daha yüksek ön ayar daha önce hedefin altında kaldıysa SALINIM yok (done)');
  ok(T({ avg: 65, p1: 18 }).action === 'down', 'karar: ortalama iyi ama %1 düşük çok kötü (takılma) → düşürür');
  ok(T({ preset: 'medium', resIdx: 2, avg: 140, p1: 120, allowRes: true }).action === 'res-up', 'karar: önce çözünürlük geri yükseltilir');
  ok(T({ available: ['low', 'ultra'], preset: 'ultra', avg: 40, p1: 30 }).preset === 'low', 'karar: yalnız kaydedilmiş ön ayarlar arasında geçer');

  // donanim tahmini
  ok(G.gpuPerf('NVIDIA GeForce RTX 4060') === 100 && G.gpuPerf('NVIDIA GeForce RTX 4060 Ti') === 125 && G.gpuPerf('AMD Radeon RX 7800 XT') === 200, 'gpu: RTX 4060 / 4060 Ti / RX 7800 XT tanınır');
  ok(G.gpuPerf('NVIDIA GeForce RTX 4060 Laptop GPU') === 75 && G.gpuPerf('Microsoft Basic Display Adapter') === null && G.gpuPerf('Mystery GPU 9000') === null, 'gpu: dizüstü düşer, sanal/bilinmeyen null');
  ok(G.estimatePreset({ gpu: 'x', gpuPerf: 100, cores: 8, ramGB: 16 }, 60, 1920, 1080).preset === 'high', 'tahmin: RTX 4060 sınıfı 1080p60 → Yüksek');
  ok(G.estimatePreset({ gpu: 'x', gpuPerf: 100, cores: 8, ramGB: 16 }, 60, 2560, 1440).preset === 'medium', 'tahmin: aynı kart 1440p60 → Orta');
  ok(G.estimatePreset({ gpu: 'x', gpuPerf: 42, cores: 8, ramGB: 16 }, 60, 1920, 1080).preset === 'low', 'tahmin: GTX 1650 sınıfı → Düşük');
  ok(G.estimatePreset({ gpu: 'x', gpuPerf: 400, cores: 4, ramGB: 32 }, 144, 1920, 1080).preset === 'high', 'tahmin: güçlü kart + az çekirdek + 144 FPS → Yüksek ile sınırlı');
  const unk = G.estimatePreset({ gpu: '', gpuPerf: null }, 60, 1920, 1080); ok(unk.preset === 'medium' && unk.confident === false, 'tahmin: kart tanınmazsa dürüstçe “emin değil” + Orta');

  // PresentMon CSV
  const fp = new G.FrameParser(); fp.feed('Application,ProcessID,FrameTime,CPUBusy\r\ngame.exe,1,16.7,5\r\ngame.exe,1,16.'); fp.feed('7,5\ngame.exe,1,33.4,5\n'); fp.end();
  ok(fp.ms.length === 3 && Math.abs(fp.ms[2] - 33.4) < 1e-9, 'csv: parça parça gelen akış ve CRLF doğru okunur');
  const f1 = new G.FrameParser(); f1.feed('Application,MsBetweenPresents\ng.exe,10\ng.exe,10\n'); ok(f1.ms.length === 2, 'csv: 1.x MsBetweenPresents sütunu da okunur');
  const f2 = new G.FrameParser(); f2.feed('foo,bar\n1,2\n'); ok(f2.ms.length === 0 && !f2.headerSeen, 'csv: tanınmayan başlıkla veri uydurulmaz');
  const st = G.frameStats([...Array(990).fill(10), ...Array(10).fill(50)]); ok(Math.abs(st.avg - 1000 / ((990 * 10 + 500) / 1000)) < 0.01 && st.p1 <= 25 && st.stutters === 10 && st.frames === 1000, 'istatistik: ort FPS, %1 düşük, takılma sayısı (' + st.avg.toFixed(1) + '/' + st.p1.toFixed(1) + ')');

  // ---------- host akisi (sahte kutuphane) ----------
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-game-')); const W = (p, t) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, t); };
  const steam = path.join(tmp, 'Steam'); const lib2 = path.join(tmp, 'SteamLib2'); const data = path.join(tmp, 'data'); const epicM = path.join(tmp, 'epic'); const riot = path.join(tmp, 'Riot Games'); const docs = path.join(tmp, 'Docs'); const local = path.join(tmp, 'Local');
  W(path.join(steam, 'steamapps', 'libraryfolders.vdf'), '"libraryfolders"\n{\n "0" { "path" "' + steam.replace(/\\/g, '\\\\') + '" }\n "1" { "path" "' + lib2.replace(/\\/g, '\\\\') + '" }\n}\n');
  const acf = (id, name, dir) => '"AppState"\n{\n "appid" "' + id + '"\n "name" "' + name + '"\n "installdir" "' + dir + '"\n}\n';
  W(path.join(steam, 'steamapps', 'appmanifest_9001.acf'), acf(9001, 'Resident Evil Requiem', 'Resident Evil Requiem'));
  const reDir = path.join(steam, 'steamapps', 'common', 'Resident Evil Requiem'); const CFG0 = '[Setting]\r\nShadowQuality=2\r\nTextureQuality=2\r\nResolution=1920x1080\r\nLastPlayed=100\r\nFOV=90\r\n';
  W(path.join(reDir, 'config.ini'), CFG0); W(path.join(reDir, 'REQUIEM.exe'), 'x'); fs.mkdirSync(path.join(steam, 'steamapps', 'common', 'Rocket League', 'EasyAntiCheat'), { recursive: true }); W(path.join(steam, 'steamapps', 'appmanifest_252950.acf'), acf(252950, 'Rocket League', 'Rocket League')); W(path.join(steam, 'steamapps', 'common', 'Rocket League', 'config.ini'), '[A]\nX=1\n');
  W(path.join(lib2, 'steamapps', 'appmanifest_77.acf'), acf(77, 'Cozy Farm', 'Cozy Farm')); W(path.join(lib2, 'steamapps', 'common', 'Cozy Farm', 'settings.ini'), '[V]\nQuality=1\n'); W(path.join(lib2, 'steamapps', 'appmanifest_5.acf'), acf(5, 'Steamworks Common Redistributables', 'Steamworks Shared')); fs.mkdirSync(path.join(lib2, 'steamapps', 'common', 'Steamworks Shared'), { recursive: true });
  const epicGame = path.join(tmp, 'Epic Games', 'ShooterX'); fs.mkdirSync(path.join(epicGame, 'BattlEye'), { recursive: true }); W(path.join(epicM, 'a.item'), JSON.stringify({ DisplayName: 'ShooterX', InstallLocation: epicGame, AppName: 'abc123', LaunchExecutable: 'bin\\ShooterX.exe', AppCategories: ['public', 'games'] }));
  const epicOk = path.join(tmp, 'Epic Games', 'Indie Fun'); W(path.join(epicOk, 'GameUserSettings.ini'), '[S]\nQ=1\n'); W(path.join(epicM, 'b.item'), JSON.stringify({ DisplayName: 'Indie Fun', InstallLocation: epicOk, AppName: 'idx9', AppCategories: ['public', 'games'] })); W(path.join(epicM, 'c.item'), JSON.stringify({ DisplayName: 'Indie Fun DLC', InstallLocation: epicOk, AppName: 'dlc1', MainGameAppName: 'idx9' })); W(path.join(epicM, 'd.item'), '{bozuk json');
  fs.mkdirSync(path.join(riot, 'VALORANT'), { recursive: true }); fs.mkdirSync(path.join(riot, 'Riot Client'), { recursive: true });

  let procs = []; let confirms = []; let confirmAns = true; let t = 1e9; const dialogs = { cfg: null, pm: null };
  const mk = (extra) => G.createGameHost(Object.assign({ platform: 'win32', dataDir: data, steamRoots: [steam], epicManifestDir: epicM, riotRoots: [riot], docsDir: docs, localAppData: local, listProcs: async () => procs, now: () => t, confirm: async (o) => { confirms.push(o); return confirmAns; }, chooseConfig: async () => dialogs.cfg, choosePm: async () => dialogs.pm, pmDirs: [], run: async () => '' }, extra || {}));
  let h = mk(); const H = h.handlers;
  const sc = await H['game:scan'](null, true);
  const by = (n) => sc.games.find((g) => g.name === n);
  ok(sc.games.length === 6, 'tarama: 6 oyun (Steam 3 + Epic 2 [DLC/bozuk/redist atlandı] + Riot 1 = ' + sc.games.length + ')');
  ok(by('Resident Evil Requiem') && !by('Resident Evil Requiem').blocked && by('Resident Evil Requiem').reEngine, 'tarama: Resident Evil Requiem bulundu, engelli DEĞİL, RE Engine ipucu var');
  ok(by('Rocket League').blocked && by('Rocket League').anticheat[0].name === 'Easy Anti-Cheat', 'tarama: Rocket League engelli (EAC)');
  ok(by('ShooterX').blocked && by('ShooterX').anticheat.some((a) => a.name === 'BattlEye'), 'tarama: Epic’teki ShooterX engelli (BattlEye klasörü)');
  ok(by('VALORANT').blocked && !sc.games.some((g) => g.name === 'Riot Client'), 'tarama: VALORANT engelli, Riot Client oyun sayılmaz');
  ok(by('Cozy Farm') && !by('Cozy Farm').blocked && !sc.games.some((g) => /Steamworks|DLC/.test(g.name)), 'tarama: 2. Steam kütüphanesi okunur; Steamworks/DLC elenir');
  const reId = by('Resident Evil Requiem').id; const rlId = by('Rocket League').id; const cozyId = by('Cozy Farm').id; const valId = by('VALORANT').id;

  // calisan oyun
  procs = [{ pid: 11, name: 'explorer.exe', path: 'C:\\Windows\\explorer.exe' }, { pid: 22, name: 'REQUIEM.exe', path: path.join(reDir, 'REQUIEM.exe') }, { pid: 23, name: 'CrashHandler.exe', path: path.join(reDir, 'CrashHandler.exe') }, { pid: 33, name: 'RocketLeague.exe', path: 'C:\\elsewhere\\RocketLeague.exe' }];
  let rn = await H['game:running'](); ok(rn.running.length === 2, 'çalışan: 2 kayıt (RE + RocketLeague.exe süreç adından) — CrashHandler elendi');
  ok(rn.running.find((x) => x.name === 'Resident Evil Requiem' && !x.blocked && x.exe === 'REQUIEM.exe'), 'çalışan: RE oyunu yol eşleşmesiyle otomatik algılandı');
  ok(rn.running.find((x) => x.blocked && x.anticheat[0].name === 'Easy Anti-Cheat' && x.gameId === null), 'çalışan: kütüphane dışı RocketLeague.exe anti-cheat’li olarak işaretlendi');

  // ayar dosyasi
  let cf = await H['game:config'](null, reId); ok(cf.candidates.length === 1 && /config\.ini$/.test(cf.candidates[0].path), 'ayar: RE klasöründeki config.ini aday olarak bulundu');
  ok((await H['game:snap'](null, reId, 'low')).error, 'snapshot: ayar dosyası seçilmeden reddedilir');
  const bl = await H['game:chooseConfig'](null, rlId); ok(bl.error && bl.code === 'anticheat', 'engel: anti-cheat’li oyun için ayar dosyası seçilemez');
  const bl2 = await H['game:useConfig'](null, rlId, 0); ok(bl2.error && bl2.code === 'anticheat', 'engel: anti-cheat’li oyun için aday kullanılamaz');
  ok((await H['game:apply'](null, rlId, { preset: 'low' })).code === 'anticheat' && (await H['game:snap'](null, rlId, 'low')).code === 'anticheat' && (await H['game:plan'](null, rlId, { preset: 'low' })).code === 'anticheat', 'engel: apply / snap / plan hepsi anti-cheat’li oyunda reddedilir');
  ok((await H['game:apply'](null, valId, { preset: 'low' })).code === 'anticheat', 'engel: VALORANT (Riot) reddedilir');
  ok((await H['game:snap'](null, '../../etc:passwd', 'low')).error && (await H['game:config'](null, 'steam:__proto__')).error, 'doğrulama: bozuk/olmayan oyun kimliği reddedilir');
  ok((await H['game:useConfig'](null, reId, 0)).ok, 'ayar: aday seçildi');
  ok((await H['game:snap'](null, reId, 'bogus')).error, 'snapshot: geçersiz ön ayar reddedilir');

  // dosya yolunu arayuz gonderemez; dialogdan gelen kotu yol
  dialogs.cfg = 'relative/x.ini'; ok((await H['game:chooseConfig'](null, cozyId)).error, 'diyalog: göreli yol reddedilir'); dialogs.cfg = path.join(tmp, 'x.exe'); ok((await H['game:chooseConfig'](null, cozyId)).error, 'diyalog: .exe reddedilir'); dialogs.cfg = null; ok((await H['game:chooseConfig'](null, cozyId)).canceled === true, 'diyalog: iptal');

  // ogrenme + plan + uygulama
  // oyun calisirken apply reddedilir (once snapshot'lari alalim: dosya aninda degisiyor)
  const cfgPath = path.join(reDir, 'config.ini'); const setCfg = (shadow, tex, res) => fs.writeFileSync(cfgPath, '[Setting]\r\nShadowQuality=' + shadow + '\r\nTextureQuality=' + tex + '\r\nResolution=' + res + '\r\nLastPlayed=' + (Math.random() * 1e6 | 0) + '\r\nFOV=90\r\n');
  setCfg(0, 0, '1920x1080'); ok((await H['game:snap'](null, reId, 'low')).ok, 'snapshot: Düşük kaydedildi'); setCfg(3, 4, '1920x1080'); const s2 = await H['game:snap'](null, reId, 'ultra'); ok(s2.ok && s2.keys === 2 && s2.skipped >= 1, 'snapshot: Ultra kaydedildi → 2 kalite anahtarı öğrenildi (' + s2.keys + '), gürültü atlandı');
  let pl = await H['game:plan'](null, reId, { preset: 'medium' }); ok(pl.notes.length && /Orta/.test(pl.notes[0]) && pl.total === 0, 'plan: kaydedilmemiş ön ayar için dürüst uyarı, değişiklik yok');
  setCfg(2, 2, '1920x1080'); const before = fs.readFileSync(cfgPath, 'utf8');
  pl = await H['game:plan'](null, reId, { preset: 'low', resolution: { w: 1280, h: 720 } }); ok(pl.total === 3 && pl.changes.some((c) => c.key === 'ShadowQuality' && c.from === '2' && c.to === '0') && pl.changes.some((c) => c.key === 'Resolution' && c.to === '1280x720'), 'plan: 3 değişiklik önizlenir (Shadow, Texture, Resolution)');
  ok(fs.readFileSync(cfgPath, 'utf8') === before, 'plan: dosyaya HİÇ yazmaz');
  let ap = await H['game:apply'](null, reId, { preset: 'low' }); ok(ap.code === 'running', 'uygula: oyun çalışırken reddedilir');
  procs = [];  t += 5000;
  confirmAns = false; ap = await H['game:apply'](null, reId, { preset: 'low', resolution: { w: 1280, h: 720 } }); ok(ap.error === 'declined' && fs.readFileSync(cfgPath, 'utf8') === before && !fs.existsSync(path.join(data, 'oyunayar-yedek', reId.replace(/[^\w.\-]/g, '_'), 'index.json')), 'uygula: onay verilmezse hiçbir şey değişmez, yedek de oluşmaz');
  confirmAns = true; confirms = []; ap = await H['game:apply'](null, reId, { preset: 'low', resolution: { w: 1280, h: 720 } });
  const after = fs.readFileSync(cfgPath, 'utf8'); ok(ap.ok && ap.applied === 3 && ap.verified === 3 && ap.firstBackup === true, 'uygula: 3 satır yazıldı, okuyup doğrulandı, ilk (orijinal) yedek alındı');
  ok(/ShadowQuality=0\r\n/.test(after) && /TextureQuality=0\r\n/.test(after) && /Resolution=1280x720\r\n/.test(after) && /FOV=90\r\n/.test(after) && /LastPlayed=\d+\r\n/.test(after), 'uygula: değerler yazıldı, FOV/LastPlayed ve CRLF korundu');
  ok(confirms.length === 1 && /ShadowQuality: 2 → 0/.test(confirms[0].message) && /yedeğ/i.test(confirms[0].message), 'uygula: onay penceresi değişiklikleri ve yedek bilgisini gösterdi');
  const bdir = path.join(data, 'oyunayar-yedek', reId.replace(/[^\w.\-]/g, '_')); const bidx = JSON.parse(fs.readFileSync(path.join(bdir, 'index.json'), 'utf8')); ok(bidx.length === 1 && bidx[0].orig && fs.readFileSync(path.join(bdir, bidx[0].file), 'utf8') === before, 'yedek: orijinal dosya birebir saklandı');
  ok(!fs.readdirSync(reDir).some((f) => /kovan-tmp/.test(f)), 'yazma: geçici dosya kalmadı (atomik)');
  ap = await H['game:apply'](null, reId, { preset: 'low', resolution: { w: 1280, h: 720 } }); ok(ap.nothing === true, 'uygula: değer zaten aynıysa “değişiklik yok” (gereksiz yedek/yazma yok)');
  t += 10; ap = await H['game:apply'](null, reId, { preset: 'ultra' }); ok(ap.ok && ap.firstBackup === false, 'uygula: ikinci uygulama yeni bir yedek ekler (orijinal ezilmez)');
  const bidx2 = JSON.parse(fs.readFileSync(path.join(bdir, 'index.json'), 'utf8')); ok(bidx2.length === 2 && bidx2.filter((x) => x.orig).length === 1, 'yedek: 2 kayıt, tek orijinal');
  ok((await H['game:apply'](null, reId, { preset: 'turbo' })).error && (await H['game:apply'](null, reId, { resolution: { w: 10, h: 10 } })).error && (await H['game:apply'](null, reId, {})).error, 'doğrulama: geçersiz ön ayar / çözünürlük / boş istek reddedilir');
  const ro = await H['game:restore'](null, reId, 'orig'); ok(ro.ok && fs.readFileSync(cfgPath, 'utf8') === before, 'geri yükleme: ORİJİNAL dosya birebir geri geldi');
  const bidx3 = JSON.parse(fs.readFileSync(path.join(bdir, 'index.json'), 'utf8')); ok(bidx3.length >= 3, 'geri yükleme: önce mevcut hâl de yedeklendi');

  // otomatik tahmin
  const hw = await H['game:estimate'](null, 60, 1920, 1080); ok(hw.preset && Array.isArray(hw.reasons) && hw.ladder.length === 4, 'tahmin: handler çalışır (kart yoksa dürüst varsayılan: ' + hw.preset + ')');
  ok((await H['game:estimate'](null, 5, 1920, 1080)).error && (await H['game:estimate'](null, 60, 10, 10)).error, 'tahmin: geçersiz girişler reddedilir');
  ok((await H['game:target'](null, reId, 90, true)).target === 90 && (await H['game:target'](null, reId, 999)).error, 'hedef FPS: 20–360 aralığı doğrulanır');

  // PresentMon + olcum (sahte betik)
  const fake = path.join(tmp, 'PresentMon-fake'); const body = (mode) => '#!/usr/bin/env node\nconst a = process.argv.slice(2);\nif (a.includes("--help")) { console.log("PresentMon fake help"); process.exit(0); }\n' + mode;
  fs.writeFileSync(fake, body('const proc = a[a.indexOf("--process_name") + 1]; if (proc !== "REQUIEM.exe") { console.error("wrong process " + proc); process.exit(2); }\nconsole.log("Application,ProcessID,FrameTime"); for (let i = 0; i < 600; i++) console.log("REQUIEM.exe,22," + (i % 100 === 0 ? 40 : 16.0));\n')); fs.chmodSync(fake, 0o755);
  h = mk({ pmDirs: [] }); const H2 = h.handlers; await H2['game:scan'](null, true);
  let pm = await H2['game:pm'](null, true); ok(pm.found === false && pm.help.length >= 3, 'PresentMon: yoksa bulunamadı + kurulum yönergesi');
  procs = [{ pid: 22, name: 'REQUIEM.exe', path: path.join(reDir, 'REQUIEM.exe') }];
  let ms = await H2['game:measure:start'](null, { seconds: 10 }); ok(ms.needPm === true, 'ölçüm: PresentMon yokken net hata');
  dialogs.pm = path.join(tmp, 'notpm.txt'); W(dialogs.pm, 'hi'); ok((await H2['game:choosePm']()).error, 'PresentMon: yanlış dosya doğrulanamaz');
  dialogs.pm = fake; const cp1 = await H2['game:choosePm'](); ok(cp1.ok, 'PresentMon: kullanıcının seçtiği dosya --help çıktısıyla doğrulandı');
  const waitJob = async (hh, id) => { for (let i = 0; i < 80; i++) { const j = await hh['game:measure:job'](null, id); if (j.state !== 'running') return j; await new Promise((r) => setTimeout(r, 100)); } return null; };
  // RE icin hedef/uygulanan durum ayarla: kayit + uygula (yedek akisi yeniden)
  await H2['game:useConfig'](null, reId, 0); setCfg(0, 0, '1920x1080'); await H2['game:snap'](null, reId, 'low'); setCfg(3, 4, '1920x1080'); await H2['game:snap'](null, reId, 'ultra'); procs = [];
  t += 10000; await H2['game:target'](null, reId, 60, false); const a2 = await H2['game:apply'](null, reId, { preset: 'ultra' }); ok(a2.ok, 'ölçüm hazırlığı: Ultra uygulandı');
  procs = [{ pid: 22, name: 'REQUIEM.exe', path: path.join(reDir, 'REQUIEM.exe') }]; t += 5000;
  ms = await H2['game:measure:start'](null, { seconds: 10 }); ok(ms.id && ms.exe === 'REQUIEM.exe' && ms.seconds === 10, 'ölçüm: çalışan oyun otomatik hedeflendi (' + ms.exe + ')');
  ok((await H2['game:measure:start'](null, { seconds: 10 })).error, 'ölçüm: eşzamanlı ikinci ölçüm reddedilir');
  const j = await waitJob(H2, ms.id); ok(j && j.state === 'done' && j.result.stats.frames === 600, 'ölçüm: sahte PresentMon çıktısı 600 kare okundu (' + (j && j.state) + ')');
  ok(j.result.stats.avg > 55 && j.result.stats.avg < 62 && j.result.stats.p1 < 30, 'ölçüm: ort FPS ~' + j.result.stats.avg.toFixed(1) + ', %1 düşük ~' + j.result.stats.p1.toFixed(1));
  ok(j.result.advice && j.result.advice.action === 'down' && j.result.advice.preset === 'low', 'tavsiye: takılma nedeniyle “Ultra → Düşük” (kayıtlı ön ayarlar arasında) önerildi: ' + (j.result.advice && j.result.advice.reason));
  ok(h.handlers['game:measure:job'] && (await H2['game:measure:job'](null, '999')).error, 'ölçüm: olmayan iş kimliği hata verir');
  // anti-cheat'li surec olcumu
  procs = [{ pid: 33, name: 'RocketLeague.exe', path: 'C:\\elsewhere\\RocketLeague.exe' }]; t += 5000; const mb = await H2['game:measure:start'](null, { seconds: 10 }); ok(mb.error && /anti-cheat/i.test(mb.message), 'ölçüm: anti-cheat’li oyunda ölçüm yapılmaz');
  procs = []; t += 5000; ok(/çalışan bir oyun bulunamadı/.test((await H2['game:measure:start'](null, { seconds: 10 })).message), 'ölçüm: oyun yoksa net mesaj');
  // yetki hatasi
  fs.writeFileSync(fake, body('console.error("Access denied: requires administrator privileges"); process.exit(1);\n')); procs = [{ pid: 22, name: 'REQUIEM.exe', path: path.join(reDir, 'REQUIEM.exe') }]; t += 5000; const m3 = await H2['game:measure:start'](null, { seconds: 10 }); const j3 = await waitJob(H2, m3.id); ok(j3.state === 'failed' && /yönetici|Performance Log/i.test(j3.error), 'ölçüm: yetki hatası anlaşılır Türkçe mesajla bildirilir');
  // az kare
  fs.writeFileSync(fake, body('console.log("Application,FrameTime"); for (let i = 0; i < 30; i++) console.log("x,16");\n')); t += 5000; const m4 = await H2['game:measure:start'](null, { seconds: 10 }); const j4 = await waitJob(H2, m4.id); ok(j4.state === 'failed' && /Yetersiz örnek/.test(j4.error), 'ölçüm: 30 kare “yetersiz örnek” sayılır (sonuç uydurulmaz)');
  // iptal
  fs.writeFileSync(fake, body('console.log("Application,FrameTime"); setInterval(() => console.log("x,16"), 20);\n')); t += 5000; const m5 = await H2['game:measure:start'](null, { seconds: 10 }); await new Promise((r) => setTimeout(r, 300)); await H2['game:measure:cancel'](null, m5.id); const j5 = await waitJob(H2, m5.id); ok(j5.state === 'canceled', 'ölçüm: iptal edilebilir');

  // kalicilik: yeni host ayni durumu okur
  const h3 = mk(); const c3 = await h3.handlers['game:config'](null, reId); ok(c3.config === cfgPath && c3.learned.presets.join() === 'low,ultra' && c3.backups.length >= 2, 'kalıcılık: yeniden başlatınca yapılandırma, öğrenilen ön ayarlar ve yedek listesi korunur');
  ok((await h3.handlers['game:snapClear'](null, reId, 'all')).ok && (await h3.handlers['game:config'](null, reId)).learned.presets.length === 0, 'öğrenilenleri temizle çalışır');
  // salt okunur / utf16 korumasi
  const ucfg = path.join(tmp, 'u16.ini'); fs.writeFileSync(ucfg, Buffer.from('\ufeff[A]\nB=1\n', 'utf16le')); dialogs.cfg = ucfg; ok(/UTF-16|ikili/.test((await h3.handlers['game:chooseConfig'](null, cozyId)).message || ''), 'koruma: UTF-16/ikili dosya reddedilir (bozmamak için)');
  // ---------- otomatik ayar dosyasi bulma (tum oyunlar) ----------
  {
    const t2 = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-detect-')); const st2 = path.join(t2, 'Steam'); const docs2 = path.join(t2, 'Docs'); const loc2 = path.join(t2, 'Local'); const data2 = path.join(t2, 'data');
    const acf2 = (id, n) => '"AppState"\n{\n "appid" "' + id + '"\n "name" "' + n + '"\n "installdir" "' + n + '"\n}\n'; const com = (n) => path.join(st2, 'steamapps', 'common', n);
    W(path.join(st2, 'steamapps', 'libraryfolders.vdf'), '"libraryfolders" { "0" { "path" "' + st2.replace(/\\/g, '\\\\') + '" } }');
    for (const [id, n] of [[10, 'Hollow Realms'], [11, 'Pixel Tavern'], [555, 'Mystery Kart'], [13, 'Lonely Game'], [14, 'Twin Config'], [15, 'Shooter Zero'], [16, 'Stranger Things']]) { W(path.join(st2, 'steamapps', 'appmanifest_' + id + '.acf'), acf2(id, n)); fs.mkdirSync(com(n), { recursive: true }); }
    fs.mkdirSync(path.join(com('Shooter Zero'), 'EasyAntiCheat'), { recursive: true });
    // A) Unreal: proje klasoru HollowProj, ayar LocalAppData\HollowProj\Saved\Config\Windows\ icinde (oyun adiyla ESLESMEZ)
    fs.mkdirSync(path.join(com('Hollow Realms'), 'HollowProj', 'Binaries', 'Win64'), { recursive: true }); fs.mkdirSync(path.join(com('Hollow Realms'), 'HollowProj', 'Content'), { recursive: true });
    const ueFile = path.join(loc2, 'HollowProj', 'Saved', 'Config', 'Windows', 'GameUserSettings.ini'); const ueTxt = '[ScalabilityGroups]\nsg.ResolutionQuality=100.000000\nsg.ViewDistanceQuality=3\nsg.AntiAliasingQuality=3\nsg.ShadowQuality=3\nsg.PostProcessQuality=3\nsg.TextureQuality=3\nsg.EffectsQuality=3\n\n[/Script/Engine.GameUserSettings]\nResolutionSizeX=2560\nResolutionSizeY=1440\nFullscreenMode=1\n'; W(ueFile, ueTxt);
    // B) Documents\My Games\<oyun adi>
    const myg = path.join(docs2, 'My Games', 'Pixel Tavern', 'settings.ini'); W(myg, '[Video]\nQuality=2\nShadowQuality=1\nTextureQuality=1\nResolution=1920x1080\n');
    // C) Steam bulut: userdata\<id>\<appid>\remote\graphics.cfg
    const cloud = path.join(st2, 'userdata', '777', '555', 'remote', 'graphics.cfg'); W(cloud, '[G]\nShadowQuality=2\nTextureQuality=2\nAntiAliasing=1\nVSync=1\n');
    // E) iki esit aday: belirsiz
    W(path.join(com('Twin Config'), 'config.ini'), '[A]\nShadowQuality=1\nTextureQuality=1\n'); W(path.join(com('Twin Config'), 'settings.ini'), '[A]\nShadowQuality=2\nTextureQuality=2\n');
    // G) alakasiz klasor: oyun adina ('Stranger Things') benzemeyen dosya alinmaz
    W(path.join(docs2, 'Pictures Archive', 'config.ini'), '[A]\nShadowQuality=1\nTextureQuality=1\n'); W(path.join(com('Lonely Game'), 'input.ini'), '[Keys]\nJump=Space\n'); W(path.join(com('Lonely Game'), 'readme.cfg'), 'x\n');
    const h4 = G.createGameHost({ platform: 'win32', dataDir: data2, steamRoots: [st2], epicManifestDir: path.join(t2, 'noepic'), riotRoots: [], docsDir: docs2, localAppData: loc2, home: t2, listProcs: async () => [], now: () => t, confirm: async () => true, pmDirs: [], run: async () => '' }); const H4 = h4.handlers; await H4['game:scan'](null, true);
    const da = await H4['game:detectAll'](null, true); const g4 = (n) => da.games.find((x) => x.name === n);
    ok(da.counts.total === 7 && da.counts.auto === 3 && da.counts.choose === 1 && da.counts.none === 2 && da.counts.blocked === 1, 'otomatik bulma: 7 oyun → 3 otomatik, 1 belirsiz, 2 bulunamadı, 1 engelli (' + JSON.stringify(da.counts) + ')');
    ok(g4('Hollow Realms').status === 'auto' && g4('Hollow Realms').path === ueFile && g4('Hollow Realms').kind === 'ue', 'Unreal: proje klasöründen LocalAppData\\HollowProj yolu bulundu (oyun adıyla eşleşmese de) ve UE olarak tanındı');
    ok(g4('Pixel Tavern').status === 'auto' && g4('Pixel Tavern').path === myg, 'Documents\\My Games\\<oyun adı>\\settings.ini otomatik bulundu');
    ok(g4('Mystery Kart').status === 'auto' && g4('Mystery Kart').path === cloud, 'Steam userdata\\<id>\\<appid>\\remote\\graphics.cfg otomatik bulundu');
    ok(g4('Twin Config').status === 'choose' && g4('Twin Config').found === 2, 'iki eşit aday varsa tahmin edilmez: kullanıcıya bırakılır');
    ok(g4('Lonely Game').status === 'none' && g4('Stranger Things').status === 'none', 'bulunamadı: giriş/tuş dosyaları (input.ini) ve alakasız klasörler aday sayılmaz');
    ok(g4('Shooter Zero').status === 'blocked', 'anti-cheat’li oyun otomatik aramaya da girmez (engelli)');
    const sc2 = await H4['game:scan'](null, false); const pg = (n) => sc2.games.find((x) => x.name === n); ok(pg('Hollow Realms').config === ueFile && pg('Hollow Realms').auto === true && pg('Hollow Realms').kind === 'ue' && pg('Twin Config').config === null && pg('Twin Config').found === 2, 'liste: otomatik seçilen yol, auto/kind ve aday sayısı arayüze gelir');
    // yerlesik UE on ayari: kaydetmeye gerek yok; ResolutionQuality dokunulmaz; cozunurluk yazilir
    const cfg4 = await H4['game:config'](null, pg('Hollow Realms').id); ok(cfg4.builtin && cfg4.builtin.kind === 'ue' && cfg4.presets.every((p) => p.builtin) && cfg4.candidates[0].path === ueFile && cfg4.candidates[0].score >= 10, 'UE: dört ön ayar yerleşik hazır (öğretmeye gerek yok), aday puanı yüksek');
    const pl4 = await H4['game:plan'](null, pg('Hollow Realms').id, { preset: 'low', resolution: { w: 1920, h: 1080 } }); ok(pl4.total === 8 && pl4.changes.filter((c) => /^sg\./.test(c.key)).length === 6 && !pl4.changes.some((c) => /ResolutionQuality/.test(c.key)) && pl4.notes.some((n) => /Unreal Engine/.test(n)), 'UE planı: 6 sg.* kalite + 2 çözünürlük satırı; sg.ResolutionQuality (yüzde) DOKUNULMAZ; ölçek notu var');
    const ap4 = await H4['game:apply'](null, pg('Hollow Realms').id, { preset: 'low', resolution: { w: 1920, h: 1080 } }); const t4 = fs.readFileSync(ueFile, 'utf8'); ok(ap4.ok && ap4.applied === 8 && /sg\.ShadowQuality=0/.test(t4) && /sg\.TextureQuality=0/.test(t4) && /sg\.ResolutionQuality=100\.000000/.test(t4) && /ResolutionSizeX=1920/.test(t4) && /ResolutionSizeY=1080/.test(t4) && /FullscreenMode=1/.test(t4), 'UE uygula: sg.* = 0, çözünürlük 1920×1080, diğer satırlar aynen');
    await H4['game:apply'](null, pg('Hollow Realms').id, { preset: 'ultra' }); ok(/sg\.ShadowQuality=3/.test(fs.readFileSync(ueFile, 'utf8')), 'UE: Ultra → 3 (Epic)');
    ok((await H4['game:restore'](null, pg('Hollow Realms').id, 'orig')).ok && fs.readFileSync(ueFile, 'utf8') === ueTxt, 'UE geri yükleme: orijinal dosya birebir döndü');
    // UE olmayan oyunda yerlesik yok -> uyari
    const pl5 = await H4['game:plan'](null, pg('Pixel Tavern').id, { preset: 'low' }); ok(pl5.total === 0 && /kaydedilmiş ayar yok/.test(pl5.notes[0]), 'UE olmayan oyun: ön ayar uydurulmaz, “önce oyunda kaydet” der');
    // kullanici secimi korunur, belirsizde elle sec
    ok((await H4['game:useConfig'](null, pg('Twin Config').id, 0)).ok, 'belirsiz oyunda kullanıcı adayı elle seçer'); const keep = await H4['game:detectAll'](null, true); ok(keep.games.find((x) => x.name === 'Twin Config').status === 'kept', 'yeniden taramada kullanıcının elle seçtiği dosya DEĞİŞTİRİLMEZ');
    // dosya silinirse yeniden bul
    fs.rmSync(myg); const re = await H4['game:detectAll'](null, true); ok(re.games.find((x) => x.name === 'Pixel Tavern').status === 'none', 'seçili dosya silinirse otomatik seçim temizlenir');
    fs.rmSync(t2, { recursive: true, force: true });
  }
  // windows disi
  const hl = G.createGameHost({ platform: 'linux', dataDir: data, listProcs: async () => [], pmDirs: [] }); const ls = await hl.handlers['game:scan'](null, true); ok(ls.games.length === 0 && /yalnızca Windows/.test(ls.note), 'platform: Windows dışında dürüst not, boş liste');
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(bad ? '\n' + bad + ' BAŞARISIZ' : '\nTÜMÜ GEÇTİ'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
