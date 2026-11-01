'use strict';
// Oyun klasorunde ic ice (kokte olmayan) ayar dosyasini bulma testi. Calistir: node tools/test/game-deep.cjs
const path = require('path'); const fs = require('fs'); const os = require('os');
const { gameModule: G } = require(path.join(__dirname, '../../app/desktop/host.js'));
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const W = (p, t) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, t); };
(async () => {
  const t = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-deep-')); const st = path.join(t, 'Steam'); const data = path.join(t, 'data');
  const name = 'RESIDENT EVIL requiem BIOHAZARD requiem'; const dir = path.join(st, 'steamapps', 'common', name);
  W(path.join(st, 'steamapps', 'libraryfolders.vdf'), '"libraryfolders" { "0" { "path" "' + st.replace(/\\/g, '\\\\') + '" } }');
  W(path.join(st, 'steamapps', 'appmanifest_99.acf'), '"AppState"\n{\n "appid" "99"\n "name" "' + name + '"\n "installdir" "' + name + '"\n}\n');
  // kokte config.ini YOK; ayar 3 klasor icinde ve dosya adi 'config' ile baslamiyor; yaninda dev 'natives' klasoru
  for (let i = 0; i < 1500; i++) W(path.join(dir, 'natives', 'x64', 'd' + (i % 30), 'f' + i + '.bin'), 'x');
  W(path.join(dir, 'win64_save', 'profile', 'game_options.ini'), '[Graphics]\nShadowQuality=2\nTextureQuality=2\nAntiAliasing=1\nResolution=1920x1080\nVSync=1\n');
  W(path.join(dir, 'win64_save', 'profile', 'input.ini'), '[Keys]\nJump=Space\n');
  const h = G.createGameHost({ platform: 'win32', dataDir: data, steamRoots: [st], epicManifestDir: path.join(t, 'noepic'), riotRoots: [], docsDir: path.join(t, 'Docs'), localAppData: path.join(t, 'Local'), home: t, listProcs: async () => [], now: () => Date.now(), confirm: async () => true, pmDirs: [], run: async () => '' }).handlers;
  const da = await h['game:detectAll'](null, true); const g = da.games.find((x) => x.name === name);
  ok(g && g.status === 'auto' && /game_options\.ini$/.test(g.path), 'kokte config.ini yokken alt klasordeki ayar dosyasi bulunup secilir');
  ok(!(g && /input\.ini$/.test(g.path)), 'input.ini aday olarak alinmaz');
  fs.rmSync(t, { recursive: true, force: true }); console.log(bad ? bad + ' HATA' : 'TUMU GECTI'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
