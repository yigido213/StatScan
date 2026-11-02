// Karsi Secim (LoL counter) host testi: sahte Data Dragon + sahte LCU; gercek ag yok. Calistir: node tools/test/lol-host.cjs
const fs = require('fs'); const os = require('os'); const path = require('path');
const { lolModule: L, createHost } = require('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kovan-lol-'));

const mk = (id, key, tags, a, d, m, df, range, hp, armor, mr) => [id, { id, key: String(key), name: id, tags, info: { attack: a, defense: d, magic: m, difficulty: df }, stats: { hp, hpperlevel: 100, armor, armorperlevel: 4, spellblock: mr, spellblockperlevel: 1.3, attackrange: range } }];
const DATA = Object.fromEntries([
  mk('Darius', 122, ['Fighter', 'Tank'], 9, 5, 1, 2, 175, 652, 39, 32), mk('Garen', 86, ['Fighter', 'Tank'], 7, 7, 1, 5, 175, 690, 36, 32), mk('Teemo', 17, ['Marksman', 'Assassin'], 5, 3, 7, 6, 500, 598, 24, 30),
  mk('Kayle', 10, ['Fighter', 'Support'], 6, 6, 7, 7, 175, 600, 26, 30), mk('Zed', 238, ['Assassin'], 9, 2, 1, 7, 125, 654, 32, 32), mk('Ahri', 103, ['Mage', 'Assassin'], 3, 4, 8, 5, 550, 590, 21, 30),
  mk('Malphite', 54, ['Tank', 'Fighter'], 5, 9, 7, 2, 125, 644, 37, 32), mk('Jinx', 222, ['Marksman'], 9, 2, 4, 6, 525, 610, 26, 30), mk('Lux', 99, ['Mage', 'Support'], 2, 4, 9, 5, 550, 560, 18, 30),
  mk('Sion', 14, ['Tank', 'Fighter'], 5, 9, 3, 5, 175, 655, 36, 32), mk('Ornn', 516, ['Tank', 'Fighter'], 5, 9, 3, 5, 175, 660, 33, 28), mk('Vayne', 67, ['Marksman', 'Assassin'], 10, 1, 1, 8, 550, 550, 23, 30)
]);
const champJson = { data: DATA };
let calls = []; let offline = false; let extBody = null;
const get = async (host, p) => {
  calls.push(host + p); if (offline) throw new Error('çevrimdışı');
  if (host === 'ddragon.leagueoflegends.com') {
    if (p === '/api/versions.json') return JSON.stringify(['16.21.1', '16.20.1']); if (/\/data\/tr_TR\/champion\.json$/.test(p)) return JSON.stringify(champJson);
    const m = /\/champion\/([A-Za-z0-9]+)\.json$/.exec(p); if (m) return JSON.stringify({ data: { [m[1]]: { name: m[1], enemytips: ['İpucu 1 ' + m[1], 'İpucu 2'] } } });
  }
  if (host === 'stats.example.org') { if (extBody === 'fail') throw new Error('HTTP 500'); return JSON.stringify(extBody); }
  throw new Error('beklenmeyen: ' + host + p);
};
let confirmAns = true; const confirms = [];
const wrapH = (o) => Object.assign(o, { handlers: Object.fromEntries(Object.entries(o.handlers).map(([k, f]) => [k, (...a) => f(null, ...a)])) });
const mkHost = (extra, dir) => wrapH(L.createLolHost(Object.assign({ dataDir: dir || path.join(tmp, 'data'), get, confirm: async (o) => { confirms.push(o); return confirmAns; }, platform: 'win32' }, extra || {})));

(async () => {
  // ---- saf fonksiyonlar
  const roster = L.parseChampions(champJson); ok(roster.length === 12 && roster[0].name === 'Ahri', 'parseChampions: 12 şampiyon, ada göre sıralı');
  ok(L.parseChampions({}).length === 0 && L.parseChampions(null).length === 0, 'parseChampions: bozuk girdide boş liste');
  ok(L.normChamp({ id: '../x' }) === null && L.normChamp({ id: 'A b' }) === null, 'normChamp: geçersiz kimlik reddedilir');
  const W = L.wilson; ok(W(0, 0) === 50 && W(8, 10) > 50 && W(8, 10) < 80 && W(80, 100) > W(8, 10), 'wilson: az maç temkinli, çok maç daha güvenli');
  const Z = L.rosterZ(roster); const teemo = roster.find((c) => c.id === 'Teemo'); const darius = roster.find((c) => c.id === 'Darius');
  const h = L.heuristic(teemo, darius, 'top', Z); ok(h.pos.some((x) => x.k === 'rangeEdge') && h.delta > 0, 'tahmin: menzilli şampiyon yakın dövüşçüye karşı menzil avantajı alır');
  const h2 = L.heuristic(darius, teemo, 'top', Z); ok(h2.delta < 0 && h2.neg.some((x) => x.k === 'rangeEdge'), 'tahmin: tersi dezavantaj (simetrik)');
  ok(L.heuristic(darius, darius, 'top', Z).delta === 0, 'tahmin: ayna eşleşme 0');
  ok(L.parseLcuCmd('"x" --app-port=51234 "--remoting-auth-token=abc_DEF-12345678" --foo') .port === 51234 && L.parseLcuCmd('--app-port=1') === null && L.parseLcuCmd('') === null && L.parseLcuCmd('--app-port=70000 --remoting-auth-token=abcdefgh1234') === null, 'LCU komut satırı: port+token ayrıştırılır, bozuk/geçersiz reddedilir');
  const st = L.parseStats({ matchups: [{ champ: 'Garen', wr: 53.5, games: 1200 }, { champ: '../x', wr: 50, games: 5 }, { champ: 'Teemo', wr: 140, games: 5 }, { champ: 'Zed', wr: 50, games: -1 }] }); ok(st.size === 1 && st.get('Garen').wr === 53.5, 'dış veri: yalnız geçerli satırlar alınır (kimlik, aralık)');
  ok(L.parseStats({}) === null && L.parseStats(null) === null, 'dış veri: şekil bozuksa null');

  // ---- host: veri + önbellek
  const hs = mkHost(); const H = hs.handlers;
  let r = await H['lol:status'](); ok(r.ready && r.meta.version === '16.21.1' && r.meta.locale === 'tr_TR' && r.meta.count === 12 && !r.meta.offline, 'status: sürüm ve şampiyon sayısı');
  const n1 = calls.length; await H['lol:champs'](); ok(calls.length === n1, 'champs: bellekten, yeniden ağ isteği yok');
  offline = true; const hs2 = mkHost(); r = await hs2.handlers['lol:status'](); ok(r.ready && r.meta.offline === true && r.meta.count === 12, 'çevrimdışı: önbellekten açılır (offline=true)');
  const hsEmpty = mkHost({}, path.join(tmp, 'bos')); r = await hsEmpty.handlers['lol:status'](); ok(!r.ready && /alınamadı/.test(r.error), 'çevrimdışı + önbellek yok: anlaşılır hata, çökme yok');
  offline = false;

  // ---- öneri
  r = await H['lol:suggest']({ role: 'top', enemy: 'Darius' }); ok(!r.error && r.enemy.id === 'Darius' && r.picks.length > 0 && r.picks.every((p) => p.id !== 'Darius'), 'suggest: rakip kendisi listede yok');
  ok(r.picks.every((p) => p.score >= 0 && p.score <= 100 && p.sources.includes('est')), 'suggest: skor 0-100, kaynak "tahmin" etiketli');
  ok(r.picks.every((p, i, a) => i === 0 || a[i - 1].score >= p.score), 'suggest: skora göre azalan sıralı');
  ok(!r.picks.some((p) => p.id === 'Jinx') && r.picks.some((p) => p.id === 'Garen'), 'suggest: rol uygunluğu — top için nişancı yok, dövüşçü/tank var');
  r = await H['lol:suggest']({ role: 'top', enemy: 'Darius', poolOnly: true }); ok(r.needPool === true, 'suggest: havuz boşken poolOnly → needPool');
  let pr = await H['lol:pool:set']('top', ['Garen', 'Teemo', 'Garen', '../etc', 'Yok']); ok(pr.ok && pr.pool.join() === 'Garen,Teemo', 'havuz: tekrar ve geçersiz kimlikler elenir');
  ok((await H['lol:pool:set']('mid2', [])).error === 'lol' && (await H['lol:pool:set']('top', 'x')).error === 'lol', 'havuz: geçersiz rol/girdi reddedilir');
  r = await H['lol:suggest']({ role: 'top', enemy: 'Darius', poolOnly: true }); ok(r.picks.length === 2 && r.picks.every((p) => p.inPool), 'poolOnly: yalnız havuzdaki şampiyonlar');
  ok(r.picks[0].id === 'Teemo', 'tahmin: menzilli Teemo, havuzda Darius’a karşı Garen’den önde');
  ok((await H['lol:suggest']({ role: 'x', enemy: 'Darius' })).error === 'lol' && (await H['lol:suggest']({ role: 'top', enemy: '../Darius' })).error === 'lol' && (await H['lol:suggest']({ role: 'top', enemy: 'Bilinmiyor' })).error === 'lol', 'suggest: geçersiz rol/rakip reddedilir');
  const pool = await H['lol:pool'](); ok(pool.pool.top.join() === 'Garen,Teemo' && pool.pool.mid.length === 0, 'havuz: okunur');

  // ---- kişisel kayıt
  for (let i = 0; i < 8; i++) await H['lol:log']({ role: 'top', me: 'Garen', enemy: 'Darius', win: true }); for (let i = 0; i < 2; i++) await H['lol:log']({ role: 'top', me: 'Teemo', enemy: 'Darius', win: false });
  r = await H['lol:suggest']({ role: 'top', enemy: 'Darius', poolOnly: true }); const g = r.picks.find((p) => p.id === 'Garen'); const t = r.picks.find((p) => p.id === 'Teemo');
  ok(g.personal.games === 8 && g.personal.wins === 8 && g.sources.includes('personal') && t.personal.games === 2, 'kişisel: maç sayıları doğru');
  ok(r.picks[0].id === 'Garen' && g.score > t.score, 'kişisel: 8-0 geçmiş tahmini geçer (Garen öne çıkar)');
  ok((await H['lol:log']({ role: 'top', me: 'Garen', enemy: 'Darius' })).error === 'lol' && (await H['lol:log']({ role: 'top', me: 'X y', enemy: 'Darius', win: true })).error === 'lol', 'kayıt: eksik/geçersiz alan reddedilir');
  const hist = await H['lol:hist'](); ok(hist.total === 10 && hist.recent.length === 10 && hist.byChamp[0].me === 'Garen' && hist.byChamp[0].wins === 8, 'geçmiş: toplam ve şampiyon özeti');
  const u = await H['lol:hist:undo'](); ok(u.ok && u.total === 9, 'geri al: son kayıt silinir');
  const persisted = JSON.parse(fs.readFileSync(path.join(tmp, 'data', 'lolcounter.json'), 'utf8')); ok(persisted.hist.length === 9 && persisted.pool.top.length === 2, 'kalıcı: dosyaya yazıldı');
  const hs3 = mkHost(); ok((await hs3.handlers['lol:hist']()).total === 9 && (await hs3.handlers['lol:pool']()).pool.top.length === 2, 'kalıcı: yeni host aynı veriyi okur');
  confirmAns = false; const c0 = await H['lol:hist:clear'](); ok(c0.canceled === true && (await H['lol:hist']()).total === 9, 'silme: onay reddedilince kayıtlar durur');
  confirmAns = true; const c1 = await H['lol:hist:clear'](); ok(c1.ok && (await H['lol:hist']()).total === 0, 'silme: onayla tüm kayıtlar silinir');

  // ---- ipuçları
  const tp = await H['lol:tips']('Darius'); ok(tp.tips.length === 2 && /Darius/.test(tp.tips[0]) && tp.source === 'Riot Data Dragon', 'ipuçları: Data Dragon’dan, kaynak etiketli');
  const n2 = calls.length; await H['lol:tips']('Darius'); ok(calls.length === n2, 'ipuçları: önbellekten');
  ok((await H['lol:tips']('../x')).error === 'lol', 'ipuçları: geçersiz kimlik reddedilir');

  // ---- dış veri adresi
  ok((await H['lol:statsurl:set']('http://stats.example.org/{enemy}')).error === 'lol', 'dış adres: http reddedilir');
  ok((await H['lol:statsurl:set']('https://localhost/{enemy}')).error === 'lol' && (await H['lol:statsurl:set']('https://192.168.1.5/{enemy}')).error === 'lol' && (await H['lol:statsurl:set']('https://127.0.0.1/{enemy}')).error === 'lol', 'dış adres: yerel/özel ağ reddedilir');
  ok((await H['lol:statsurl:set']('https://stats.example.org/x')).error === 'lol' && (await H['lol:statsurl:set']('https://user:pw@stats.example.org/{enemy}')).error === 'lol', 'dış adres: {enemy} şart, kimlik bilgisi reddedilir');
  confirmAns = false; ok((await H['lol:statsurl:set']('https://stats.example.org/{enemy}/{role}')).canceled === true && !(await H['lol:statsurl:get']()).configured, 'dış adres: onay reddedilince kaydedilmez');
  confirmAns = true; const sset = await H['lol:statsurl:set']('https://stats.example.org/{enemy}/{role}'); ok(sset.ok && sset.host === 'stats.example.org' && /stats\.example\.org/.test(confirms[confirms.length - 1].message), 'dış adres: onay penceresi sunucu adını gösterir, kaydedilir');
  extBody = { matchups: [{ champ: 'Garen', wr: 40, games: 5000 }, { champ: 'Teemo', wr: 60, games: 5000 }] };
  r = await H['lol:suggest']({ role: 'top', enemy: 'Darius', poolOnly: true }); ok(r.extUsed && r.picks.find((p) => p.id === 'Teemo').sources.includes('ext') && r.picks[0].id === 'Teemo' && r.picks.find((p) => p.id === 'Teemo').ext.wr === 60, 'dış veri: karışıma girer, kaynak etiketli');
  extBody = 'fail'; r = await H['lol:suggest']({ role: 'top', enemy: 'Darius', poolOnly: true }); ok(!r.error && r.extUsed === false && r.statsConfigured === true && r.picks.length === 2, 'dış veri: sunucu hata verirse tahmine düşer, çökmez');
  ok((await H['lol:statsurl:set'](null)).configured === false && !(await H['lol:statsurl:get']()).configured, 'dış adres: kaldırılabilir');

  // ---- LCU (salt-okunur)
  const byKey = new Map(roster.map((c) => [c.key, c.id]));
  const ses = { localPlayerCellId: 2, myTeam: [{ cellId: 0, championId: 99, assignedPosition: 'utility' }, { cellId: 2, championId: 0, championPickIntent: 86, assignedPosition: 'top' }], theirTeam: [{ cellId: 5, championId: 122, assignedPosition: '' }, { cellId: 6, championId: 0 }] };
  const m = L.mapSession(ses, byKey); ok(m.myRole === 'top' && m.myPick === 'Garen' && m.enemies.length === 1 && m.enemies[0].id === 'Darius' && m.allies.length === 2 && m.allies.find((a) => a.me).id === 'Garen', 'LCU oturumu: rol, kendi seçimi, rakipler eşlenir; boş seçimler atlanır');
  ok(L.mapSession(null, byKey) === null, 'LCU oturumu: null güvenli');
  let lcuState = 'none'; const gets = [];
  const hl = mkHost({ lcu: { find: async () => (lcuState === 'noclient' ? null : { port: 1234, token: 'abcdefgh1234' }), get: async (info, p) => { gets.push(p); if (lcuState === 'idle') return null; if (lcuState === 'err') throw new Error('bağlantı reddedildi'); return ses; } } });
  lcuState = 'noclient'; ok((await hl.handlers['lol:lcu']()).state === 'noclient', 'LCU: istemci yoksa noclient');
  lcuState = 'idle'; ok((await hl.handlers['lol:lcu']()).state === 'idle', 'LCU: şampiyon seçimi yoksa idle');
  lcuState = 'err'; ok((await hl.handlers['lol:lcu']()).state === 'noclient', 'LCU: bağlantı hatası noclient olarak döner, çökme yok');
  lcuState = 'ok'; const ls = await hl.handlers['lol:lcu'](); ok(ls.state === 'champselect' && ls.enemies[0].id === 'Darius' && ls.myRole === 'top', 'LCU: şampiyon seçimi okunur');
  ok(gets.every((p) => p === '/lol-champ-select/v1/session'), 'LCU: yalnızca tek GET uç noktası kullanıldı (yazma yok)');
  const hmac = mkHost({ platform: 'darwin' }); ok((await hmac.handlers['lol:lcu']()).state === 'noclient', 'LCU: Windows dışında bulunmaz → noclient');

  // ---- TUM sampiyonlar: ~170 sentetik sampiyon (gercek Data Dragon sekliyle; ozel kimlikler dahil), her sampiyon rakip, her rol
  const TAGS = [['Fighter', 'Tank'], ['Fighter'], ['Tank'], ['Mage'], ['Mage', 'Support'], ['Assassin'], ['Marksman'], ['Support'], ['Support', 'Tank'], ['Fighter', 'Assassin'], ['Marksman', 'Assassin'], ['Mage', 'Assassin'], ['Tank', 'Mage']];
  const SPECIAL = [['MonkeyKing', 'Wukong'], ['Nunu', 'Nunu & Willump'], ['Kaisa', "Kai'Sa"], ['Belveth', "Bel'Veth"], ['KSante', "K'Sante"], ['Renata', 'Renata Glasc'], ['DrMundo', 'Dr. Mundo'], ['Chogath', "Cho'Gath"], ['Khazix', "Kha'Zix"], ['Velkoz', "Vel'Koz"], ['Leblanc', 'LeBlanc'], ['JarvanIV', 'Jarvan IV']];
  const big = {}; const mkBig = (id, name, i) => { const tg = TAGS[i % TAGS.length]; const rng = (i * 37) % 7; big[id] = { id, key: String(1000 + i), name, tags: tg, info: { attack: 1 + (i * 3) % 10, defense: 1 + (i * 5) % 10, magic: 1 + (i * 7) % 10, difficulty: 1 + (i * 11) % 10 }, stats: { hp: 520 + (i * 13) % 140, hpperlevel: 85 + (i * 3) % 30, armor: 20 + (i * 5) % 22, armorperlevel: 3.5, spellblock: 28 + (i % 6), spellblockperlevel: 1.3, attackrange: [125, 175, 500, 525, 550, 600, 650][rng] } }; };
  SPECIAL.forEach(([id, nm], i) => mkBig(id, nm, i)); for (let i = SPECIAL.length; i < 170; i++) mkBig('Champ' + i, 'Champ ' + i, i);
  const getBig = async (host, p) => { if (p === '/api/versions.json') return JSON.stringify(['16.21.1']); if (/champion\.json$/.test(p)) return JSON.stringify({ data: big }); throw new Error('beklenmeyen ' + p); };
  const hb = mkHost({ get: getBig }, path.join(tmp, 'buyuk')); const HB = hb.handlers;
  const cl = await HB['lol:champs'](); ok(cl.champs.length === 170 && cl.champs.some((c) => c.id === 'MonkeyKing' && c.name === 'Wukong') && cl.champs.some((c) => c.id === 'Kaisa'), 'tam liste: 170 şampiyon, özel kimlikler (MonkeyKing=Wukong, Kaisa) dahil');
  let allOk = true; let minPicks = 1e9; let bad1 = ''; let nRuns = 0;
  for (const c of cl.champs) for (const role of ['top', 'jungle', 'mid', 'bot', 'support']) {
    const q = await HB['lol:suggest']({ role, enemy: c.id }); nRuns++;
    if (q.error || !q.picks || !q.picks.length || q.picks.some((p) => p.id === c.id || !(p.score >= 0 && p.score <= 100)) || q.picks.some((p, i, a) => i && a[i - 1].score < p.score)) { allOk = false; bad1 = c.id + '/' + role; break; }
    minPicks = Math.min(minPicks, q.picks.length);
  }
  ok(allOk && nRuns === 850, 'tam liste: 170 şampiyon × 5 rol = 850 öneri, hepsi geçerli (kendisi yok, skor 0-100, sıralı) ' + bad1); ok(minPicks >= 3, 'tam liste: her rakip/rol için en az 3 öneri (en az ' + minPicks + ')');
  const all1 = await HB['lol:suggest']({ role: 'top', enemy: 'MonkeyKing', anyRole: true, limit: 500 }); ok(all1.picks.length === 169 && all1.total === 169 && !all1.picks.some((p) => p.id === 'MonkeyKing'), 'anyRole: rol filtresi yok → rakip hariç 169 şampiyonun hepsi');
  const filt = await HB['lol:suggest']({ role: 'bot', enemy: 'MonkeyKing', limit: 500 }); ok(filt.total < 169 && filt.total > 0, 'rol filtresi açıkken aday sayısı daha az (' + filt.total + ')');
  const tp2 = await HB['lol:tips']('JarvanIV'); ok(!tp2.error || /alınamadı/.test(tp2.message), 'özel kimlikli şampiyon için ipucu çağrısı çökmez');

  // ---- host entegrasyonu: kanallar kayıtlı, arayüz yol/URL gönderemez
  const host = createHost({ service: { closeAll() {} }, lol: { dataDir: path.join(tmp, 'entegre'), get } });
  const chans = ['lol:status', 'lol:champs', 'lol:pool', 'lol:pool:set', 'lol:suggest', 'lol:tips', 'lol:log', 'lol:hist', 'lol:hist:undo', 'lol:hist:clear', 'lol:statsurl:get', 'lol:statsurl:set', 'lol:lcu'];
  ok(chans.every((c) => typeof host.handlers[c] === 'function'), 'createHost: tüm lol kanalları kayıtlı');
  const hd = createHost({ service: { closeAll() {} }, lol: false }); ok(!hd.handlers['lol:status'], 'createHost: lol:false ile kanallar kapanır');
  const src = fs.readFileSync(path.join(__dirname, '../../app/desktop/host.js'), 'utf8'); const lolSrc = src.slice(src.indexOf('const LOLMOD'), src.indexOf("/* --- Oyun Ayarlayici (Kovan 'oyunayar'"));
  ok(!/\bPOST\b|method: 'P(OST|UT)'|method: 'DELETE'/.test(lolSrc), 'kaynak: LOLMOD içinde yazma yöntemi (POST/PUT/DELETE) yok');
  ok(!/child_process'\)\.exec\(|\.spawn\(|ReadProcessMemory|WriteProcessMemory/.test(lolSrc), 'kaynak: LOLMOD oyun sürecine/belleğe dokunmaz');
  const pre = fs.readFileSync(path.join(__dirname, '../../app/desktop/preload.js'), 'utf8'); ok(/lolStatsUrlSet/.test(pre) && !/lolSuggest:[^\n]*url/i.test(pre), 'preload: dar API var, öneri çağrısı URL taşımaz');
  console.log(bad ? '\n' + bad + ' BAŞARISIZ' : '\nhepsi geçti'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
