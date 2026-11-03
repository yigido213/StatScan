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

  // ---- PROFIL / LP / MACLAR (sahte League istemcisi, salt-okunur)
  const T0 = Date.UTC(2026, 10, 2, 12, 0, 0); let NOW = T0; const MIN = 60000; const HR = 3600e3;
  const KEY = { Darius: 122, Garen: 86, Teemo: 17, Zed: 238, Ahri: 103, Jinx: 222, Lux: 99, Malphite: 54, Sion: 14, Ornn: 516, Vayne: 67, Kayle: 10 };
  const ID = (n) => ({ participantId: n, player: { puuid: n === 1 ? 'P-ME' : 'P-' + n, gameName: n === 1 ? 'retired toplane' : (n === 2 ? 'Duoboy' : 'Oyuncu' + n), tagLine: n === 1 ? 'yigit' : 'TR1' } });
  function game(id, start, durSec, queueId, win, o) {
    o = o || {}; const champs = o.champs || ['Darius', 'Duo', 'Ahri', 'Jinx', 'Lux', 'Garen', 'Teemo', 'Zed', 'Vayne', 'Sion']; const ck = (n) => (champs[n - 1] === 'Duo' ? KEY.Kayle : KEY[champs[n - 1]]);
    const parts = []; for (let n = 1; n <= 10; n++) parts.push({ participantId: n, teamId: n <= 5 ? 100 : 200, championId: ck(n), timeline: n === 1 || n === 6 ? { lane: 'TOP', role: 'SOLO' } : { lane: 'NONE', role: 'NONE' },
      stats: n === 1 ? { win, kills: o.k == null ? 5 : o.k, deaths: o.d == null ? 2 : o.d, assists: o.a == null ? 3 : o.a, totalMinionsKilled: 180, neutralMinionsKilled: 10, goldEarned: 12000, totalDamageDealtToChampions: 20000, visionScore: 18, champLevel: 16, item0: 3074, item1: 3053, item2: 0, item3: 0, item4: 0, item5: 0, item6: 3340, gameEndedInEarlySurrender: !!o.remake } : { win: !win, kills: 1, deaths: 1, assists: 1 } });
    return { gameId: id, gameCreation: start, gameDuration: durSec, queueId, participants: parts, participantIdentities: parts.map((x) => ID(x.participantId)) };
  }
  const partialOf = (g) => Object.assign({}, g, { participants: [g.participants[0]], participantIdentities: [g.participantIdentities[0]] });
  let GAMES = [
    game(2001, T0 - 26 * HR, 1500, 420, true), game(2002, T0 - 25 * HR, 1600, 420, false, { k: 1, d: 8, a: 2 }), game(2003, T0 - 24 * HR, 1200, 450, true, { champs: ['Garen', 'Duo', 'Ahri', 'Jinx', 'Lux', 'Darius', 'Teemo', 'Zed', 'Vayne', 'Sion'] }), game(2004, T0 - 23 * HR, 200, 400, false, { remake: true })
  ];
  let RANK = { queues: [{ queueType: 'RANKED_SOLO_5x5', tier: 'PLATINUM', division: 'III', leaguePoints: 79, wins: 265, losses: 285 }, { queueType: 'RANKED_FLEX_SR', tier: 'SILVER', division: 'IV', leaguePoints: 40, wins: 10, losses: 8 }, { queueType: 'RANKED_TFT', tier: 'GOLD', division: 'I', leaguePoints: 1 }] };
  let clientUp = true; const lcuCalls = []; const SUM = { puuid: 'P-ME', gameName: 'retired toplane', tagLine: 'yigit', summonerLevel: 108, profileIconId: 29 };
  const lcuG = async (info, p) => {
    lcuCalls.push(p); if (p === '/lol-summoner/v1/current-summoner') return SUM; if (p === '/lol-ranked/v1/current-ranked-stats') return RANK;
    let m = /matches\?begIndex=(\d+)&endIndex=(\d+)/.exec(p); if (m) { const b = Number(m[1]); const sorted = GAMES.slice().sort((x, y) => y.gameCreation - x.gameCreation); return { games: { games: sorted.slice(b, Number(m[2])).map(partialOf) } }; }
    m = /games\/(\d+)$/.exec(p); if (m) return GAMES.find((g) => String(g.gameId) === m[1]) || null; return null;
  };
  const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(120, 7)]); let binCalls = 0; const bins = [];
  const hp = mkHost({ now: () => NOW, lcu: { find: async () => (clientUp ? { port: 9, token: 'abcdefgh1234' } : null), get: lcuG }, getBin: async (h, p) => { binCalls++; bins.push(p); if (/item\/9999/.test(p)) throw new Error('HTTP 404'); return PNG; } }, path.join(tmp, 'profil')); const HP = hp.handlers;
  clientUp = false; ok((await HP['lol:sync']()).state === 'noclient', 'sync: istemci kapalıyken noclient, çökme yok'); clientUp = true;
  let sy = await HP['lol:sync'](); ok(sy.state === 'ok' && sy.added === 4 && sy.snaps === 2 && sy.me.name === 'retired toplane' && sy.me.tag === 'yigit' && sy.me.level === 108, 'sync: profil, 4 maç, 2 derece anlık görüntüsü (solo+flex; TFT yok sayıldı)');
  ok(lcuCalls.every((p) => L.LCU_OK.some((re) => re.test(p))) && lcuCalls.filter((p) => /games\/\d+$/.test(p)).length === 4, 'sync: yalnız beyaz listedeki GET uç noktaları; kısmi maçlar için ayrıntı çekildi');
  let pf = await HP['lol:profile'](); ok(pf.rank.solo.tier === 'PLATINUM' && pf.rank.solo.div === 'III' && pf.rank.solo.lp === 79 && pf.rank.flex.tier === 'SILVER' && pf.matches === 4 && pf.snaps === 2, 'profil: solo/flex derece, maç ve anlık görüntü sayıları');
  sy = await HP['lol:sync'](); ok(sy.added === 0 && sy.snaps === 0 && sy.total === 4, 'sync tekrar: yeni kayıt yok, anlık görüntü tekrarlanmaz');
  let ms = await HP['lol:matches']({ queue: 'all' }); ok(ms.total === 4 && ms.rows[0].id === '2004' && ms.rows[0].remake === true && ms.rows[0].win === null, 'maçlar: yeni→eski sıralı, yeniden başlatma win=null');
  const g1 = ms.rows.find((m) => m.id === '2001'); ok(g1.win === true && g1.champ === 'Darius' && g1.role === 'top' && g1.opp === 'Garen' && g1.k === 5 && g1.cs === 190 && g1.items.join() === '3074,3053,3340' && g1.players.length === 10 && g1.partial === false, 'maç normalleştirme: şampiyon, hat, rakip (Garen), CS, eşyalar, 10 oyuncu');
  ok(g1.players.find((x) => x.me).name === 'retired toplane' && (await HP['lol:matches']({ queue: 'aram' })).total === 1 && (await HP['lol:matches']({ queue: 'ranked' })).total === 2 && (await HP['lol:matches']({ queue: 'normal' })).total === 1 && (await HP['lol:matches']({ queue: 'olmayan' })).total === 4, 'maç filtreleri: aram/ranked/normal; bilinmeyen filtre → tümü');
  // LP farki: kesin cevreleyen iki goruntu
  NOW = T0 + 5 * MIN; GAMES.push(game(2005, T0 + 10 * MIN, 1800, 420, true)); RANK.queues[0].leaguePoints = 99; RANK.queues[0].wins = 266; NOW = T0 + 45 * MIN; sy = await HP['lol:sync'](); ok(sy.added === 1 && sy.snaps === 1, 'LP: maç sonrası senkron yeni derece anlık görüntüsü alır');
  ms = await HP['lol:matches']({ queue: 'solo' }); ok(ms.rows[0].id === '2005' && ms.rows[0].lpDelta === 20 && ms.rows.slice(1).every((m) => m.lpDelta === null), 'LP farkı: kesin çevrelenen maça +20, eski maçlara atanmaz (tahmin yok)');
  // terfi
  RANK.queues[0].division = 'II'; RANK.queues[0].leaguePoints = 18; NOW = T0 + 3 * HR; await HP['lol:sync'](); GAMES.push(game(2006, T0 + 100 * MIN, 1500, 440, false)); RANK.queues[1].leaguePoints = 20; NOW = T0 + 5 * HR; await HP['lol:sync']();
  let lp = await HP['lol:lp']('solo'); ok(lp.count === 3 && lp.current.tier === 'PLATINUM' && lp.current.div === 'II' && lp.events.length === 1 && lp.events[0].type === 'up' && lp.events[0].from.div === 'III' && lp.events[0].to.div === 'II' && lp.peak.lp === 18, 'LP geçmişi: 3 nokta, Platin 3 → 2 terfi olayı, zirve');
  RANK.queues[0].division = 'III'; RANK.queues[0].leaguePoints = 75; NOW = T0 + 6 * HR; await HP['lol:sync'](); lp = await HP['lol:lp']('solo'); ok(lp.events[0].type === 'down' && lp.events.length === 2, 'LP geçmişi: lige düşme olayı (down)');
  const lf = await HP['lol:lp']('flex'); ok(lf.queue === 'flex' && lf.count === 2 && lf.current.lp === 20 && (await HP['lol:lp']('x')).queue === 'solo', 'LP geçmişi: flex ayrı, geçersiz kuyruk solo olur');
  pf = await HP['lol:profile'](); ok(pf.today.games >= 1 && pf.spark.solo.length === 4 && pf.aram.w === 1 && pf.normal.w + pf.normal.l === 0, 'profil: bugün özeti, sparkline, ARAM W/L (yeniden başlatma sayılmaz)');
  // istatistik
  const sx = await HP['lol:stats']({ queue: 'all' }); ok(sx.overview.games === 5 && sx.overview.wins === 3 && sx.overview.wr === 60 && sx.overview.losses === 2, 'istatistik: yeniden başlatma hariç 5 maç, 3 galibiyet, %60');
  ok(sx.overview.kda === 2.19 && sx.overview.k === 4.2 && sx.overview.csm > 5 && sx.overview.gpm > 300 && sx.overview.fav === 'top', 'istatistik: KDA, CS/dk, altın/dk, favori hat');
  const stRanked = await HP['lol:stats']({ queue: 'ranked' }); ok(stRanked.overview.games === 4 && stRanked.overview.streak.win === false && stRanked.overview.streak.n === 1, 'istatistik: dereceli filtre (solo+flex 4 maç, son maç yenilgi serisi 1)');
  const dc = sx.champs.find((c) => c.champ === 'Darius'); ok(dc.games === 4 && dc.wins === 2 && dc.wr === 50 && sx.champs[0].champ === 'Darius' && sx.champs.find((c) => c.champ === 'Garen').games === 1, 'şampiyon performansı: Darius 4 maç %50, Garen 1');
  ok(sx.roles[0].role === 'top' && sx.roles[0].games === 5 && sx.roles[0].wr === 60, 'hat istatistiği: top 5 maç %60');
  const duo = sx.partners.rows.find((r) => r.name === 'Duoboy'); ok(duo && duo.games === 5 && duo.wins === 3 && duo.wr === 60 && duo.top[0] === 'Kayle' && sx.partners.covered === 5, 'birlikte oynadıklarım: Duoboy 5 maç %60 (ayrıntısı olan maçlar)');
  ok(sx.partners.rows.every((r) => r.name !== 'retired toplane'), 'birlikte oynadıklarım: kendim listede yok');
  ok((await HP['lol:stats']({ queue: 'all', role: 'jungle' })).overview.games === 0, 'istatistik: hat filtresi (jungle → 0)');
  // otomatik kisisel eslesme (maclardan) -> oneri
  const auto = await HP['lol:suggest']({ role: 'top', enemy: 'Garen', poolOnly: false, limit: 50 }); const dar = auto.picks.find((x) => x.id === 'Darius'); ok(dar && dar.personal.games === 4 && dar.sources.includes('personal'), 'öneri: maç geçmişinden otomatik kişisel eşleşme (Darius vs Garen 4 maç)');
  // ban + draft analizi
  ok((await HP['lol:bans']({ role: 'top' })).needPool === true, 'ban önerisi: havuz boşken needPool'); await HP['lol:pool:set']('top', ['Darius', 'Teemo']); const bn = await HP['lol:bans']({ role: 'top', limit: 5 });
  ok(!bn.error && bn.bans.length > 0 && bn.bans.length <= 5 && bn.bans.every((b, i, a) => !i || a[i - 1].avg <= b.avg) && bn.bans.every((b) => b.worst && ['Darius', 'Teemo'].includes(b.worst.id)), 'ban önerisi: havuza göre en zor rakipler, azalan zorluk, en çok zorlanan seçim belli');
  const cp = await HP['lol:comp']({ allies: ['Zed', 'Darius', 'Jinx', 'Vayne'], enemies: ['Ahri', 'Lux', 'Malphite', 'Sion'] }); ok(cp.ally.n === 4 && cp.notes.some((n) => n.k === 'allAD' && n.side === 'ally'), 'takım analizi: AD ağırlıklı müttefik uyarısı');
  const cp2 = await HP['lol:comp']({ allies: ['Zed', 'Jinx', 'Vayne', 'Teemo'], enemies: ['Zed', 'Teemo', 'Ahri', 'Lux'] }); ok(cp2.notes.some((n) => n.k === 'noTank' && n.side === 'ally') && cp2.notes.some((n) => n.k === 'enemyNoTank'), 'takım analizi: tanksız müttefik/rakip uyarısı');
  ok((await HP['lol:comp']({ allies: ['../x', 'Zed'], enemies: 5 })).ally.n === 1, 'takım analizi: geçersiz kimlikler elenir');
  // simgeler
  const ic = await HP['lol:icon']({ kind: 'champion', id: 'Darius' }); ok(/^data:image\/png;base64,/.test(ic.data) && binCalls === 1 && /champion\/Darius\.png$/.test(bins[0]) && /\/cdn\/16\.21\.1\//.test(bins[0]), 'simge: Data Dragon’dan sabit yolla, data: URI olarak döner');
  await HP['lol:icon']({ kind: 'champion', id: 'Darius' }); ok(binCalls === 1, 'simge: ikinci istek bellekten (ağ yok)'); const hp2 = mkHost({ getBin: async () => { binCalls++; return PNG; } }, path.join(tmp, 'profil')); await hp2.handlers['lol:icon']({ kind: 'champion', id: 'Darius' }); ok(binCalls === 1, 'simge: yeni oturum diskteki önbellekten');
  ok((await HP['lol:icon']({ kind: 'item', id: '3074' })).data && (await HP['lol:icon']({ kind: 'profile', id: '29' })).data, 'simge: eşya ve profil simgesi');
  ok((await HP['lol:icon']({ kind: 'item', id: '9999' })).error === 'lol' && (await HP['lol:icon']({ kind: 'champion', id: '../etc' })).error === 'lol' && (await HP['lol:icon']({ kind: 'item', id: '1; rm' })).error === 'lol' && (await HP['lol:icon']({ kind: 'x', id: '1' })).error === 'lol', 'simge: 404 ve geçersiz kimlik/tür reddedilir, yol enjeksiyonu yok');
  ok(!bins.some((p) => /\.\.|;|\s/.test(p)), 'simge: istenen hiçbir yol şüpheli karakter içermez');
  // beyaz liste
  ok(L.LCU_OK.every((re) => !re.test('/lol-chat/v1/me') && !re.test('/lol-champ-select/v1/session/actions/1') && !re.test('/lol-login/v1/session') && !re.test('/lol-lobby/v2/lobby')) && L.LCU_OK.some((re) => re.test('/lol-champ-select/v1/session')), 'LCU beyaz listesi: sohbet/giriş/lobi/eylem uç noktaları kapalı');
  // veri silme
  confirmAns = false; ok((await HP['lol:data:clear']()).canceled === true && (await HP['lol:profile']()).matches === 6, 'veri silme: onay reddedilince veri durur'); confirmAns = true;
  const dcr = await HP['lol:data:clear'](); pf = await HP['lol:profile'](); ok(dcr.ok && pf.matches === 0 && pf.snaps === 0 && pf.me === null && (await HP['lol:pool']()).pool.top.length === 2, 'veri silme: maç/LP/profil silinir, havuz kalır');
  // saf fonksiyonlar
  ok(L.absLp('PLATINUM', 'III', 99) === 1799 && L.absLp('MASTER', '', 120) === 2920 && L.absLp('CHALLENGER', '', 0) === 2800 && L.absLp('BOZUK', 'I', 1) === null, 'absLp: kademe/lig/LP birleşik sayı, usta+ ortak ölçek');
  ok(L.normRank({ queueType: 'RANKED_SOLO_5x5', tier: '', wins: 3, losses: 2 }).unranked === true && L.normRank({ queueType: 'RANKED_TFT', tier: 'GOLD' }) === null && L.parseRanked(null).solo === null, 'derece ayrıştırma: derecesiz, TFT yok sayılır, bozuk girdi güvenli');
  ok(L.laneRole({ lane: 'BOTTOM', role: 'DUO_SUPPORT' }) === 'support' && L.laneRole({ lane: 'BOTTOM', role: 'DUO_CARRY' }) === 'bot' && L.laneRole({ lane: 'MIDDLE' }) === 'mid' && L.laneRole(null) === null, 'hat çıkarımı: destek/nişancı/orta');
  ok(L.normMatch({ gameId: 'x' }, 'P', () => null) === null && L.normMatch(null, 'P', () => null) === null && L.normMatch({ gameId: 1, participants: [{ participantId: 1, stats: { win: true } }, { participantId: 2, stats: {} }], participantIdentities: [] }, 'P', () => null) === null, 'maç ayrıştırma: bozuk/benim olmayan veri null');

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
