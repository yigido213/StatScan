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
// ---- esya onerisi: sahte item.json (gercek esya adlari/degerleri DEGIL; yalniz sema ve kurallar test edilir)
const itm = (name, total, tags, stats, extra) => Object.assign({ name, description: '<mainText>' + name + '</mainText>', gold: { base: total, total, sell: total / 2, purchasable: true }, tags, maps: { 11: true, 12: false }, stats: stats || {} }, extra || {});
const ITEM_EN = { type: 'item', version: '16.21.1', data: {
  3001: itm('Bruiser Plate', 3000, ['Damage', 'Armor'], { FlatPhysicalDamageMod: 50, FlatArmorMod: 45 }), 3002: itm('Guardian Mail', 3000, ['Damage', 'Armor', 'Health'], { FlatPhysicalDamageMod: 35, FlatArmorMod: 40, FlatHPPoolMod: 100 }),
  3003: itm('Pure Armor', 2800, ['Armor', 'Health'], { FlatArmorMod: 80, FlatHPPoolMod: 300 }), 3004: itm('Mage Cloak', 3000, ['SpellDamage', 'Armor'], { FlatMagicDamageMod: 90, FlatArmorMod: 40 }),
  3005: itm('Wizard Veil', 3000, ['SpellDamage', 'SpellBlock'], { FlatMagicDamageMod: 80, FlatSpellBlockMod: 40 }), 3006: itm('Warrior Veil', 3000, ['Damage', 'SpellBlock'], { FlatPhysicalDamageMod: 40, FlatSpellBlockMod: 50 }),
  3007: itm('Pure MR', 2700, ['SpellBlock', 'Health'], { FlatSpellBlockMod: 80, FlatHPPoolMod: 250 }),
  3008: itm('Sunder Blade', 3100, ['Damage', 'ArmorPenetration'], { FlatPhysicalDamageMod: 60 }, { description: 'Gives <attention>18</attention> Lethality' }), 3009: itm('Void Rod', 3200, ['SpellDamage', 'MagicPenetration'], { FlatMagicDamageMod: 80 }),
  3010: itm('Wound Blade', 3000, ['Damage'], { FlatPhysicalDamageMod: 45 }, { description: 'Applies <status>40% Grievous Wounds</status> to champions' }), 3011: itm('Wound Orb', 3000, ['SpellDamage'], { FlatMagicDamageMod: 80 }, { description: 'Applies <status>40% Grievous Wounds</status>' }),
  3012: itm('Thorn Armor', 2700, ['Armor', 'Health'], { FlatArmorMod: 60, FlatHPPoolMod: 300 }, { description: 'Applies <status>Grievous Wounds</status> if they are a champion.' }),
  3100: itm('Steel Treads', 1200, ['Armor', 'Boots']), 3101: itm('Mercury Treads', 1100, ['Boots', 'SpellBlock', 'Tenacity']),
  3102: itm('Plain Boots', 300, ['Boots'], {}, { into: ['3100', '3101'] }), 3200: itm('Health Potion', 50, ['Consumable']), 3201: itm('Ward Trinket', 0, ['Trinket']), 3202: itm('Cheap Component', 800, ['Damage'], { FlatPhysicalDamageMod: 25 }, { into: ['3001'] }),
  3203: itm('Champion Locked', 3000, ['Armor'], { FlatArmorMod: 90 }, { requiredChampion: 'Viktor' }), 3204: itm('Support Quest', 2200, ['GoldPer', 'Armor'], { FlatArmorMod: 20 }), 3205: itm('Unpurchasable', 3000, ['Armor'], { FlatArmorMod: 99 }, { gold: { total: 3000, purchasable: false } }),
  223075: itm('Arena Copy', 2500, ['Armor'], { FlatArmorMod: 60 }, { maps: { 11: false, 30: true } }), 3206: itm('No Map Item', 3000, ['Armor'], { FlatArmorMod: 70 }, { maps: {} }) } };
const ITEM_TR = { data: { 3001: { name: 'Savaşçı Plaka' }, 3101: { name: 'Merkür Çizme' }, 3003: { name: 'Saf Zırh' } } };
let itemsFail = false;
let muBody = null; const muCalls = [];
let calls = []; let offline = false; let extBody = null; const cpCalls = []; let cpPages = {};
const get = async (host, p) => {
  calls.push(host + p); if (offline) throw new Error('çevrimdışı');
  if (host === 'ddragon.leagueoflegends.com') {
    if (p === '/api/versions.json') return JSON.stringify(['16.21.1', '16.20.1']); if (/\/data\/tr_TR\/champion\.json$/.test(p)) return JSON.stringify(champJson);
    if (/\/data\/(en_US|tr_TR)\/item\.json$/.test(p)) { if (itemsFail) throw new Error('HTTP 500'); return JSON.stringify(/en_US/.test(p) ? ITEM_EN : ITEM_TR); }
    if (/\/data\/tr_TR\/summoner\.json$/.test(p)) return JSON.stringify({ data: { Flash: { key: '4', name: 'Sıçra', image: { full: 'SummonerFlash.png' } }, TP: { key: '12', name: 'Işınlan', image: { full: 'SummonerTeleport.png' } }, Bad: { key: '9', name: 'Bad', image: { full: '../../secret.png' } } } });
    if (/\/data\/tr_TR\/runesReforged\.json$/.test(p)) return JSON.stringify([{ id: 8000, name: 'İlham', slots: [{ runes: [{ id: 8010, name: 'Fatih', icon: 'perk-images/Styles/Precision/Conqueror/Conqueror.png' }] }, { runes: [{ id: 9111, name: 'Zafer' }] }, { runes: [{ id: 9104, name: 'Efsane' }] }, { runes: [{ id: 8299, name: 'Son Direniş', icon: 'perk-images/../bad.png' }] }] }, { id: 8400, name: 'Direniş', icon: 'perk-images/Styles/7204_Resolve.png', slots: [{ runes: [{ id: 8437, name: 'Eller' }] }, { runes: [{ id: 8444, name: 'Şahlanış' }] }, { runes: [{ id: 8473, name: 'Kemik' }] }, { runes: [{ id: 8451, name: 'Taşma' }] }] }]);
    const m = /\/champion\/([A-Za-z0-9]+)\.json$/.exec(p); if (m) return JSON.stringify({ data: { [m[1]]: { name: m[1], enemytips: ['ESKI IPUCU ' + m[1]], passive: { name: 'Pasif', description: 'Pasif <b>metin</b><br>' + m[1] }, spells: ['Q', 'W', 'E', 'R'].map((k) => ({ name: k + ' yeteneği', cooldownBurn: '8/7/6', description: k + ' <i>güncel</i> açıklama' })) } } });
  }
  if (host === 'www.counterpick.lol') { cpCalls.push(p); if (cpPages[p] === undefined) throw new Error('HTTP 404'); return cpPages[p]; }
  if (host === 'mu.example.org') { muCalls.push(p); if (muBody === 'fail') throw new Error('HTTP 500'); if (muBody === '404') throw new Error('HTTP 404'); return JSON.stringify(muBody); }
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
  const tp = await H['lol:tips']('Darius'); ok(tp.abilities.length === 5 && tp.abilities[0].desc === 'Pasif metin Darius' && tp.abilities[4].key === 'R' && tp.abilities[4].cd === '8/7/6' && /yama 16\.21\.1/.test(tp.source) && tp.tips.length === 0 && !JSON.stringify(tp).includes('ESKI IPUCU'), 'ipuçları: eski enemytips KULLANILMAZ; aynı yamanın güncel yetenek metinleri (HTML temizlenmiş), yama etiketli');
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

  // ---- HAT VERİSİ (Meraki positions): yanlış hattaki şampiyon hiçbir listede çıkmaz
  { const mk = (id, key, name, tags, hp, range, pos) => ({ id, key: String(key), name, tags, info: { attack: 5, defense: 5, magic: 5, difficulty: 5 }, stats: { hp, hpperlevel: 100, armor: 30, armorperlevel: 4, spellblock: 32, spellblockperlevel: 1.3, attackrange: range }, _pos: pos });
    const rs = [mk('Aatrox', 266, 'Aatrox', ['Fighter', 'Tank'], 650, 175, ['TOP']), mk('Bard', 432, 'Bard', ['Support', 'Mage'], 630, 500, ['SUPPORT']), mk('Garen', 86, 'Garen', ['Fighter', 'Tank'], 690, 175, ['TOP']), mk('Ahri', 103, 'Ahri', ['Mage', 'Assassin'], 590, 550, ['MIDDLE']), mk('Vayne', 67, 'Vayne', ['Marksman', 'Assassin'], 550, 550, ['BOTTOM']), mk('Sett', 875, 'Sett', ['Fighter', 'Tank'], 600, 175, ['TOP', 'SUPPORT'])];
    const dd = {}; const mer = {}; for (const c of rs) { const x = Object.assign({}, c); delete x._pos; dd[c.id] = x; mer[c.id] = { id: Number(c.key), key: c.id, name: c.name, positions: c._pos, roles: [], lore: 'x'.repeat(2000) }; }
    for (let i = 0; i < 60; i++) { dd['Fill' + i] = mk('Fill' + i, 3000 + i, 'Fill ' + i, ['Fighter'], 600, 175, ['TOP']); delete dd['Fill' + i]._pos; mer['Fill' + i] = { id: 3000 + i, positions: ['JUNGLE'] }; }
    let merCalls = 0; let merFail = false; const getR = async (host, p) => { if (p === '/api/versions.json') return JSON.stringify(['16.21.1']); if (/champion\.json$/.test(p)) return JSON.stringify({ data: dd }); if (host === L.ROLE_HOST) { merCalls++; if (merFail) throw new Error('HTTP 500'); return JSON.stringify(mer); } throw new Error('beklenmeyen ' + p); };
    const dirR = path.join(tmp, 'roller'); const hr = mkHost({ get: getR }, dirR); const HR2 = hr.handlers;
    const cs = await HR2['lol:champs'](); const bard = cs.champs.find((c) => c.id === 'Bard'); ok(bard && bard.pos && bard.pos.join() === 'support' && cs.meta.roles >= 6, 'hat verisi: Bard yalnız support, hat verisi yüklendi (' + cs.meta.roles + ' şampiyon)');
    const top = await HR2['lol:suggest']({ role: 'top', enemy: 'Aatrox', limit: 100 }); ok(top.picks.some((p) => p.id === 'Garen') && !top.picks.some((p) => ['Bard', 'Ahri', 'Vayne'].includes(p.id)), 'hat filtresi: Aatrox\'a karşı üst hat önerisinde Bard/Ahri/Vayne yok, Garen var');
    const mid = await HR2['lol:suggest']({ role: 'mid', enemy: 'Ahri', limit: 100 }); ok(!mid.picks.some((p) => ['Bard', 'Aatrox', 'Garen', 'Vayne'].includes(p.id)), 'hat filtresi: orta hatta üst/destek/nişancı çıkmaz');
    const sup = await HR2['lol:suggest']({ role: 'support', enemy: 'Bard', limit: 100 }); ok(sup.picks.some((p) => p.id === 'Sett') && !sup.picks.some((p) => p.id === 'Aatrox'), 'çok hatlı şampiyon (Sett) iki hatta da çıkar, tek hatlı olan çıkmaz');
    const anyr = await HR2['lol:suggest']({ role: 'top', enemy: 'Aatrox', anyRole: true, limit: 500 }); ok(anyr.picks.some((p) => p.id === 'Bard'), 'anyRole bilerek açılırsa hat filtresi kalkar (kullanıcı tercihi)');
    ok(merCalls === 1, 'hat verisi bir kez indirildi'); await HR2['lol:champs'](true); ok(merCalls === 1, 'hat verisi önbellekten (haftalık), tekrar indirilmedi');
    const cached = JSON.parse(fs.readFileSync(path.join(dirR, 'lolcounter-cache', 'roles.json'), 'utf8')); ok(cached.map['432'] && cached.map['432'].join() === 'support' && JSON.stringify(cached).length < 20000, 'önbellek yalnız küçük hat özeti (lore/yetenek yok)');
    ok(L.parseRoles({ a: { id: 1, positions: ['TOP'] } }) === null && L.parseRoles(null) === null && L.parseRoles(mer)['266'].join() === 'top', 'parseRoles: az/bozuk veri reddedilir, geçerli veri hat listesine çevrilir');
    // veri hiç alınamazsa: etiket tahmini ama Bard gibi destek-ağırlıklı büyücü üst hatta ÇIKMAZ
    merFail = true; const hf = mkHost({ get: getR }, path.join(tmp, 'roller2')); const HF = hf.handlers; const cf = await HF['lol:champs'](); ok(cf.meta.roles === 0, 'hat verisi alınamazsa meta.roles = 0 (tahmine düşer)');
    const tf = await HF['lol:suggest']({ role: 'top', enemy: 'Aatrox', limit: 100 }); ok(!tf.picks.some((p) => p.id === 'Bard') && tf.picks.some((p) => p.id === 'Garen'), 'yedek tahmin: Bard (Support/Mage, yüksek can) artık üst hatta çıkmaz');
    ok(!L.roleFit({ tags: ['Support', 'Mage'], range: 500, hp: 1454 }, 'top') && L.roleFit({ tags: ['Support', 'Mage'], range: 500, hp: 1454 }, 'support'), 'roleFit yedek: destek ana sınıflı büyücü üst hat değil, destek');
    const wBard = L.roleWeights({ tags: ['Support', 'Mage'], range: 500, hp: 1454, pos: ['support'] }, null); ok(wBard.support > 20 * wBard.top && wBard.support > 20 * wBard.mid, 'hat tahmini: hat verisi olan şampiyonda ağırlık gerçek hatta yığılır');
  }
  const tp2 = await HB['lol:tips']('JarvanIV'); ok(!tp2.error || /alınamadı/.test(tp2.message), 'özel kimlikli şampiyon için ipucu çağrısı çökmez');

  // ---- PROFIL / LP / MACLAR (sahte League istemcisi, salt-okunur)
  const T0 = Date.UTC(2026, 10, 2, 12, 0, 0); let NOW = T0; const MIN = 60000; const HR = 3600e3;
  const KEY = { Darius: 122, Garen: 86, Teemo: 17, Zed: 238, Ahri: 103, Jinx: 222, Lux: 99, Malphite: 54, Sion: 14, Ornn: 516, Vayne: 67, Kayle: 10 };
  const ID = (n) => ({ participantId: n, player: { puuid: n === 1 ? 'P-ME' : 'P-' + n, gameName: n === 1 ? 'retired toplane' : (n === 2 ? 'Duoboy' : 'Oyuncu' + n), tagLine: n === 1 ? 'yigit' : 'TR1' } });
  function game(id, start, durSec, queueId, win, o) {
    o = o || {}; const champs = o.champs || ['Darius', 'Duo', 'Ahri', 'Jinx', 'Lux', 'Garen', 'Teemo', 'Zed', 'Vayne', 'Sion']; const ck = (n) => (champs[n - 1] === 'Duo' ? KEY.Kayle : KEY[champs[n - 1]]);
    const parts = []; for (let n = 1; n <= 10; n++) parts.push({ participantId: n, teamId: n <= 5 ? 100 : 200, championId: ck(n), spell1Id: 4, spell2Id: 12, timeline: n === 1 || n === 6 ? { lane: 'TOP', role: 'SOLO' } : { lane: 'NONE', role: 'NONE' },
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
  const nb = bins.length; const rk = await HP['lol:icon']({ kind: 'rank', id: 'gold' }); ok(/^data:image\/png;base64,/.test(rk.data) && /ranked-emblem\/emblem-gold\.png$/.test(bins[nb]) && !/\/cdn\//.test(bins[nb]), 'simge: gerçek derece amblemi (CommunityDragon sabit yolu), data: URI');
  const hostsSeen = []; const hr0 = mkHost({ getBin: async (h, p) => { hostsSeen.push(h); return PNG; } }, path.join(tmp, 'rank')); await hr0.handlers['lol:icon']({ kind: 'rank', id: 'challenger' }); ok(hostsSeen[0] === 'raw.communitydragon.org', 'simge: derece amblemi yalnızca CommunityDragon sunucusundan');
  ok((await HP['lol:icon']({ kind: 'rank', id: 'bogus' })).error === 'lol' && (await HP['lol:icon']({ kind: 'rank', id: '../../x' })).error === 'lol' && (await HP['lol:icon']({ kind: 'rank', id: 'GOLD ' })).error === 'lol', 'simge: geçersiz/yol içeren derece adı reddedilir');
  { const nb2 = bins.length; await HP['lol:icon']({ kind: 'rank', id: 'gold' }); ok(bins.length === nb2, 'simge: derece amblemi bellekten (ağ yok)'); }
  // ---- canli mac
  const Pl = (champ, name, team, sp, pos) => ({ championName: champ, rawChampionName: 'game_character_displayname_' + champ, riotIdGameName: name, riotIdTagLine: 'TR1', riotId: name + '#TR1', team, level: 7, position: pos || '', summonerSpells: { summonerSpellOne: { rawDisplayName: 'GeneratedTip_SummonerSpell_' + sp[0] + '_DisplayName' }, summonerSpellTwo: { rawDisplayName: 'GeneratedTip_SummonerSpell_' + sp[1] + '_DisplayName' } } });
  let liveJson = null; let liveGets = [];
  const mkLive = () => ({ activePlayer: { riotId: 'Yigit#TR1', riotIdGameName: 'Yigit' }, gameData: { gameMode: 'CLASSIC', gameTime: 600 }, allPlayers: [Pl('Darius', 'Yigit', 'ORDER', ['Flash', 'Teleport'], ''), Pl('Sion', 'A2', 'ORDER', ['Flash', 'Smite']), Pl('Ahri', 'A3', 'ORDER', ['Flash', 'Ignite']), Pl('Jinx', 'A4', 'ORDER', ['Flash', 'Heal']), Pl('Lux', 'A5', 'ORDER', ['Flash', 'Exhaust']),
    Pl('Garen', 'E1', 'CHAOS', ['Flash', 'Teleport']), Pl('Ornn', 'E2', 'CHAOS', ['Flash', 'Smite']), Pl('Zed', 'E3', 'CHAOS', ['Flash', 'Ignite']), Pl('Vayne', 'E4', 'CHAOS', ['Flash', 'Heal']), Pl('Malphite', 'E5', 'CHAOS', ['Flash', 'Exhaust'])] });
  const hv = mkHost({ live: { get: async (p) => { liveGets.push(p); return liveJson; } } }, path.join(tmp, 'live')); const HV = hv.handlers;
  r = await HV['lol:live'](); ok(r.state === 'nogame' && liveGets.join() === '/liveclientdata/allgamedata', 'canlı: maçta değilken nogame; yalnızca /liveclientdata/allgamedata okunur');
  liveJson = mkLive(); r = await HV['lol:live'](); const en = (c) => r.enemies.find((x) => x.champ === c);
  ok(r.state === 'ingame' && r.classic && r.allies.length === 5 && r.enemies.length === 5 && r.me.champ === 'Darius' && r.me.role === 'top', 'canlı: 5v5 okundu, kendim bulundu, hat: Üst (Işınlan + dövüşçü)');
  ok(en('Garen').role === 'top' && en('Ornn').role === 'jungle' && en('Zed').role === 'mid' && en('Vayne').role === 'bot' && en('Malphite').role === 'support', 'canlı: rakip hatları (Garen üst, Ornn orman[Çarp], Zed orta, Vayne alt, Malphite destek[Bitkinlik])');
  ok(new Set(r.enemies.map((x) => x.role)).size === 5 && r.enemies.every((x) => x.conf > 0 && x.conf <= 1 && x.known === false), 'canlı: her hat tek oyuncuya atanır; güven 0-1; hat oyundan gelmedi → known=false');
  ok(r.lane === 'Garen' && r.matchup && r.matchup.enemy === 'Garen' && r.matchup.role === 'top' && r.matchup.mine && r.matchup.pos >= 1 && r.matchup.total >= 3 && r.matchup.list.length >= 3 && r.matchup.list.every((x) => x.id !== 'Vayne' && x.id !== 'Jinx') && r.matchup.extUsed === false && r.matchup.statsConfigured === false, 'canlı: hat eşleşmesi (Darius vs Garen), sıra/toplam, yalnız üst hat şampiyonları, dış veri yok');
  liveJson = mkLive(); liveJson.allPlayers[5].position = 'JUNGLE'; liveJson.allPlayers[6].position = 'TOP'; r = await HV['lol:live'](); ok(en('Ornn').role === 'top' && en('Garen').role === 'jungle' && en('Ornn').known === true && r.lane === 'Ornn', 'canlı: oyunun verdiği hat tahmini ezer (known=true)');
  liveJson = mkLive(); liveJson.gameData.gameMode = 'ARAM'; r = await HV['lol:live'](); ok(r.state === 'ingame' && !r.classic && r.enemies.every((x) => x.role === null) && r.matchup === undefined, 'canlı: ARAM’da hat tahmini ve eşleşme yok');
  liveJson = mkLive(); liveJson.activePlayer = {}; r = await HV['lol:live'](); ok(r.state === 'ingame' && r.me === null && r.matchup === undefined, 'canlı: kendi oyuncum belirlenemezse eşleşme yok, çökme yok');
  liveJson = { allPlayers: 'x' }; ok((await HV['lol:live']()).state === 'nogame', 'canlı: bozuk veri → nogame');
  // ---- Tab altin farki (esya degeri)
  { const it = (price, count) => ({ itemID: 1, price, count: count || 1 }); const G = mkLive(); G.allPlayers.forEach((p, i) => { p.items = [it(450), it(1100)]; p.scores = { kills: 1 }; });
    G.allPlayers[0].items = [it(3000), it(1100), it(50, 3)]; G.allPlayers[0].scores = { kills: 4 }; G.allPlayers[5].items = [it(450)]; G.allPlayers[5].scores = { kills: 2 };
    liveJson = G; liveGets = []; const g = await HV['lol:gold']();
    ok(g.state === 'ok' && g.mine.gold === 4250 + 4 * 1550 && g.enemy.gold === 450 + 4 * 1550 && g.diff === g.mine.gold - g.enemy.gold, 'altın: takım toplamı = Σ fiyat×adet; fark bizim − rakip');
    ok(g.mine.kills === 4 + 4 && g.enemy.kills === 2 + 4, 'altın: takım kill toplamları');
    ok(g.lanes.length === 5 && g.lanes.every((l) => l.diff === l.mine.gold - l.enemy.gold) && g.lanes.some((l) => l.mine.me) && g.guessed === true, 'altın: 5 hat farkı, ben işaretli, tahmin bayrağı');
    ok(liveGets.every((p) => p === '/liveclientdata/allgamedata'), 'altın: yalnız /liveclientdata/allgamedata okunur');
    const L2 = mkLive(); L2.allPlayers.forEach((p) => { p.items = [{ itemID: 1, price: 'x', count: -5 }, null, { price: 99999, count: 999 }]; }); liveJson = L2; const g2 = await HV['lol:gold'](); ok(g2.state === 'ok' && g2.mine.gold === 5 * 6000 * 20 && Number.isFinite(g2.diff), 'altın: bozuk/uç değerler sınırlanır, çökmez');
    liveJson = mkLive(); const g3 = await HV['lol:gold'](); ok(g3.state === 'ok' && g3.mine.gold === 0 && g3.partial === true, 'altın: eşya alanı yoksa 0 + partial');
    liveJson = mkLive(); liveJson.activePlayer = {}; ok((await HV['lol:gold']()).state === 'nogame', 'altın: kendi oyuncum belirsizse nogame');
    liveJson = null; ok((await HV['lol:gold']()).state === 'nogame', 'altın: maç yokken nogame');
    liveJson = mkLive(); liveJson.gameData.gameMode = 'ARAM'; const g4 = await HV['lol:gold'](); ok(g4.state === 'ok' && g4.lanes.length === 0, 'altın: ARAM’da hat yok, takım toplamı var');
    ok((await HV['lol:gold:get']()).on === true, 'altın bindirmesi: varsayılan AÇIK'); await HV['lol:gold:set']({ on: false }); ok((await HV['lol:gold:get']()).on === false, 'altın ayarı kapanır');
    const dg = path.join(tmp, 'goldset'); const h1 = mkHost({}, dg); await h1.handlers['lol:gold:set']({ on: false }); ok((await mkHost({}, dg).handlers['lol:gold:get']()).on === false, 'altın ayarı yeniden açılışta korunur'); }
  // ---- Tab izleyici (sahte spawn)
  { const { EventEmitter } = require('events'); const mk = () => { const c = new EventEmitter(); c.stdout = new EventEmitter(); c.killed = false; c.kill = () => { c.killed = true; c.emit('exit'); }; return c; };
    let calls = []; let kid = null; const ev = []; const w = L.createTabWatcher({ platform: 'win32', spawn: (cmd, args, opt) => { calls.push({ cmd, args, opt }); kid = mk(); return kid; }, onChange: (d) => ev.push(d) });
    ok(w.start() === true && w.start() === true && calls.length === 1 && calls[0].cmd === 'powershell.exe' && calls[0].opt.shell === false && calls[0].opt.windowsHide === true, 'tab izleyici: tek PowerShell süreci, shell yok, gizli');
    const enc = calls[0].args[calls[0].args.indexOf('-EncodedCommand') + 1]; ok(Buffer.from(enc, 'base64').toString('utf16le') === L.TAB_PS && /GetAsyncKeyState\(9\)/.test(L.TAB_PS) && !/Send|keybd_event|SetWindowsHook|GetKeyboardState|Get-Content|Invoke-|http/i.test(L.TAB_PS), 'tab izleyici: betik sabit, yalnız Tab durumunu yoklar (tuş gönderme/kanca/ağ yok)');
    kid.stdout.emit('data', 'D\r\nU\nD'); kid.stdout.emit('data', '\nU\n'); ok(ev.join() === 'true,false,true,false', 'tab izleyici: D/U satırları (parça parça gelse de) doğru çevrilir');
    kid.stdout.emit('data', 'garbage\nX\n'); ok(ev.length === 4, 'tab izleyici: bilinmeyen satır yok sayılır');
    kid.stdout.emit('data', 'D\n'); kid.emit('exit'); ok(ev[ev.length - 1] === false && !w.running(), 'tab izleyici: süreç ölürse "bırakıldı" + yeniden başlatılabilir'); ok(w.start() === true && calls.length === 2, 'tab izleyici: çıkıştan sonra yeniden başlar');
    w.stop(); ok(kid.killed && !w.running(), 'tab izleyici: stop süreci öldürür');
    ok(L.createTabWatcher({ platform: 'linux', spawn: () => { throw new Error('olmamalı'); } }).start() === false, 'tab izleyici: Windows dışında başlamaz');
    ok(L.createTabWatcher({ platform: 'win32', spawn: () => { throw new Error('x'); } }).start() === false, 'tab izleyici: spawn hatasında çökmez'); }
  const hvOff = mkHost({ platform: 'win32', live: { get: async () => { throw new Error('ECONNREFUSED'); } } }, path.join(tmp, 'live2')); ok((await hvOff.handlers['lol:live']()).state === 'nogame', 'canlı: bağlantı reddedilince nogame (oyun yok)');
  ok(L.LIVE_OK.test('/liveclientdata/allgamedata') && !L.LIVE_OK.test('/liveclientdata/allgamedata/x') && !L.LIVE_OK.test('/lol-summoner/v1/current-summoner') && !L.LIVE_OK.test('http://evil/liveclientdata/allgamedata'), 'canlı: beyaz liste yalnızca allgamedata');
  // ---- counterpick.lol (isteğe bağlı; sentetik HTML, gerçek siteyle DENENMEDİ)
  const MU = '<html><body><h1>Darius vs Garen</h1><div class="vs">VS <b>53.6%</b> <span>994 games</span> B+</div><section><h2>Runes</h2><img src="/wp-content/uploads/lol/rune/8100.webp"><img src="/wp-content/uploads/lol/rune/8010.webp"><img src="/wp-content/uploads/lol/rune/9111.webp"><img src="/wp-content/uploads/lol/rune/9104.webp"><img src="/wp-content/uploads/lol/rune/8299.webp"><img src="/wp-content/uploads/lol/rune/8300.webp"><img src="/wp-content/uploads/lol/rune/8444.webp"><img src="/wp-content/uploads/lol/rune/8473.webp"><img src="/wp-content/uploads/lol/rune/5008.webp"></section><script>var x="VS 1% 5 games"</script></body></html>';
  const row = (a, b, v) => '<li><a href="https://www.counterpick.lol/champion/' + b + '/"><img src="x.png"></a> ' + b + ' <a href="https://www.counterpick.lol/matchup/' + a + '-vs-' + b + '/">Matchup detail</a> <span>' + v + '% WR</span> <em>+1.0%</em></li>';
  const CT = '<html><h2>Best Counters Against Garen</h2><ul>' + row('garen', 'teemo', '45.0') + row('garen', 'zed', '47.5') + '</ul><h2>Garen is Strong Against</h2><ul>' + row('garen', 'sion', '52.0') + row('garen', 'notachamp', '60.0') + row('darius', 'vayne', '60.0') + '</ul></html>';
  ok(L.parseCpMatchup(MU).wr === 53.6 && L.parseCpMatchup(MU).games === 994 && L.parseCpMatchup(MU).runes.perks.join() === '8010,9111,9104,8299,8444,8473' && L.parseCpMatchup(MU).runes.primary === 8100 && L.parseCpMatchup(MU).runes.secondary === 8300, 'cp ayrıştırıcı: oran, oyun sayısı, rün kimlikleri (ağaç/şarj ayrıldı; script içeriği yok sayıldı)');
  ok(L.parseCpMatchup('<p>VS 153% 5 games</p>') === null && L.parseCpMatchup('<p>nothing</p>') === null && L.parseCpMatchup('<p>VS 50% 10 games</p><img src="/lol/rune/8010.webp">').runes === null, 'cp ayrıştırıcı: saçma/eksik veri → null, az rün → rün yok');
  { const rows = L.parseCpCounters(CT, 'garen'); ok(rows.length === 4 && rows[0].slug === 'teemo' && rows[0].wr === 55 && rows.find((x) => x.slug === 'sion').wr === 48 && !rows.find((x) => x.slug === 'vayne'), 'cp counters: rakip oranı = 100 − konu oranı, başka konu satırı alınmaz'); }
  ok(L.cpKebab("Kai'Sa") === 'kaisa' && L.cpKebab('Jarvan IV') === 'jarvan-iv' && L.cpKebab('Nunu & Willump') === 'nunu-willump', 'cp: adres adı (kebab) üretimi');
  { cpCalls.length = 0; confirmAns = true; cpPages = { '/matchup/darius-vs-garen/': MU, '/champion/garen/counters/': CT };
    const hc = mkHost({ cpDelay: 0, live: { get: async () => mkLive() } }, path.join(tmp, 'cp')); const HC = hc.handlers;
    ok((await HC['lol:cp:get']()).on === false, 'cp: varsayılan KAPALI');
    let rr = await HC['lol:live'](); ok(cpCalls.length === 0 && rr.matchup.extUsed === false, 'cp kapalıyken siteye HİÇ istek gitmez');
    confirmAns = false; ok((await HC['lol:cp:set'](true)).canceled === true && (await HC['lol:cp:get']()).on === false, 'cp: onay reddedilince açılmaz'); confirmAns = true; const c0 = confirms.length; ok((await HC['lol:cp:set'](true)).on === true && /counterpick\.lol/.test(confirms[c0].message) && /kullanım şartlarını/.test(confirms[c0].message), 'cp: onay penceresi sunucuyu ve şart uyarısını gösterir');
    rr = await HC['lol:live'](); const mu = rr.matchup; ok(mu.extUsed && mu.cp && mu.mine.ext.wr === 53.6 && mu.mine.ext.games === 994 && mu.mine.ext.runes.perks.length === 6, 'cp canlı: kendi şampiyonum için gerçek oran + oyun sayısı + rün kimlikleri');
    const tm = mu.list.find((x) => x.id === 'Teemo'); ok(tm && tm.wr === 55 && mu.list.find((x) => x.id === 'Sion').wr === 48 && !mu.list.find((x) => x.id === 'Vayne'), 'cp canlı: counters sayfasındaki şampiyonlar tabloya oranla girer (Teemo %55); hat dışı şampiyon (Vayne üst hatta) tabloya girmez');
    const n1 = cpCalls.length; await HC['lol:live'](); ok(cpCalls.length === n1 && cpCalls.every((p) => /^\/(matchup|champion)\//.test(p)) && new Set(cpCalls).size === cpCalls.length, 'cp: ikinci çağrı önbellekten (ağ yok), yalnız /matchup ve /champion yolları');
    const sg = await HC['lol:suggest']({ role: 'top', enemy: 'Garen', anyRole: true, limit: 50 }); ok(sg.extUsed && sg.picks.find((x) => x.id === 'Teemo').ext.wr === 55 && sg.picks.find((x) => x.id === 'Teemo').ext.approx === true, 'cp: Karşı seçim sekmesi de counters oranlarını kullanır (oyun sayısı bilinmez → approx)');
    cpPages = {}; const hd = mkHost({ cpDelay: 0, live: { get: async () => mkLive() } }, path.join(tmp, 'cp2')); await hd.handlers['lol:cp:set'](true); rr = await hd.handlers['lol:live'](); ok(rr.state === 'ingame' && rr.matchup.extUsed === false && rr.matchup.statsConfigured === true, 'cp: site 404/ulaşılamaz → sessizce tahmine düşer, çökmez');
    ok((await HC['lol:cp:set'](false)).on === false && (await HC['lol:cp:get']()).on === false, 'cp: kapatılabilir'); }
  // ---- rün sayfasını League'e yazma (LCU, tek yazma türü)
  const IDX = { 8010: { t: 8000, s: 0 }, 9111: { t: 8000, s: 1 }, 9104: { t: 8000, s: 2 }, 8299: { t: 8000, s: 3 }, 8437: { t: 8400, s: 0 }, 8444: { t: 8400, s: 1 }, 8473: { t: 8400, s: 2 }, 8451: { t: 8400, s: 3 } };
  ok(L.validateRunePage([8010, 9111, 9104, 8299, 8444, 8473], IDX).primary === 8000 && L.validateRunePage([8010, 9111, 9104, 8299, 8444, 8473], IDX).sub === 8400, 'rün yapısı: geçerli sayfa (anahtar taş + 3 + ikinci ağaçtan 2) kabul');
  ok(L.validateRunePage([9111, 8010, 9104, 8299, 8444, 8473], IDX) === null && L.validateRunePage([8010, 9111, 9104, 8299, 8444, 8451], IDX) !== null && L.validateRunePage([8010, 9111, 9104, 8299, 8010, 9111], IDX) === null && L.validateRunePage([8010, 9111, 9104, 8299, 8444, 8444], IDX) === null && L.validateRunePage([8010, 9111, 9104, 8299, 8444, 7777], IDX) === null && L.validateRunePage([8010, 9111], IDX) === null, 'rün yapısı: sıra bozuk / aynı slot / aynı ağaç / bilinmeyen kimlik / eksik → reddedilir');
  { let pagesL = [{ id: 1, name: 'Benim sayfam', isDeletable: true, selectedPerkIds: [1, 2, 3, 4, 5, 6, 5008, 5008, 5001] }, { id: 5, name: 'Kovan vs Zed', isDeletable: true, selectedPerkIds: [] }]; const writes = []; let curP = { selectedPerkIds: [8010, 9111, 9104, 8299, 8444, 8473, 5008, 5008, 5001] }; let hasClient = true;
    const mkR = () => mkHost({ lcu: { find: async () => (hasClient ? { port: 1, token: 'abcdefgh1234' } : null), get: async (i, p) => (p === '/lol-perks/v1/pages' ? pagesL : p === '/lol-perks/v1/currentpage' ? curP : null), write: async (i, m, p, b) => { writes.push([m, p, b]); if (m === 'DELETE') pagesL = pagesL.filter((x) => '/lol-perks/v1/pages/' + x.id !== p); else pagesL = pagesL.concat(Object.assign({ id: 9, isDeletable: true }, b)); return null; } } }, path.join(tmp, 'runeapply')); const HR = mkR().handlers; const good = { me: 'Darius', enemy: 'Garen', perks: [8010, 9111, 9104, 8299, 8444, 8473] };
    confirmAns = false; let ra = await HR['lol:runes:apply'](good); ok(ra.canceled === true && writes.length === 0, 'rün yaz: onay reddedilince League’e HİÇ yazılmaz'); confirmAns = true; const c1 = confirms.length;
    ra = await HR['lol:runes:apply'](good); ok(ra.ok && ra.verified === true && ra.name === 'Kovan vs Garen' && /Fatih/.test(confirms[c1].message) && /Diğer sayfalarına dokunulmaz/.test(confirms[c1].message), 'rün yaz: onay penceresi rün adlarını gösterir; sayfa yazıldı ve okunarak doğrulandı');
    ok(writes.length === 2 && writes[0][0] === 'DELETE' && writes[0][1] === '/lol-perks/v1/pages/5' && writes[1][0] === 'POST' && writes[1][1] === '/lol-perks/v1/pages' && writes[1][2].selectedPerkIds.join() === '8010,9111,9104,8299,8444,8473,5008,5008,5001' && writes[1][2].primaryStyleId === 8000 && writes[1][2].subStyleId === 8400 && writes[1][2].current === true && !writes.some((w) => w[1] === '/lol-perks/v1/pages/1') && pagesL.some((x) => x.id === 1), 'rün yaz: yalnız eski “Kovan” sayfası silindi, yenisi 9 kimlikle (6 rün + mevcut sayfadan 3 şarj) yazıldı; kullanıcının sayfasına dokunulmadı');
    writes.length = 0; ra = await HR['lol:runes:apply'](Object.assign({}, good, { perks: [9111, 8010, 9104, 8299, 8444, 8473] })); ok(ra.error === 'lol' && /doğrulanamadı/.test(ra.message) && writes.length === 0, 'rün yaz: yapı geçersizse yazılmaz');
    ra = await HR['lol:runes:apply']({ me: '../x', enemy: 'Garen', perks: good.perks }); ok(ra.error === 'lol' && writes.length === 0, 'rün yaz: geçersiz şampiyon kimliği reddedilir');
    curP = { selectedPerkIds: [1, 2, 3] }; ra = await HR['lol:runes:apply'](good); ok(ra.error === 'lol' && /Şarj parçaları/.test(ra.message) && writes.length === 0, 'rün yaz: şarj parçaları okunamazsa uydurulmaz, yazılmaz'); curP = { selectedPerkIds: [8010, 9111, 9104, 8299, 8444, 8473, 5008, 5008, 5001] };
    hasClient = false; ra = await HR['lol:runes:apply'](good); ok(ra.error === 'lol' && ra.state === 'noclient' && writes.length === 0, 'rün yaz: istemci yoksa anlaşılır hata'); hasClient = true;
    const hnw = mkHost({ lcu: { find: async () => ({ port: 1, token: 'abcdefgh1234' }), get: async (i, p) => (p === '/lol-perks/v1/pages' ? [] : { selectedPerkIds: [8010, 9111, 9104, 8299, 8444, 8473, 5008, 5008, 5001] }), write: async () => { throw new Error('HTTP 400'); } } }, path.join(tmp, 'runeapply2')); ra = await hnw.handlers['lol:runes:apply'](good); ok(ra.error === 'lol' && /yazılamadı/.test(ra.message), 'rün yaz: istemci reddederse çökmez, açıklayıcı hata'); }
  { cpPages = { '/matchup/darius-vs-garen/': MU }; const hq = mkHost({ cpDelay: 0 }, path.join(tmp, 'runesug')); let rs = await hq.handlers['lol:runes:suggest']({ me: 'Darius', enemy: 'Garen', role: 'top' }); ok(rs.runes === null && rs.statsConfigured === false, 'rün önerisi: dış kaynak kapalıyken yok, yönlendirme için statsConfigured=false'); confirmAns = true; await hq.handlers['lol:cp:set'](true);
    rs = await hq.handlers['lol:runes:suggest']({ me: 'Darius', enemy: 'Garen', role: 'top' }); ok(rs.runes && rs.runes.perks.length === 6 && rs.wr === 53.6 && rs.games === 994 && rs.cp === true, 'rün önerisi: counterpick açıkken eşleşmeye özel rünler + oran'); ok((await hq.handlers['lol:runes:suggest']({ me: 'x/y', enemy: 'Garen', role: 'top' })).error === 'lol', 'rün önerisi: geçersiz istek reddedilir'); }
  // dis veri run onerisi (yalniz sayilar)
  ok(L.parseRunes({ perks: [8010, 9111, '8444', 'x', 12, 99999], primary: 8000, secondary: 8400 }).perks.join() === '8010,9111,8444' && L.parseRunes({ perks: ['<script>'] }) === null && L.parseRunes({ perks: [8010], primary: 'x' }).primary === null && L.parseRunes(null) === null, 'run verisi: yalnızca tam sayı kimlikleri alınır, metin/uç değerler elenir');
  { const hx = mkHost({ live: { get: async () => mkLive() } }, path.join(tmp, 'live3')); confirmAns = true; await hx.handlers['lol:statsurl:set']('https://stats.example.org/{enemy}/{role}');
    extBody = { matchups: [{ champ: 'Darius', wr: 56, games: 4000, runes: { perks: [8010, 9111, 8444], primary: 8000, secondary: 8400 } }, { champ: 'Teemo', wr: 44, games: 3000, runes: { perks: ['<b>x</b>'] } }] };
    r = await hx.handlers['lol:live'](); ok(r.matchup.extUsed && r.matchup.mine.ext.wr === 56 && r.matchup.mine.ext.runes.perks.join() === '8010,9111,8444' && r.matchup.list.find((x) => x.id === 'Teemo').wr === 44, 'canlı + dış veri: gerçek oran ve run önerisi eşleşmeye girer, kaynak etiketli');
    const rn = await hx.handlers['lol:runes'](); ok(rn.perks[8010] === 'Fatih' && rn.trees[8000] === 'İlham' && rn.perks[8444] === 'Şahlanış', 'run adları: Data Dragon runesReforged’den (kimlik → ad)');
    extBody = 'fail'; r = await hx.handlers['lol:live'](); ok(r.matchup && r.matchup.extUsed === false && r.matchup.statsConfigured === true, 'canlı + dış veri hata: tahmine düşer'); }
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
  {
    const ng = game(9090, T0, 1800, 420, true); const nm = L.normMatch(ng, 'P-ME', (id) => String(id));
    ok(JSON.stringify(nm.spells) === '[4,12]', 'maç büyüleri: gerçek D/F sırası korunur (Flash/TP)');
    delete ng.participants[0].spell1Id; ok(JSON.stringify(L.normMatch(ng, 'P-ME', String).spells) === '[null,12]', 'maç büyüleri: eksik ilk büyüde ikinci büyü yer değiştirmez');
    ng.participants[0].spell2Id = '../bad'; ok(L.normMatch(ng, 'P-ME', String).spells === null, 'maç büyüleri: eksik/geçersiz veri tahmin edilmez');
    const before = bins.length;
    const [flash, tp, rune, tree] = await Promise.all([['spell', '4'], ['spell', '12'], ['rune', '8010'], ['rune', '8400']].map(([kind,id]) => HP['lol:icon']({kind,id})));
    ok(flash.data && flash.name === 'Sıçra' && tp.name === 'Işınlan' && rune.name === 'Fatih' && tree.name === 'Direniş', 'büyü/rün simgeleri: Data Dragon isimleri ve PNG');
    ok(bins.slice(before).includes('/cdn/16.21.1/img/spell/SummonerFlash.png') && bins.slice(before).includes('/cdn/img/perk-images/Styles/Precision/Conqueror/Conqueror.png') && bins.slice(before).includes('/cdn/img/perk-images/Styles/7204_Resolve.png'), 'büyü sürümlü, rün ve ikincil ağaç sürümsüz resmi CDN yolundan');
    const cached = bins.length; await HP['lol:icon']({kind:'spell',id:'4'}); await HP['lol:icon']({kind:'rune',id:'8010'}); ok(bins.length === cached, 'büyü/rün simgeleri bellekten döner');
    const invalid = await Promise.all([['spell','../4'],['spell','9'],['rune','8299'],['rune','9999'],['rune','https://x']].map(([kind,id]) => HP['lol:icon']({kind,id})));
    ok(invalid.every((r) => r.error) && bins.length === cached, 'büyü/rün: bilinmeyen kimlik, URL ve metadata yol geçişi ağ isteği yapmadan reddedilir');
    const old = L.normMatch(GAMES[0], 'P-ME', String); delete old.spells;
    const md = path.join(tmp, 'spells-migration'); fs.mkdirSync(md); fs.writeFileSync(path.join(md,'lolcounter.json'), JSON.stringify({v:1,me:SUM,matches:{[old.id]:old}}));
    const mh = mkHost({now:()=>NOW,lcu:{find:async()=>({port:9,token:'abcdefgh1234'}),get:lcuG}},md);
    const migrationSync = await mh.handlers['lol:sync'](); ok(migrationSync.updated > 0, 'eski kayıt tamamlama arayüz yenilemesini tetikler'); const migrated = await mh.handlers['lol:matches']({});
    ok(JSON.stringify(migrated.rows.find((m)=>m.id===old.id).spells)==='[4,12]', 'eski LCU kaydı: sonraki senkronizasyonda büyüler tamamlanır');
  }
  ok(L.normMatch({ gameId: 'x' }, 'P', () => null) === null && L.normMatch(null, 'P', () => null) === null && L.normMatch({ gameId: 1, participants: [{ participantId: 1, stats: { win: true } }, { participantId: 2, stats: {} }], participantIdentities: [] }, 'P', () => null) === null, 'maç ayrıştırma: bozuk/benim olmayan veri null');

  // ---- esya onerisi
  { const items = L.parseItems(ITEM_EN); const ids = items.map((x) => x.id);
    ok(items.length === 14 && ['3001', '3012', '3100', '3101'].every((i) => ids.includes(i)), 'parseItems: 12 tamamlanmış eşya + 2 ayakkabı (14)');
    ok(!ids.some((i) => ['3102', '3200', '3201', '3202', '3203', '3204', '3205', '223075', '3206'].includes(i)), 'parseItems: bileşen/tüketilebilir/muska/şampiyona özel/görev/satılmayan/Arena/harita dışı elenir');
    const byId = new Map(items.map((x) => [x.id, x])); ok(byId.get('3008').penP && !byId.get('3008').gw && byId.get('3009').penM && byId.get('3010').gw && byId.get('3012').gw && byId.get('3101').boots && byId.get('3101').tags.includes('Tenacity'), 'parseItems: delme (Lethality/etiket), yara azaltma, ayakkabı, tenacity işaretleri');
    ok(byId.get('3001').st.ad === 50 && byId.get('3001').st.armor === 45 && byId.get('3003').st.hp === 300, 'parseItems: yalnız sayısal istatistikler okunur');
    ok(L.parseItems({}).length === 0 && L.parseItems(null).length === 0 && L.parseItems({ data: { 3001: null, abc: {} } }).length === 0, 'parseItems: bozuk girdide boş liste');
    const R2 = roster.concat(L.parseChampions({ data: Object.fromEntries([mk('Soraka', 16, ['Support', 'Mage'], 2, 5, 7, 5, 550, 560, 32, 30), mk('Aatrox', 266, ['Fighter', 'Tank'], 8, 4, 3, 4, 175, 650, 38, 32)]) }));
    const A = (me, en, role) => L.buildItemAdvice(R2, me, en, role, items, null, '16.21.1'); const sec = (r, k) => r.sections.find((x) => x.k === k); const idsOf = (s) => s.items.map((x) => x.id).join();
    let a = A('Jinx', ['Zed', 'Darius', 'Garen'], 'bot'); ok(a.type === 'ad' && a.profile.apPct <= 11 && sec(a, 'armor').pri === 'high' && !sec(a, 'mr'), 'eşya: fiziksel ağırlıklı rakibe karşı zırh önceliklidir, büyü direnci yok');
    ok(idsOf(sec(a, 'armor')) === '3001,3002,3003', 'eşya: AD şampiyon önce hasar+zırh eşyalarını, sonra saf zırhı görür (AP eşya çıkmaz)'); ok(idsOf(sec(a, 'boots')) === '3100' && sec(a, 'pen').pri === 'mid' && idsOf(sec(a, 'pen')) === '3008', 'eşya: zırh ayakkabısı; 2 dayanıklı rakipte delme (Lethality) eşyası');
    ok(a.sections[0].pri === 'high' && a.sections.every((s, i, l) => i === 0 || (s.pri === 'mid') || l[i - 1].pri === 'high'), 'eşya: öncelikli bölümler önce gelir');
    a = A('Ahri', ['Zed', 'Darius', 'Jinx'], 'mid'); ok(a.type === 'ap' && idsOf(sec(a, 'armor')) === '3004,3003,3012', 'eşya: AP şampiyon AP+zırh eşyasını (Mage Cloak) görür; AD eşya çıkmaz');
    a = A('Ornn', ['Ahri', 'Lux', 'Teemo'], 'top'); ok(a.type === 'tank' && sec(a, 'mr').pri === 'high' && idsOf(sec(a, 'mr')) === '3007,3006' && !sec(a, 'pen') && idsOf(sec(a, 'boots')) === '3101', 'eşya: tank büyü ağırlıklı rakibe karşı yalnız savunma eşyaları (AP eşya yok), delme yok, Mercury ayakkabısı');
    a = A('Jinx', ['Ahri', 'Darius'], 'bot'); ok(sec(a, 'armor').pri === 'mid' && sec(a, 'mr').pri === 'mid' && sec(a, 'boots').items.length === 2 && sec(a, 'boots').pri === 'mid' && a.partial === true, 'eşya: karışık hasarda hem zırh hem büyü direnci "olabilir"; az rakip → partial');
    a = A('Jinx', ['Zed', 'Darius', 'Garen'], 'bot'); ok(a.partial === false, 'eşya: 3 rakipte partial değil');
    a = A('Jinx', ['Soraka', 'Aatrox', 'Zed'], 'bot'); ok(sec(a, 'antiheal').pri === 'high' && idsOf(sec(a, 'antiheal')) === '3010,3012' && sec(a, 'antiheal').why[0].v[0] === 'Soraka, Aatrox', 'eşya: 2 iyileşmeli rakipte yara azaltma öncelikli, AD için AP eşya yok');
    a = A('Ahri', ['Soraka', 'Darius', 'Zed'], 'mid'); ok(sec(a, 'antiheal').pri === 'mid' && idsOf(sec(a, 'antiheal')) === '3011,3012', 'eşya: 1 iyileşmeli rakip → "olabilir"; AP şampiyon AP yara azaltma eşyası görür');
    a = A('Jinx', ['Darius'], 'support'); ok(a.support === true && a.sections.length === 0, 'eşya: destek hattında öneri yok (not döner)');
    a = A('Jinx', [], 'bot'); ok(a.sections.length === 0 && a.profile.n === 0, 'eşya: rakip yoksa bölüm yok'); ok(A('Yok', ['Zed'], 'bot') === null, 'eşya: bilinmeyen şampiyon → null');
    const tn = L.buildItemAdvice(R2, 'Jinx', ['Zed', 'Darius', 'Garen'], 'bot', items, { 3001: 'Savaşçı Plaka' }, '16.21.1'); ok(tn.sections[0].items[0].name === 'Savaşçı Plaka' && tn.sections[0].items[1].name === 'Guardian Mail', 'eşya: yerel ad varsa o, yoksa İngilizce ad'); }
  { const dir = path.join(tmp, 'esya'); calls = []; const hi = mkHost({}, dir); const HI = hi.handlers;
    let ri = await HI['lol:items']({ me: 'Jinx', role: 'bot', enemies: ['Zed', 'Darius', 'Garen'] });
    ok(!ri.error && ri.version === '16.21.1' && ri.sections.length >= 2 && ri.sections[0].items[0].name === 'Savaşçı Plaka', 'lol:items: sürüm + yerel (tr_TR) eşya adı');
    ok(calls.some((c) => /\/data\/en_US\/item\.json$/.test(c)) && calls.some((c) => /\/data\/tr_TR\/item\.json$/.test(c)), 'lol:items: mantık için en_US, ad için yerel dil indirilir');
    const n0 = calls.length; ri = await HI['lol:items']({ me: 'Ahri', enemies: ['Zed', 'Jinx'] }); ok(!ri.error && calls.length === n0, 'lol:items: ikinci çağrı bellekten (ağ yok)');
    ok((await HI['lol:items']({ me: '../x', enemies: ['Zed'] })).error === 'lol' && (await HI['lol:items']({ me: 'Jinx', enemies: [] })).error === 'lol' && (await HI['lol:items']({ me: 'Jinx', enemies: 'Zed' })).error === 'lol' && (await HI['lol:items']({ me: 'Jinx', role: 'x', enemies: ['Zed'] })).error === 'lol', 'lol:items: geçersiz şampiyon/rol/boş rakip reddedilir');
    ri = await HI['lol:items']({ me: 'Jinx', enemies: ['../etc', 'Zed', 'Yok', 'Darius', 'Garen', 'Teemo', 'Ahri', 'Lux'] }); ok(!ri.error && ri.enemies.length <= 5 && ri.enemies.every((x) => /^[A-Za-z0-9]+$/.test(x)), 'lol:items: rakip listesi 5 ile sınırlı, geçersiz kimlikler elenir');
    offline = true; const hj = mkHost({}, dir); const rj = await hj.handlers['lol:items']({ me: 'Jinx', role: 'bot', enemies: ['Zed', 'Darius', 'Garen'] }); ok(!rj.error && rj.sections.length >= 2 && rj.sections[0].items[0].name === 'Savaşçı Plaka', 'lol:items: çevrimdışıyken önbellekten çalışır (adlar dahil)'); offline = false;
    const dir2 = path.join(tmp, 'esya-yok'); const hk = mkHost({}, dir2); await hk.handlers['lol:status'](); itemsFail = true; const rk = await hk.handlers['lol:items']({ me: 'Jinx', role: 'bot', enemies: ['Zed'] }); ok(rk.error === 'lol' && /Eşya verisi alınamadı/.test(rk.message), 'lol:items: veri yok + ağ hatası → anlaşılır hata, çökme yok'); itemsFail = false; }
  // ---- başka oyuncu profili (sentetik LCU; gerçek istemciyle DENENMEDİ)
  { const OP = 'OTHERpuuid_abcdefghijklmnopqrstuvwxyz0123456789'; const pcalls = [];
    const pgm = (id, win, champId, queueId) => ({ gameId: id, gameCreation: T0 - id * 1000, gameDuration: 1800, queueId: queueId || 420, participants: [{ participantId: 1, teamId: 100, championId: champId, stats: { win, kills: 5, deaths: 2, assists: 7, totalMinionsKilled: 180, neutralMinionsKilled: 10, goldEarned: 12000, totalDamageDealtToChampions: 20000, visionScore: 20, champLevel: 16 }, timeline: { lane: 'TOP', role: 'SOLO' } }], participantIdentities: [{ participantId: 1, player: { puuid: OP, gameName: 'Rakip', tagLine: 'TR1' } }] });
    const PG = [pgm(11, true, 122), pgm(12, false, 122), pgm(13, true, 86, 450)]; const FR = [{ puuid: OP, gameName: 'Rakip', gameTag: 'TR1', icon: 5, availability: 'chat' }, { puuid: 'x', gameName: 'Bozuk' }, { puuid: 'FRIEND_puuid_abcdefghijklmnopqrstuvwxyz012', gameName: 'Cevrimdisi', gameTag: 'EUW', availability: 'offline' }];
    const pl = mkHost({ now: () => T0, lcu: { find: async () => ({ port: 9, token: 'abcdefgh1234' }), get: async (i, pth) => { pcalls.push(pth);
      if (pth.startsWith('/lol-summoner/v1/alias/lookup')) { if (/gameName=Rakip&tagLine=TR1$/i.test(pth)) return { puuid: OP, gameName: 'Rakip', tagLine: 'TR1' }; throw new Error('HTTP 404'); }
      if (pth.startsWith('/lol-summoner/v1/summoners?name=')) throw new Error('HTTP 404'); if (pth.endsWith('/' + OP) && pth.includes('summoners-by-puuid-cached')) return { gameName: 'Rakip', tagLine: 'TR1', summonerLevel: 77, profileIconId: 5 };
      if (pth === '/lol-ranked/v1/ranked-stats/' + OP) return RANK; if (pth.includes('/products/lol/' + OP + '/matches')) return { games: { games: PG } }; if (pth === '/lol-chat/v1/friends') return FR; if (/games\/\d+$/.test(pth)) throw new Error('HTTP 404'); return null; } } }, path.join(tmp, 'player')); const HPL = pl.handlers; await HPL['lol:status']();
    ok((await HPL['lol:player:search']({ query: 'abc' })).state === 'badquery' && !pcalls.length, 'oyuncu ara: geçersiz kimlik → badquery, istemciye istek yok');
    ok((await HPL['lol:player:search']({ query: 'Yok#TR1' })).state === 'notfound', 'oyuncu ara: bulunamayan oyuncu → notfound');
    const ps = await HPL['lol:player:search']({ query: 'rakip#tr1' }); ok(ps.state === 'ok' && ps.player.name === 'Rakip' && ps.player.level === 77 && ps.rank.solo.tier === 'PLATINUM' && ps.counts.matches === 3 && ps.view.overview.games === 3 && ps.view.rows.length === 3 && ps.view.rows[0].champ === 'Darius', 'oyuncu ara: profil, derece, 3 maç, istatistikler');
    ok(pcalls.every((x) => L.LCU_OK.some((re) => re.test(x))), 'oyuncu ara: yalnız beyaz listedeki GET uç noktaları'); const nRank = pcalls.filter((x) => x.includes('ranked-stats')).length;
    const pc = await HPL['lol:player:search']({ puuid: OP }); ok(pc.state === 'ok' && pc.cached === true && pcalls.filter((x) => x.includes('ranked-stats')).length === nRank, 'oyuncu ara: ikinci arama bellek önbelleğinden (ağ yok)');
    const pv = await HPL['lol:player:view']({ puuid: OP, queue: 'aram' }); ok(pv.state === 'ok' && pv.view.total === 1 && pv.view.rows[0].champ === 'Garen', 'oyuncu görünümü: kuyruk filtresi önbellekte çalışır');
    ok((await HPL['lol:player:view']({ puuid: 'BILINMEYEN_puuid_abcdefghijklmnop' })).state === 'expired', 'oyuncu görünümü: önbellekte yoksa expired');
    ok((await HPL['lol:player:search']({ puuid: 'kötü kimlik!' })).error, 'oyuncu ara: geçersiz puuid reddedilir');
    const stFile = path.join(tmp, 'player', 'lolcounter.json'); ok(!fs.existsSync(stFile) || !/Rakip|OTHERpuuid/.test(fs.readFileSync(stFile, 'utf8')), 'oyuncu ara: başkasının verisi diske YAZILMAZ');
    // ---- 'Bu filtrede maç yok' hatası: istemci başkasının geçmişini boş/farklı biçimde döndürürse sessizce 0 maç olmasın
    { const mkP = (matchesReply, rankReply) => { const calls2 = []; const h2 = mkHost({ now: () => T0, lcu: { find: async () => ({ port: 9, token: 'abcdefgh1234' }), get: async (i, pth) => { calls2.push(pth);
        if (pth.startsWith('/lol-summoner/v1/summoners-by-puuid-cached')) return { gameName: 'Rakip', tagLine: 'TR1', summonerLevel: 77, profileIconId: 5 };
        if (pth === '/lol-ranked/v1/ranked-stats/' + OP) return rankReply; if (pth.includes('/products/lol/' + OP + '/matches')) return typeof matchesReply === 'function' ? matchesReply(pth) : matchesReply; return null; } } }, path.join(tmp, 'player-x' + Math.random().toString(36).slice(2))); return { h: h2.handlers, calls: calls2 }; };
      // 1) istemci 404/boş döndürür (lcuGet null verir): 0 maç + sebep notu + önbelleğe alınmaz, yeniden arama gerçekten yeniden dener
      let X = mkP(null, RANK); await X.h['lol:status'](); let r1 = await X.h['lol:player:search']({ puuid: OP });
      ok(r1.state === 'ok' && r1.counts.matches === 0 && r1.notes.some((x) => /^maçlar/.test(x)), 'oyuncu ara: istemci maç geçmişini vermezse (null) sebep notu döner, sessiz "0 maç" olmaz');
      const n1 = X.calls.filter((x) => x.includes('/matches')).length; r1 = await X.h['lol:player:search']({ puuid: OP }); ok(r1.cached === false && X.calls.filter((x) => x.includes('/matches')).length > n1, 'oyuncu ara: maçsız sonuç önbelleğe takılmaz, yeniden arama yeniden dener');
      // 2) maç listesi doğrudan dizi olarak gelirse de okunur
      X = mkP({ games: PG }, RANK); await X.h['lol:status'](); let r2 = await X.h['lol:player:search']({ puuid: OP }); ok(r2.state === 'ok' && r2.counts.matches === 3 && !r2.notes.some((x) => /^maçlar/.test(x)), 'oyuncu ara: games dizi biçiminde gelirse maçlar okunur');
      // 3) tanınmayan yanıt biçimi: sebep nota yazılır
      X = mkP({ foo: 1 }, RANK); await X.h['lol:status'](); let r3 = await X.h['lol:player:search']({ puuid: OP }); ok(r3.counts.matches === 0 && r3.notes.some((x) => /biçimi tanınmadı/.test(x)), 'oyuncu ara: tanınmayan yanıt biçimi nota yazılır');
      // 4) istemci kayıp sayısı vermezse '%100 WR, 0M' uydurulmaz
      X = mkP({ games: { games: PG } }, { queues: [{ queueType: 'RANKED_SOLO_5x5', tier: 'SILVER', division: 'II', leaguePoints: 52, wins: 110 }] }); await X.h['lol:status'](); let r4 = await X.h['lol:player:search']({ puuid: OP });
      ok(r4.rank.solo && r4.rank.solo.noL === true && r4.rank.solo.w === 110, 'oyuncu ara: losses alanı yoksa derece noL ile işaretlenir (uydurma 0M yok)');
      ok(!('noL' in (L.parseRanked({ queues: [{ queueType: 'RANKED_SOLO_5x5', tier: 'GOLD', division: 'I', leaguePoints: 10, wins: 5, losses: 3 }] }).solo)), 'derece: losses varsa noL işareti yok (kendi profil davranışı değişmedi)'); }
    // ---- zaman aşımı: başkasının maç geçmişi yavaş gelir -> uzun süre + 1 yeniden deneme; ve 0 kayıplı derece 'bilinmiyor'
    { const msSeen = []; let tries = 0; let failAll = false; const hT = mkHost({ now: () => T0, lcu: { find: async () => ({ port: 9, token: 'abcdefgh1234' }), get: async (i, pth, ms) => {
        if (pth.startsWith('/lol-summoner/v1/summoners-by-puuid-cached')) return { gameName: 'Rakip', tagLine: 'TR1', summonerLevel: 77, profileIconId: 5 };
        if (pth === '/lol-ranked/v1/ranked-stats/' + OP) return { queues: [{ queueType: 'RANKED_SOLO_5x5', tier: 'SILVER', division: 'II', leaguePoints: 61, wins: 185, losses: 0 }, { queueType: 'RANKED_FLEX_SR', tier: 'GOLD', division: 'IV', leaguePoints: 5, wins: 3, losses: 0 }] };
        if (pth.includes('/products/lol/' + OP + '/matches')) { msSeen.push(ms); tries++; if (failAll || tries === 1) throw new Error('zaman aşımı'); return { games: { games: PG } }; } return null; } } }, path.join(tmp, 'player-slow')); await hT.handlers['lol:status']();
      const rT = await hT.handlers['lol:player:search']({ puuid: OP });
      ok(rT.state === 'ok' && rT.counts.matches === 3 && tries === 2, 'oyuncu ara: maç listesi zaman aşımında bir kez yeniden denenir ve başarırsa maçlar gelir');
      ok(msSeen.length === 2 && msSeen.every((x) => x >= 10000), 'oyuncu ara: başkasının maç geçmişi için uzun zaman aşımı istenir (varsayılan 4 sn değil)');
      ok(rT.rank.solo.noL === true && !rT.rank.flex.noL, 'oyuncu ara: 10+ galibiyet ve 0 kayıp → noL (uydurma %100 WR yok); az maçta işaretlenmez');
      failAll = true; const rT2 = await hT.handlers['lol:player:search']({ puuid: OP, fresh: true }); ok(rT2.counts.matches === 0 && rT2.notes.some((x) => /zaman aşımı/.test(x)), 'oyuncu ara: iki deneme de zaman aşımına uğrarsa sebep nota yazılır'); }
    const fr = await HPL['lol:friends'](); ok(fr.state === 'ok' && fr.friends.length === 2 && fr.friends[0].name === 'Rakip' && fr.friends[1].name === 'Cevrimdisi', 'arkadaşlar: bozuk kayıt atılır, çevrimiçi olanlar önce');
    ok(L.parsePlayerQuery('Rakip#TR1').tag === 'TR1' && L.parsePlayerQuery('Ad Soyad#TR1').name === 'Ad Soyad' && !L.parsePlayerQuery('a#b') && !L.parsePlayerQuery('#TAG1') && !L.parsePlayerQuery('x'.repeat(30) + '#TR1') && !L.parsePlayerQuery('Ad%#TR1') && !L.parsePlayerQuery(null), 'Riot Kimliği ayrıştırma: geçerli/geçersiz biçimler');
    ok(L.LCU_OK.some((re) => re.test('/lol-summoner/v1/alias/lookup?gameName=Rakip&tagLine=TR1')) && !L.LCU_OK.some((re) => re.test('/lol-summoner/v1/summoners?name=a/../b')) && !L.LCU_OK.some((re) => re.test('/lol-match-history/v1/products/lol/' + OP + '/matches?begIndex=0&endIndex=20&x=1')), 'LCU beyaz liste: oyuncu uçları yalnız kesin kalıplar'); }
  // ---- rün kaynakları: metinden rün, ters yön, kendi maç geçmişi (sentetik; gerçek site/istemciyle DENENMEDİ)
  { const T = L.parseCpMatchup('<p>VS 48.2% 769 games</p><h2>Runes</h2><p>Rune 8010 Rune 9111 Rune 9104 Rune 8299 Rune 8444 Rune 8473</p>'); ok(T && T.wr === 48.2 && T.games === 769 && T.runes && T.runes.perks.join() === '8010,9111,9104,8299,8444,8473', 'cp: rün kimlikleri görsel yoksa “Rune <id>” metninden okunur');
    ok(L.parseCpMatchup('<p>VS 48.2% 769 games</p><h2>Runes</h2><p>Rune 8010 Rune 9111</p>').runes === null, 'cp: 6’dan az rün metni → rün yok (uydurulmaz)');
    const mkR = (n) => ({ perks: [8010, 9111, 9104, 8299, 8444, 8473].map((x, i) => (i === 0 ? n : x)), primary: 8000, secondary: 8400 });
    const mm = {}; const add = (id, champ, opp, win, role, rn) => { mm[id] = { id, champ, opp, win, role, queue: 'solo', remake: false, runes: rn }; };
    add(1, 'Darius', 'Garen', true, 'top', mkR(8010)); add(2, 'Darius', 'Garen', false, 'top', mkR(8010)); add(3, 'Darius', 'Teemo', true, 'top', mkR(8021)); add(4, 'Darius', 'Zed', true, 'top', mkR(8021));
    let hr = L.histRunes(mm, 'Darius', 'Garen', 'top'); ok(hr.state === 'ok' && hr.scope === 'vs' && hr.games === 2, 'geçmiş rünü: bu eşleşmede ≥2 maç varsa eşleşmeye özel');
    hr = L.histRunes(mm, 'Darius', 'Ahri', 'top'); ok(hr.state === 'ok' && hr.scope === 'champ' && hr.total === 4 && hr.runes.perks[0] === 8021, 'geçmiş rünü: yoksa şampiyon+hat, en iyi Wilson alt sınırı');
    ok(L.histRunes(mm, 'Jinx', 'Zed', 'bot').state === 'none' && L.histRunes({ 9: { champ: 'Jinx', win: true, queue: 'solo' } }, 'Jinx', 'Zed', 'bot').state === 'sync', 'geçmiş rünü: kayıt yok → none; rün alanı hiç yoksa → sync (senkron gerek)');
    ok(L.histRunes({ 1: mm[1] }, 'Darius', 'Ahri', 'top').state === 'few', 'geçmiş rünü: az maç → few'); }
  { cpCalls.length = 0; cpPages = { '/matchup/garen-vs-darius/': '<p>VS 46.4% 800 games</p>', '/champion/garen/counters/': '<html></html>' }; confirmAns = true;
    const hr2 = mkHost({ cpDelay: 0 }, path.join(tmp, 'rev')); const HR = hr2.handlers; await HR['lol:status'](); await HR['lol:cp:set'](true);
    const sg = await HR['lol:runes:suggest']({ me: 'Darius', enemy: 'Garen', role: 'top' }); ok(!sg.error && sg.runes === null && sg.approx === true && sg.wr === 53.6 && sg.games === 800 && cpCalls.includes('/matchup/darius-vs-garen/') && cpCalls.includes('/matchup/garen-vs-darius/'), 'cp: ben-vs-rakip yoksa rakip-vs-ben denenir; oran 100 − x, rün yok');
    ok(Array.isArray(sg.tried) && sg.tried.some((x) => x.src === 'cp' && x.state === 'rev') && sg.tried.some((x) => x.src === 'hist') && sg.tried.some((x) => x.src === 'lcu'), 'runes:suggest: denenen kaynaklar ve neden bulunamadığı döner');
    const nCp = cpCalls.length; const hc2 = mkHost({}, path.join(tmp, 'rev2')); await hc2.handlers['lol:status'](); const sg2 = await hc2.handlers['lol:runes:suggest']({ me: 'Darius', enemy: 'Garen', role: 'top' }); ok(!sg2.error && sg2.runes === null && sg2.tried.find((x) => x.src === 'cp').state === 'off' && cpCalls.length === nCp, 'cp kapalıyken runes:suggest siteye istek göndermez, nedeni “off”'); }
  ok(L.LCU_OK.some((re) => re.test('/lol-perks/v1/recommended-pages/champion/122/position/top/map/11')) && !L.LCU_OK.some((re) => re.test('/lol-perks/v1/recommended-pages/champion/122/position/top/map/11/x')), 'LCU beyaz liste: yalnız önerilen rün sayfası GET kalıbı eklendi');
  // ---- rank kovaları: eşleşme verisi (kaynaktan bağımsız), 'Tüm ranklar' = Emerald+ oyun sayısıyla ağırlıklı
  { const raw = { matchup: { patch: '16.22', ranks: {
      iron: { games: 300, wr: 80, items: { core: [{ id: 3001, games: 50, wr: 90 }] } }, platinum: { games: 500, wr: 70, items: { core: [{ id: 3001, games: 400, wr: 70 }] } },
      emerald: { games: 400, wr: 50, items: { core: [{ id: 3001, games: 100, wr: 60 }, { id: 3003, games: 30, wr: 50 }], boots: [{ id: 3101, games: 80, wr: 55 }], start: [{ id: 3200, games: 20, wr: 50 }] } },
      diamond: { games: 100, wr: 60, items: { core: [{ id: 3001, games: 50, wr: 40 }, { id: 3002, games: 70, wr: 50 }], boots: [{ id: 3101, games: 40, wr: 45 }] } },
      master: { games: 50, wr: 40, items: { core: [{ id: 3003, games: 40, wr: 25 }] } } } } };
    const pm = L.parseMu(raw); ok(pm && pm.patch === '16.22' && Object.keys(pm.ranks).length === 5, 'parseMu: beş kova okunur, yama alınır');
    const al = L.aggMu(pm, 'all'); ok(al.games === 550 && al.wr === 50.9 && al.ranksUsed.join() === 'emerald,diamond,master' && al.missing.join() === 'grandmaster,challenger', 'Tüm ranklar = Emerald+: oyun sayısıyla ağırlıklı (400@50 + 100@60 + 50@40 → 550 maç, %50.9); Iron/Plat DAHİL DEĞİL');
    const c3001 = al.items.core.find((x) => x.id === '3001'); ok(c3001.games === 150 && c3001.wr === 53.3 && al.items.core[0].id === '3001', 'eşya toplama: aynı eşya kovalar arası toplanır (150 maç, %53.3), oyun sayısına göre sıralı');
    ok(al.items.core.find((x) => x.id === '3003').games === 70 && al.items.core.find((x) => x.id === '3003').wr === 35.7, 'eşya toplama: Emerald+Master (30@50 + 40@25 → %35.7)');
    const ir = L.aggMu(pm, 'iron'); ok(ir.games === 300 && ir.wr === 80 && ir.ranksUsed.join() === 'iron' && ir.items.core.length === 1, 'tek rank seçimi: yalnız o kova (Iron 300 maç %80)');
    ok(L.aggMu(pm, 'plat') === null && L.aggMu(pm, '../x') === null && L.aggMu(null, 'all') === null, 'aggMu: geçersiz rank/veri null');
    ok(L.aggMu(pm, 'challenger').empty === true && L.aggMu(pm, 'gold').empty === true, 'aggMu: kovası olmayan rank boş döner (uydurma yok)');
    ok(L.muRankSet('all').join() === L.MU_ALL.join() && L.MU_ALL.join() === 'emerald,diamond,master,grandmaster,challenger' && L.muRankSet('gold').join() === 'gold' && L.muRankSet('x') === null && L.MU_RANKS.length === 10, 'rank kümeleri: all = Emerald, Diamond, Master, Grandmaster, Challenger; 10 rank');
    const bad = { matchup: { patch: 'x<y', ranks: { emerald: { games: 10, wr: 50, items: { core: [{ id: '../x', games: 5, wr: 50 }, { id: 3001, games: 5, wr: 140 }, { id: 3001, games: -1, wr: 50 }, { id: 3002, games: 5, wr: 50 }] } }, godlike: { games: 5, wr: 50 }, gold: { games: 5, wr: 120 }, silver: 'x' } } };
    const pb = L.parseMu(bad); ok(pb && pb.patch === null && Object.keys(pb.ranks).join() === 'emerald' && pb.ranks.emerald.items.core.length === 1 && pb.ranks.emerald.items.core[0].id === '3002', 'parseMu: bozuk rank/oran/eşya/yama ayıklanır');
    ok(L.parseMu(null) === null && L.parseMu({}) === null && L.parseMu({ matchup: { ranks: {} } }) === null && L.parseMu({ matchup: { ranks: { emerald: { games: 'x', wr: 5 } } } }) === null, 'parseMu: şekil bozuksa null'); }

  // ---- host: eşleşme detayı (muUrl), rank seçimi, kişisel not, bindirme ayarı
  { const dir = path.join(tmp, 'mu'); const hm = mkHost({ muDelay: 0 }, dir); const HM = hm.handlers; await HM['lol:status']();
    let m0 = await HM['lol:mu']({ me: 'Kayle', enemy: 'Darius', role: 'top' }); ok(m0.state === 'off' && m0.configured === false && m0.rank === 'all' && m0.note === '', 'lol:mu: adres yokken state=off (tahmin YOK)');
    ok((await HM['lol:mu']({ me: '../x', enemy: 'Darius', role: 'top' })).error === 'lol' && (await HM['lol:mu']({ me: 'Kayle', enemy: 'Darius', role: 'mid2' })).error === 'lol', 'lol:mu: geçersiz şampiyon/rol reddedilir');
    ok((await HM['lol:mu:url:set']('http://mu.example.org/{me}/{enemy}')).error === 'lol' && (await HM['lol:mu:url:set']('https://mu.example.org/{enemy}')).error === 'lol' && (await HM['lol:mu:url:set']('https://localhost/{me}/{enemy}')).error === 'lol' && (await HM['lol:mu:url:set']('https://192.168.1.5/{me}/{enemy}')).error === 'lol' && (await HM['lol:mu:url:set']('https://u:p@mu.example.org/{me}/{enemy}')).error === 'lol', 'muUrl: http / {me} eksik / yerel ağ / kimlik bilgisi reddedilir');
    confirmAns = false; ok((await HM['lol:mu:url:set']('https://mu.example.org/{me}/{enemy}/{role}')).canceled === true && !(await HM['lol:mu:cfg']()).configured, 'muUrl: onay reddedilince kaydedilmez');
    confirmAns = true; const us = await HM['lol:mu:url:set']('https://mu.example.org/{me}/{enemy}/{role}'); ok(us.ok && us.host === 'mu.example.org' && /mu\.example\.org/.test(confirms[confirms.length - 1].message), 'muUrl: onay penceresi sunucuyu gösterir, kaydedilir');
    muBody = { matchup: { patch: '16.22', ranks: { emerald: { games: 400, wr: 50, items: { core: [{ id: 3001, games: 100, wr: 60 }, { id: 3999, games: 10, wr: 50 }], boots: [{ id: 3101, games: 80, wr: 55 }] } }, diamond: { games: 100, wr: 60, items: { core: [{ id: 3002, games: 70, wr: 50 }] } }, iron: { games: 300, wr: 80, items: {} } } } };
    const cfg0 = await HM['lol:mu:cfg'](); ok(cfg0.configured && cfg0.rank === 'all' && cfg0.host === 'mu.example.org' && cfg0.ranks.length === 10, 'lol:mu:cfg: adres, varsayılan rank=all');
    const m1 = await HM['lol:mu']({ me: 'Kayle', enemy: 'Darius', role: 'top' }); ok(m1.state === 'ok' && m1.rank === 'all' && m1.games === 500 && m1.wr === 52 && m1.patch === '16.22' && m1.ranksUsed.join() === 'emerald,diamond' && m1.src === 'url', 'lol:mu: Tüm ranklar → Emerald+ kovaları toplanır (500 maç %52), Iron dışarıda');
    ok(muCalls.length === 1 && /\/Kayle\/Darius\/top$/.test(muCalls[0]), 'lol:mu: istek şablona göre (ad/rakip/rol), tek istek');
    const nm = (id) => m1.items.core.concat(m1.items.boots).find((x) => x.id === id); ok(nm('3001').name === 'Savaşçı Plaka' && nm('3101').name === 'Merkür Çizme' && nm('3002').name === 'Guardian Mail' && nm('3999').name === null, 'lol:mu: eşya adı kimlikten (yerel dil → en_US → yok); kaynaktan metin alınmaz');
    await HM['lol:mu']({ me: 'Kayle', enemy: 'Darius', role: 'top', rank: 'iron' }); ok(muCalls.length === 1, 'lol:mu: önbellek (rank değişince yeniden istek yok)');
    const mi = await HM['lol:mu']({ me: 'Kayle', enemy: 'Darius', role: 'top', rank: 'iron' }); ok(mi.state === 'ok' && mi.games === 300 && mi.wr === 80 && mi.rank === 'iron', 'lol:mu: tek rank (Iron 300 maç)');
    const mg = await HM['lol:mu']({ me: 'Kayle', enemy: 'Darius', role: 'top', rank: 'challenger' }); ok(mg.state === 'norank' && mg.available.join() === 'iron,emerald,diamond' && mg.missing.includes('challenger'), 'lol:mu: seçilen rankta veri yoksa norank + mevcut rankler (uydurma yok)');
    ok((await HM['lol:mu:rank']('x')).error === 'lol' && (await HM['lol:mu:rank']('gold')).ok, 'lol:mu:rank: geçersiz reddedilir, geçerli kaydedilir');
    ok((await mkHost({ muDelay: 0 }, dir).handlers['lol:mu:cfg']()).rank === 'gold', 'rank seçimi yeniden açılışta korunur');
    ok((await HM['lol:mu']({ me: 'Kayle', enemy: 'Darius', role: 'top' })).rank === 'gold' && (await HM['lol:mu']({ me: 'Kayle', enemy: 'Darius', role: 'top', rank: 'bogus' })).rank === 'gold', 'lol:mu: rank verilmezse/geçersizse kayıtlı seçim');
    muBody = '404'; ok((await HM['lol:mu']({ me: 'Kayle', enemy: 'Garen', role: 'top' })).state === 'none', 'lol:mu: 404 → none');
    muBody = 'fail'; ok((await HM['lol:mu']({ me: 'Kayle', enemy: 'Teemo', role: 'top' })).state === 'net', 'lol:mu: ağ hatası → net (çökme yok)');
    muBody = { matchup: { ranks: {} } }; ok((await HM['lol:mu']({ me: 'Kayle', enemy: 'Zed', role: 'top' })).state === 'none', 'lol:mu: bozuk/boş yanıt → none');
    // kişisel not
    ok((await HM['lol:note:set']({ me: 'Ahri', enemy: 'Lux', role: 'mid', text: '  Q ile it, W sakla.  ' })).saved === true && (await HM['lol:mu']({ me: 'Ahri', enemy: 'Lux', role: 'mid' })).note === 'Q ile it, W sakla.', 'not: kaydedilir, lol:mu ile döner (veri yokken de)');
    ok((await HM['lol:mu']({ me: 'Lux', enemy: 'Ahri', role: 'mid' })).note === '' && (await HM['lol:mu']({ me: 'Ahri', enemy: 'Lux', role: 'top' })).note === '', 'not: eşleşme + rol anahtarlı (ters yön/başka rol karışmaz)');
    await HM['lol:note:set']({ me: 'Ahri', enemy: 'Lux', role: 'mid', text: 'x'.repeat(2000) }); ok((await HM['lol:mu']({ me: 'Ahri', enemy: 'Lux', role: 'mid' })).note.length === 600, 'not: en çok 600 karakter');
    ok((await mkHost({ muDelay: 0 }, dir).handlers['lol:mu']({ me: 'Ahri', enemy: 'Lux', role: 'mid' })).note.length === 600, 'not: yeniden açılışta korunur');
    ok((await HM['lol:note:set']({ me: 'Ahri', enemy: 'Lux', role: 'mid', text: '   ' })).saved === false && (await HM['lol:mu']({ me: 'Ahri', enemy: 'Lux', role: 'mid' })).note === '', 'not: boş metin notu siler');
    ok((await HM['lol:note:set']({ me: '../x', enemy: 'Lux', role: 'mid', text: 'a' })).error === 'lol' && (await HM['lol:note:set']({ me: 'Ahri', enemy: 'Lux', role: 'mid2', text: 'a' })).error === 'lol', 'not: geçersiz şampiyon/rol reddedilir');
    for (let i = 0; i < 4; i++) await HM['lol:note:set']({ me: 'Ahri', enemy: ['Zed', 'Garen', 'Teemo', 'Jinx'][i], role: 'mid', text: 'n' + i }); ok(Object.keys(hm._state().notes).length === 4, 'not: her eşleşme ayrı kayıt');
    // bindirme ayarı
    ok(JSON.stringify(await HM['lol:ov:get']()) === JSON.stringify({ on: false, secs: 20 }), 'bindirme: varsayılan KAPALI, 20 sn');
    ok((await HM['lol:ov:set']({ on: true, secs: 500 })).secs === 60 && (await HM['lol:ov:set']({ secs: 1 })).secs === 8 && (await HM['lol:ov:set']({ on: 'evet' })).on === true, 'bindirme: süre 8–60 sn arasına sıkışır, boolean olmayan açma değeri yok sayılır');
    ok((await mkHost({ muDelay: 0 }, dir).handlers['lol:ov:get']()).on === true, 'bindirme: ayar yeniden açılışta korunur');
    const rawState = JSON.parse(fs.readFileSync(path.join(dir, 'lolcounter.json'), 'utf8')); ok(!/mu\.example\.org\/Kayle|Savaşçı/.test(JSON.stringify(rawState)), 'diske eşleşme verisi/eşya adı yazılmaz (yalnız adres, rank, not, bindirme ayarı)'); }

  // ---- maç açılış bindirmesi: karar + sayfa
  { const live = { state: 'ingame', classic: true, me: { champ: 'Ahri' }, matchup: { enemy: 'Veigar', role: 'mid' } };
    const d1 = L.overlayDecide(false, { on: true }, live); ok(d1.inGame && d1.open, 'bindirme: oyun dışından oyuna geçişte açılır');
    const d2 = L.overlayDecide(true, { on: true }, live); ok(d2.inGame && !d2.open, 'bindirme: oyun sürerken tekrar açılmaz');
    ok(!L.overlayDecide(false, { on: false }, live).open, 'bindirme: kapalıyken açılmaz');
    ok(!L.overlayDecide(false, { on: true }, { state: 'nogame' }).inGame, 'bindirme: maç yokken oyunda sayılmaz');
    ok(!L.overlayDecide(false, { on: true }, Object.assign({}, live, { classic: false })).open, 'bindirme: Summoner’s Rift dışı modda açılmaz');
    ok(!L.overlayDecide(false, { on: true }, Object.assign({}, live, { matchup: null })).open, 'bindirme: rakip bilinmiyorsa açılmaz');
    ok(!L.overlayDecide(false, null, null).open, 'bindirme: boş girdide çökmez');
    const h = L.lolOverlayHtml(999); ok(/SECS=60/.test(h) && /Content-Security-Policy/.test(h) && !/https?:\/\//.test(h), 'bindirme sayfası: süre 60 ile sınırlı, CSP var, dış adres yok');
    ok(!/innerHTML|eval\(|fetch\(|XMLHttpRequest/.test(h), 'bindirme sayfası: innerHTML/eval/ağ çağrısı yok');
    ok(!/cooldown|bekleme|flash|çarp|\bult\b/i.test(h), 'bindirme sayfası: büyü/yetenek bekleme sayacı yok'); }
  // ---- Riot API (istemci kapaliyken): sahte Riot, gercek ag yok
  { const KEY = 'RGAPI-e9b4a092-2fba-4951-b69d-2320e9c025e4'; const rcalls = []; let rmode = 'ok';
    const mkMatch = (n, win) => ({ info: { gameCreation: 1.7e12 + n * 1e6, gameDuration: 1800, queueId: 420, participants: Array.from({ length: 10 }, (_, i) => ({ puuid: i === 0 ? 'PU-ME-' + 'x'.repeat(30) : 'PU-O' + i, riotIdGameName: i === 0 ? 'Ben' : 'Op' + i, riotIdTagline: 'TR1', teamId: i < 5 ? 100 : 200, championId: i === 0 ? 122 : 86, summoner1Id: 12, summoner2Id: 4, teamPosition: i === 0 ? 'TOP' : ['JUNGLE', 'MIDDLE', 'BOTTOM', 'UTILITY'][i % 4], kills: 7, deaths: 2, assists: 5, totalMinionsKilled: 180, neutralMinionsKilled: 10, goldEarned: 12000, totalDamageDealtToChampions: 20000, visionScore: 25, champLevel: 16, win: i < 5 ? win : !win, item0: 3001, item1: 0, item2: 0, item3: 0, item4: 0, item5: 0, item6: 3201, perks: { styles: [{ style: 8000, selections: [{ perk: 8010 }, { perk: 9111 }, { perk: 9104 }, { perk: 8014 }] }, { style: 8200, selections: [{ perk: 8226 }, { perk: 8210 }] }] } })) } });
    const rget = async (host, pth, key) => { rcalls.push(host + pth); if (key !== KEY) return { status: 401, body: null, retry: 0 }; if (rmode === '429') return { status: 429, body: null, retry: 10 }; if (rmode === '401') return { status: 401, body: null, retry: 0 };
      if (/by-riot-id\/Ben\/TR1$/.test(pth)) return { status: 200, body: { puuid: 'PU-ME-' + 'x'.repeat(30), gameName: 'Ben', tagLine: 'TR1' }, retry: 0 };
      if (/entries\/by-puuid/.test(pth)) return { status: 200, body: [{ queueType: 'RANKED_SOLO_5x5', tier: 'GOLD', rank: 'II', leaguePoints: 47, wins: 30, losses: 20 }], retry: 0 };
      if (/matches\/by-puuid\/.+\/ids/.test(pth)) return { status: 200, body: ['TR1_1000000001', 'TR1_1000000002'], retry: 0 };
      const m = /matches\/TR1_(\d+)$/.exec(pth); if (m) return { status: 200, body: mkMatch(Number(m[1]) % 10, m[1].endsWith('1')), retry: 0 }; return { status: 404, body: null, retry: 0 }; };
    const dd = path.join(tmp, 'riot'); const hr = mkHost({ now: () => NOW, lcu: { find: async () => null }, riot: { get: rget } }, dd);
    ok((await hr.handlers['lol:sync']({})).state === 'noclient', 'riot: anahtar yok + istemci yok → noclient');
    ok((await hr.handlers['lol:riot:set']({ key: 'bozuk' })).error, 'riot: geçersiz anahtar biçimi reddedilir');
    ok((await hr.handlers['lol:riot:set']({ id: 'bozukid' })).error, 'riot: geçersiz Riot Kimliği reddedilir');
    ok((await hr.handlers['lol:riot:set']({ region: '../evil' })).error, 'riot: geçersiz bölge reddedilir');
    const sv = await hr.handlers['lol:riot:set']({ key: KEY, id: 'Ben#TR1', region: 'tr1' }); ok(sv.ok && sv.hasKey, 'riot: kaydedildi');
    const gj = JSON.stringify(await hr.handlers['lol:riot:get']()); ok(!gj.includes('RGAPI') && !gj.includes(KEY.slice(6)), 'riot: anahtar arayüze geri DÖNMEZ');
    const f = path.join(dd, 'lolriot.json'); ok(fs.existsSync(f) && (process.platform === 'win32' || (fs.statSync(f).mode & 0o077) === 0), 'riot: ayar dosyası yalnız sahibine açık');
    const r1 = await hr.handlers['lol:sync']({}); ok(r1.state === 'ok' && r1.source === 'riot' && r1.added === 2 && r1.snaps >= 1, 'riot: istemci kapalıyken senkron: 2 maç + derece (' + JSON.stringify(r1.notes) + ')');
    const pr = await hr.handlers['lol:profile'](); ok(pr.rank && pr.rank.solo && pr.rank.solo.tier === 'GOLD' && pr.rank.solo.div === 'II' && pr.rank.solo.lp === 47 && pr.matches === 2 && pr.me.name === 'Ben', 'riot: profil derece (GOLD II 47 LP) + 2 maç');
    const ml = await hr.handlers['lol:matches']({}); ok(ml.rows.length === 2 && ml.rows[0].champ === 'Darius' && ml.rows[0].role === 'top' && ml.rows[0].k === 7 && ml.rows[0].queue === 'solo' && ml.rows[0].runes && ml.rows[0].runes.perks.length === 6, 'riot: maç biçimi (şampiyon/hat/KDA/kuyruk/rün) LCU maçıyla aynı');
    ok(JSON.stringify(ml.rows[0].spells) === '[12,4]', 'Riot match-v5: summoner1Id/2Id D/F sırasıyla saklanır');
    const n1 = rcalls.length; const r2 = await hr.handlers['lol:sync']({}); ok(r2.throttled === true && rcalls.length === n1, 'riot: 2 dakikadan sık istek atılmaz (3 sn otomatik yenileme Riot\'u yormaz)');
    const r3 = await hr.handlers['lol:sync']({ force: true }); ok(r3.added === 0 && rcalls.filter((c) => /matches\/TR1_/.test(c)).length === 2, 'riot: aynı maç iki kez indirilmez/eklenmez');
    ok(rcalls.every((c) => /^(europe|tr1)\.api\.riotgames\.com\//.test(c)), 'riot: yalnız beklenen Riot adreslerine gidildi');
    const oldStore = JSON.parse(fs.readFileSync(path.join(dd,'lolcounter.json'),'utf8')); for(const m of Object.values(oldStore.matches)) delete m.spells; fs.writeFileSync(path.join(dd,'lolcounter.json'), JSON.stringify(oldStore));
    const backfill = mkHost({now:()=>NOW,lcu:{find:async()=>null},riot:{get:rget}},dd); const br=await backfill.handlers['lol:sync']({force:true}); const bm=await backfill.handlers['lol:matches']({});
    ok(br.added===0 && br.updated===2 && bm.rows.every((m)=>JSON.stringify(m.spells)==='[12,4]'), 'eski Riot kaydı: büyüler tamamlanır, maçlar yeniden eklenmiş sayılmaz');
    rmode = '401'; const r4 = await hr.handlers['lol:sync']({ force: true }); ok(r4.riotError && /geçersiz|süresi/.test(r4.riotError) && !JSON.stringify(r4).includes('RGAPI'), 'riot: 401 → anlaşılır hata, anahtar sızmaz');
    rmode = '429'; const r5 = await hr.handlers['lol:sync']({ force: true }); const n2 = rcalls.length; const r6 = await hr.handlers['lol:sync']({ force: true }); ok(r5.riotError && r6.throttled && rcalls.length === n2, 'riot: 429 → geri çekilme, yeniden vurmaz');
    const cl = await hr.handlers['lol:riot:set']({ clear: true }); ok(cl.ok && !cl.hasKey && (await hr.handlers['lol:sync']({})).state === 'noclient', 'riot: anahtar silinince yine noclient');
    const hr2 = mkHost({ now: () => NOW, lcu: { find: async () => null }, riot: { get: rget } }, dd); ok((await hr2.handlers['lol:riot:get']()).hasKey === false && (await hr2.handlers['lol:riot:get']()).id === 'Ben#TR1', 'riot: ayar yeniden açılışta korunur (silinen anahtar yok)');
  }
  // ---- host entegrasyonu: kanallar kayıtlı, arayüz yol/URL gönderemez
  const host = createHost({ service: { closeAll() {} }, lol: { dataDir: path.join(tmp, 'entegre'), get } });
  const chans = ['lol:status', 'lol:champs', 'lol:pool', 'lol:pool:set', 'lol:suggest', 'lol:tips', 'lol:log', 'lol:hist', 'lol:hist:undo', 'lol:hist:clear', 'lol:statsurl:get', 'lol:statsurl:set', 'lol:lcu', 'lol:items', 'lol:mu', 'lol:mu:cfg', 'lol:mu:rank', 'lol:mu:url:set', 'lol:note:set', 'lol:ov:get', 'lol:ov:set', 'lol:gold', 'lol:gold:get', 'lol:gold:set'];
  ok(chans.every((c) => typeof host.handlers[c] === 'function'), 'createHost: tüm lol kanalları kayıtlı');
  const hd = createHost({ service: { closeAll() {} }, lol: false }); ok(!hd.handlers['lol:status'], 'createHost: lol:false ile kanallar kapanır');
  const src = fs.readFileSync(path.join(__dirname, '../../app/desktop/host.js'), 'utf8'); const lolSrc = src.slice(src.indexOf('const LOLMOD'), src.indexOf("/* --- Oyun Ayarlayici (Kovan 'oyunayar'"));
  { const wSrc = lolSrc.replace(/\/\* LCU-WRITE-BEGIN[\s\S]*?LCU-WRITE-END \*\//, ''); const wc = [...wSrc.matchAll(/lcuWrite\(info, '(\w+)', ('[^']+')/g)]; const rest = wSrc.replace(/lcuWrite\(info, '(POST|DELETE)'/g, 'lcuWrite(info, X');
    ok(wc.length === 2 && wc.every((c) => /^'\/lol-perks\/v1\/pages(\/'|')/.test(c[2])) && !/\bPOST\b|\bPUT\b|method: 'DELETE'|\bPATCH\b/.test(rest), 'kaynak: LOLMOD’da tek yazma türü var: kendi rün sayfası (POST/DELETE yalnız /lol-perks/v1/pages); PUT/PATCH yok');
    ok(L.LCU_WRITE_OK.length === 2 && L.LCU_WRITE_OK.every(([m, re]) => ['POST', 'DELETE'].includes(m) && re.source.includes('lol-perks')) && !L.LCU_WRITE_OK.some(([m, re]) => re.test('/lol-champ-select/v1/session') || re.test('/lol-perks/v1/pages/1/x')), 'yazma beyaz listesi: yalnız rün sayfaları'); }
  ok(!/child_process'\)\.exec\(|\.spawn\(|ReadProcessMemory|WriteProcessMemory/.test(lolSrc), 'kaynak: LOLMOD oyun sürecine/belleğe dokunmaz');
  const pre = fs.readFileSync(path.join(__dirname, '../../app/desktop/preload.js'), 'utf8'); ok(/lolMu:/.test(pre) && /lolNoteSet/.test(pre) && !/lolMu:[^\n]*(url|path)/i.test(pre.split('\n').filter((l) => /lolMu:/.test(l)).join('\n')), 'preload: lolMu dar API (URL/yol göndermez)');
  ok(/lolStatsUrlSet/.test(pre) && !/lolSuggest:[^\n]*url/i.test(pre), 'preload: dar API var, öneri çağrısı URL taşımaz');
  console.log(bad ? '\n' + bad + ' BAŞARISIZ' : '\nhepsi geçti'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
