// Vanilla manifestlerinden surumler arasi doku yeniden adlandirma tablosu uretir -> src/engine/96-mcdata.js
// Kullanim: node tools/gen-mc-renames.mjs <manifest_dizini> [items.json]  (items.json: tools/gen-mc-items.sh ciktisi)
// Kural 1 (kanitli): eski yol B'de yok, yeni yol A'da yok ve ikisinin icerik ozeti (sha1) AYNI ve birebir eslesiyor.
// Kural 2 (orta): ayni dosya adi + ayni ust klasor ailesi (blocks->block, items->item) ve tek aday; icerik farkli olabilir.
// Eslesmeyenler "gone" (hedefte vanilla karsiligi yok / belirsiz) olarak listelenir; hicbiri tahmin edilmez.
import fs from 'node:fs';
const dir = process.argv[2]; const VERS = ['1.8.9', '1.9', '1.11', '1.13', '1.15', '1.16.2', '1.17', '1.18', '1.19', '1.19.3', '1.19.4', '1.20', '1.20.2', '1.20.3', '1.20.5', '1.21', '1.21.2', '1.21.4', '1.21.5', '1.21.6', '1.21.7', '1.21.9', '1.21.11', '26.1', '26.2', '26.3'];
const load = (v) => { const j = JSON.parse(fs.readFileSync(dir + '/' + v + '.json', 'utf8')).files; const o = {}; for (const [k, [, h]] of Object.entries(j)) if (/^textures\/.*\.png$/.test(k)) o[k.slice(9, -4)] = h; return o; };
const top = (p) => { const t = p.split('/')[0]; return t === 'blocks' ? 'block' : t === 'items' ? 'item' : t; };
const base = (p) => p.slice(p.lastIndexOf('/') + 1);

// Kural 3 (ad kuralı, elle): bilinen adlandırma desenleri; yalnızca eski yol A'da kaldırılmış VE üretilen yeni yol B'de gerçekten eklenmişse uygulanır (varlık doğrulaması).
const COLORS = { white: 'white', orange: 'orange', magenta: 'magenta', light_blue: 'light_blue', yellow: 'yellow', lime: 'lime', pink: 'pink', gray: 'gray', silver: 'light_gray', cyan: 'cyan', purple: 'purple', blue: 'blue', brown: 'brown', green: 'green', red: 'red', black: 'black' };
const NAMED = {
  '1.11>1.13': [
    [/^blocks\/wool_colored_(\w+)$/, (m) => COLORS[m[1]] ? 'block/' + COLORS[m[1]] + '_wool' : null],
    [/^blocks\/leaves_oak$/, () => 'block/oak_leaves'], [/^blocks\/leaves_birch$/, () => 'block/birch_leaves'], [/^blocks\/leaves_big_oak$/, () => 'block/dark_oak_leaves'],
    [/^blocks\/(carrots|potatoes|beetroots)_stage_(\d)$/, (m) => 'block/' + m[1] + '_stage' + m[2]],
    [/^blocks\/noteblock$/, () => 'block/note_block'], [/^blocks\/farmland_dry$/, () => 'block/farmland'],
    [/^blocks\/(melon|pumpkin)_stem_connected$/, (m) => 'block/attached_' + m[1] + '_stem'], [/^blocks\/(melon|pumpkin)_stem_disconnected$/, (m) => 'block/' + m[1] + '_stem'],
    [/^blocks\/observer_back_lit$/, () => 'block/observer_back_on']
  ],
  '1.13>1.15': [[/^item\/cactus_green$/, () => 'item/green_dye'], [/^item\/dandelion_yellow$/, () => 'item/yellow_dye'], [/^item\/rose_red$/, () => 'item/red_dye'], [/^item\/sign$/, () => 'item/oak_sign']],
  '1.15>1.16.2': [[/^entity\/zombie_pigman$/, () => 'entity/piglin/zombified_piglin']],
  '1.21.4>1.21.5': [[/^entity\/cow\/cow$/, () => 'entity/cow/temperate_cow'], [/^entity\/pig\/pig$/, () => 'entity/pig/temperate_pig']]
};
const steps = {}; let totals = { strong: 0, mod: 0, named: 0, gone: 0 };
for (let i = 0; i + 1 < VERS.length; i++) {
  const A = load(VERS[i]), B = load(VERS[i + 1]); const rem = Object.keys(A).filter((p) => !(p in B)), add = Object.keys(B).filter((p) => !(p in A));
  const claimedNew = new Set(), pairs = new Map(); const hr = new Map(), ha = new Map();
  for (const p of rem) (hr.get(A[p]) || hr.set(A[p], []).get(A[p])).push(p); for (const p of add) (ha.get(B[p]) || ha.set(B[p], []).get(B[p])).push(p);
  const strong = [], mod = [];
  for (const [h, R] of hr) { const Ad = ha.get(h); if (!Ad) continue; if (R.length === 1 && Ad.length === 1) { strong.push([R[0], Ad[0]]); pairs.set(R[0], 1); claimedNew.add(Ad[0]); } else if (R.length > 1 || Ad.length > 1) { for (const r of R) { const c = Ad.filter((a) => base(a) === base(r) && !claimedNew.has(a)); if (c.length === 1 && R.filter((x) => base(x) === base(r)).length === 1) { strong.push([r, c[0]]); pairs.set(r, 1); claimedNew.add(c[0]); } } } }
  const addLeft = add.filter((p) => !claimedNew.has(p)); const byBase = new Map(); for (const p of addLeft) (byBase.get(base(p)) || byBase.set(base(p), []).get(base(p))).push(p);
  const remLeft = rem.filter((p) => !pairs.has(p)); const remBase = new Map(); for (const p of remLeft) (remBase.get(base(p)) || remBase.set(base(p), []).get(base(p))).push(p);
  for (const r of remLeft) { const c = (byBase.get(base(r)) || []).filter((a) => top(a) === top(r) && !claimedNew.has(a)); if (c.length === 1 && (remBase.get(base(r)) || []).filter((x) => top(x) === top(r)).length === 1) { mod.push([r, c[0]]); pairs.set(r, 1); claimedNew.add(c[0]); } }
  const named = []; const addFree = new Set(add.filter((p) => !claimedNew.has(p)));
  for (const r of rem) { if (pairs.has(r)) continue; for (const [re, fn] of NAMED[VERS[i] + '>' + VERS[i + 1]] || []) { const m = re.exec(r); if (!m) continue; const c = fn(m); if (c && addFree.has(c)) { named.push([r, c]); pairs.set(r, 1); claimedNew.add(c); addFree.delete(c); break; } } }
  const gone = rem.filter((p) => !pairs.has(p)); const enc = (l) => l.sort((x, y) => x[0] < y[0] ? -1 : 1).map(([a, b]) => a + '>' + b).join('\n');
  steps[VERS[i] + '>' + VERS[i + 1]] = { s: enc(strong), m: enc(mod), n: enc(named), g: gone.sort().join('\n') }; totals.strong += strong.length; totals.mod += mod.length; totals.named += named.length; totals.gone += gone.length;
  console.log(VERS[i].padEnd(8), '->', VERS[i + 1].padEnd(8), 'kanıtlı', String(strong.length).padStart(5), 'orta', String(mod.length).padStart(4), 'ad-kuralı', String(named.length).padStart(3), 'eşleşmeyen', String(gone.length).padStart(4), '| eklenen', add.length, 'kaldırılan', rem.length);
}
const itemsFile = process.argv[3]; const ic = {}; if (itemsFile) { const j = JSON.parse(fs.readFileSync(itemsFile, 'utf8')); for (const [v, o] of Object.entries(j)) ic[v] = o.complex.filter((n) => !n.startsWith('_')).join(' '); }
const out = '/* 4.x: UCRETSIZ vanilla manifestlerinden uretildi (tools/gen-mc-renames.mjs). Elle DUZENLEME. s=icerik eslesmesi (kanitli), m=ad eslesmesi (orta), g=hedefte karsiligi olmayan/belirsiz. Yollar textures/ ve .png olmadan. */\nconst MC_STEPS = ' + JSON.stringify(steps) + ';\n/* 1.21.4+ item tanimlari: yalnizca BASIT model olmayan (tint/ozel mantik tasiyan) vanilla ogeler. */\nconst MC_ITEMS_COMPLEX = ' + JSON.stringify(ic) + ';\nconst MC_STEP_ORDER = ' + JSON.stringify(VERS) + ';\n';
fs.writeFileSync(new URL('../src/engine/96-mcdata.js', import.meta.url), out); console.log('toplam', totals, 'bayt', out.length);
