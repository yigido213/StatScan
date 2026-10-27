// 98-mcconv: kaynak paketi donusturucu — sentetik paketler, cikti yollari hedef sürüm manifestinde olmali
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { spawnSync } from 'node:child_process'; import { loadEngine } from './engine.mjs';
const E = loadEngine(); let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const enc = (s) => new TextEncoder().encode(s); const dec = (u) => new TextDecoder().decode(u);
const MF = process.argv[2] || '/tmp/claude-0/-home-claude/524379be-6697-54a3-bccb-d78e73a409ac/scratchpad/manifests';
const man = (v) => { const j = JSON.parse(fs.readFileSync(MF + '/' + v + '.json', 'utf8')); return new Set(Object.keys(j.files).map((k) => 'assets/minecraft/' + k)); };
async function mk(files) { return E.mzWrite(Object.entries(files).map(([n, d]) => ({ name: n, data: typeof d === 'string' ? enc(d) : d }))); }
const png = (s) => enc('\x89PNG' + s); const rd = async (u8) => { const z = E.mzRead(u8); const m = {}; for (const e of z.entries) if (!e.isDir) m[e.name] = await E.mzData(z, e); return m; };
const T = 'assets/minecraft/textures/';
// 1) 1.12 -> 1.21.4
{
  const m11 = man('1.11'); const pick = [...m11].filter((p) => /^assets\/minecraft\/textures\/blocks\/(dirt|stone|anvil_base|log_oak)\.png$/.test(p)); console.log('örnek:', pick.length);
  const pk = await mk({ 'pack.mcmeta': '{"pack":{"pack_format":3,"description":"t"}}', [T + 'blocks/dirt.png']: png('d'), [T + 'blocks/anvil_base.png']: png('a'), [T + 'items/apple.png']: png('p'), [T + 'misc/custom.png']: png('c'),
    'assets/minecraft/models/block/foo.json': JSON.stringify({ textures: { all: 'blocks/dirt', p: 'minecraft:blocks/anvil_base', r: '#all' } }) });
  const r = await E.mcConvertPack(pk, { src: '1.11', dst: '1.21.4', name: 'x.zip' }); ok(r.ok, '1.11→1.21.4 başarılı ' + (r.reason || ''));
  const f = await rd(r.out); const names = Object.keys(f); const m214 = man('1.21.4');
  ok(f[T + 'block/dirt.png'] && !f[T + 'blocks/dirt.png'], 'blocks/dirt → block/dirt');
  ok(f[T + 'item/apple.png'], 'items/apple → item/apple');
  ok(f[T + 'misc/custom.png'], 'bilinmeyen özel doku dokunulmadı');
  ok(names.filter((n) => n.startsWith(T) && n !== T + 'misc/custom.png').every((n) => m214.has(n)), 'çevrilen vanilla yolları hedef manifestte var: ' + names.filter((n) => n.startsWith(T) && !m214.has(n)).join(','));
  const mod = JSON.parse(dec(f['assets/minecraft/models/block/foo.json'])); ok(mod.textures.all === 'block/dirt' && mod.textures.p === 'minecraft:block/anvil' && mod.textures.r === '#all', 'model dokü başvuruları yazıldı, #ref korundu: ' + JSON.stringify(mod.textures));
  const mm = JSON.parse(dec(f['pack.mcmeta'])); ok(mm.pack.pack_format === 46 && mm.pack.min_format === undefined && mm.pack.description === 't', 'pack.mcmeta: 46, açıklama korundu');
  ok(dec(f[T + 'block/dirt.png']) === '\x89PNGd', 'doku baytları aynı');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mc-')); fs.writeFileSync(dir + '/o.zip', r.out); ok(spawnSync('unzip', ['-t', dir + '/o.zip']).status === 0, 'unzip -t temiz'); fs.rmSync(dir, { recursive: true });
  ok(/Yeniden adlandırmalar/.test(E.mcReportText(r.report, 'x.zip')), 'rapor üretildi');
}
// 2) mcmeta sözdizimi
{
  const mkp = (o) => mk({ 'pack.mcmeta': JSON.stringify(o), [T + 'block/stone.png']: png('s') });
  let r = await E.mcConvertPack(await mkp({ pack: { pack_format: 18, supported_formats: [15, 18], description: 'x' } }), { src: '1.20.2', dst: '1.21.9' }); let mm = JSON.parse(dec((await rd(r.out))['pack.mcmeta']));
  ok(mm.pack.pack_format === 69 && mm.pack.min_format === 69 && mm.pack.max_format === 69 && mm.pack.supported_formats === undefined, 'yeni sürüm: pack_format+min/max, supported_formats silindi');
  r = await E.mcConvertPack(await mkp({ pack: { min_format: 69, max_format: 75, description: 'x' } }), { dst: '1.20' }); mm = JSON.parse(dec((await rd(r.out))['pack.mcmeta']));
  ok(r.ok && mm.pack.pack_format === 15 && mm.pack.min_format === undefined && mm.pack.max_format === undefined, 'sadece min/max_format olan paket okundu, eski sürüme düşürüldü');
}
// 3) hatalar
{
  const nr = await E.mcConvertPack(await mk({ 'a.txt': 'x' }), { dst: '1.21' }); ok(!nr.ok && /pack\.mcmeta/.test(nr.reason), 'pack.mcmeta yok → açık hata');
  const bj = await E.mcConvertPack(await mk({ 'pack.mcmeta': '{bad' }), { dst: '1.21' }); ok(!bj.ok && /JSON/.test(bj.reason), 'bozuk JSON → açık hata');
  const nested = await E.mcConvertPack(await mk({ 'Pack/pack.mcmeta': '{"pack":{"pack_format":3}}', ['Pack/' + T + 'blocks/dirt.png']: png('d') }), { src: '1.11', dst: '1.13' }); const f = await rd(nested.out); ok(nested.ok && f['pack.mcmeta'] && f[T + 'block/dirt.png'], 'iç klasörlü paket köke alındı');
  const col = await E.mcConvertPack(await mk({ 'pack.mcmeta': '{"pack":{"pack_format":3}}', [T + 'blocks/dirt.png']: png('1'), [T + 'block/dirt.png']: png('2') }), { src: '1.11', dst: '1.13' }); const cf = await rd(col.out); ok(col.ok && col.report.conflicts.length === 1 && dec(cf[T + 'block/dirt.png']) === '\x89PNG2' && cf[T + 'blocks/dirt.png'], 'çakışmada mevcut dosya ezilmedi, kayıp yok');
  const same = await E.mcConvertPack(await mk({ 'pack.mcmeta': '{"pack":{"pack_format":46}}' }), { src: '1.21.4', dst: '1.21.4' }); ok(same.ok, 'aynı sürüm hatasız');
}
// 4) 1.21.4 item tanımı
{
  const pk = await mk({ 'pack.mcmeta': '{"pack":{"pack_format":42}}', 'assets/minecraft/models/item/stick.json': JSON.stringify({ parent: 'item/handheld', textures: { layer0: 'item/stick' }, overrides: [{ predicate: { custom_model_data: 1 }, model: 'item/custom/a' }, { predicate: { custom_model_data: 2 }, model: 'item/custom/b' }] }), 'assets/minecraft/models/item/bow.json': JSON.stringify({ overrides: [{ predicate: { pulling: 1 }, model: 'item/bow_pulling_0' }] }) });
  const r = await E.mcConvertPack(pk, { src: '1.21.2', dst: '1.21.4' }); const f = await rd(r.out); const d = f['assets/minecraft/items/stick.json'];
  ok(r.ok && d && JSON.parse(dec(d)).model.type === 'minecraft:range_dispatch' && JSON.parse(dec(d)).model.entries.length === 2, 'stick: custom_model_data → items/stick.json');
  ok(!f['assets/minecraft/items/bow.json'] && r.report.items.skipped.some((s) => /bow/.test(s.item)), 'bow: karmaşık, atlandı ve raporlandı');
}
console.log(bad ? bad + ' HATA' : 'TAMAM'); process.exit(bad ? 1 : 0);
