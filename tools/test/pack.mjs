// PyInstaller / asar acici testleri: SAMPLES=<dizin> node tools/test/pack.mjs
import fs from 'node:fs'; import { loadEngine, scan } from './engine.mjs';
const E = loadEngine(); const S = process.env.SAMPLES; let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const flat = (r, a = []) => { a.push(r); for (const c of r.children || []) flat(c, a); return a; }; const ids = (r) => flat(r).flatMap((x) => x.findings.map((f) => f.id));
for (const f of ['pyi_app.exe', 'pyi_app_elf']) {
  const r = await scan(E, f, fs.readFileSync(S + '/pack/' + f), 'deep'); const all = flat(r); const t = E.iocTree(r);
  ok(ids(r).includes('pyi_pack') && r.info.pyinstaller && /3\.10/.test(r.info.pyinstaller.py), f + ': PyInstaller tanındı (' + (r.info.pyinstaller && r.info.pyinstaller.py) + ')');
  ok(all.some((x) => / › scripts\/main\.pyc/.test(x.name)) && all.some((x) => / › pyz\/helper\.pyc/.test(x.name)), f + ': giriş betiği ve özgün modül çocuk olarak tarandı');
  ok(!all.some((x) => /json\/decoder/.test(x.name)), f + ': standart kütüphane modülü atlandı');
  ok(t.items.some((i) => i.type === 'url' && /evil\.example\.test\/payload\.exe/.test(i.value)) && t.items.some((i) => i.type === 'ip' && i.value === '198.51.100.77') && t.items.some((i) => i.type === 'webhook'), f + ': .pyc içindeki URL/IP/webhook IOC olarak çıktı');
  ok(!JSON.stringify(t).includes('abcdefghijklmnopqrstuvwxyz0123456789ABCD'), f + ': webhook token ham haliyle sızmadı');
  ok(all.some((x) => / › data\/config\.json$/.test(x.name)) || t.items.some((i) => /203\.0\.113\.9/.test(i.value)), f + ': data girdisi (config.json) incelendi');
}
let r = await scan(E, 'pyi_enc.exe', fs.readFileSync(S + '/pack/pyi_enc.exe'), 'deep'); ok(ids(r).includes('pyi_encrypted'), 'şifreli PYZ: açılamadı diye işaretlendi (başarılıymış gibi gösterilmedi)');
r = await scan(E, 'pyi_armor.exe', fs.readFileSync(S + '/pack/pyi_armor.exe'), 'deep'); ok(ids(r).includes('pyi_pyarmor'), 'PyArmor (pytransform) tespit edildi');
const plain = await scan(E, 'pe_chk.exe', fs.readFileSync(S + '/pe_chk.exe'), 'deep'); ok(!ids(plain).includes('pyi_pack'), 'normal PE: PyInstaller tespiti yok (yanlış alarm yok)');
r = await scan(E, 'app.asar', fs.readFileSync(S + '/pack/app.asar'), 'deep'); const all = flat(r); const t = E.iocTree(r);
ok(r.type === 'Electron asar paketi' && ids(r).includes('asar_pack') && r.info.asar.main === 'main.js', 'asar tanındı, ana dosya main.js');
ok(all.some((x) => / › main\.js$/.test(x.name)) && !all.some((x) => /node_modules/.test(x.name)) && ids(r).includes('asar_nm'), 'uygulama dosyaları tarandı, node_modules atlandı ve belirtildi');
ok(t.items.some((i) => i.type === 'url' && /evil\.example\.test\/s\.ps1/.test(i.value)) && t.items.some((i) => i.type === 'webhook'), 'main.js içindeki URL/webhook IOC çıktı'); ok(r.score >= 20, 'şüpheli main.js skora yansıdı: ' + r.score);
r = await scan(E, 'clean.asar', fs.readFileSync(S + '/pack/clean.asar'), 'deep'); ok(r.score <= 5, 'temiz asar düşük skor: ' + r.score);
r = await scan(E, 'x.bin', Buffer.from([4, 0, 0, 0, 9, 9, 9, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9]), 'deep'); ok(r.type !== 'Electron asar paketi', 'asar benzeri ama geçersiz başlık asar sayılmadı');
// obfuscation/cikarma paneli (obf) entegrasyonu
const u8 = (f) => new Uint8Array(fs.readFileSync(S + '/pack/' + f)); const get = (res, re) => res.outputs.filter((o) => re.test(o.name));
let o = await E.obf(u8('pyi_app.exe'), 'pyi_app.exe', {}); ok(o.supported && get(o, /^pyinstaller\/scripts\/main\.pyc$/).length === 1 && get(o, /^pyinstaller\/pyz\/helper\.pyc$/).length === 1, 'obf: PyInstaller .pyc dosyaları çıktı olarak üretildi');
const pyc = get(o, /main\.pyc$/)[0].bytes; ok(pyc[0] === 0x6f && pyc[1] === 0x0d && pyc.length > 40, 'obf: .pyc başlığı (sihirli sayı) eklendi');
ok(get(o, /sabit-dizeler\.txt$/)[0].text.includes('http://evil.example.test/payload.exe'), 'obf: dize sabitleri dökümü'); ok(!get(o, /json\/decoder/).length, 'obf: kütüphane modülleri çıkarılmadı');
ok(o.steps.some((s) => s.id === 'pydecomp' && s.status === 'unsupported'), 'obf: Python decompile "yapılmıyor" olarak dürüstçe işaretli');
o = await E.obf(u8('pyi_enc.exe'), 'pyi_enc.exe', {}); ok(o.status === 'partial' && o.steps.some((s) => s.id === 'unpack' && s.status === 'partial'), 'obf: şifreli PYZ kısmi, başarılıymış gibi gösterilmedi (' + o.status + ')');
o = await E.obf(u8('app.asar'), 'app.asar', {}); ok(o.kind.id === 'asar' && get(o, /^asar-icerik\/main\.js$/).length === 1 && !get(o, /node_modules/).length, 'obf: asar içeriği çıkarıldı (node_modules hariç)');
ok(get(o, /^asar-icerik\/package\.json$/).length === 1, 'obf: package.json çıktı');
o = await E.obf(u8('clean.asar'), 'clean.asar', {}); ok(o.status === 'done' && o.obfuscation.detected === false, 'obf: temiz asar → obfuscation tespit edilmedi (' + o.status + ')');
const orig = u8('app.asar'); const cp = orig.slice(); await E.obf(orig, 'app.asar', {}); ok(Buffer.compare(Buffer.from(orig), Buffer.from(cp)) === 0, 'obf: girdi baytları değiştirilmedi');
console.log(bad ? bad + ' TEST BAŞARISIZ' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
