// IOC agaci toplama/disa aktarma testi: SAMPLES=<dizin> node tools/test/ioc.mjs
import fs from 'node:fs'; import { loadEngine, scan } from './engine.mjs';
const E = loadEngine(); const S = process.env.SAMPLES; let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const r = await scan(E, 'pack.zip', fs.readFileSync(S + '/ioc/pack.zip'), 'deep'); const t = E.iocTree(r); const v = (ty) => t.items.filter((i) => i.type === ty).map((i) => i.value);
ok(t.items.some((i) => i.type === 'url' && /evil\.example\.test\/stage2/.test(i.value) && i.sources.some((s) => /run\.ps1/.test(s))), 'alt dosyadaki URL toplandı, kaynak dosya belli');
ok(v('ip').includes('198.51.100.23'), 'IP toplandı');
ok(v('webhook').length === 1 && /\.\.\.|…\[gizlendi\]/.test(v('webhook')[0]) && !/abcdefghijklmnopqrstuvwxyz0123456789ABCD/.test(JSON.stringify(t)), 'webhook toplandı ve token maskeli (ham değer hiçbir yerde yok)');
ok(v('onion').length === 1, '.onion adresi toplandı');
const gh = t.items.find((i) => /github\.com/.test(i.value) && i.type === 'url'); ok(gh && gh.benign, 'bilinen meşru site (github) benign işaretli');
const txt = E.iocExport(t, 'txt', { defang: true }); ok(/hxxp:\/\/evil\[\.\]example\[\.\]test/.test(txt) && !/https?:\/\/evil/.test(txt), 'txt: defang uygulandı');
ok(!E.iocExport(t, 'txt', {}).includes('github.com') && E.iocExport(t, 'txt', { includeBenign: true }).includes('github.com'), 'meşru siteler varsayılan olarak hariç, istenirse dahil');
const bl = E.iocExport(t, 'blocklist', { defang: false }).trim().split('\n'); ok(bl.includes('evil.example.test') && bl.includes('198.51.100.23') && !bl.includes('github.com'), 'engelleme listesi: alan adı + IP');
const csv = E.iocExport(t, 'csv', {}); ok(csv.startsWith('﻿') && /evil\.example\.test/.test(csv), 'csv üretildi');
const js = JSON.parse(E.iocExport(t, 'json', {})); ok(js.items.length > 3 && js.counts.url >= 2, 'json geçerli: ' + js.items.length + ' öğe');
console.log(bad ? bad + ' TEST BAŞARISIZ' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
