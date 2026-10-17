import fs from 'node:fs';
import { loadEngine, scan } from './engine.mjs';
const E = loadEngine();
const [file, mode = 'deep', json] = process.argv.slice(2);
const r = await scan(E, file.split('/').pop(), fs.readFileSync(file), mode);
if (json) { console.log(JSON.stringify(r, null, 1)); process.exit(0); }
const show = (x, ind = '') => { console.log(ind + x.name, '|', x.type, '| skor', x.score); for (const f of x.findings) console.log(ind + '  [' + f.sev + ' ' + f.w + ' ' + (f.basis || '-') + '] ' + f.id + ' — ' + f.title + (f.mitre && f.mitre.length ? '  {' + f.mitre.join(',') + '}' : '')); for (const c of x.children || []) show(c, ind + '    '); };
show(r);
if (r.analyses) console.log('analyses:', r.analyses.map((a) => a.id + ':' + a.status).join(' '));
