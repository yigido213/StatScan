'use strict';
/* Kovan Derleyici (cok dilli): gercek C/C++/Rust/C#/Go/Zig/Kotlin/Pascal/Fortran/D derleyicileriyle uctan uca.
   Kurulu olmayan dil ATLANIR. Uretilen cikti yalnizca bu test tarafindan (kendi yazdigimiz hello programi) calistirilir. */
const fs = require('fs'), os = require('os'), path = require('path'), cp = require('child_process');
const { createHost, compileModule } = require('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms)); const B = (s) => Buffer.from(s, 'utf8');
const extraDirs = ['/usr/local/lib/python3.13/site-packages/ziglang'].filter((d) => fs.existsSync(d));
(async () => {
  const dl = fs.mkdtempSync(path.join(os.tmpdir(), 'kn-dl-')); const before = fs.readdirSync(os.tmpdir()).filter((n) => /^kovan-(c|cpp|rust|csharp|go|zig|kotlin|pascal|fortran|d)-/.test(n)).length;
  const H = createHost({ service: { closeAll() {} }, downloadsDir: dl, compileToolDirs: extraDirs }).handlers; const V = compileModule.validate;
  const T = await H['compile:tools'](); const have = Object.fromEntries(T.list.map((x) => [x.id, x]));
  console.log('araçlar:', T.list.map((x) => x.id + (x.ok ? '=' + x.tool + ' ' + x.version : '=YOK')).join(', '));
  // --- doğrulama ---
  const f = (name, s) => ({ name, bytes: B(s || 'x') });
  for (const [m, req] of [
    ['bilinmeyen dil', { lang: 'cobol', files: [f('a.cob')], name: 'a' }], ['yol gezintisi', { lang: 'c', files: [f('../a.c')], name: 'a' }], ['seçenek gibi ad (-o)', { lang: 'c', files: [f('-o.c')], name: 'a' }], ['boşluklu ad', { lang: 'c', files: [f('my file.c')], name: 'a' }],
    ['yanlış uzantı', { lang: 'c', files: [f('a.rs')], name: 'a' }], ['Windows ayrılmış ad', { lang: 'c', files: [f('con.c')], name: 'a' }], ['büyük/küçük aynı ad', { lang: 'c', files: [f('A.c'), f('a.C')], name: 'a' }],
    ['yalnız başlık', { lang: 'c', files: [f('a.h')], name: 'a' }], ['kötü uygulama adı', { lang: 'c', files: [f('a.c')], name: '../x' }], ['bilinmeyen seçenek', { lang: 'c', files: [f('a.c')], name: 'a', options: { cflags: '-fplugin=x' } }],
    ['std enum dışı', { lang: 'c', files: [f('a.c')], name: 'a', options: { std: 'c99 -fplugin=x' } }], ['winlibs enum dışı', { lang: 'c', files: [f('a.c')], name: 'a', options: { winlibs: ['x;calc'] } }], ['rust ana dosya yok', { lang: 'rust', files: [f('a.rs')], name: 'a', main: 'b.rs' }],
    ['kotlin sınıf geçersiz', { lang: 'kotlin', files: [f('a.kt')], name: 'a', main: 'A;rm' }], ['go hedef geçersiz', { lang: 'go', files: [f('a.go')], name: 'a', options: { target: 'plan9/386' } }], ['sıra geçersiz', { lang: 'fortran', files: [f('a.f90')], name: 'a', order: ['zz.f90'] }]
  ]) ok(V(req) !== null, 'reddedilir: ' + m);
  ok(V({ lang: 'c', files: [f('a.c'), f('a.h')], name: 'ok', options: { std: 'c11', opt: 'speed', static: false } }) === null, 'geçerli C isteği kabul');
  ok(V({ files: [{ name: 'A.java', bytes: B('x') }], mainClass: 'A', name: 'a' }) === null, 'lang yoksa Java yolu bozulmadı');
  let r; const noTools = createHost({ service: { closeAll() {} }, downloadsDir: dl, compileOnlyToolDirs: [] }).handlers;
  r = await noTools['compile:start']({}, { lang: 'rust', files: [f('main.rs', 'fn main(){}')], name: 'a', main: 'main.rs' }); ok(r.error === 'compile' && r.needTool, 'araç yoksa açık hata + needTool');
  const poll = async (id) => { for (let i = 0; i < 1500; i++) { const s = await H['compile:job']({}, id); if (s.state !== 'running') return s; await sleep(200); } throw new Error('zaman aşımı'); };
  const runOut = (p, args) => { const x = cp.spawnSync(p, args || [], { encoding: 'utf8', timeout: 20000 }); return (x.stdout || '') + (x.stderr || ''); };
  const cases = [
    ['c', { files: [f('main.c', '#include <stdio.h>\n#include <math.h>\n#include "u.h"\nint main(void){ printf("%s %d\\n", "merhaba", u(2)+(int)sqrt(16.0)); return 0; }'), f('u.h', 'static int u(int x){return x*10;}')], name: 'chello' }, /merhaba 24/],
    ['cpp', { files: [f('main.cpp', '#include <iostream>\n#include "u.hpp"\nint main(){ std::cout << "merhaba " << u(3) << std::endl; }'), f('u.hpp', 'inline int u(int x){return x+1;}')], name: 'cpphello', options: { std: 'c++17' } }, /merhaba 4/],
    ['cpp', { files: [f('main.cpp', 'extern "C" int cadd(int,int);\n#include <cstdio>\nint main(){ std::printf("karisik %d\\n", cadd(2,3)); }'), f('add.c', 'int cadd(int a,int b){return a+b;}')], name: 'mixed' }, /karisik 5/],
    ['rust', { files: [f('main.rs', 'mod h;\nfn main(){ println!("merhaba {}", h::f()); }'), f('h.rs', 'pub fn f()->i32{7}')], name: 'rhello', main: 'main.rs' }, /merhaba 7/],
    ['go', { files: [f('main.go', 'package main\nimport "fmt"\nfunc main(){ fmt.Println("merhaba", add(2,3)) }'), f('u.go', 'package main\nfunc add(a,b int) int { return a+b }')], name: 'gohello' }, /merhaba 5/],
    ['zig', { files: [f('main.zig', 'const std = @import("std");\npub fn main() void { std.debug.print("merhaba {d}\\n", .{42}); }')], name: 'zhello', main: 'main.zig' }, /merhaba 42/],
    ['pascal', { files: [f('hello.pas', "program Hello;\nuses u;\nbegin writeln('merhaba ', dbl(21)); end."), f('u.pas', 'unit u;\ninterface\nfunction dbl(x:integer):integer;\nimplementation\nfunction dbl(x:integer):integer; begin dbl:=x*2; end;\nend.')], name: 'phello', main: 'hello.pas' }, /merhaba 42/],
    ['fortran', { files: [f('p.f90', 'program p\nuse m\nprint *, "merhaba", twice(4)\nend program'), f('m.f90', 'module m\ncontains\ninteger function twice(x)\ninteger :: x\ntwice = 2*x\nend function\nend module')], name: 'fhello', order: ['m.f90', 'p.f90'], options: { static: true } }, /merhaba\s+8/],
    ['d', { files: [f('a.d', 'import std.stdio;\nvoid main(){ writeln("merhaba ", 6*7); }')], name: 'dhello' }, /merhaba 42/],
    ['csharp', { files: [f('P.cs', 'using System;\nnamespace A { class P { static void Main(string[] a){ Console.WriteLine("merhaba " + (6*7)); } } }')], name: 'cshello' }, /merhaba 42/],
    ['csharp', { files: [f('Program.cs', 'Console.WriteLine("ust duzey " + (1+2));')], name: 'cstop' }, /ust duzey 3/],
    ['kotlin', { files: [f('Main.kt', 'fun main(args: Array<String>) { println("merhaba " + (6*7)) }')], name: 'kthello', main: 'MainKt' }, /merhaba 42/]
  ];
  for (const [lang, body, re] of cases) {
    const label = lang + ' ' + body.name; if (!have[lang] || !have[lang].ok) { console.log('SKIP ' + label + ': ' + (have[lang] ? have[lang].why : 'araç yok')); continue; }
    r = await H['compile:start']({}, Object.assign({ lang }, body)); if (!r.id) { ok(false, label + ' başlatılamadı: ' + JSON.stringify(r)); continue; } const s = await poll(r.id);
    if (s.state !== 'done') { ok(false, label + ' derleme (' + s.state + '): ' + s.error + '\n' + s.log.slice(-1200)); continue; }
    ok(s.steps.every((x) => x.status === 'ok'), label + ' adımlar tamam'); const R = s.result; ok(R.outDir.startsWith(path.join(dl, 'Kovan-Derleme')) && fs.existsSync(R.launcher), label + ' çıktı İndirilenler/Kovan-Derleme altında');
    if (lang === 'kotlin') { ok(/merhaba 42/.test(runOut(R.launcher)), label + ' paketlenmiş uygulama çalışır'); continue; }
    ok(/^[0-9a-f]{64}$/.test(R.sha256 || ''), label + ' sha256 var'); const o = lang === 'csharp' && !fs.statSync(R.launcher).mode ? '' : runOut(R.launcher); ok(re.test(o), label + ' çıktı çalışır: ' + o.trim().slice(0, 60));
  }
  // --- çapraz hedef (çıktı çalıştırılmaz; yalnız PE başlığına bakılır) ---
  if (have.go && have.go.ok) { r = await H['compile:start']({}, { lang: 'go', files: [f('main.go', 'package main\nfunc main(){ println("x") }')], name: 'gowin', options: { target: 'windows/amd64' } }); const s = await poll(r.id); ok(s.state === 'done' && /gowin\.exe$/.test(s.result.launcher) && fs.readFileSync(s.result.launcher).subarray(0, 2).toString() === 'MZ' && s.result.windows === true, 'go → windows/amd64: .exe + MZ başlığı'); }
  if (have.zig && have.zig.ok) { r = await H['compile:start']({}, { lang: 'zig', files: [f('main.zig', 'pub fn main() void {}')], name: 'zwin', main: 'main.zig', options: { target: 'x86_64-windows', opt: 'size' } }); const s = await poll(r.id); ok(s.state === 'done' && /zwin\.exe$/.test(s.result.launcher) && fs.readFileSync(s.result.launcher).subarray(0, 2).toString() === 'MZ', 'zig → x86_64-windows: .exe + MZ başlığı'); if (s.state !== 'done') console.log(s.log.slice(-600)); }
  // --- hata: çıktı döner, geçici yol sızmaz, çıktı klasörü oluşmaz ---
  if (have.c && have.c.ok) { r = await H['compile:start']({}, { lang: 'c', files: [f('bad.c', 'int main( { }')], name: 'badc' }); const s = await poll(r.id); ok(s.state === 'failed' && s.steps.find((x) => x.id === 'compile').status === 'fail' && s.result && /error/.test(s.result.compilerOutput) && !/kovan-c-/.test(s.result.compilerOutput), 'C hatası: başarısız, çıktı döner, geçici yol sızmaz'); ok(!fs.existsSync(path.join(dl, 'Kovan-Derleme', 'badc')), 'hatada çıktı klasörü yok'); }
  if (have.c && have.c.ok) { r = await H['compile:start']({}, { lang: 'c', files: [f('a.c', 'int main(void){return 0;}')], name: 'one' }); ok((await H['compile:start']({}, { lang: 'c', files: [f('a.c', 'int main(void){return 0;}')], name: 'two' })).error === 'compile', 'aynı anda ikinci derleme reddedilir'); await poll(r.id); }
  const after = fs.readdirSync(os.tmpdir()).filter((n) => /^kovan-(c|cpp|rust|csharp|go|zig|kotlin|pascal|fortran|d)-/.test(n)).length; ok(after === before, 'geçici çalışma klasörleri temizlendi');
  // --- komut kurucu: Windows yolları / bayraklar (sahte araçlarla, hiçbir şey çalışmaz) ---
  compileModule._setPlatform('win32'); const fake = (id, tool, major, fam) => ({ id, ok: true, tool, path: 'C:\\tools\\' + tool + '.exe', version: major + '.0.0', major, minor: 0, family: fam });
  const tl = { byId: { c: fake('c', 'gcc', 13, 'gcc'), cpp: fake('cpp', 'g++', 13, 'gcc'), go: fake('go', 'go', 1, 'other'), zig: fake('zig', 'zig', 0, 'other') }, jdk: {} }; tl.byId.go.minor = 22; const d = { work: 'W', src: 'S', out: 'O', obj: 'B', cache: 'C' };
  let p = compileModule.planNative({ lang: 'c', files: [{ name: 'a.c' }], name: 'app', console: 'no', options: { winlibs: ['ws2_32'], static: true, opt: 'size', std: 'c23' } }, tl, d); const a = p.cmds[0].args;
  ok(p.outName === 'app.exe' && a.includes('-mwindows') && a.includes('-lws2_32') && a.includes('-static') && a.includes('-Os') && a.includes('-std=c2x') && !a.includes('-pthread'), 'Windows C: .exe, -mwindows, -lws2_32, -static, gcc13 için c23→c2x');
  p = compileModule.planNative({ lang: 'go', files: [{ name: 'a.go' }], name: 'app', console: 'no', options: { target: 'linux/arm64' } }, tl, d); ok(p.outName === 'app' && p.cmds[0].env.GOOS === 'linux' && p.cmds[0].env.GOARCH === 'arm64' && p.cmds[0].env.CGO_ENABLED === '0' && p.cmds[0].env.GOPROXY === 'off' && /go 1\.22/.test(p.gen['go.mod']), 'Go: hedef linux/arm64 → uzantısız, CGO kapalı, modül indirme kapalı, go.mod sürümü');
  p = compileModule.planNative({ lang: 'go', files: [{ name: 'a.go' }], name: 'app', console: 'no', options: { target: 'windows/amd64' } }, tl, d); ok(p.outName === 'app.exe' && p.cmds[0].args.join(' ').includes('-H=windowsgui'), 'Go: windows hedefi GUI alt sistemi');
  p = compileModule.planNative({ lang: 'zig', files: [{ name: 'a.zig' }], name: 'app', main: 'a.zig', options: { target: 'x86_64-linux' } }, tl, d); ok(p.outName === 'app' && p.cmds[0].args.includes('-target'), 'Zig: linux hedefi uzantısız');
  compileModule._setPlatform(null);
  console.log(bad ? bad + ' HATA' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
