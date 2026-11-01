/* Obfuscate araci testleri: 1) birim testleri (temel sadelestirme + isim karistirma guvenlik kurallari)
   2) gercek derleyiciyle once/sonra derleme + calistirma karsilastirmasi (gcc/g++/javac/rustc/go varsa).
   Derleyici yoksa o dilin derleme testi ATLANIR (fail sayilmaz), ciktida acikca belirtilir. */
const fs = require('fs'); const path = require('path'); const os = require('os'); const cp = require('child_process');
const code = fs.readFileSync(path.join(__dirname, '../../src/engine/101-srcscan.js'), 'utf8') + ';\n' + fs.readFileSync(path.join(__dirname, '../../src/engine/103-srcobf.js'), 'utf8');
const api = new Function(code + ';return {srcObf,srcObfSupport,sobStripBasic,sobRenameLocals,srcLangOf,scStrip};')();
let fail = 0, pass = 0;
const ok = (n, cond) => { if (cond) { pass++; } else { fail++; console.log('FAIL', n); } };
const eq = (n, a, b) => ok(n, JSON.stringify(a) === JSON.stringify(b)) || console.log('  got:', JSON.stringify(a), 'want:', JSON.stringify(b));

/* ---------- 1) temel sadelestirme: dize/karakter sabiti BOZULMAMALI, yorum kaldirilmali ---------- */
(() => {
  const src = 'int main() {\n  // yorum\n  int x = 5; /* blok */\n  char *s = "// not yorum /* bu da degil */";\n\n\n  return x;\n}\n';
  const r = api.sobStripBasic(src, 'c');
  ok('c: dize icinde sahte yorum korunur', r.text.includes('"// not yorum /* bu da degil */"'));
  ok('c: gercek yorum kalkar', !/yorum\s*$/m.test(r.text.replace(/"[^"]*"/g, '')) && !r.text.includes('blok'));
  ok('c: bos satirlar silinir', !/\n\s*\n\s*\n/.test(r.text));
  ok('c: kod hala derlenebilir sekilde', /int\s+x\s*=\s*5\s*;/.test(r.text));
})();
(() => {
  // rust ham dize + cok satirli
  const src = 'fn main() {\n    // yorum\n    let s = r"satir1\nsatir2  \n  satir3";\n    println!("{}", s);\n}\n';
  const r = api.sobStripBasic(src, 'rust');
  ok('rust: ham dize icindeki satir sonu bosluklari korunur (dize satiri hic dokunulmaz)', r.text.includes('satir2  \n'));
})();
(() => {
  const src = 'fun main() {\n  // yorum\n  val x = """\n    cok satirli\n      girintili metin\n  """\n  println(x)\n}\n';
  const r = api.sobStripBasic(src, 'kotlin');
  ok('kotlin: triple-quote icindeki girinti korunur', r.text.includes('      girintili metin'));
})();
(() => {
  const src = 'program T\n  ! yorum\n  integer :: x\n  x = 5\n  print *, x\nend program\n';
  const r = api.sobStripBasic(src, 'fortran');
  ok('fortran serbest: yorum kalkar', !r.text.includes('yorum'));
  ok('fortran serbest: kod kalir', /integer :: x/.test(r.text));
})();
(() => {
  const src = 'C this is a comment\n      PROGRAM T\n      INTEGER X\n      X = 5\n      END\n';
  const r = api.sobStripBasic(src, 'fortran-fixed');
  ok('fortran fixed: kolon-1 yorum kalkar', !r.text.includes('this is a comment'));
  ok('fortran fixed: kolonlara dokunulmaz', r.text.includes('      PROGRAM T'));
})();
(() => {
  // python: girintiye asla dokunulmamali, yorum kalkmali, bos satirlar (dize disi) silinmeli
  const src = 'def add(a, b):\n    # yorum\n    total = a + b   \n    return total\n\n\nclass Foo:\n    def bar(self):\n        if True:\n            return 1\n';
  const r = api.sobStripBasic(src, 'python');
  ok('python: yorum kalkar', !r.text.includes('yorum'));
  ok('python: 4-boslukluk girinti korunur', r.text.includes('    total = a + b'));
  ok('python: 8-boslukluk girinti korunur (ic ice blok)', r.text.includes('        if True:'));
  ok('python: sondaki fazla bosluk kirpilir', !/total = a \+ b\s+$/m.test(r.text));
  ok('python: ust uste bos satirlar silinir', !/\n\s*\n\s*\n/.test(r.text));
})();
(() => {
  // python: docstring/triple-quote icindeki BOS SATIRLAR dahil hicbir sey degismemeli (kritik guvenlik testi)
  const src = 'def f():\n    """Ozet.\n\n    Daha uzun aciklama.\n\n    """\n    # bu yorum kalkmali\n    x = 1\n    return x\n';
  const r = api.sobStripBasic(src, 'python');
  ok('python: docstring icindeki bos satir SILINMEZ (dize icerigi degismez)', r.text.includes('"""Ozet.\n\n    Daha uzun aciklama.\n\n    """'));
  ok('python: docstring disindaki yorum kalkar', !r.text.includes('bu yorum kalkmali'));
})();
(() => {
  // python: f-string / raw-string / tek tirnakli dize icerigi hic degismemeli
  const src = 'name = "world"\n# yorum\ngreeting = f"hello {name}!  "\npattern = r"\\d+  "\nsingle = \'kept  \'\n';
  const r = api.sobStripBasic(src, 'python');
  ok('python: f-string icerigi (ic bosluklar dahil) degismez', r.text.includes('f"hello {name}!  "'));
  ok('python: raw string icerigi degismez', r.text.includes('r"\\d+  "'));
  ok('python: tek tirnakli dize icerigi degismez', r.text.includes("'kept  '"));
})();
(() => {
  // python: isim karistirma desteklenmemeli (Pascal/Fortran gibi yalnizca temel katman)
  const sup = api.srcObfSupport().find((x) => x.id === 'python');
  ok('python: destek tablosunda var, basic:true rename:false', !!sup && sup.basic === true && sup.rename === false);
  const obf = api.srcObf([{ name: 'a.py', text: 'x = 1\n' }], { basic: true, rename: true });
  ok('python: srcObf isim karistirmayi atlar (renameSupported:false)', obf.files[0].supported === true && obf.files[0].renameSupported === false);
})();

/* ---------- 2) isim karistirma guvenlik kurallari (derleyicisiz, saf mantik testleri) ---------- */
(() => {
  // alan adiyla cakisan yerel degisken ASLA degismemeli (struct field vs local var ayni ad)
  const src = 'struct S { int count; };\nvoid f(struct S s) {\n  int count = 5;\n  s.count = count;\n}\n';
  const r = api.sobRenameLocals(src, 'c', {});
  ok('c: alan adiyla cakisan ad degismez', !r.renamed.some((x) => x.from === 'count'));
  ok('c: s.count erisimi aynen kalir', r.text.includes('s.count = count') || r.text.includes('s.count ='));
})();
(() => {
  // ayni adin BASKA bir fonksiyonda da yerel degisken olmasi GUVENLIDIR (her ikisi de ayni yeni ada donusur)
  const src = 'void a(){ int tmp = 1; use(tmp); }\nvoid b(){ int tmp = 2; use(tmp); }\n';
  const r = api.sobRenameLocals(src, 'c', {});
  const t = r.renamed.find((x) => x.from === 'tmp');
  ok('c: iki fonksiyonda da yerel olan ad degisir', !!t);
  if (t) { const occ = (r.text.match(new RegExp(t.to, 'g')) || []).length; ok('c: her iki fonksiyonda da tutarli degisir (bildirim+kullanim x2 fonksiyon = 4)', occ === 4); }
})();
(() => {
  // global degiskenle ayni adli yerel degisken ASLA degismemeli
  const src = 'int total = 0;\nvoid f(){ int total2 = total; use(total2); }\nvoid g(){ int total = 9; use(total); }\n';
  const r = api.sobRenameLocals(src, 'c', {});
  ok('c: global ile ayni adli yerel degismez', !r.renamed.some((x) => x.from === 'total'));
  ok('c: ilgisiz baska yerel (total2) degisebilir', r.renamed.some((x) => x.from === 'total2'));
})();
(() => {
  // rust: struct kisayol baslatma (field shorthand) alan adiyla cakistigi icin guvenli kalmali
  const src = 'struct P { x: i32, y: i32 }\nfn main(){ let x = 1; let y = 2; let p = P { x, y }; use(p); }\n';
  const r = api.sobRenameLocals(src, 'rust', {});
  ok('rust: kisayol alan adlariyla cakisan yerel degismez', !r.renamed.some((x) => x.from === 'x' || x.from === 'y'));
})();
(() => {
  // parametre adlari (govde disinda, parantez listesinde) degismemeli
  const src = 'int f(int count) { int total = count; return total; }\n';
  const r = api.sobRenameLocals(src, 'c', {});
  ok('c: parametre adi degismez', !r.renamed.some((x) => x.from === 'count'));
  ok('c: govde ici yerel degisir', r.renamed.some((x) => x.from === 'total'));
  ok('c: parametre kullanimi (govde icinde) aynen kalir', r.text.includes('= count;'));
})();
(() => {
  // java: alan adiyla ayni adli yerel degisken, bu.alan erisimi bozulmamali
  const src = 'class A { int count; void f(){ int count = 5; this.count = count; } }\n';
  const r = api.sobRenameLocals(src, 'java', {});
  ok('java: alan adiyla cakisan yerel degismez (this.count guvenligi)', !r.renamed.some((x) => x.from === 'count'));
})();
(() => {
  // go: struct literal alan etiketi (name: value) ile ayni adli yerel cakisirsa degismemeli
  const src = 'type P struct { count int }\nfunc f() { count := 5; p := P{count: count}; use(p) }\n';
  const r = api.sobRenameLocals(src, 'go', {});
  ok('go: struct alan etiketiyle cakisan yerel degismez', !r.renamed.some((x) => x.from === 'count'));
})();

console.log(pass + ' gecti, ' + fail + ' basarisiz (birim testleri)');

/* ---------- 3) gercek derleyiciyle once/sonra davranis karsilastirmasi ---------- */
function which(bin) { try { cp.execFileSync(process.platform === 'win32' ? 'where' : 'which', [bin], { stdio: 'pipe' }); return true; } catch (e) { return false; } }
function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'sob-')); }
function runCompileCase(name, lang, files, buildAndRun) {
  if (!api.srcObfSupport().find((x) => x.id === lang)) { console.log('ATLANDI (' + lang + '): dil desteklenmiyor'); return; }
  const obf = api.srcObf(files.map(([n, t]) => ({ name: n, text: t })), { basic: true, rename: true });
  const dOrig = tmp(), dObf = tmp();
  for (const [n, t] of files) fs.writeFileSync(path.join(dOrig, n), t);
  for (const row of obf.files) fs.writeFileSync(path.join(dObf, row.name), row.text);
  let outOrig, outObf;
  try { outOrig = buildAndRun(dOrig, files.map((x) => x[0])); } catch (e) { console.log('ATLANDI (' + lang + '/' + name + '): orijinal derleme hatasi — ' + String(e.message || e).split('\n')[0]); return; }
  try { outObf = buildAndRun(dObf, files.map((x) => x[0])); } catch (e) { fail++; console.log('FAIL (' + lang + '/' + name + '): obfuscate edilmis dosya derlenemedi — ' + String(e.message || e).split('\n')[0]); console.log('  --- obfuscate edilmis kaynak ---'); for (const row of obf.files) console.log('  [' + row.name + ']\n' + row.text.split('\n').map((l) => '    ' + l).join('\n')); return; }
  const renamedTotal = obf.files.reduce((a, r) => a + (r.renamed ? r.renamed.length : 0), 0);
  ok(lang + '/' + name + ': derleniyor + davranis AYNI (yeniden adlandirilan: ' + renamedTotal + ')', outOrig === outObf);
  if (outOrig !== outObf) { console.log('  orijinal cikti:', JSON.stringify(outOrig)); console.log('  obf cikti     :', JSON.stringify(outObf)); }
  fs.rmSync(dOrig, { recursive: true, force: true }); fs.rmSync(dObf, { recursive: true, force: true });
}
if (which('gcc')) {
  runCompileCase('temel', 'c',
    [['main.c', '#include <stdio.h>\n// baslik yorum\nstruct Point { int x; int y; };\nint add(int a, int b) { int sum = a + b; return sum; }\nint main(void) {\n  int total = 0;\n  for (int i = 0; i < 5; i++) { int tmp = add(i, i); total += tmp; }\n  struct Point p; p.x = 1; p.y = 2;\n  printf("%d %d %d\\n", total, p.x, p.y);\n  return 0;\n}\n']],
    (dir) => { cp.execFileSync('gcc', ['main.c', '-o', 'a.out'], { cwd: dir, stdio: 'pipe' }); return cp.execFileSync('./a.out', [], { cwd: dir }).toString(); });
} else console.log('ATLANDI (c): gcc yok');
if (which('g++')) {
  runCompileCase('temel', 'cpp',
    [['main.cpp', '#include <iostream>\n#include <vector>\n// yorum\nclass Counter { public: int count = 0; void inc(int by) { int delta = by; count += delta; } };\nint main() {\n  Counter c; std::vector<int> v;\n  for (int i = 0; i < 4; i++) { int step = i * 2; c.inc(step); v.push_back(step); }\n  std::cout << c.count;\n  for (int x : v) std::cout << " " << x;\n  std::cout << std::endl;\n  return 0;\n}\n']],
    (dir) => { cp.execFileSync('g++', ['-std=c++17', 'main.cpp', '-o', 'a.out'], { cwd: dir, stdio: 'pipe' }); return cp.execFileSync('./a.out', [], { cwd: dir }).toString(); });
} else console.log('ATLANDI (cpp): g++ yok');
if (which('javac') && which('java')) {
  runCompileCase('temel', 'java',
    [['Main.java', 'class Helper { int count; int add(int a, int b) { int sum = a + b; this.count = sum; return sum; } }\npublic class Main {\n  // yorum\n  public static void main(String[] args) {\n    Helper h = new Helper();\n    int total = 0;\n    for (int i = 0; i < 5; i++) { int tmp = h.add(i, 1); total += tmp; }\n    System.out.println(total + " " + h.count);\n  }\n}\n']],
    (dir) => { cp.execFileSync('javac', ['Main.java'], { cwd: dir, stdio: 'pipe' }); return cp.execFileSync('java', ['Main'], { cwd: dir }).toString(); });
} else console.log('ATLANDI (java): javac/java yok');
if (which('rustc')) {
  runCompileCase('temel', 'rust',
    [['main.rs', 'struct Point { x: i32, y: i32 }\n// yorum\nfn add(a: i32, b: i32) -> i32 { let sum = a + b; sum }\nfn main() {\n    let mut total = 0;\n    for i in 0..5 { let tmp = add(i, i); total += tmp; }\n    let x = 1; let y = 2; let p = Point { x, y };\n    println!("{} {} {}", total, p.x, p.y);\n}\n']],
    (dir) => { cp.execFileSync('rustc', ['main.rs', '-o', 'a.out'], { cwd: dir, stdio: 'pipe' }); return cp.execFileSync('./a.out', [], { cwd: dir }).toString(); });
} else console.log('ATLANDI (rust): rustc yok');
if (which('go')) {
  runCompileCase('temel', 'go',
    [['main.go', 'package main\nimport "fmt"\n// yorum\ntype Point struct { X int; Y int }\nfunc add(a int, b int) int { sum := a + b; return sum }\nfunc main() {\n  total := 0\n  for i := 0; i < 5; i++ { tmp := add(i, i); total += tmp }\n  x := 1; y := 2; p := Point{X: x, Y: y}\n  fmt.Println(total, p.X, p.Y)\n}\n']],
    (dir) => { cp.execFileSync('go', ['build', '-o', 'a.out', 'main.go'], { cwd: dir, stdio: 'pipe', env: Object.assign({}, process.env, { GOCACHE: path.join(os.tmpdir(), 'gocache') }) }); return cp.execFileSync('./a.out', [], { cwd: dir }).toString(); });
} else console.log('ATLANDI (go): go yok');
const PY_BIN = which('python3') ? 'python3' : (which('python') ? 'python' : null);
if (PY_BIN) {
  runCompileCase('temel', 'python',
    [['main.py', 'import sys\n# yorum\n\n\nclass Counter:\n    """Basit sayac.\n\n    Bos satir docstring icinde.\n    """\n    def __init__(self):\n        self.count = 0\n\n    def inc(self, by):\n        # yerel degisken (Python\'da yeniden adlandirilmaz, yalniz yorum/bosluk katmani test edilir)\n        delta = by\n        self.count += delta\n        return self.count\n\n\ndef main():\n    c = Counter()\n    total = 0\n    for i in range(5):\n        step = i * 2\n        total += c.inc(step)\n    print(total, c.count)\n\n\nif __name__ == "__main__":\n    main()\n']],
    (dir, names) => cp.execFileSync(PY_BIN, [names[0]], { cwd: dir }).toString());
} else console.log('ATLANDI (python): python3/python yok');

console.log('\n' + 'TOPLAM: ' + pass + ' gecti, ' + fail + ' basarisiz');
process.exit(fail ? 1 : 0);
