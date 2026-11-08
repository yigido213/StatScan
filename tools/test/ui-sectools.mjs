// Kovan Güvenlik araçları: İmza ve Sertifika Denetçisi, Paketleyici/Obfuscation Dedektörü, IOC Çıkarıcı (Playwright).
// Örnek dosyalar SENTETİKTİR (tools/test/gen/build_sig.py, build_packsec.py üretir; python3 + cryptography gerekir). Hiçbiri çalıştırılmaz.
import { createRequire } from 'node:module'; const require = createRequire('/home/claude/.npm-global/lib/node_modules/'); const { chromium } = require('playwright');
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { execFileSync } from 'node:child_process';
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
const ROOT = '/home/claude/statscan'; const wd = fs.mkdtempSync(path.join(os.tmpdir(), 'ui-sec-')); const sig = wd + '/sig', pk = wd + '/pk';
try { execFileSync('python3', [ROOT + '/tools/test/gen/build_sig.py', sig], { stdio: 'pipe' }); execFileSync('python3', [ROOT + '/tools/test/gen/build_packsec.py', pk], { stdio: 'pipe' }); } catch (e) { console.log('ATLANDI: örnekler üretilemedi (python3/cryptography yok?) ' + String(e.message).slice(0, 80)); process.exit(0); }
fs.writeFileSync(wd + '/drop.ps1', '$u = "https://evil-c2.example.net/gate.php"\nInvoke-WebRequest -Uri $u\n$w = "https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcdefghijklmnopqrstuvwxyz"\n$t = "https://api.telegram.org/bot123456789:AAE_fakefakefakefakefakefakefakefakeabc/sendMessage"\n$ip = "203.0.113.77"\n"https://github.com/user/repo"\n');
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
const ctx = await b.newContext({ viewport: { width: 1280, height: 900 }, acceptDownloads: true }); const pg = await ctx.newPage(); const errs = []; pg.on('pageerror', (e) => errs.push(e.message));
const open = async (id) => { await pg.goto('file://' + ROOT + '/app/StatScan.html#/' + id); await pg.waitForTimeout(250); };
const txt = (sel) => pg.textContent(sel);
/* ---- kabuk ---- */
await pg.goto('file://' + ROOT + '/app/StatScan.html#/c-guvenlik'); await pg.waitForTimeout(250);
const cards = await pg.$$eval('#app-c-guvenlik .toolcard[data-open]:not(.empty)', (l) => l.map((x) => x.dataset.open).join(','));
ok(cards === 'statscan,imza,paketleyici,ioc', 'Güvenlik kategorisinde 4 araç: ' + cards);
/* ---- İmza ve Sertifika Denetçisi ---- */
await open('imza'); ok(/İmza ve Sertifika Denetçisi/.test(await txt('#app-imza h1')), 'imza: başlık'); ok(/çalıştırılmaz/.test(await txt('#app-imza .cv-drop')), 'imza: dosya çalıştırılmaz notu');
ok(/YOK/.test(await txt('#app-imza .cv-note')) && /iptal/i.test(await txt('#app-imza .cv-note')), 'imza: kök deposu/iptal sınırı açıkça yazılı');
const sg = async (f) => { await pg.setInputFiles('#sg-file', sig + '/' + f); await pg.waitForSelector('#sg-res:not([hidden]) .sc-body', { timeout: 20000 }); await pg.waitForTimeout(150); return txt('#sg-res'); };
let r = await sg('ok.exe'); ok(/Dosya içi denetimlerde sorun görülmedi/.test(r) && /Acme Software Ltd/.test(r), 'imza ok.exe: sorun yok + imzalayan görünür');
ok(/Zararlılık puanı/.test(r) && /\/100/.test(r), 'imza: StatScan zararlılık puanı (/100) gösterilir'); ok(/Güven zinciri \(kök\) ve iptal durumu doğrulanmadı/.test(r), 'imza: “güvenli” hükmü verilmez, kök/iptal uyarısı var');
ok(/İmza matematiği doğru/.test(r) && /tutarlı/.test(r), 'imza: imza matematiği + zincir tutarlılığı doğrulandı'); ok(/2024-06-01/.test(r), 'imza: zaman damgası gösterilir'); ok(/İptal durumu SORGULANMADI/.test(r) && /crl\.acme-test\.example/.test(r), 'imza: iptal adresleri yalnızca listelenir');
ok(await pg.$$eval('#sg-res .mtable tbody tr', (x) => x.length) === 3, 'imza: zincirde 3 sertifika');
r = await sg('tampered.exe'); ok(/UYUŞMUYOR/.test(r) && /Ciddi sorun/.test(r), 'imza tampered.exe: özet uyuşmuyor → ciddi sorun');
r = await sg('badmath.exe'); ok(/İmza matematiği GEÇERSİZ/.test(r), 'imza badmath.exe: imza matematiği geçersiz');
r = await sg('expired.exe'); ok(/süresi dolmuş/.test(r) && /Zaman damgası yok/.test(r), 'imza expired.exe: süresi dolmuş + damgasız');
r = await sg('selfms.exe'); ok(/KENDİNDEN İMZALI/.test(r) && /Microsoft/.test(r), 'imza selfms.exe: Microsoft adlı kendinden imzalı yakalandı');
r = await sg('typo.exe'); ok(/taklidi/.test(r), 'imza typo.exe: Micros0ft homoglif taklidi yakalandı');
r = await sg('typo2.exe'); ok(/çok benziyor/.test(r), 'imza typo2.exe: Gooogle yazım taklidi yakalandı');
r = await sg('noeku.exe'); ok(/kod imzalama amaçlı değil/.test(r), 'imza noeku.exe: kod imzalama EKU yok');
r = await sg('sha1.exe'); ok(/Zayıf özet/.test(r), 'imza sha1.exe: SHA-1 uyarısı');
r = await sg('ec.exe'); ok(/yalnızca RSA/.test(r) && !/GEÇERSİZ/.test(r), 'imza ec.exe: ECDSA doğrulanamaz diye dürüstçe yazılır (geçersiz denmez)');
r = await sg('unsigned.exe'); ok(/Dijital imza yok/.test(r), 'imza unsigned.exe: imza yok');
fs.writeFileSync(wd + '/n.txt', 'merhaba'); await pg.setInputFiles('#sg-file', wd + '/n.txt'); await pg.waitForTimeout(800); ok(/PE dosyaları içindir/.test(await txt('#sg-res')), 'imza: PE olmayan dosya için açık mesaj');
/* ---- Paketleyici / Obfuscation Dedektörü ---- */
await open('paketleyici'); ok(/Paketleyici \/ Obfuscation Dedektörü/.test(await txt('#app-paketleyici h1')), 'paket: başlık'); ok(/tek başına zararlı DEĞİLDİR/.test(await txt('#app-paketleyici .cv-note')), 'paket: “paketli = zararlı değil” notu');
const pkf = async (f) => { await pg.setInputFiles('#pk-file', pk + '/' + f); await pg.waitForSelector('#pk-res:not([hidden]) .sc-body', { timeout: 20000 }); await pg.waitForTimeout(150); return txt('#pk-res'); };
r = await pkf('upx.exe'); ok(/Paketleyici \/ koruyucu izi kesin/.test(r) && /UPX/.test(r) && /upx -d/.test(r), 'paket upx.exe: UPX kesin iz + geri açma ipucu'); ok(/UPX0/.test(r) && /UPX1/.test(r) && await pg.$$eval('#pk-res .sc-ent', (x) => x.length) >= 2, 'paket: bölüm tablosu entropi çubuklarıyla'); ok(/Zararlılık puanı/.test(r), 'paket: zararlılık puanı gösterilir');
r = await pkf('vmp.exe'); ok(/VMProtect/.test(r) && /kesin/.test(r), 'paket vmp.exe: VMProtect');
r = await pkf('plain.exe'); ok(/Paketleme izi yok/.test(r) && /KANITLAMAZ/.test(r), 'paket plain.exe: iz yok, ama “kanıtlamaz” notu');
r = await pkf('dnobf.exe'); ok(/ConfuserEx/.test(r), 'paket dnobf.exe: ConfuserEx dizesi');
r = await pkf('nsis.exe'); ok(/NSIS/.test(r) && /Paketleme izi yok/.test(r), 'paket nsis.exe: kurulum paketi paketleyici sayılmaz');
r = await pkf('obf.jar'); ok(/Allatori/.test(r) && /Java sınıf adları/.test(r), 'paket obf.jar: Allatori izi + kısa sınıf adı istatistiği');
r = await pkf('enc.jar'); ok(/0xCAFEBABE/.test(r), 'paket enc.jar: bozuk/şifreli .class başlığı');
r = await pkf('plain.jar'); ok(/Paketleme izi yok/.test(r), 'paket plain.jar: normal jar temiz');
/* ---- IOC Çıkarıcı ---- */
await open('ioc'); ok(/IOC Çıkarıcı/.test(await txt('#app-ioc h1')), 'ioc: başlık'); ok(/maskelenir/.test(await txt('#app-ioc .cv-note')), 'ioc: token maskeleme notu');
await pg.setInputFiles('#ic-file', wd + '/drop.ps1'); await pg.waitForSelector('#ic-res:not([hidden]) .sc-ioc', { timeout: 30000 }); await pg.waitForTimeout(200);
r = await txt('#ic-res'); ok(/evil-c2\.example\.net/.test(r), 'ioc: URL/alan adı listelendi'); ok(/203\.0\.113\.77/.test(r), 'ioc: IP listelendi'); ok(/webhook/i.test(r) && /telegram/i.test(r), 'ioc: Discord webhook + Telegram bot göstergeleri var');
ok(!/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/.test(r) && !/AAE_fakefakefake/.test(r), 'ioc: tam token ekrana yazılmaz (maskeli)'); ok(/Zararlılık puanı/.test(r), 'ioc: zararlılık puanı gösterilir');
ok(!/github\.com\/user\/repo/.test(r), 'ioc: bilinen meşru site varsayılan gizli'); await pg.check('#ic-benign'); await pg.waitForTimeout(100); ok(/github\.com/.test(await txt('#ic-res')), 'ioc: “bilinen meşru siteleri göster” açılınca görünür'); await pg.uncheck('#ic-benign');
await pg.check('#ic-defang'); await pg.waitForTimeout(100); ok(/hxxps?:\/\//.test(await txt('#ic-res')) && /\[\.\]/.test(await txt('#ic-res')), 'ioc: güvenli yazım (hxxp, [.])');
for (const f of ['txt', 'csv', 'json', 'blocklist']) { const [dl] = await Promise.all([pg.waitForEvent('download', { timeout: 8000 }), pg.click('button[data-fmt="' + f + '"]')]); const p = await dl.path(); const body = fs.readFileSync(p, 'utf8'); ok(body.length > 20 && !/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789|AAE_fakefakefake/.test(body), 'ioc dışa aktar ' + f + ': dosya var, tam token yok'); if (f === 'blocklist') ok(/evil-c2/.test(body) && body.split('\n').filter(Boolean).every((l) => /^[\w.\[\]-]+$/.test(l)), 'ioc blocklist: yalnızca alan adı/IP satırları'); }
/* ---- İngilizce ---- */
await pg.evaluate(() => { try { localStorage.setItem('kovan.lang', 'en'); } catch (e) { /* yoksay */ } });
for (const id of ['imza', 'paketleyici', 'ioc']) { await pg.goto('file://' + ROOT + '/app/StatScan.html#/' + id); await pg.reload(); await pg.waitForTimeout(400); const t = await pg.evaluate((i) => document.querySelector('#app-' + i).innerText, id); ok(!/[ığşöüçİĞŞÖÜÇ]/.test(t), 'EN ' + id + ': Türkçe kalıntı yok'); }
ok(/Signature & Certificate Inspector/.test(await pg.evaluate(() => document.querySelector('#app-imza h1').textContent)), 'EN: imza başlığı çevrildi');
await pg.goto('file://' + ROOT + '/app/StatScan.html#/imza'); await pg.waitForTimeout(300); await pg.setInputFiles('#sg-file', sig + '/ok.exe'); await pg.waitForSelector('#sg-res:not([hidden]) .sc-body', { timeout: 20000 }); ok(/Maliciousness score/.test(await txt('#sg-res')) && /Signature math/.test(await txt('#sg-res')), 'EN: sonuç etiketleri çevrildi');
/* ---- dar ekran ---- */
await pg.evaluate(() => { try { localStorage.removeItem('kovan.lang'); } catch (e) { /* yoksay */ } }); await pg.setViewportSize({ width: 390, height: 844 });
for (const id of ['imza', 'paketleyici', 'ioc']) { await pg.goto('file://' + ROOT + '/app/StatScan.html#/' + id); await pg.reload(); await pg.waitForTimeout(300); ok(await pg.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 2), 'dar ekran ' + id + ': yatay taşma yok'); }
await pg.setInputFiles('#sg-file', sig + '/ok.exe').catch(() => {});
ok(errs.length === 0, 'sayfa hatası yok' + (errs.length ? ': ' + errs[0] : '')); await b.close(); fs.rmSync(wd, { recursive: true, force: true }); console.log(bad ? bad + ' BAŞARISIZ' : 'HEPSİ GEÇTİ'); process.exit(bad ? 1 : 0);
