# StatScan

StatScan Autoupdate

## Kaynak (3.6)

`app/` klasörü uygulamanın güncel kaynağıdır:

- `app/StatScan.html` arayüz + tarama motoru (tek dosya, çevrimdışı, sistem fontları)
- `app/dyn/` dinamik analiz (Windows Sandbox) yardımcıları
- `app/desktop/` Electron masaüstü kabuğu

`latest.json` ve `*.ssu` dosyaları otomatik güncelleme akışı içindir. Şu an yayında olan imzalı paket 3.3.0'dır.

## 3.6 geliştirme akışı

- Motor parçaları `src/engine/NN-*.js` içindedir; `node tools/inject.mjs` bunları `app/StatScan.html` içine yerleştirir (her değişiklikten sonra çalıştır).
- Testler: `node tools/test/smoke.mjs`, `node tools/test/run.mjs <dosya> [quick|normal|deep]`, yanlış alarm taraması `tools/test/fpsweep.mjs`, arayüz kontrolü `tools/test/ui.mjs` (Playwright).
- İmzalı güncelleme paketi: `node tools/make-ssu.mjs 3.6.0 private.pem "notlar"` (özel anahtar repoda yoktur). Üretilen `StatScan-3.6.0.ssu` ve `latest.json` commit edilip push edilince uygulamalar otomatik güncellenir.

## 3.7: obfuscation analizi ve deobfuscation

- Motor: `src/engine/70-obf.js` (`StatScan.obf(bytes, name, { scan, signal, onProgress })`). Tür otomatik tespit edilir; JS/PowerShell/VBS/batch/Python/sh için güvenli statik dönüşümler, .NET/Java için yapı dökümü, yerel PE/ELF/Mach-O için yalnızca paketleme/obfuscation analizi yapılır. Hiçbir şey çalıştırılmaz.
- Masaüstü: `app/desktop/obf.js` makinede kurulu ilspycmd/CFR/Procyon/jadx araçlarını bulur ve yalnızca onayla çalıştırır; hiçbir şey indirilmez/kurulmaz. Çıktı `Belgeler/StatScan-Cikti/` altına yazılır.
- Testler: `SAMPLES=<dizin> node tools/test/obf.mjs`, `node tools/test/obf-host.cjs`, `node tools/test/ui-obf.mjs <dosya>`.


## 3.8 — IDA Pro / Ghidra ile yerel kod decompile (isteğe bağlı)

EXE/DLL/ELF/Mach-O için obfuscation panelinde, makinede **zaten kurulu** IDA Pro (Hex-Rays, `idat64`/`idat`) veya Ghidra (`analyzeHeadless`) bulunursa "decompile et" düğmesi çıkar.

- Araç bulma: PATH, `IDADIR` / `GHIDRA_INSTALL_DIR`, standart konumlar (Program Files, `C:\`, İndirilenler…). Başka yerdeyse kullanıcı verisi `tools` klasörüne `paths.json` koy: `{"ida":"C:\\yol\\idat64.exe","ghidra":"C:\\yol\\support\\analyzeHeadless.bat"}`. Yalnızca bilinen dosya adları kabul edilir.
- Her çalıştırmada onay istenir; dosya çalıştırılmaz, araç yalnızca yükleyip analiz eder. Betikleri StatScan sabit olarak üretir (girdiden gelmez). Çıktı `Documents/StatScan-Cikti/…` altında: `decompiled.c`, `functions.txt` (+ IDA'da `disassembly.asm`).
- Kısmi sonuç başarılı gösterilmez: durum dosyası yoksa "başarısız", fonksiyonların bir kısmı decompile edilemediyse "kısmi" olarak raporlanır.
- Bilinen sınırlar: gerçek IDA/Ghidra ile test edilmedi (yalnızca sahte araçlarla); paketli/obfuscated dosyada çıktı anlamsız olabilir; Hex-Rays lisansı hedef mimariyi içermiyorsa yalnızca disassembly üretilir.


## 4.0

3.5'ten bu yana eklenenlerin toplu sürümü: kanıt modeli + analiz defteri, PE/.NET/ELF/Mach-O/Office/PDF/arşiv çözümleyiciler, otomatik obfuscation analizi ve güvenli statik deobfuscation, onaylı harici decompiler köprüsü (ILSpy, CFR, Procyon, jadx, **IDA Pro**, **Ghidra**).

- IDA/Ghidra decompile artık 4000 fonksiyonla sınırlı değil (üst sınır 1.000.000 fonksiyon / 400 MB çıktı); varsayılan zaman aşımı 60 dk, en çok 4 saat. Çok büyük programlarda süre ve disk kullanımı artar; panelden İptal edilebilir.
- IDAPython yoksa Hex-Rays toplu moduna otomatik geçiş; araç kaydı `_statscan_arac-log.txt`.
- Bilinen sınırlar: IDA/Ghidra köprüsü gerçek araçlarla yalnızca kullanıcı denemesiyle doğrulandı, otomatik testler sahte araçlarla; kod çalıştırmaya bağlı obfuscation (string şifreleme, sanallaştırma, CFF) açılmaz; Windows Sandbox kısmı bu ortamda çalıştırılmadı.


## 4.1

- **Fonksiyon risk sıralaması:** IDA/Ghidra decompile bitince `decompiled.c` taranır; her fonksiyona API/dize göstergelerine göre sezgisel puan verilir, en riskli 25 fonksiyon panelde ve `_statscan_risk.md` dosyasında listelenir. Hüküm değildir.
- **Minecraft mod/eklenti kontrolleri:** bildirilen giriş sınıfı/`plugin.yml` main sınıfı jar'da yok, meta veride bildirilmeyen gömülü jar (`META-INF/jars`), jar'da olmayan mixin sınıfları, bilinen mod adını taşıyan şüpheli jar.
- **java.exe / javaw.exe muafiyeti:** dosyada `java.exe`/`javaw.exe` adı geçiyorsa ve çalma/sızdırma belirtisi yoksa (tarayıcı verisi, token, Minecraft hesap dosyası, webhook, DPAPI, keylogger, stealer kombinasyonu) ReadProcessMemory/WriteProcessMemory/enjeksiyon bulgusu puanlanmaz (bulgu bilgi olarak listede kalır). Çalma belirtisi varsa muafiyet uygulanmaz. Not: bu muafiyet, java'ya enjekte olan ama çalma göstergesi taşımayan bir dosyayı da düşük puanlar; zararsız anlamına gelmez.
- **Toplu rapor:** HTML raporun başına "Önce bunlara bak" tablosu (en yüksek skorlu ilk 15 dosya). Klasör tarama, süzgeç ve CSV zaten vardı.
