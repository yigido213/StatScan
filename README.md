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


## 4.2

- **Kendi dosyalarım:** sonuç kartından bir dosyayı "Kendi dosyam olarak işaretle" ile kaydedersin (SHA-256 + ad ailesi + bulgu listesi). Aynı dosya tanınır; adı benzeyen yeni sürümde önceki sürüme göre **eklenen bulgular** ve skor farkı uyarı olarak gösterilir. İşaretlemek hiçbir bulguyu gizlemez veya puanı düşürmez. Liste soldaki "Kendi dosyalarım" panelinde; JSON dışa/içe aktarma var. Masaüstünde `userData/store.json`, tarayıcıda localStorage.
- **java/javaw.exe muafiyet modu:** Herkese (varsayılan) / yalnızca işaretli dosyalara / kapalı. Muafiyet yine yalnızca çalma-sızdırma belirtisi yoksa uygulanır.
- **Klasör izleme (yalnızca masaüstü):** seçtiğin klasörlere (İndirilenler, .minecraft/mods önerilir, otomatik açılmaz) gelen yeni dosyalar indirme bitince okunur, motorla taranır, eşik üstünde bildirim gelir; günlük tutulur. Dosya çalıştırılmaz/değiştirilmez/silinmez; StatScan çıktı klasörü izlenmez; 64 MB üstü taranmaz; yalnızca uygulama açıkken çalışır; izleme öncesi dosyalar taranmaz.
- **Ağ IOC çıkarımı:** URL/IP/alan adı/webhook/Telegram/onion/davet bağlantıları tüm iç dosyalardan toplanır, tekilleştirilir, zararsız hostlar işaretlenir; txt/csv/json/engel listesi olarak dışa aktarılır (webhook/token maskeli, defang seçeneği).
- **PyInstaller ve Electron asar açıcı:** PyInstaller CArchive/PYZ içindeki modül dizeleri ve `.pyc` dosyaları çıkarılıp taranır (AES şifreli PYZ/PyArmor "kısmi" bildirilir, `.pyc` decompile edilmez); `.asar` arşivleri açılıp taranır (`node_modules` atlanır, `.node` eklentileri işaretlenir; `.unpacked` dosyalar yoktur).
- Testler: `node tools/test/{trust,ioc,pack,mc,smoke}.mjs`, `node tools/test/{watch,obf-host}.cjs`.


## 4.5

- **Bilgi sekmesi:** Tüm açıklama/uyarı yazıları (StatScan nedir, sonuçlar nasıl okunur, sınırlar, mod kapsamı, kaynaklar, özellik açıklamaları) tarama ekranından ayrı "Bilgi" sekmesine taşındı. Teknik korumalar ve gerçek durum bilgisi (kısmi tarama, atlanan girdiler, analiz defteri, tarama kapsamı, onay pencereleri) tarama ekranında kaldı. Dışa aktarılan raporlar (HTML/JSON) kendi uyarılarını taşımaya devam eder.
- **Yöntem kataloğu:** `StatScan.methodMatrix()`; her analiz yöntemi için dosya türleri ve Hızlı/Normal/Derin kapsamı mod ayarlarından hesaplanır (elle yazılmış değil). Bilgi sekmesinde, JSON raporda (`methodCatalog`) ve HTML raporda (analiz defteri) görünür.
- **Modlar:** `tools/test/modes.mjs`, Hızlı/Normal/Derin'in gerçekten farklı iş yaptığını sınar (Base64/XOR çözme, IOC seviyeleri, imphash yalnızca Derin; her örnekte adım sayısı Hızlı ≤ Normal ≤ Derin). Derin modun küçük dosyada hızlı bitmesi yapay bekleme yokluğundandır.
- **Yeni yöntemler:** PE hata ayıklama bilgisi (CodeView/PDB yolu, `pdb_path`/`pdb_susp`), homoglif/görünmez karakterli ad (`name_confusable`/`name_invisible`), bulanık hash (CTPH; ssdeep ailesi, birebir ssdeep uyumu iddia edilmez) ve toplu taramada aile/varyant gruplama (bulanık hash + imphash + birebir kopya).
- **.pyc → Python kaynağı:** PyInstaller çıktısındaki `.pyc` dosyaları, makinede zaten kurulu pycdc/decompyle3/uncompyle6 ile (masaüstü, her seferinde onayla, dosya başına zaman aşımı, kısmi/başarısız dosyalar işaretlenir) çevrilebilir. Araç indirilmez/kurulmaz.
- **Yanlış-pozitif regresyon seti:** `tools/test/fp.mjs` + `tools/test/benign/`; temiz örnekler her modda düşük skor almalı, yüksek/kritik bulgu çıkmamalı. Yeni bir yanlış alarm görürsen dosyayı `benign/` klasörüne ekle.
- Testler: `node tools/test/{methods,modes,fp,ui45}.mjs`, `node tools/test/pyc-host.cjs` (+ önceki testler).


## 4.6

- **Yerel kod: birebir disassembly ve ana kod (x86/x64):** Yerleşik x86/x86-64 disassembler (`src/engine/94-disasm.js`) + PE/ELF yükleyici, özyinelemeli işlev keşfi, çağrı grafiği ve ana kodu bulma (`95-native.js`). Küçük (~50 KB) EXE/ELF dosyalarında ana kod ve çağırdığı işlevler `*.ana-kod.asm`, tüm keşfedilen kod `*.tum-kod.asm`, işlev/çağrı/import özeti `*.cagri-grafigi.txt` olarak, obfuscation panelinden (Kod çıkar) üretilir. Dosya ÇALIŞTIRILMAZ.
- **Tahmin yok:** Her satır dosyadaki gerçek bayttan çözülmüş komuttur; çözülemeyen komut "çözülemedi" diye işaretlenir (VEX/AVX, MMX, 0F38/0F3A, sistem komutları, 16-bit adresleme desteklenmez). Yorumlar yalnızca import (IAT/GOT/PLT), dize ve hedef adlarıdır.
- **Ana kod bulma dürüstlüğü:** ELF'te `__libc_start_main` ilk argümanı veya sembol = *kesin*; PE'de MSVC/MinGW CRT çağrı kalıbı = *sezgisel* (kanıt başlıkta); kalıp yoksa giriş noktası = *giriş-noktası*; bulunamazsa *bulunamadı*. Dolaylı atlamalar (anahtar tablosu, IFUNC) ve keşif sınırları listede UYARI olarak görünür, sonuç "kısmi" işaretlenir.
- **Decompile (C kodu) hâlâ yok:** bilerek; yerine birebir disassembly verilir. IDA/Ghidra köprüsü ayrıdır.
- **Doğrulama:** `tools/test/disasm-objdump.mjs` — 50 ikilide 21.346 komut objdump ile birebir; büyük sistem kütüphaneleriyle (libc, libcrypto, libstdc++, clang) 2,49 milyon komutta 0 metin/uzunluk farkı (VEX hariç, "çözülemedi" sayılır). `tools/test/native.mjs` — gcc ELF (PIE/no-PIE/strip) ve clang+lld-link PE (x64/x86, CRT'li/CRT'siz) örnekleri; main adresi ve işlev sınırları `nm`/`objdump` ile karşılaştırılır; bozulmuş 300 dosyada istisna yok.
- Bilinen sınırlar: PE'de ana kod seçimi kalıp eşleştirmesidir (farklı CRT'lerde yanılabilir); WinMain/DllMain ve C++/Rust/Go çalışma zamanı girişleri tanınmaz; paketli dosyada paketleyici kodu görünür; ARM/Mach-O desteklenmez.


## Kovan (uygulama kabuğu)

StatScan artık "Kovan" adlı daha büyük, modüler bir çalışma alanının ilk aracıdır. Kovan'ın adı: kovandaki her petek gözü ayrı bir araç; logo üç altıgen petek.

- **Kabuk:** `app/StatScan.html` içinde (dosya adı bilerek aynı: güncelleyici yeni dosya kabul etmez). Sol dikey kenar çubuğu (Home + Araçlar), sağda sahne. ≥900 px: 220 px sütun; <900 px: alt gezinme çubuğu. StatScan'in kendi kırılma noktaları kenar çubuğu genişliği kadar kaydırıldı.
- **Home:** sol üstte *kalın + eğik* "Welcome home, yigit717", harf harf yazılır (yalnızca açılışta bir kez, ~1,5 sn; bitince imleç kalkar). `prefers-reduced-motion: reduce` ise yazı doğrudan gösterilir. Altında araç kartları (yalnızca gerçek araç: StatScan; boş yer tutucu tıklanamaz) ve çalışma alanı bilgileri.
- **Gezinme:** `#/home`, `#/statscan` (eski `#bilgi` bağlantısı StatScan'in Bilgi sekmesini açar). Geri/ileri tuşları çalışır. Açılış sayfası Home'dur.
- **Araç eklemek:** (1) `<section id="app-ID" hidden>` kabını `.kstage` içine koy, (2) `kovanShell` içindeki `MODULES` listesine `{ id, name, icon, desc }` ekle. Kenar çubuğu girdisi, Home kartı ve rota listeden üretilir.
- Kullanıcı adı `kovanShell` içindeki `USER` sabitindedir (şimdilik elle yazılı; ayar ekranı yok).
- Test: `node tools/test/ui-shell.mjs` (Playwright; Home, animasyon, hareket azaltma, geçiş, 4 genişlik). Eski arayüz testleri `#/statscan` adresine gider.

### Kovan ana menü 2 (4.7.1)

- **Kenar çubuğu daraltma:** alt köşedeki ok düğmesi; 68 px simge çubuğuna iner (tooltip'li), tercih tarayıcıda/uygulamada saklanır. 900 px altında alt çubuk kullanıldığı için düğme yoktur.
- **Komut paleti:** `Ctrl+K` (macOS `Cmd+K`) veya Home'daki/kenar çubuğundaki "Ara" düğmesi. Araçlar ve komutlar (Home, araç aç, StatScan sekmeleri, tema, kenar çubuğu, kullanıcı adı) listeden üretilir; `MODULES` içindeki `actions` ile araç komutu eklenir. ↑↓/Enter/Esc.
- **Kullanıcı adı:** Home'daki "Adı değiştir" veya paletten; 24 karaktere kadar, metin olarak gösterilir (HTML yorumlanmaz), "Varsayılan" yigit717'ye döner. Yalnızca bu cihazda saklanır.
- Test: `node tools/test/ui-shell.mjs` (bu özellikleri de kapsar).

### Kovan beta 0.0.1: Minecraft dönüştürücüler (paket 4.8.0)

Kovan'ın kendi sürümü **beta 0.0.1**'den yeniden başlar (kenar çubuğu ve Home'da görünür). Güncelleme paketi numarası (4.8.0) yükleyicinin sürüm karşılaştırması için yükselmeye devam eder; StatScan'in kendi etiketi 4.8'dir.

- **Doku paketi dönüştürücü** (`#/texpack`): kaynak paketi (.zip) → seçilen Minecraft Java sürümü (1.6.1 … 26.3). `pack.mcmeta` (pack_format; 1.21.9+ için min/max_format; eski sürümde supported_formats kaldırılır), vanilla doku yeniden adlandırmaları (gerçek vanilla dosyalarının içerik/ad karşılaştırmasından üretildi: `src/engine/96-mcdata.js`, üretici `tools/gen-mc-renames.mjs`), model/font içindeki doku başvuruları, 1.21.4+ için yalnızca güvenli `custom_model_data` override'larından `items/` tanımı. Çakışmada mevcut dosya ezilmez; hedefte karşılığı olmayan dosyalar silinmez, raporlanır. Değişmeyen girdiler sıkıştırılmış haliyle kopyalanır; çıktı yeni bir zip'tir.
- **Mod sürüm ayarlayıcı** (`#/modconv`): fabric.mod.json, quilt.mod.json, mods.toml, neoforge.mods.toml, mcmod.info, plugin.yml içindeki hedef Minecraft aralığını günceller; imza dosyalarını çıkarır; Java sürümü, Mixin, access widener için risk raporu üretir. **Derlenmiş kodu çevirmez; çalışacağını garanti etmez.**
- Doğrulanmayanlar: 1.21.9+ `min_format/max_format` biçimi ve 26.3 oyunda denenmedi; GUI sprite bölünmesi (1.20.2), 26.2 yatak/tabela, spawn egg değişiklikleri otomatik çevrilmez; eski sürüme dönüşüm kayıplıdır; 26.x için gereken Java sürümü doğrulanmış tabloda yok.
- Testler: `mczip.mjs`, `mcconv.mjs` (manifest dizini argüman olabilir), `modconv.mjs`, `ui-conv.mjs`.

### Kovan Ayarlar menüsü

Sol altta **Ayarlar** (veya `Ctrl+,`, komut paletinde "Ayarlar"): tema, kenar çubuğu daraltma, karşılama animasyonu, kullanıcı adı, tercihleri sıfırlama. Masaüstü uygulamasında ayrıca **Windows ile başlat** (`--autostart` ile oturum açılışında), **simge durumunda başlat** ve **açılışta güncelleme denetimi** (`statscan-app.config.json`: `update.auto`, `startup.minimized`) ile "Şimdi denetle". Tarayıcıda bu bölümler kapalıdır ve nedeni yazar. Paketlenmemiş (geliştirme) çalıştırmada ve Windows/macOS dışında oturum açılışı ayarı reddedilir; işletim sistemi ayarı uygulamazsa anahtar geri döner. Gerçek bir Windows girişiyle denenmedi (Linux'ta test edildi: `settings-host.cjs`, `ui-settings.mjs`).
