# StatScan dinamik analiz (Windows Sandbox)

Statik taramada anlamlı bulgu çıkmayan çalıştırılabilir dosyaları (exe, dll, jar, betik, lnk, msi…) **geçici bir Windows Sandbox içinde** çalıştırıp davranışını gözlemler. Dosya ana sistemde **asla** çalıştırılmaz.

## Masaüstü uygulama (önerilen)
`StatScan.exe` (Electron) arayüzü ve yardımcıyı tek pakette verir: ayrıca Node.js, komut ya da tarayıcı gerekmez. Dinamik analiz durumu pencerenin üstündeki şeritte görünür; eksik bir koşul varsa (Home sürümü, kapalı Windows Sandbox özelliği vb.) nedeni ve çözüm adımları orada yazar. Windows Sandbox kapalı ve sürüm Pro ise **"Windows Sandbox'ı etkinleştir"** düğmesi yönetici izni (UAC) isteyip özelliği açar; sonrasında bilgisayarı yeniden başlatman gerekir.

Görev ayrımı: **arayüz** tarar, sorar, raporlar ve dosyayı hiçbir zaman çalıştırmaz; **yardımcı hizmet** (uygulamada yerleşik, tarayıcıda `serve`) Windows Sandbox'ı başlatır. Dinamik analiz her seferinde onay penceresi ister; ağ/pano gibi riskli ayarlar açıksa ayrıca yerel bir uyarı penceresiyle tekrar onay alınır.

Kaynaktan derlemek için: `npm install`, `npm run icon`, `npm run build` → `dist/StatScan-win32-x64/StatScan.exe`. Yapılandırma: uygulamanın kullanıcı klasöründeki `statscan-dyn.config.json` (varsa) ya da `resources\app\dyn\statscan-dyn.config.json`; Yardım menüsünden gösterilir.

## Gereksinimler
- Windows 10 Pro (build 18362+) veya Windows 11 Pro. Home, Enterprise, Education ve Server'da özellik kapalı kalır; arayüz nedenini yazar.
- Windows Sandbox etkin olmalı: yönetici PowerShell'de `Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All` ya da *Windows özelliklerini aç/kapat → Windows Sandbox*, sonra yeniden başlat. BIOS'ta sanallaştırma açık olmalı.
- Node.js 18+.

## Kullanım (tarayıcı modu)
1. `baslat-dinamik.cmd` çalıştır (ya da `node dyn/statscan-dyn.js serve`). Sayfa `http://127.0.0.1:<port>` üzerinde açılır.
2. Dosyayı tara. Statik sonuçta anlamlı bulgu yoksa **"Dinamik analize geçilsin mi?"** sorusu çıkar. Evet → Sandbox arka planda çalışır, ilerleme ve İptal düğmesi görünür. Hayır → mevcut rapor gösterilir.
3. "Dinamik analiz" kutusundan ayarlar: Ağ, Pano, Yazıcı, Mikrofon, Kamera, vGPU, süre, Sandbox içi Defender, ekran görüntüsü.
- Sayfayı çift tıklayıp açarsan (file://) yalnızca statik tarama çalışır; Sandbox'ı tarayıcı başlatamaz.
- Komut satırı: `node dyn/statscan-dyn.js scan dosya.exe --dinamik --ag --sure 120`, `check`, `dry-run`, `config`, `help`.

## Güvenlik varsayılanları
- **Ağ ve pano kapalı**, yazıcı/mikrofon/kamera/vGPU kapalı. Riskli seçenekler her oturumda kapalı başlar, tarayıcıda kaydedilmez.
- Sandbox'a yalnızca StatScan'in geçici `in` (salt okunur) ve `out` (yazılabilir) klasörleri eşlenir. Ek klasörler yalnızca yapılandırma dosyasından, en çok 4 tane, varsayılan salt okunur eklenir; çok geniş yollar (`C:\`, kullanıcı klasörü) reddedilir.
- Yerel hizmet yalnızca 127.0.0.1'de dinler; rastgele oturum jetonu ve Host/Origin denetimi vardır. Tarayıcı komut veya klasör gönderemez, yalnızca beyaz listedeki ayarları değiştirebilir.
- Sandbox çıktısı güvenilmez sayılır: boyut/biçim sınırlanır, bırakılan dosyalar sha256 ile doğrulanır.
- `.wsb` dosyası üretilmeden önce şemaya göre doğrulanır; geçersizse Sandbox başlatılmaz.
- Ağ açıksa örnek internete çıkabilir. Yerel ağ engeli (güvenlik duvarı) en iyi çaba düzeyindedir, güvenlik sınırı değildir.

## Yapılandırma (`statscan-dyn.config.json`)
`sandbox` (Windows Sandbox seçenekleri, `mappedFolders`), `analysis` (süre, `launch` ile uzantıya göre başlatma komutu, `preSteps`/`postSteps` Sandbox içi PowerShell adımları), `host` (staging klasörü, `keepArtifacts`, boyut sınırları). Tam liste: `node dyn/statscan-dyn.js config`.

Örnek, .dll için farklı dışa aktarım ve ek adım:
```json
{ "analysis": { "dllExport": "Run", "preSteps": ["Write-Output hazir"] } }
```

## Skor
Birleşik skor = yüksek olan + diğerinin yarısı (en çok 100). Dinamik bulgular "dinamik" etiketi taşır. Dinamik bulgu yoksa rapor "temiz" demez.

## Sınırlar (dürüst not)
- Zararlı Sandbox'ı algılayıp saklanabilir, tarih/sunucu/kullanıcı etkileşimi bekleyebilir; "davranış gözlenmedi" ≠ güvenli.
- Sandbox içindeki Defender örneği ya da bırakılan dosyaları silebilir; bu bulgu olarak raporlanır. İstersen kapatabilirsin (yalnızca Sandbox içinde).
- Ana makinedeki Defender, staging klasöründeki örneği karantinaya alabilir; gerekirse hariç tutma ekle.
- Kodun Node tarafı ve .wsb/akış mantığı sahte Sandbox ile 53 testten geçti; **gerçek Windows Sandbox üzerinde henüz denenmedi** (toplayıcı `collector.ps1` dahil). İlk denemede `keepArtifacts: true` ile çalışıp `out\` klasörünü incelemeni öneririm.
- Testler: `node dyn/test/test-dyn.js` (Sandbox gerektirmez).

## v3.3 yenilikleri

**Doğrudan dinamik analiz.** Statik taramayı beklemeden dosyayı seçip kartta "Doğrudan dinamik analiz"e basabilirsin (onay penceresi yine çıkar; dosya ana sistemde asla çalıştırılmaz). Statik atlanırsa puan yalnızca dinamik bulgulardan hesaplanır.

**Tuzak veri (varsayılan açık, `analysis.bait`).** Sandbox içinde örnek çalışmadan önce SAHTE Chrome/Edge/Brave/Firefox parola-çerez dosyaları, Discord/Telegram/Steam oturum dosyaları, kripto cüzdanları (Exodus, Electrum, Bitcoin, MetaMask…), `.ssh`, `.aws`, FileZilla ve `passwords.txt` oluşturulur; bunlara "okunursa denetim kaydı yaz" kuralı (SACL, Security 4663) konur. Örneği hangi sürecin okuduğu bulgu olur (bilgi hırsızı). Ayrıca panoya sahte BTC/ETH adresi konur; örnek bunu başka bir adresle değiştirirse "clipper" bulgusu çıkar. Sahte fare hareketi de yapılır. Defender/Arama dizinleyici okumaları sayılmaz. Dokunulmazsa bu **temiz kanıtı değildir** ("tuzak dokunulmadı" bilgi notu). Denetim etkinleşemezse arayüz bunu açıkça söyler.

**Çalışma klasörü boş mu?** Varsayılan olarak iş bittikten sonra `%LOCALAPPDATA%\StatScan\dyn\` içindeki klasör silinir. İncelemek için ayarlardan "Çalışma klasörünü silme" (`host.keepArtifacts`) aç.

**Otomatik güncelleme.** Güncellemeler Ed25519 ile imzalı `.ssu` paketleridir; uygulama yalnızca gömülü açık anahtarla doğrulananı kurar, her açılışta yeniden doğrular, iki başarısız açılıştan sonra eski sürüme döner. Yükleyici (main.js) hiç güncellenmez.
- Elle: Yardım → "Güncelleme dosyası uygula" → `.ssu` seç.
- Otomatik: güncelleme yapılandırma dosyasında (Yardım → Güncelleme kaynağı; ilk çalıştırmada oluşur) `"feedUrl": "https://…/latest.json"` ver (yalnızca https). Uygulama açılışta kontrol eder.
- Yayın üretme: `node desktop/build/release.js pack --notes "…" [--base-url https://…/]` → `dist/StatScan-<sürüm>.ssu` + `dist/latest.json`. `release/private.pem` GİZLİDİR; sahibi bu bilgisayarlara kod gönderebilir.
