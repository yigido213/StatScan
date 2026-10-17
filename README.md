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
