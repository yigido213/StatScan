# Çok-Claude çalışma kuralları (StatScan / Kovan)

Bu proje 3 ayrı Claude hesabıyla aynı anda geliştirilir. Hafızalar ortak DEĞİLDİR; ortak hafıza bu dosya ve git geçmişidir. Çalışmaya başlamadan önce bu dosyayı oku.

## Başlamadan önce
1. `git fetch origin && git log --oneline HEAD..origin/main` çalıştır; yeni commit varsa `git pull --ff-only` yap ve ne eklendiğini `git show --stat` ile oku.
2. "Çalışma günlüğü" bölümüne bak: aynı iş başka hesapta yapılıyor veya yapılmışsa TEKRAR YAPMA, onun üstüne ekle.
3. Yapacağın işi günlüğe bir satır olarak ekleyip hemen push'la ("başladı").

## Çalışırken
- Kendi branch'inde çalış (`claude-a`, `claude-b`, `claude-c`), `main`'e birleştirmeden önce tekrar `git fetch` + rebase yap.
- Başkasının yazdığı dosyayı baştan yazma; gerekiyorsa küçük, hedefli değişiklik yap. `app/StatScan.html` büyük tek dosyadır: motor parçaları `src/engine/NN-*.js` içinde yazılır, `node tools/inject.mjs` ile içeri yerleştirilir (HTML'i elle yeniden yazma).
- Çakışma çıkarsa kendi sürümünü zorla (`--force`) push'LAMA; kullanıcıya sor.

## Sürüm yayınlama (kritik)
- `latest.json` ve `StatScan-X.Y.Z.ssu` yalnızca TEK hesap tarafından, kullanıcı isteyince üretilir. İki hesap aynı anda paketlerse biri diğerinin `latest.json` dosyasını ezer ve autoupdate bozulur.
- Paket imzası için özel anahtar (private.pem) kullanıcıdadır; yoksa imzalı paket üretme.
- Yeni sürüm numarası, `latest.json` ve `src`'deki `version` birbiriyle tutarlı olmalı.

## Hotfix kuralı (kullanıcı kararı)
- Hata düzeltmeleri (hotfix) Kovan sürüm etiketini ARTIRMAZ (ör. "beta 0.0.3" kalır); yalnızca paket numarasının son hanesi yükselir (4.9.1 → 4.9.2) ki güncelleyici yeni paketi görsün. Yeni özellik/araç eklenirse Kovan etiketi artar. Günlükte "HOTFIX" yazın.

## Bitirince
- Testleri çalıştır (`tools/test/`), günlüğe "bitti" yaz, kısa commit mesajı ver.

## Çalışma günlüğü (en yeni üstte)
- Derleyici çok dilli: C, C++, Rust, C#, Go, Zig, Kotlin, Pascal, Fortran, D (Java'ya ek) — claude-derleyici-diller dalı: bitti (kod host.js COMPMOD + StatScan.html + src/engine/101-srcscan.js; yeni dosya app/ altına eklenmedi). PAKETLENMEDİ (yeni özellik → yayında Kovan etiketi artacak, kullanıcı onayı bekliyor). Testler: `node tools/test/srcscan.cjs`, `compile-native.cjs`, `ui-compiler.mjs`. Windows yolları gerçek Windows'ta denenmedi.
- (planlandı, sırada) Yalnızca kullanıcıya özel: "Notlarım" aracı (otomatik kayıt) + imzalı engelli listesi (kurulum kimliği, blocklist.json, geliştirici modu private.pem ile açılır). Başka hesap bunlara BAŞLAMASIN, önce günlüğe bak.
- 4.9.4 — YAYINLANDI (kullanıcı istedi, claude-a paketledi): Kovan beta 0.0.4 + Derleyici aracı (Java → paketlenmiş uygulama, JDK 17+ gerekir) + Ayarlar'da English dil seçeneği. latest.json = 4.9.4. Sonraki paketi yapacak hesap önce git pull yapsın; sürüm 4.9.4 üstünden artsın. Windows .exe çıktısı gerçek Windows'ta denenmedi. Test: `node tools/test/ui-lang.mjs`, `ui-compiler.mjs`, `compile-host.cjs`
- Derleyici aracı (Java .java → paketlenmiş uygulama, JDK gerekir, yalnız masaüstü) + Ayarlar'a İngilizce dil seçeneği — claude-a: bitti (branch claude-a); PAKETLENMEDİ (yeni araç → yayında Kovan etiketi artacak, kullanıcı onayı bekliyor). Windows çıktısı denenmedi. Yeni dosya EKLENMEZ: güncelleyici app/ altına yeni dosyayı reddedebiliyor, kod host.js + StatScan.html içine yazılır.
- 4.9.3 — HOTFIX YAYINLANDI (kullanıcı istedi, claude-a paketledi): geniş pencerede Home arka planı (nokta/ışık) `max-width: 1180px` yüzünden sağda sert kenarla bitiyordu → `.home` tam genişlik, içerik aynı yerde (sağ dolgu `max(..., 100% - 1136px)`). Kovan etiketi beta 0.0.3 kaldı. latest.json = 4.9.3. Sonraki paketi yapacak hesap önce git pull yapsın.
- 4.9.2 — HOTFIX YAYINLANDI (kullanıcı istedi, claude-a paketledi): Home başlığındaki italik yazının son harfi ("yigit717" 7'si) parlama efektinde kesiliyordu → `.tw.done .typed` sağ dolgu eklendi. Kovan etiketi beta 0.0.3 kaldı. latest.json = 4.9.2. Sonraki paketi yapacak hesap önce git pull yapsın.
- Test düzeltmeleri — claude-a: bitti. mcconv.mjs artık repoya göre çalışır (manifest yoksa gen-mc-manifests.sh ile yalnız 1.11 + 1.21.4 üretir, ağ yoksa ATLAR; MC_MANIFESTS veya argv[2] ile yol verilebilir); ui45.mjs örnek klasörü varsayılan tools/test/benign. ui.mjs ve ui-obf.mjs paket testi değil, dosya argümanlı araçlardır. Paketleme yok.
- 4.9.1 — YAYINLANDI (kullanıcı istedi, claude-animasyon paketledi): Kovan beta 0.0.3 + arayüz animasyonları + Ayarlar'da "Arayüz animasyonları" anahtarı. latest.json = 4.9.1. Sonraki paketi yapacak hesap önce git pull yapsın; sürüm 4.9.1 üstünden artsın (4.10.0 yerine 4.9.2 gibi: güncelleyicinin sürüm karşılaştırması doğrulanmadı). Test: `node tools/test/ui-fx.mjs`
- 4.9.0 — YAYINLANDI (kullanıcı istedi, claude-a paketledi): Kovan beta 0.0.2 + Ayarlar menüsü. latest.json = 4.9.0. Sonraki paketi yapacak hesap önce git pull yapsın; sürüm 4.9.0 üstünden artsın.
- Ayarlar menüsü (sol alt; Windows ile başlat, simge durumunda başlat, otomatik güncelleme, tema, kenar çubuğu, ad, sıfırlama) — claude-a: bitti (branch claude-a; sürüm paketlenmedi, latest.json/.ssu değişmedi)
- 4.8.0 — Kovan beta 0.0.1: doku paketi dönüştürücü + mod sürüm ayarlayıcı (bir Claude hesabı ekledi)
