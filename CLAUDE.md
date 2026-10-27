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

## Bitirince
- Testleri çalıştır (`tools/test/`), günlüğe "bitti" yaz, kısa commit mesajı ver.

## Çalışma günlüğü (en yeni üstte)
- Kovan arayüz animasyonları + Ayarlar'a "Arayüz animasyonları" anahtarı (kovan.fx) — claude-animasyon: bitti (branch claude-animasyon; main'e BİRLEŞTİRİLMEDİ, sürüm paketlenmedi, latest.json/.ssu değişmedi). Test: `node tools/test/ui-fx.mjs`
- 4.9.0 — YAYINLANDI (kullanıcı istedi, claude-a paketledi): Kovan beta 0.0.2 + Ayarlar menüsü. latest.json = 4.9.0. Sonraki paketi yapacak hesap önce git pull yapsın; sürüm 4.9.0 üstünden artsın.
- Ayarlar menüsü (sol alt; Windows ile başlat, simge durumunda başlat, otomatik güncelleme, tema, kenar çubuğu, ad, sıfırlama) — claude-a: bitti (branch claude-a; sürüm paketlenmedi, latest.json/.ssu değişmedi)
- 4.8.0 — Kovan beta 0.0.1: doku paketi dönüştürücü + mod sürüm ayarlayıcı (bir Claude hesabı ekledi)
