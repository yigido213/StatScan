# Kod haritası (StatScan / Kovan) — yeni sohbetteki Claude için

Bu dosya, hafızası olmayan yeni bir Claude oturumunun projeyi 5 dakikada kavraması içindir. **Önce `CLAUDE.md` (kurallar + çalışma günlüğü), sonra bu dosya.** Günlük "ne zaman neyi yaptık" der; bu dosya "kod nerede, nasıl çalışır" der. Bir şeyi değiştirince bu dosyayı da güncelle (ilgili satırı).

## Genel yapı
- **Uygulama**: Windows Electron uygulaması "Kovan" (StatScan'in yeni adı). Çoğu araç yalnız masaüstünde çalışır; arayüz tarayıcıda da açılır ama host gerektiren araçlar orada kapalıdır.
- **Tek dosya arayüz**: `app/StatScan.html` (~1,4 MB). HTML + CSS + tüm arayüz JS'i. Elle baştan yazma; hedefli düzenle. Motor parçaları `src/engine/NN-*.js` içinde yazılır, `node tools/inject.mjs` ile HTML'e yerleştirilir.
- **Host (ana süreç)**: `app/desktop/host.js` tek dosya, içinde bağımsız modüller (hepsi `const XMOD = (() => {...})()`): `OBFMOD`, `COMPMOD` (derleyici), `ACCESSMOD` (sahip/Notlarım/Yönetim — **güvenlik hassas, dokunma**), `SYSMOD` (görev yöneticisi, ağ), `LOLMOD` (League Asistanı), `GAMEMOD` (Oyun Ayarlayıcı), `MEMMOD` (RAM analizi). Sıra önemli: `mem-host.cjs` kaynak taramasında MEMMOD..riskyList dilimine bakar; GAMEMOD MEMMOD'dan önce durmalı.
- **Köprü**: `app/desktop/preload.js` arayüze dar bir API verir (`window.statscanHost.lolXxx(...)`); argümanları burada şekillendirilir (arayüz yol/URL gönderemez). `app/desktop/app.js` pencere + modül bağlama (ör. `lol: { dataDir }`).
- **Güncelleme**: `latest.json` + `StatScan-X.Y.Z.ssu` (imzalı, `tools/make-ssu.mjs`). Güncelleyici `main` dalındaki `latest.json`'a bakar (`app.js` DEFAULT_FEED). Yeni dosya `app/` altına eklenmez (güncelleyici reddedebilir) — kod host.js/StatScan.html içine yazılır.
- Arayüz modülleri `MODULES` listesinde (kategori: Güvenlik / Windows / Minecraft / Kodlama); her araç `#app-<id>` paneli + bir `kovanXxx` IIFE'si. İngilizce çeviri `KT()`/EN sözlüğü (Türkçe metin eklersen EN karşılığı da ekle; `ui-lang.mjs` Türkçe kalıntı tarar).

## League Asistanı (LOLMOD + `kovanLol`)
Veri akışı (hepsi arka planda, tarayıcı açmaz; yalnız sabit sunucular):
- **Data Dragon** (`ddragon.leagueoflegends.com`): şampiyon listesi/istatistikleri (`champion.json`, yerel dil tr_TR→en_US), yetenek metinleri (`champion/<id>.json`; `enemytips` KULLANILMAZ — Riot güncellemiyor), rünler (`runesReforged.json`), şampiyon/eşya simgeleri.
- **Hat verisi**: Meraki Analytics `cdn.merakianalytics.com/riot/lol/resources/latest/en-US/champions.json` → yalnız `id` + `positions` özeti `lolcounter-cache/roles.json` (7 gün TTL). Roster'daki her şampiyona `c.pos` (['top','jungle','mid','bot','support']) eklenir. **Hat filtresi her yerde `roleFit(c, role)` ile yapılır**: `c.pos` varsa yalnız ona bakar, yoksa (veri alınamadı/yeni şampiyon) ana sınıftan kaba tahmin. `roleWeights` (hat tahmini) da `c.pos`'u kullanır. Yeni bir öneri/liste yazarken şampiyon filtrelerken **`roleFit` kullan**, etiketlere (`tags`) doğrudan bakma (Bard'ın üst hatta çıkması böyle oldu).
- **CommunityDragon**: derece amblemleri (`lol:icon` kind 'rank'); arayüz PNG'nin saydam kenarını `cropAlpha()` ile kırpar.
- **League istemcisi (LCU, 127.0.0.1)**: `LCU_OK` beyaz listesi (yalnız GET: seçim oturumu, hesap, derece, maç geçmişi, rün sayfaları). **TEK yazma türü**: `LCU_WRITE_OK` (`/* LCU-WRITE-BEGIN..END */`) — `POST /lol-perks/v1/pages` ve `DELETE /lol-perks/v1/pages/<id>`; yalnız adı 'Kovan …' ile başlayan kendi sayfamız, her yazmada onay penceresi, rün yapısı doğrulanır, yazdıktan sonra okunup kontrol edilir. Oyuna/belleğe dokunma YOK (testle kaynak taranır).
- **Riot Live Client API** (127.0.0.1:2999, yalnız GET `allgamedata`, `LIVE_OK`): canlı maç.
- **counterpick.lol** (İSTEĞE BAĞLI, varsayılan KAPALI, açmak onay ister): yalnız GET, yalnız `/matchup/<ben>-vs-<rakip>/` ve `/champion/<rakip>/counters/` (`cpGet` regex), ≥1 sn aralık, 6 sa önbellek, yalnız sayı alınır. Gerçek HTML'iyle denenmedi.
- **Kullanıcının kendi https dış veri adresi** (`statsUrl`): onay penceresi, yerel/özel ağ reddedilir, yalnız sayı okunur.

Puanlama: `heuristic()/adv()` (menzil, zırh/BD, sınıf kuralları — kaba, gerçek maçtan öğrenilmemiş), `rank()` (50+delta; dış veri %70/%30 ağırlıkla; kişisel kayıt Wilson alt sınırı ile en çok %60; havuz +4), `banPicks()`, `compAnalysis()`.
Eşya önerisi (`lol:items`): `parseItems()` Data Dragon `item.json`'dan yalnız Summoner's Rift (harita 11), tamamlanmış (`into` boş) satın alınabilir eşyaları + son kademe ayakkabıları alır (en_US sürümü: `Grievous Wounds`/`Lethality` metni için; yerel dil yalnız ad için, `items-<sürüm>.json` + `itemnames-…` önbelleği). `buildItemAdvice()` rakip takımın hasar dağılımından (`teamProfile`) zırh / büyü direnci / yara azaltma (kısa elle `SUSTAIN` listesi) / delme / ayakkabı bölümleri çıkarır; şampiyonun AD/AP/Tank türüne göre ters hasar eşyalarını eler; destek hattında öneri yok. KABA kural — kazanma oranı değil. Arayüz: `itemsCard()` (kovanLol), canlı maç + şampiyon seçimi panelinde `#lg-items`.
Canlı/seçim: `parseLive`, `analyzeLive`, `assignRoles` (120 permütasyon, hat tahmini güveni), `roleWeights` (etiket + büyüler + oyunun verdiği position + `c.pos`).
Handlerlar (`createLolHost(deps).handlers`): `lol:status/champs/pool/suggest/record/hist/tips/lcu/sync/profile/lp/matches/stats/bans/comp/icon/live/runes/runes:suggest/runes:apply/cp:get/cp:set/data:clear`. Durum `lolcounter.json`, önbellek `lolcounter-cache/` (kullanıcının bilgisayarında).
Arayüz (`kovanLol`): 6 sekme (Genel bakış, Şampiyonlarım, LP geçmişi, Birlikte oynadıklarım, Canlı maç, Karşı seçim); kendi teması `#app-lolcounter.lg` / `.lg-*` CSS; yardımcılar `h() put() icon() champIc() emblem() cropAlpha() dropdown() acWrap() cpToggle() compCard() drawSelect() drawLive() goalText() KT()`.
Rün önerisi zinciri (`lol:runes:suggest`, sırayla): (1) dış veri adresi / counterpick.lol (`fetchExt`; `cpMatchup` önce ben-vs-rakip, yoksa rakip-vs-ben → oran 100−x, rün YOK, `approx`; rünler `/lol/rune/<id>` görsellerinden, yoksa 'Runes' bölümündeki metinden — ad ya da 'Rune <id>', adlar en_US `runesReforged` → `buildRuneNames`/`cpRunesFromText`), (2) kendi maç geçmişin (`normMatch` artık `runes` saklar, `lol:sync` eski tam maçlara geriye dönük doldurur; `histRunes`: eşleşme ≥2 maç, yoksa şampiyon+hat ≥3, Wilson), (3) istemcinin önerilen rün sayfası (`lcuRecRunes`, LCU_OK'a yalnız GET kalıbı eklendi; uç nokta belgesiz). Yanıtta `src`, `hist`, `tried[{src,state}]`; arayüz kaynak rozeti + 'neden bulunamadı' listesi gösterir (`srcLine`/`why`).

Yapılmayanlar: maç kartında büyü/rün gösterimi (büyü kimliği→ad eşlemesi gerek), diğer kategorilerin kendi teması.
**Gerçekte hiç denenmedi**: gerçek Windows, gerçek League istemcisi/rün uç noktaları (belgesiz, bellekten), gerçek counterpick.lol HTML'i, gerçek Meraki/CommunityDragon indirmesi (yol WebFetch ile görüldü; sandbox kabuğundan ağ yok).

## Testler (`tools/test/`)
- Host: `node tools/test/lol-host.cjs` (sahte `deps.get/getBin/lcu/live/confirm`), `game-host.cjs`, `mem-host.cjs`, `sys-host.cjs`, `access-host.cjs`, `compile-host.cjs`, `obf-host.cjs`, `srcobf.cjs` …
- Arayüz (Playwright, gerçek host koduna köprü): `node tools/test/ui-lol.mjs`, `ui-shell.mjs`, `ui-lang.mjs`, `ui-conv.mjs`, `ui-game.mjs`, `ui-mem.mjs` … Playwright yolu testlerde `/home/claude/.npm-global/lib/node_modules/`. Ekran görüntüsü: `SHOT=<klasör> node tools/test/ui-lol.mjs`.
- HTML değişince sözdizimi: her `<script>` bloğunu `new Function` ile dene (testler zaten sayfayı açar).
- Bilinen: `ui-fx` 'daralma animasyonlu' kararsız; `compile-native` paralel yükte kararsız; ioc/mc/methods/modes/pack/trust fixture dizini (ortam değişkeni) olmadan düşer; `ui-lol` 'bugün özeti' gece yarısından sonraki ilk saatlerde atlanır.

## Sürüm / paketleme (özet; ayrıntı CLAUDE.md)
- Yalnız TEK hesap, kullanıcı isteyince paketler; `private.pem` kullanıcıdadır (ek dosya yolundan okunur, repoya/diske kopyalanmaz). `node tools/make-ssu.mjs <sürüm> <pem> "<notlar>"`; sonra imza host.js `EMBEDDED_PUBKEY`'e karşı doğrulanır. Kovan etiketi `app/StatScan.html` içinde `KOVAN_VER` (+ `tools/test/ui-conv.mjs` sabitleri). Hotfix etiketi artırmaz; yeni özellik artırır. `main`'e yalnız fast-forward, `--force` yok, onaysız merge yok.
- Mevcut: paket 5.0.9, Kovan beta 0.1.4.

## Çalışma düzeni
- 3 Claude hesabı aynı repoda çalışır (`claude-a`, `claude-b`, `claude-c` dalları); hafıza = `CLAUDE.md` günlüğü + git geçmişi + bu dosya. Başlamadan `git fetch` + `git log HEAD..origin/main`; bitince günlüğe bir satır yaz (ne yapıldı, ne DENENMEDİ).
- Kullanıcı Türkçe konuşur (Yiğit); dürüst ol: denenmeyeni "denenmedi" yaz, tahmini "tahmin" diye etiketle.
