/* Gizlenmis bilgi calici (stealer) PE profili — STATIK, dosya CALISTIRILMAZ, yalnizca bayt kaliplari + import adlari.
   Neden: Lumma gibi aileler dizelerini yigina sifreli yazip calisma aninda MBA (and/or/not/add/sub kimlikleriyle gizlenmis
   aritmetik) ile cozer, API'leri gizli cozer, araya NOP kizaklari koyar. Dizeye/import'a bakan kurallar bunlarda 0 verir.
   Her sinyal tek basina ZAYIFTIR (korumali/ticari yazilimlarda da gorulebilir); bulgu ancak sinyaller birlesince guclenir.
   Aile adi KOYMAZ: 'bu davranis profili stealer ile uyumlu' der. Eslesme kesin hukum degildir. */
const STL_LIM = { scan: 6e6, window: 160 };
function stlExec(p) { return p.sections.filter((s) => (s.ch & 0x20000000) && s.rsize > 0); }
/* NOP kizaklari: >=8 ardisik 0x90 (derleyici dolgusu 0x90 degil int3/cok baytli nop kullanir). */
function stlNopSleds(b, s, e) {
  let n = 0, run = 0;
  for (let i = s; i < e; i++) { if (b[i] === 0x90) run++; else { if (run >= 8) n++; run = 0; } }
  if (run >= 8) n++;
  return n;
}
/* Yigina dize yazma bloklari: >=4 ardisik 'mov dword [esp/ebp+d8], imm32' (C7 44 24 d8 imm32 / C7 45 d8 imm32). */
function stlStackBlocks(b, s, e) {
  let blocks = 0, i = s;
  while (i < e - 8) {
    let k = 0, j = i;
    for (;;) {
      if (j + 8 <= e && b[j] === 0xc7 && b[j + 1] === 0x44 && b[j + 2] === 0x24) { j += 8; k++; }
      else if (j + 7 <= e && b[j] === 0xc7 && b[j + 1] === 0x45) { j += 7; k++; }
      else break;
    }
    if (k >= 4) { blocks++; i = j; } else i++;
  }
  return blocks;
}
/* MBA bayt-cozme dongusu: yigin tamponundan bayt oku (movzx r32, byte [esp+idx+d8]), araya >=3 mantik islemi
   (and/or/not) koy, ayni adrese geri yaz (mov [esp+idx+d8], r8). Sade kod (CRC, toupper) bu kalibi tasimaz. */
function stlMbaLoops(b, s, e) {
  let loops = 0;
  for (let i = s; i < e - 12; i++) {
    if (b[i] !== 0x0f || b[i + 1] !== 0xb6 || (b[i + 2] & 0xc7) !== 0x44 || (b[i + 3] & 7) !== 4) continue;
    const sib = b[i + 3], d = b[i + 4]; const end = Math.min(e - 4, i + STL_LIM.window); let logic = 0, store = false;
    for (let j = i + 5; j < end; j++) {
      const c = b[j];
      if (c === 0xf7 && b[j + 1] >= 0xd0 && b[j + 1] <= 0xd7) logic++;                               /* not r */
      else if ((c === 0x21 || c === 0x23 || c === 0x09 || c === 0x0b) && b[j + 1] >= 0xc0) logic++;    /* and/or r,r */
      else if ((c === 0x81 || c === 0x83) && (b[j + 1] & 0xf8) === 0xc8) logic++;                       /* or r,imm */
      else if ((c === 0x81 || c === 0x83) && (b[j + 1] & 0xf8) === 0xe0) logic++;                       /* and r,imm */
      if (c === 0x88 && (b[j + 1] & 0xc7) === 0x44 && b[j + 2] === sib && b[j + 3] === d) { store = true; break; }
    }
    if (store && logic >= 3) { loops++; i += 4; }
  }
  return loops;
}
function peStealth(u8, p, apis, info) {
  const out = []; if (!p || p.clr) return out;
  const has = (n) => { n = n.toLowerCase(); return apis.has(n) || apis.has(n + 'a') || apis.has(n + 'w') || apis.has(n + 'exa') || apis.has(n + 'exw') || apis.has(n + 'ex'); };
  const secs = stlExec(p); let codeSize = 0, nop = 0, stack = 0, mba = 0, budget = STL_LIM.scan;
  for (const s of secs) {
    const a = s.rptr, e = Math.min(u8.length, s.rptr + s.rsize, a + budget); if (e <= a) continue; budget -= e - a; codeSize += e - a;
    nop += stlNopSleds(u8, a, e); stack += stlStackBlocks(u8, a, e); mba += stlMbaLoops(u8, a, e);
    if (budget <= 0) break;
  }
  if (codeSize < 4096) return out;
  const dyn = has('LoadLibrary') || has('GetProcAddress') || has('LdrGetProcedureAddress') || has('LdrLoadDll') || has('GetModuleHandle') || has('LoadLibraryEx');
  const net = ['InternetOpen', 'InternetConnect', 'InternetReadFile', 'HttpSendRequest', 'WinHttpOpen', 'WinHttpConnect', 'WSAStartup', 'socket', 'connect', 'send', 'recv', 'getaddrinfo', 'URLDownloadToFile', 'DnsQuery'].some(has);
  const screen = has('BitBlt') && (has('CreateCompatibleBitmap') || has('GetDIBits') || has('CreateDIBSection'));
  const clip = has('OpenClipboard') && has('GetClipboardData');
  const wmi = has('CoCreateInstance') && (has('CoSetProxyBlanket') || has('CoInitializeSecurity'));
  const disk = has('GetDiskFreeSpace');
  const caps = [screen && 'ekran görüntüsü (BitBlt)', clip && 'pano okuma', wmi && 'WMI/COM sorgusu', disk && 'disk boyutu sorgusu'].filter(Boolean);
  const nImp = info && info.importCount != null ? info.importCount : apis.size;
  const sig = {};
  if (mba >= 6) { sig.mba = true; out.push(mk('pe_stl_mba', 'med', mba >= 40 ? 18 : 14, 'Şifreli dizeler yığında açılıyor (MBA çözme döngüleri)', mba + ' bayt çözme döngüsü bulundu: yığın tamponundan bayt okuyup and/or/not aritmetiğiyle değiştirip geri yazıyor' + (stack ? '; ' + stack + ' yığın dizi bloğu da var' : '') + '. Bilgi çalıcılar URL, tarayıcı yolu ve API adlarını düz metin bırakmamak için bunu kullanır.', 'Dosyayı bir sanal makinede/Sandbox’ta incele; çözülen dizeler bellekte görünür.', [mba + ' çözme döngüsü', stack + ' yığın dizi bloğu'], 'pe')); }
  if (nop >= 100) { sig.nop = true; out.push(mk('pe_stl_nop', 'low', 6, 'Kodda çok sayıda NOP kızağı', nop + ' adet 8+ baytlık NOP dizisi var. Derleyiciler dolguyu bu biçimde yazmaz; gizleme/imza kaçırma için araya eklenir.', 'Tek başına zararlı değildir; diğer gizleme izleriyle birlikte değerlendir.', [nop + ' NOP dizisi'], 'pe')); }
  if (!dyn && !net && codeSize >= 100000 && nImp <= 80) { sig.hid = true; out.push(mk('pe_stl_hidden', 'med', 10, 'Büyük kod, küçük import tablosu, dinamik yükleme yok', 'Kod ' + Math.round(codeSize / 1024) + ' KB ama yalnızca ' + nImp + ' işlev import ediliyor; LoadLibrary/GetProcAddress da yok ve hiç ağ API’si import edilmiyor. Ağ ve dosya işlevleri çalışırken gizlice çözülüyor olabilir (çıkarım; doğrulanmadı).', 'Dinamik analizde ağ bağlantılarına ve yüklenen modüllere bak.', [nImp + ' import', Math.round(codeSize / 1024) + ' KB kod'], 'pe')); }
  if (caps.length >= 3 && !net) { sig.caps = true; out.push(mk('pe_stl_caps', 'med', 10, 'Bilgi toplama işlevleri var, ağ import’u yok', 'Birlikte bulunan işlevler: ' + caps.join(', ') + '. Ağ API’si import edilmiyor; veri dışarı başka yolla çıkıyor olabilir. Tek tek zararsız işlevlerdir.', 'İşlev kombinasyonunu programın amacıyla karşılaştır (ekran kaydedici, uzaktan destek vb. meşru olabilir).', caps, 'pe')); }
  const n = (sig.mba ? 1 : 0) + (sig.nop ? 1 : 0) + (sig.hid ? 1 : 0) + (sig.caps ? 1 : 0);
  if (n >= 3 && (sig.mba || sig.hid)) out.push(mk('pe_stl_profile', 'high', 25, 'Gizlenmiş bilgi çalıcı (stealer) davranış profiliyle uyumlu', n + ' bağımsız sinyal bir arada: ' + [sig.mba && 'MBA dize çözme', sig.nop && 'NOP kızakları', sig.hid && 'gizli API çözümleme izi', sig.caps && 'ekran/pano/WMI işlevleri'].filter(Boolean).join(', ') + '. Bu bir aile tespiti değil, davranış profili eşleşmesidir; kesin hüküm için dinamik analiz veya imza gerekir.', 'Çalıştırma. Sandbox’ta dinamik analizle ağ ve dosya erişimlerini doğrula; şüphe sürüyorsa paylaşan kaynağı ve hash’i bir ücretsiz çok motorlu servisle karşılaştır.', [n + '/4 sinyal'], 'pe'));
  if (out.length) { info.stealth = { mbaLoops: mba, stackBlocks: stack, nopSleds: nop, codeKB: Math.round(codeSize / 1024), dynLoad: dyn, netImports: net, caps }; }
  return out;
}
