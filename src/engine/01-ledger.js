/* Analiz defteri: bu dosya icin hangi analizlerin gercekten yapildigi. Mod ve dosya turune gore olusturulur. */
function baseLedger(kind, cfg, res, st) {
  const L = [];
  L.push(led('type', 'Dosya türü tespiti (imza/magic)', 'done', kind));
  L.push(led('hash', 'SHA-256, SHA-1 ve entropi', 'done', res.sha256 ? '' : 'SHA-256 hesaplanamadı (tarayıcı kısıtı)'));
  L.push(led('names', 'Ad/uzantı sahtekarlığı kontrolleri (RTLO, çift uzantı, içerik–uzantı uyumu)', 'done'));
  L.push(led('rules', 'Dize/regex kural kataloğu', cfg.ids ? 'partial' : 'done', cfg.ids ? 'Hızlı mod: yalnızca yüksek riskli kural alt kümesi' : (st.rules && st.rules.some((r) => r.user) ? 'kullanıcı kural paketiyle birlikte' : '')));
  L.push(led('deobf', 'Base64/hex/PowerShell/gzip katmanlarını çözüp yeniden tarama', cfg.deobf ? 'done' : 'skipped', cfg.deobf ? '' : 'yalnızca Derin modda'));
  L.push(led('xor', 'Tek baytlık XOR ile gizlenmiş PE arama', cfg.xor ? 'done' : 'skipped', cfg.xor ? '' : 'yalnızca Derin modda'));
  L.push(led('ioc', 'IOC çıkarımı (URL/IP' + (cfg.ioc >= 2 ? ', e-posta, kayıt defteri, yol, cüzdan' : '') + ')', cfg.ioc ? 'done' : 'skipped', cfg.ioc ? '' : 'Hızlı modda yapılmaz'));
  return L;
}
const NEVER_LED = [
  led('dyn', 'Dinamik/davranış analizi ve emülasyon', 'unsupported', 'Statik taramada dosya çalıştırılmaz. İsteğe bağlı Windows Sandbox analizi ayrıdır ve yalnızca onayınla çalışır.'),
  led('yara', 'Çoklu antivirüs motoru / itibar sorgusu', 'unsupported', 'Hiçbir dosya içeriği veya özet bu araçtan dışarı gönderilmez.')
];
