/* Tum sonuc agacindaki gostergeleri (IOC) tek listede toplar ve disa aktarir.
 * Webhook/bot token'lari maskelidir (finalizeIoc). Hicbir ag istegi yapilmaz. */
const IOC_ORDER = ['webhook', 'telegram', 'url', 'domain', 'ip', 'onion', 'invite', 'email', 'btc', 'eth', 'reg', 'path'];
const IOC_LABEL = { webhook: 'Discord webhook', telegram: 'Telegram bot', url: 'URL', domain: 'Alan adı', ip: 'IP adresi', onion: '.onion adresi', invite: 'Discord daveti', email: 'E-posta', btc: 'Bitcoin cüzdanı', eth: 'Ethereum cüzdanı', reg: 'Kayıt defteri', path: 'Dosya yolu', wallet: 'Cüzdan', hash: 'Hash benzeri', cmd: 'Komut' };
function iocHostOf(t, v) { if (t === 'domain') return v; if (t === 'url' || t === 'webhook') { try { return new URL(v.replace(/…\[gizlendi\]/g, '')).hostname; } catch (e) { return ''; } } if (t === 'telegram') return 'api.telegram.org'; if (t === 'onion') return v; return ''; }
function collectIocTree(root) {
  const map = new Map(); let truncated = false;
  const walk = (r, depth) => {
    if (depth > 12) return; const io = r.info && r.info.iocs;
    if (io) for (const t of Object.keys(io)) for (const v of io[t] || []) { const k = t + '\0' + v; let e = map.get(k); if (!e) { if (map.size >= 5000) { truncated = true; continue; } e = { type: t, value: v, sources: new Set() }; map.set(k, e); } e.sources.add(r.name); }
    for (const c of r.children || []) walk(c, depth + 1);
  };
  walk(root, 0);
  const items = [...map.values()].map((e) => { const host = iocHostOf(e.type, e.value); return { type: e.type, label: IOC_LABEL[e.type] || e.type, value: e.value, host, benign: !!(host && BENIGN_HOSTS.test(host)), sources: [...e.sources].slice(0, 5), nsrc: e.sources.size }; });
  items.sort((a, b) => (IOC_ORDER.indexOf(a.type) + 1 || 99) - (IOC_ORDER.indexOf(b.type) + 1 || 99) || a.value.localeCompare(b.value));
  const counts = {}; for (const i of items) counts[i.type] = (counts[i.type] || 0) + 1;
  return { items, counts, total: items.length, truncated, note: 'Göstergeler dosya içeriğindeki metinlerden çıkarıldı; hiçbirine bağlanılmadı. Bir göstergenin listede olması kötü amaçlı olduğunu göstermez (meşru adresler de çıkar). Webhook/bot token’ları maskelidir.' };
}
function iocDefangStr(s) { return String(s).replace(/^http/i, 'hxxp').replace(/\./g, '[.]').replace(/@/g, '[@]'); }
const iocCsvCell = (v) => { v = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
/* fmt: 'txt' | 'csv' | 'json' | 'blocklist'; opts: { defang, includeBenign } */
function iocExport(tree, fmt, opts) {
  opts = opts || {}; const df = (t, v) => (opts.defang && /^(url|domain|ip|email|onion|telegram|webhook|invite)$/.test(t) ? iocDefangStr(v) : v);
  const list = tree.items.filter((i) => opts.includeBenign || !i.benign);
  if (fmt === 'json') return JSON.stringify({ tool: 'StatScan', kind: 'ioc', generated: new Date().toISOString(), note: tree.note, defanged: !!opts.defang, counts: tree.counts, truncated: tree.truncated, items: list.map((i) => ({ type: i.type, value: df(i.type, i.value), sources: i.sources, benignHost: i.benign })) }, null, 2);
  if (fmt === 'csv') return '﻿' + [['tür', 'değer', 'bilinen_meşru_site', 'kaynak_dosyalar']].concat(list.map((i) => [i.label, df(i.type, i.value), i.benign ? 'evet' : '', i.sources.join(' | ') + (i.nsrc > i.sources.length ? ' …+' + (i.nsrc - i.sources.length) : '')])).map((r) => r.map(iocCsvCell).join(',')).join('\n');
  if (fmt === 'blocklist') { const set = new Set(); for (const i of list) { if (i.type === 'ip') set.add(i.value); else if (i.host) set.add(i.host); } return [...set].sort().map((x) => (opts.defang ? iocDefangStr(x) : x)).join('\n') + '\n'; }
  const L = ['# StatScan IOC listesi', '# ' + tree.note, '']; let cur = ''; for (const i of list) { if (i.type !== cur) { cur = i.type; L.push('', '## ' + i.label); } L.push(df(i.type, i.value)); } return L.join('\n') + '\n';
}
