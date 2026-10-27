'use strict';
/* Kovan ayarlari (masaustu ana sureci): beyaz liste, dogrulama, OS ayari uygulanmazsa hata */
const { createHost } = require('../../app/desktop/host.js');
let bad = 0; const ok = (c, m) => { console.log((c ? 'OK   ' : 'FAIL ') + m); if (!c) bad++; };
(async () => {
  const st = { login: false, app: { startMinimized: false, auto: true, feedUrl: 'x' }, supported: { supported: true, reason: '' }, stuck: false, upd: 0 };
  const settings = { autostartSupport: () => st.supported, getLogin: () => st.login, setLogin: (v) => { if (!st.stuck) st.login = v; }, getApp: () => st.app, setApp: (p) => { if ('auto' in p) st.app.auto = p.auto; if ('startMinimized' in p) st.app.startMinimized = p.startMinimized; }, checkUpdate: async () => { st.upd++; } };
  const host = createHost({ service: { closeAll() {} }, version: '9.9.9', settings }); const H = host.handlers;
  let g = await H['settings:get'](); ok(g.desktop && g.version === '9.9.9' && g.openAtLogin === false && g.autoUpdate === true && g.startMinimized === false && g.autostart.supported, 'get: varsayılanlar');
  g = await H['settings:set']({}, 'openAtLogin', true); ok(g.openAtLogin === true && st.login === true, 'openAtLogin açıldı');
  g = await H['settings:set']({}, 'startMinimized', true); ok(g.startMinimized === true, 'startMinimized');
  g = await H['settings:set']({}, 'autoUpdate', false); ok(g.autoUpdate === false && st.app.auto === false, 'autoUpdate kapandı');
  for (const [k, v] of [['openAtLogin', 'yes'], ['feedUrl', true], ['__proto__', true], [5, true], ['autoUpdate', 1]]) { const r = await H['settings:set']({}, k, v); ok(r.error === 'bad', 'reddedildi: ' + String(k) + '=' + String(v)); }
  st.stuck = true; st.login = false; let r = await H['settings:set']({}, 'openAtLogin', true); ok(r.error === 'failed' && st.login === false, 'OS ayarı uygulamazsa sessizce başarılı denmez');
  st.stuck = false; st.supported = { supported: false, reason: 'dev' }; r = await H['settings:set']({}, 'openAtLogin', true); g = await H['settings:get'](); ok(r.error === 'unsupported' && g.openAtLogin === false && !g.autostart.supported, 'desteklenmeyen ortamda hata + get false');
  await H['settings:checkUpdate'](); ok(st.upd === 1, 'checkUpdate çağrıldı');
  const h2 = createHost({ service: { closeAll() {} } }); ok(!h2.handlers['settings:get'], 'settings verilmezse (tarayıcı/test) uç yok');
  console.log(bad ? bad + ' HATA' : 'tüm testler geçti'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.log('FAIL ' + e.stack); process.exit(1); });
