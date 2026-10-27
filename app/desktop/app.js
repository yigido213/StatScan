'use strict';
/* StatScan masaustu uygulamasi (Electron ana sureci). main.js (yukleyici) tarafindan baslatilir; guncellenebilir. */
const path = require('path');
const fs = require('fs');
const { app, BrowserWindow, Menu, dialog, ipcMain, shell, session } = require('electron');

function start(ctx) {
  const D = require(path.join(ctx.root, 'dyn', 'statscan-dyn.js'));
  const { createHost } = require('./host.js');
  const U = ctx.updater;
  const HTML = path.join(ctx.root, 'StatScan.html');
  const ICON = path.join(ctx.root, 'desktop', 'assets', 'icon.png');
  let win = null; let host = null; let updating = false;

  const userFile = (n) => path.join(app.getPath('userData'), n);
  function configPath() {
    const user = userFile('statscan-dyn.config.json'); if (fs.existsSync(user)) return user;
    const shipped = path.join(ctx.bundledRoot, 'dyn', 'statscan-dyn.config.json'); return fs.existsSync(shipped) ? shipped : user;
  }
  /* Uygulama ayarlari (guncelleme kaynagi). Dosya yoksa ornek olusturulur. */
  const DEFAULT_FEED = 'https://raw.githubusercontent.com/yigido213/StatScan/main/latest.json'; /* ayar bossa kullanilir; paket imzasi her durumda dogrulanir */
  function appConfig() {
    const f = userFile('statscan-app.config.json'); let c = null;
    try { c = JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) { c = null; }
    if (!c) { c = { update: { feedUrl: '', auto: true } }; try { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, JSON.stringify(c, null, 2)); } catch (e) { /* yazilamazsa varsayilan */ } }
    const u = c.update && typeof c.update === 'object' ? c.update : {};
    const st = c.startup && typeof c.startup === 'object' ? c.startup : {};
    return { file: f, feedUrl: typeof u.feedUrl === 'string' && u.feedUrl.trim() ? u.feedUrl.trim() : DEFAULT_FEED, auto: u.auto !== false, startMinimized: st.minimized === true };
  }
  function saveAppConfig(patch) { /* okuma-degistirme-yazma; baska alanlar korunur */
    const f = userFile('statscan-app.config.json'); let c = {}; try { c = JSON.parse(fs.readFileSync(f, 'utf8')) || {}; } catch (e) { c = {}; }
    if (typeof c !== 'object') c = {}; c.update = c.update && typeof c.update === 'object' ? c.update : {}; c.startup = c.startup && typeof c.startup === 'object' ? c.startup : {};
    if ('auto' in patch) c.update.auto = !!patch.auto; if ('startMinimized' in patch) c.startup.minimized = !!patch.startMinimized;
    fs.mkdirSync(path.dirname(f), { recursive: true }); const t = f + '.tmp'; fs.writeFileSync(t, JSON.stringify(c, null, 2)); fs.renameSync(t, f);
  }
  const LOGIN_ARGS = ['--autostart'];
  const autostartSupport = () => (process.platform !== 'win32' && process.platform !== 'darwin' ? { supported: false, reason: 'Oturum açılışında başlatma yalnızca Windows ve macOS’ta desteklenir.' } : !app.isPackaged ? { supported: false, reason: 'Geliştirme modunda (paketlenmemiş) çalışıyor; yalnızca kurulu uygulamada ayarlanabilir.' } : { supported: true, reason: '' });
  const settingsDeps = { autostartSupport, getLogin: () => app.getLoginItemSettings({ args: LOGIN_ARGS }).openAtLogin, setLogin: (on) => app.setLoginItemSettings({ openAtLogin: !!on, args: LOGIN_ARGS }), getApp: appConfig, setApp: saveAppConfig, checkUpdate: () => checkFeed(true) };
  function buildService() {
    const engine = D.loadEngine(HTML); let cfg;
    try { cfg = D.loadConfig(configPath()); } catch (e) { dialog.showErrorBox('StatScan yapılandırması okunamadı', String(e && e.message || e) + '\n\nVarsayılan (güvenli) ayarlarla devam ediliyor.'); cfg = D.loadConfig(null); }
    return D.createService({ config: cfg, engine, deps: {} });
  }
  async function confirm(o) {
    const r = await dialog.showMessageBox(win, { type: 'warning', buttons: [o.cancel || 'Vazgeç', o.ok || 'Tamam'], defaultId: 0, cancelId: 0, title: o.title, message: o.title, detail: o.message, noLink: true });
    return r.response === 1;
  }
  async function offerRestart(version, notes) {
    const r = await dialog.showMessageBox(win, { type: 'info', buttons: ['Sonra', 'Şimdi yeniden başlat'], defaultId: 1, cancelId: 0, title: 'StatScan güncellendi', message: 'Sürüm ' + version + ' hazır.', detail: (notes ? notes + '\n\n' : '') + 'Yeni sürüm uygulama yeniden başlatılınca geçerli olur. Devam eden bir dinamik analiz varsa bitmesini bekle.', noLink: true });
    if (r.response === 1) { try { host && host.svc.closeAll(); } catch (e) { /* kapanirken */ } app.relaunch(); app.exit(0); }
  }
  async function checkFeed(manual) {
    if (updating) return; const cfg = appConfig();
    if (!cfg.feedUrl) { if (manual) dialog.showMessageBox(win, { type: 'info', title: 'Güncelleme', message: 'Güncelleme kaynağı ayarlanmamış.', detail: 'Otomatik güncelleme için ' + cfg.file + ' dosyasındaki "feedUrl" alanına güncelleme bildirimi adresini (https) yaz.\n\nAdres olmadan da gönderilen .ssu güncelleme dosyasını Yardım > "Güncelleme dosyası uygula" ile kurabilirsin.' }); return; }
    updating = true;
    try {
      const r = await U.checkAndInstall({ feedUrl: cfg.feedUrl, currentVersion: ctx.version, userData: app.getPath('userData'), publicKey: ctx.publicKey });
      if (r.updated) await offerRestart(r.version, r.notes); else if (manual) dialog.showMessageBox(win, { type: 'info', title: 'Güncelleme', message: 'StatScan güncel.', detail: 'Sürüm ' + ctx.version + (r.latest ? ' (sunucudaki en yeni: ' + r.latest + ')' : '') });
    } catch (e) { if (manual) dialog.showErrorBox('Güncelleme başarısız', String(e && e.message || e)); } finally { updating = false; }
  }
  async function applyFile() {
    const r = await dialog.showOpenDialog(win, { title: 'Güncelleme dosyası seç', filters: [{ name: 'StatScan güncellemesi', extensions: ['ssu'] }], properties: ['openFile'] });
    if (r.canceled || !r.filePaths[0]) return;
    try {
      const st = fs.statSync(r.filePaths[0]); if (st.size > 64 * 1024 * 1024) throw new Error('Dosya çok büyük.');
      const res = U.installPackage(fs.readFileSync(r.filePaths[0]), { publicKey: ctx.publicKey, userData: app.getPath('userData'), currentVersion: ctx.version });
      await offerRestart(res.version, res.notes);
    } catch (e) { dialog.showErrorBox('Güncelleme uygulanmadı', String(e && e.message || e)); }
  }

  function createWindow() {
    win = new BrowserWindow({
      width: 1280, height: 900, minWidth: 900, minHeight: 640, show: false, backgroundColor: '#0b1118', title: 'Kovan', icon: ICON,
      webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true, spellcheck: false, devTools: !app.isPackaged }
    });
    win.once('ready-to-show', () => { if (process.argv.includes('--autostart') && appConfig().startMinimized) { win.showInactive(); win.minimize(); } else win.show(); });
    win.webContents.setWindowOpenHandler(({ url }) => { if (/^https:\/\//i.test(url)) shell.openExternal(url); return { action: 'deny' }; });
    win.webContents.on('will-navigate', (e, url) => { if (!url.startsWith('file://')) e.preventDefault(); });
    win.webContents.once('did-finish-load', () => setTimeout(() => { try { U.markGood(app.getPath('userData')); U.cleanOld(app.getPath('userData'), ctx.source === 'update' ? ctx.version : ''); } catch (e) { /* yoksay */ } }, 4000));
    win.loadFile(HTML);
    win.on('closed', () => { win = null; });
  }
  function setMenu() {
    const t = [
      { label: 'Dosya', submenu: [{ role: 'quit', label: 'Çıkış' }] },
      { label: 'Görünüm', submenu: [{ role: 'resetZoom', label: 'Yakınlaştırmayı sıfırla' }, { role: 'zoomIn', label: 'Yakınlaştır' }, { role: 'zoomOut', label: 'Uzaklaştır' }, { role: 'togglefullscreen', label: 'Tam ekran' }] },
      { label: 'Yardım', submenu: [
        { label: 'Güncellemeleri denetle', click: () => checkFeed(true) },
        { label: 'Güncelleme dosyası uygula (.ssu)…', click: applyFile },
        { label: 'Yapılandırma dosyasını göster', click: () => host && host.handlers['app:showConfig']() },
        { label: 'Uygulama ayarlarını göster (güncelleme kaynağı)', click: () => shell.showItemInFolder(appConfig().file) },
        { type: 'separator' },
        { label: 'StatScan hakkında', click: () => dialog.showMessageBox(win, { type: 'info', title: 'StatScan', message: 'StatScan ' + ctx.version, detail: 'Statik tarama + isteğe bağlı Windows Sandbox dinamik analizi.\nSezgisel bir araçtır; her zararlıyı yakalayamaz.\nDosyalar ana sistemde asla çalıştırılmaz.\n\nKaynak: ' + (ctx.source === 'update' ? 'imzalı güncelleme' : 'uygulamayla gelen sürüm') }) }
      ] }
    ];
    if (!app.isPackaged) t[1].submenu.push({ role: 'toggleDevTools', label: 'Geliştirici araçları' });
    Menu.setApplicationMenu(Menu.buildFromTemplate(t));
  }

  if (!app.requestSingleInstanceLock()) { app.quit(); return; }
  app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
  app.whenReady().then(() => {
    session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
    session.defaultSession.setPermissionCheckHandler(() => false);
    host = createHost({ obfOutputRoot: path.join(app.getPath('documents'), 'StatScan-Cikti'), obfToolsDir: userFile('tools'), storePath: userFile('store.json'), downloadsDir: app.getPath('downloads'), modsDirs: (() => { const o = []; const ad = app.getPath('appData'); o.push({ label: 'Minecraft mods (.minecraft)', path: path.join(ad, '.minecraft', 'mods') }); return o; })(), chooseFolder: async () => { const r = await dialog.showOpenDialog({ title: 'İzlenecek klasörü seç', properties: ['openDirectory'] }); return r.canceled ? null : r.filePaths[0]; }, notify: (t, b) => { try { const { Notification } = require('electron'); if (Notification.isSupported()) new Notification({ title: t, body: b }).show(); } catch (e) { /* yoksay */ } }, service: buildService(), confirm, openExternal: (u) => shell.openExternal(u), showItemInFolder: (p) => shell.showItemInFolder(p), configPath: configPath(), version: ctx.version, settings: settingsDeps });
    host.register(ipcMain);
    setMenu(); createWindow();
    if (ctx.rolledBack) setTimeout(() => dialog.showMessageBox(win, { type: 'warning', title: 'Güncelleme geri alındı', message: 'Önceki güncelleme kullanılmadı; uygulamayla gelen sürüm açıldı.', detail: String(ctx.rolledBack) }), 1500);
    const cfg = appConfig(); if (cfg.feedUrl && cfg.auto) setTimeout(() => checkFeed(false), 10000);
    app.on('activate', () => { if (!BrowserWindow.getAllWindows().length) createWindow(); });
  });
  app.on('before-quit', () => { try { host && host.svc.closeAll(); } catch (e) { /* kapanirken */ } });
  app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
}
module.exports = { start };
