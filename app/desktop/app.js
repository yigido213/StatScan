'use strict';
/* StatScan masaustu uygulamasi (Electron ana sureci). main.js (yukleyici) tarafindan baslatilir; guncellenebilir. */
const path = require('path');
const fs = require('fs');
const { app, BrowserWindow, Menu, dialog, ipcMain, shell, session } = require('electron');

/* Depodan dogrudan guncelleme: userData/kovan-repo icinde dogrulanmis bir yapi varsa uygulama ORADAN calisir (host.js REPOMOD).
   Kapatmak: statscan-app.config.json -> update.repo=false. Yapi bozuksa/acilmiyorsa REPOMOD kendiliginden geri alir; sorunsuzsa uygulamayla gelen kod calisir. */
function repoEnabled() { try { const c = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'statscan-app.config.json'), 'utf8')); return !(c && c.update && c.update.repo === false); } catch (e) { return true; } }
function repoHandOff(ctx) {
  let R; try { R = require('./host.js').repoModule; } catch (e) { return false; } if (!R || !repoEnabled()) return false;
  /* Ikinci kopya (ornegin yeniden baslat sirasinda) acilis sayacini ARTIRMASIN: kilit pickBoot'tan once alinir (ayni surecte tekrar istemek zararsiz). */
  if (!app.requestSingleInstanceLock()) { app.quit(); return true; }
  const ud = app.getPath('userData'); const b = R.pickBoot({ dataDir: ud }); if (!b) return false;
  let m; try { m = require(path.join(b.root, 'desktop', 'app.js')); } catch (e) { R.rollback(ud, 'yuklenemedi: ' + String(e && e.message || e).slice(0, 120)); return false; }
  try { m.start(Object.assign({}, ctx, { root: b.root, repoRoot: b.root, repo: b.info })); return true; } catch (e) { R.rollback(ud, 'baslatilamadi: ' + String(e && e.message || e).slice(0, 120)); try { app.relaunch(); } catch (e2) { /* yoksay */ } app.exit(0); return true; }
}

/* Acilis suresi olcumu: userData/kovan-startup.log (son 20 satir; yalniz sure, kisisel veri yok). */
const T0 = Date.now() - Math.round(process.uptime() * 1000);
function tmark(label) { try { const f = path.join(app.getPath('userData'), 'kovan-startup.log'); let old = ''; try { old = fs.readFileSync(f, 'utf8'); } catch (e) { old = ''; } const lines = old.split('\n').filter(Boolean).slice(-19); lines.push(new Date().toISOString().slice(0, 19) + '  +' + (Date.now() - T0) + ' ms  ' + label); fs.writeFileSync(f, lines.join('\n') + '\n'); } catch (e) { /* olcum yazilamazsa sessiz */ } }

function start(ctx) {
  if (!ctx.repoRoot && repoHandOff(ctx)) return;
  const D = require(path.join(ctx.root, 'dyn', 'statscan-dyn.js'));
  const { createHost, repoModule } = require('./host.js');
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
    return { file: f, feedUrl: typeof u.feedUrl === 'string' && u.feedUrl.trim() ? u.feedUrl.trim() : DEFAULT_FEED, auto: u.auto !== false, startMinimized: st.minimized === true, repo: u.repo !== false };
  }
  function saveAppConfig(patch) { /* okuma-degistirme-yazma; baska alanlar korunur */
    const f = userFile('statscan-app.config.json'); let c = {}; try { c = JSON.parse(fs.readFileSync(f, 'utf8')) || {}; } catch (e) { c = {}; }
    if (typeof c !== 'object') c = {}; c.update = c.update && typeof c.update === 'object' ? c.update : {}; c.startup = c.startup && typeof c.startup === 'object' ? c.startup : {};
    if ('auto' in patch) c.update.auto = !!patch.auto; if ('startMinimized' in patch) c.startup.minimized = !!patch.startMinimized;
    fs.mkdirSync(path.dirname(f), { recursive: true }); const t = f + '.tmp'; fs.writeFileSync(t, JSON.stringify(c, null, 2)); fs.renameSync(t, f);
  }
  const LOGIN_ARGS = ['--autostart'];
  const autostartSupport = () => (process.platform !== 'win32' && process.platform !== 'darwin' ? { supported: false, reason: 'Oturum açılışında başlatma yalnızca Windows ve macOS’ta desteklenir.' } : !app.isPackaged ? { supported: false, reason: 'Geliştirme modunda (paketlenmemiş) çalışıyor; yalnızca kurulu uygulamada ayarlanabilir.' } : { supported: true, reason: '' });
  const settingsDeps = { autostartSupport, getLogin: () => app.getLoginItemSettings({ args: LOGIN_ARGS }).openAtLogin, setLogin: (on) => app.setLoginItemSettings({ openAtLogin: !!on, args: LOGIN_ARGS }), getApp: appConfig, setApp: saveAppConfig, checkUpdate: () => (appConfig().repo ? checkRepo(true) : checkFeed(true)) };
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
  /* Depodan guncelleme denetimi: yeni app/ varsa indirir + dogrular + hazirlar, yeniden baslatinca gecerli olur (offerRestart). */
  async function checkRepo(manual) {
    if (updating) return; updating = true;
    try {
      const r = await repoModule.check({ dataDir: app.getPath('userData') }); const s7 = r.commit.slice(0, 7);
      if (r.status === 'staged') await offerRestart(s7, r.msg);
      else if (manual) dialog.showMessageBox(win, { type: 'info', title: 'Güncelleme', message: r.status === 'blocked' ? 'Bu sürüm daha önce açılmadı, geri alındı.' : 'Kovan güncel.', detail: r.status === 'blocked' ? 'Depodaki son sürüm (' + s7 + ') açılışta sorun çıkardığı için kullanılmıyor; düzeltilmiş yeni bir sürüm gelince otomatik indirilir.' : 'GitHub deposundaki son sürüm: ' + s7 + (ctx.repo ? ' (çalışan: ' + ctx.repo.commit.slice(0, 7) + ')' : '') });
    } catch (e) { if (manual) dialog.showErrorBox('Güncelleme başarısız', String(e && e.message || e)); } finally { updating = false; }
  }
  async function resetRepo() {
    if (!(await confirm({ title: 'Depodan yüklenen sürümü sıfırla', message: 'GitHub’dan indirilmiş sürümler silinir; uygulama yeniden açılınca uygulamayla gelen sürüm çalışır, sonra depodan yine güncellenir.', ok: 'Sıfırla ve yeniden başlat' }))) return;
    repoModule.reset(app.getPath('userData')); try { host && host.svc.closeAll(); } catch (e) { /* kapanirken */ } app.relaunch(); app.exit(0);
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
    const quietStart = process.argv.includes('--autostart') && appConfig().startMinimized;
    if (!quietStart) win.show(); /* koyu arka planli pencere hemen gorunur; icerik hazir olunca dolar */
    tmark('pencere olusturuldu');
    win.once('ready-to-show', () => { tmark('ilk cizim hazir'); if (process.argv.includes('--autostart') && appConfig().startMinimized) { win.showInactive(); win.minimize(); } else win.show(); });
    win.webContents.setWindowOpenHandler(({ url }) => { if (/^https:\/\//i.test(url)) shell.openExternal(url); return { action: 'deny' }; });
    win.webContents.on('will-navigate', (e, url) => { if (!url.startsWith('file://')) e.preventDefault(); });
    win.webContents.once('did-finish-load', () => { tmark('sayfa yuklendi'); }); win.webContents.once('did-finish-load', () => setTimeout(() => { try { if (ctx.repo) repoModule.markGood(app.getPath('userData'), ctx.repo.tree); U.markGood(app.getPath('userData')); U.cleanOld(app.getPath('userData'), ctx.source === 'update' ? ctx.version : ''); } catch (e) { /* yoksay */ } }, 4000));
    win.loadFile(HTML);
    win.on('closed', () => { win = null; });
  }
  function setMenu() {
    const t = [
      { label: 'Dosya', submenu: [{ role: 'quit', label: 'Çıkış' }] },
      { label: 'Görünüm', submenu: [{ role: 'resetZoom', label: 'Yakınlaştırmayı sıfırla' }, { role: 'zoomIn', label: 'Yakınlaştır' }, { role: 'zoomOut', label: 'Uzaklaştır' }, { role: 'togglefullscreen', label: 'Tam ekran' }] },
      { label: 'Yardım', submenu: [
        { label: 'Güncellemeleri denetle', click: () => (appConfig().repo ? checkRepo(true) : checkFeed(true)) },
        { label: 'Güncelleme dosyası uygula (.ssu)…', click: applyFile },
        { label: 'Depodan yüklenen sürümü sıfırla…', click: resetRepo },
        { label: 'Yapılandırma dosyasını göster', click: () => host && host.handlers['app:showConfig']() },
        { label: 'Uygulama ayarlarını göster (güncelleme kaynağı)', click: () => shell.showItemInFolder(appConfig().file) },
        { type: 'separator' },
        { label: 'StatScan hakkında', click: () => dialog.showMessageBox(win, { type: 'info', title: 'StatScan', message: 'StatScan ' + ctx.version, detail: 'Statik tarama + isteğe bağlı Windows Sandbox dinamik analizi.\nSezgisel bir araçtır; her zararlıyı yakalayamaz.\nDosyalar ana sistemde asla çalıştırılmaz.\n\nKaynak: ' + (ctx.repo ? 'GitHub deposundan indirilen sürüm (' + ctx.repo.commit.slice(0, 7) + ')' : ctx.source === 'update' ? 'imzalı güncelleme' : 'uygulamayla gelen sürüm') }) }
      ] }
    ];
    if (!app.isPackaged) t[1].submenu.push({ role: 'toggleDevTools', label: 'Geliştirici araçları' });
    Menu.setApplicationMenu(Menu.buildFromTemplate(t));
  }

  if (!app.requestSingleInstanceLock()) { app.quit(); return; }
  app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
  /* Blitz mac acilis bindirmesi: League mac baslayinca (oyun disinda -> oyunda gecisinde) kucuk, tiklanamaz-odakli pencere acar.
     Yalniz statik mac oncesi bilgi gosterir (build/not); dusman buyu sayaci YOK. Ayar: lol:ov:get (varsayilan kapali). */
  let ovWin = null; let ovWasIn = false; let ovTimer = null;
  function openOverlay(secs) {
    const { BrowserWindow, screen } = require('electron'); const { lolModule } = require('./host.js');
    if (ovWin && !ovWin.isDestroyed()) ovWin.close();
    const wa = screen.getPrimaryDisplay().workArea; const w = 400; const h = 520;
    ovWin = new BrowserWindow({ width: w, height: h, x: wa.x + wa.width - w - 16, y: wa.y + 16, frame: false, transparent: true, alwaysOnTop: true, focusable: false, skipTaskbar: true, resizable: false, show: false,
      webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true, spellcheck: false, devTools: false } });
    try { ovWin.setAlwaysOnTop(true, 'screen-saver'); } catch (e) { /* yoksay */ }
    ovWin.webContents.setWindowOpenHandler(() => ({ action: 'deny' })); ovWin.webContents.on('will-navigate', (ev) => ev.preventDefault());
    ovWin.once('ready-to-show', () => { try { ovWin.showInactive(); } catch (e) { /* yoksay */ } });
    ovWin.on('closed', () => { ovWin = null; });
    ovWin.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(lolModule.lolOverlayHtml(secs)));
  }
  function startOverlay() {
    if (ovTimer || !host || !host.handlers || !host.handlers['lol:ov:get']) return; const { lolModule } = require('./host.js'); let busy = false;
    ovTimer = setInterval(async () => {
      if (busy) return; busy = true;
      try { const cfg = await host.handlers['lol:ov:get'](null); if (!cfg || !cfg.on) { ovWasIn = false; return; }
        const live = await host.handlers['lol:live'](null); const d = lolModule.overlayDecide(ovWasIn, cfg, live); ovWasIn = d.inGame; if (d.open) openOverlay(cfg.secs);
      } catch (e) { /* lig istemcisi yok: sessiz */ } finally { busy = false; }
    }, 6000);
  }
  /* Tab'a basinca altin farki bindirmesi: oyun suruyorken gizli bir pencere hazir tutulur; Tab basili = gosterilir, birakilinca gizlenir.
     Tab durumu icin tek PowerShell sureci (host.js createTabWatcher, yalniz Windows). Odak almaz, oyuna tus gondermez. */
  let gWin = null; let gTab = null; let gTimer = null;
  function closeGold() { if (gTab) { try { gTab.stop(); } catch (e) { /* yoksay */ } gTab = null; } if (gWin && !gWin.isDestroyed()) { try { gWin.close(); } catch (e) { /* yoksay */ } } gWin = null; }
  function openGold() {
    const { BrowserWindow, screen } = require('electron'); const { lolModule } = require('./host.js'); const wa = screen.getPrimaryDisplay().workArea; const w = 340; const h = 270;
    gWin = new BrowserWindow({ width: w, height: h, x: wa.x + wa.width - w - 16, y: wa.y + 16, frame: false, transparent: true, alwaysOnTop: true, focusable: false, skipTaskbar: true, resizable: false, show: false,
      webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true, spellcheck: false, devTools: false, backgroundThrottling: false } });
    try { gWin.setAlwaysOnTop(true, 'screen-saver'); } catch (e) { /* yoksay */ } try { gWin.setIgnoreMouseEvents(true); } catch (e) { /* yoksay */ }
    gWin.webContents.setWindowOpenHandler(() => ({ action: 'deny' })); gWin.webContents.on('will-navigate', (ev) => ev.preventDefault()); gWin.on('closed', () => { gWin = null; });
    gWin.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(lolModule.lolGoldHtml()));
  }
  function startGold() {
    if (gTimer || !host || !host.handlers || !host.handlers['lol:gold']) return; const { lolModule } = require('./host.js'); let busy = false;
    gTimer = setInterval(async () => {
      if (busy) return; busy = true;
      try { const cfg = await host.handlers['lol:gold:get'](null); if (!cfg || !cfg.on) { closeGold(); return; }
        const g = await host.handlers['lol:gold'](null); if (!g || g.state !== 'ok') { closeGold(); return; }
        if (!gWin || gWin.isDestroyed()) openGold();
        if (!gTab) gTab = lolModule.createTabWatcher({ onChange: (d) => { try { if (!gWin || gWin.isDestroyed()) return; if (d) gWin.showInactive(); else gWin.hide(); } catch (e) { /* yoksay */ } } });
        gTab.start();
      } catch (e) { closeGold(); } finally { busy = false; }
    }, 5000);
  }
  app.on('before-quit', () => { try { closeGold(); } catch (e) { /* yoksay */ } });
  app.whenReady().then(() => {
    session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
    session.defaultSession.setPermissionCheckHandler(() => false);
    host = createHost({ obfOutputRoot: path.join(app.getPath('documents'), 'StatScan-Cikti'), obfToolsDir: userFile('tools'), storePath: userFile('store.json'), historyPath: userFile('tarama-gecmisi.json'), downloadsDir: app.getPath('downloads'), modsDirs: (() => { const o = []; const ad = app.getPath('appData'); o.push({ label: 'Minecraft mods (.minecraft)', path: path.join(ad, '.minecraft', 'mods') }); return o; })(), chooseFolder: async () => { const r = await dialog.showOpenDialog({ title: 'İzlenecek klasörü seç', properties: ['openDirectory'] }); return r.canceled ? null : r.filePaths[0]; }, notify: (t, b) => { try { const { Notification } = require('electron'); if (Notification.isSupported()) new Notification({ title: t, body: b }).show(); } catch (e) { /* yoksay */ } }, service: buildService(), confirm, openExternal: (u) => shell.openExternal(u), showItemInFolder: (p) => shell.showItemInFolder(p), configPath: configPath(), version: ctx.repo ? ctx.version + '+' + ctx.repo.commit.slice(0, 7) : ctx.version, settings: settingsDeps, lol: { dataDir: app.getPath('userData') }, flow: { dataDir: app.getPath('userData'), chooseApp: async () => { const r = await dialog.showOpenDialog(win || undefined, { title: 'Akışa eklenecek uygulamayı seç (.exe / .lnk)', properties: ['openFile'], filters: [{ name: 'Uygulama veya kısayol', extensions: ['exe', 'lnk', 'url'] }, { name: 'Tüm dosyalar', extensions: ['*'] }] }); return r.canceled ? null : r.filePaths[0]; }, fileIcon: async (p) => {
        /* .lnk icin once hedefin/kisayolun kendi simgesi (genel 'kisayol' simgesi gelmesin); olmazsa kisayolun kendisi */
        const tryIcon = async (q) => { try { const im = await app.getFileIcon(q, { size: 'large' }); return im && !im.isEmpty() ? im.toDataURL() : null; } catch (e) { return null; } };
        const fs = require('fs'); const cand = [];
        if (/\.lnk$/i.test(p) && process.platform === 'win32') {
          try {
            const l = shell.readShortcutLink(p);
            if (l && l.icon && /\.(ico|exe|dll)$/i.test(l.icon)) { const ex = l.icon.replace(/%([^%]+)%/g, (m, k) => process.env[k] || m); cand.push(ex); }
            if (l && l.target) cand.push(l.target);
          } catch (e) { /* kisayol okunamadi: kisayolun kendi simgesi denenir */ }
        }
        for (const q of cand) {
          try { if (!fs.existsSync(q)) continue; } catch (e) { continue; }
          if (/\.ico$/i.test(q)) { try { const { nativeImage } = require('electron'); const im = nativeImage.createFromPath(q); if (im && !im.isEmpty()) return im.resize({ width: 64, height: 64 }).toDataURL(); } catch (e) { /* sonraki aday */ } continue; }
          const v = await tryIcon(q); if (v) return v;
        }
        return tryIcon(p);
      }, openPath: (p) => shell.openPath(p) }, game: { dataDir: app.getPath('userData'), chooseConfig: async (name) => { const r = await dialog.showOpenDialog(win || undefined, { title: (name ? name + ' — ' : '') + 'Ayar dosyasını seç (.ini / .cfg / .conf)', properties: ['openFile'], filters: [{ name: 'Ayar dosyası', extensions: ['ini', 'cfg', 'conf'] }] }); return r.canceled ? null : r.filePaths[0]; }, choosePm: async () => { const r = await dialog.showOpenDialog(win || undefined, { title: 'PresentMon dosyasını seç (PresentMon-*.exe)', properties: ['openFile'], filters: [{ name: 'PresentMon', extensions: process.platform === 'win32' ? ['exe'] : ['*'] }, { name: 'Tüm dosyalar', extensions: ['*'] }] }); return r.canceled ? null : r.filePaths[0]; } }, mem: { dataDir: app.getPath('userData'), engine: D.loadEngine(HTML), chooseDump: async () => { const r = await dialog.showOpenDialog(win || undefined, { title: 'Bellek dökümünü seç (yalnızca okunur)', properties: ['openFile'], filters: [{ name: 'Bellek dökümü', extensions: ['raw', 'mem', 'dmp', 'vmem', 'lime'] }, { name: 'Tüm dosyalar', extensions: ['*'] }] }); return r.canceled ? null : r.filePaths[0]; }, chooseVol: async () => { const r = await dialog.showOpenDialog(win || undefined, { title: 'Volatility 3 dosyasını seç (vol / vol.exe / vol.py)', properties: ['openFile'], filters: [{ name: 'Volatility', extensions: process.platform === 'win32' ? ['exe', 'py'] : ['*'] }, { name: 'Tüm dosyalar', extensions: ['*'] }] }); return r.canceled ? null : r.filePaths[0]; } }, access: { dataDir: app.getPath('userData'), publicKey: ctx.publicKey, chooseFile: async () => { const r = await dialog.showOpenDialog(win || undefined, { title: 'Sahip anahtarını seç (private.pem)', properties: ['openFile'], filters: [{ name: 'PEM anahtarı', extensions: ['pem', 'key'] }, { name: 'Tüm dosyalar', extensions: ['*'] }] }); return r.canceled ? null : r.filePaths[0]; } } });
    host.register(ipcMain);
    try { startOverlay(); } catch (e) { /* bindirme acilmadi: ozellik devre disi */ }
    try { startGold(); } catch (e) { /* altin bindirmesi acilmadi: ozellik devre disi */ }
    try { host.access && host.access.start(); } catch (e) { /* engelli liste denetimi acilmadi: engel uygulanmaz */ }
    setMenu(); createWindow();
    if (ctx.rolledBack) setTimeout(() => dialog.showMessageBox(win, { type: 'warning', title: 'Güncelleme geri alındı', message: 'Önceki güncelleme kullanılmadı; uygulamayla gelen sürüm açıldı.', detail: String(ctx.rolledBack) }), 1500);
    const cfg = appConfig(); if (cfg.repo) { if (cfg.auto) setTimeout(() => checkRepo(false), 10000); } else if (cfg.feedUrl && cfg.auto) setTimeout(() => checkFeed(false), 10000);
    app.on('activate', () => { if (!BrowserWindow.getAllWindows().length) createWindow(); });
  });
  app.on('before-quit', () => { try { host && host.svc.closeAll(); } catch (e) { /* kapanirken */ } });
  app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
}
module.exports = { start };
