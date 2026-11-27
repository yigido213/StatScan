(async () => {
  const invoke = (name, args) => window.__TAURI_INTERNALS__.invoke(name, args);
  const logs = [];
  const require = (truth, message) => {
    if (!truth) throw new Error(message);
    logs.push('PASS: ' + message);
  };
  const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
  const visible = id => {
    const element = document.getElementById(id);
    return element && !element.hidden && element.getClientRects().length !== 0;
  };
  try {
    require(navigator.userAgent.includes('Edg/'), 'WebView2 Edge runtime ' + navigator.userAgent);
    require(document.title.includes('Kovan') && visible('app-home'), 'Home loaded');
    require(document.getAnimations().some(a => a.playState === 'running'), 'Home animation running');
    require(innerWidth === 390 && document.documentElement.scrollWidth <= innerWidth,
      'Native window at 390 CSS px with no horizontal overflow (actual width ' + innerWidth + ')');
    location.hash = '#/c-guvenlik';
    for (let i = 0; i < 30 && !visible('app-c-guvenlik'); i++) await pause(50);
    require(visible('app-c-guvenlik') && document.documentElement.scrollWidth <= innerWidth,
      'Category routing at 390 CSS px');
    const host = window.statscanHost;
    const settings = await host.settingsGet();
    require(settings.desktop === true && settings.platform === 'win32', 'Settings returned from Rust');
    const scan = await host.scanFile(new File(['Kovan smoke check'], 'notes.txt'), { mode: 'quick' });
    require(scan.name === 'notes.txt' && !!scan.sha256, 'Rust static scan returned a SHA-256');
    await invoke('webview2_result', { result: logs.join('\n'), passed: true });
  } catch (error) {
    logs.push('FAIL: ' + String(error));
    console.error(logs.join('\n'));
    await invoke('webview2_result', { result: logs.join('\n'), passed: false });
  }
})();
