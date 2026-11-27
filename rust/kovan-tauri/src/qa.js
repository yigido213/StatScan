(async () => {
  const invoke = (name, args) => window.__TAURI_INTERNALS__.invoke(name, args);
  const logs = [];
  let failed = false;
  const require = (truth, message) => {
    failed ||= !truth;
    logs.push((truth ? 'PASS: ' : 'FAIL: ') + message);
  };
  const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
  const visible = id => {
    const element = document.getElementById(id);
    return element && !element.hidden && element.getClientRects().length !== 0;
  };
  try {
    require(navigator.userAgent.includes('Edg/'), 'WebView2 Edge runtime ' + navigator.userAgent);
    require(document.title.includes('Kovan') && visible('app-home'), 'Home loaded');
    await pause(150);
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
    const animations = document.getAnimations().some(a => a.playState === 'running');
    if (reduce) {
      require(!animations, 'Reduced motion respected');
      logs.push('SKIPPED: enabled-motion check (Windows runner requests reduced motion)');
    } else {
      require(animations, 'Home animation running (visibility ' + document.visibilityState + ')');
    }
    require(innerWidth === 390 && document.documentElement.scrollWidth <= innerWidth,
      'Native window at 390 CSS px with no horizontal overflow (actual width ' + innerWidth + ')');
    location.hash = '#/c-guvenlik';
    for (let i = 0; i < 30 && !visible('app-c-guvenlik'); i++) await pause(50);
    require(visible('app-c-guvenlik') && document.documentElement.scrollWidth <= innerWidth,
      'Category routing at 390 CSS px');
    const host = window.statscanHost;
    try {
      const settings = await host.settingsGet();
      require(settings.desktop === true && settings.platform === 'win32', 'Settings returned from Rust');
    } catch (error) { require(false, 'Settings: ' + String(error)); }
    try {
      const scan = await host.scanFile(new File(['Kovan smoke check'], 'notes.txt'), { mode: 'quick' });
      require(scan.name === 'notes.txt' && !!scan.sha256, 'Rust static scan returned a SHA-256');
    } catch (error) { require(false, 'Rust static scan: ' + String(error)); }
    await invoke('webview2_result', { result: logs.join('\n'), passed: !failed });
  } catch (error) {
    logs.push('FAIL: ' + String(error));
    console.error(logs.join('\n'));
    await invoke('webview2_result', { result: logs.join('\n'), passed: false });
  }
})();
