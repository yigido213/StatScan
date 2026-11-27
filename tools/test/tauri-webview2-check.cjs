const { chromium } = require('playwright');
const { spawn } = require('node:child_process');
const assert = require('node:assert/strict');

async function check(transparent, port) {
  const processArgs = transparent ? ['--transparent'] : [];
  const app = spawn('rust/kovan-tauri/target/debug/kovan-tauri.exe', processArgs, {
    env: { ...process.env, WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: '--remote-debugging-port=' + port },
    stdio: 'inherit',
  });
  try {
    const endpoint = 'http://127.0.0.1:' + port;
    let ready = false;
    for (let i = 0; i < 60; i++) {
      if (app.exitCode !== null) throw new Error('Kovan exited with code ' + app.exitCode);
      try {
        const result = await fetch(endpoint + '/json/version');
        if (result.ok) {
          console.log('WebView2 endpoint:', (await result.json()).Browser);
          ready = true;
          break;
        }
      } catch {}
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    assert(ready, 'WebView2 CDP endpoint did not start');
    const browser = await chromium.connectOverCDP(endpoint);
    try {
      const context = browser.contexts()[0];
      const page = context.pages()[0] || await context.waitForEvent('page');
      await page.waitForURL('**/StatScan.html*', { timeout: 15000 });
      await page.locator('#app-home').waitFor({ state: 'visible' });
      const result = await page.evaluate(async () => {
        const host = window.statscanHost;
        const settings = await host.settingsGet();
        const scan = await host.scanFile(new File(['Kovan smoke check'], 'notes.txt'), { mode: 'quick' });
        return { title: document.title, desktop: settings.desktop, scanned: scan.name };
      });
      assert.match(result.title, /Kovan/);
      assert.equal(result.desktop, true);
      assert.equal(result.scanned, 'notes.txt');
      console.log('PASS: Home, native settings and Rust scan');
      await page.emulateMedia({ reducedMotion: 'no-preference' });
      await page.waitForFunction(() => document.getAnimations().length > 0);
      console.log('PASS: WebView2 reports active animations');
      await page.setViewportSize({ width: 390, height: 800 });
      await page.locator('[data-route=c-guvenlik]').first().click();
      await page.locator('#app-c-guvenlik').waitFor({ state: 'visible' });
      assert(await page.evaluate(() => innerWidth === 390 && document.documentElement.scrollWidth <= 390));
      console.log('PASS: WebView2 category routing at 390 CSS px');
      console.log(transparent ? 'PASS: application starts with --transparent (visual alpha unchecked)' : 'PASS: regular window starts');
    } finally {
      await browser.close();
    }
  } finally {
    app.kill();
    if (app.exitCode === null) await new Promise(resolve => app.once('exit', resolve));
  }
}
(async () => {
  await check(false, 9381);
  await check(true, 9382);
})().catch(error => { console.error(error); process.exitCode = 1; });
