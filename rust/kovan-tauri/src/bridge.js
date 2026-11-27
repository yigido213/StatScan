(methods) => {
  if (window.top !== window || location.pathname !== '/StatScan.html') return;

  const message = 'Bu araç henüz Rust sürümünde yok';
  const unsupported = async () => ({ error: 'unsupported', message });
  const invoke = (command, args) => window.__TAURI_INTERNALS__.invoke(command, args);
  const call = async (command, args) => {
    try {
      return await invoke(command, args);
    } catch (error) {
      return { error: 'host', message: String(error?.message || error) };
    }
  };
  const host = Object.fromEntries(methods.map((name) => [name, unsupported]));
  // These Electron callers display caught exceptions and expect a non-error return shape.
  const unavailableDump = async () => { throw new Error(message); };
  for (const name of ['dumpProcesses', 'dumpRegions', 'dumpSave']) {
    if (name in host) host[name] = unavailableDump;
  }
  Object.assign(host, {
    desktop: true,
    info: () => call('app_info'),
    showConfig: () => call('show_config'),
    settingsGet: () => call('settings_get'),
    settingsSet: (key, value) => call('settings_set', { key: String(key), value: value === true }),
    storeGet: (key) => invoke('store_get', { key: String(key) }),
    storeSet: (key, value) => call('store_set', { key: String(key), value: String(value) }),
    uiZoom(factor) {
      const zoom = Number(factor);
      if (!(zoom >= 0.4 && zoom <= 3)) return false;
      // The Electron contract returns synchronously. Let the existing CSS fallback
      // apply immediately, then replace it only after the latest native zoom succeeds.
      pendingZoom = pendingZoom.catch(() => {}).then(async () => {
        if (wantedZoom !== zoom) return;
        await invoke('window_zoom', { zoom });
        if (wantedZoom === zoom) document.documentElement.style.removeProperty('zoom');
      }).catch(() => {});
      wantedZoom = zoom;
      return false;
    },
    windowRoute: (title) => call('window_route', { title: String(title) }),
    async scanFile(file, options = {}) {
      const mode = ['quick', 'normal', 'deep'].includes(options.mode) ? options.mode : 'normal';
      const size = file.size ?? file.data?.length ?? 0;
      const limit = Number(options.timeLimitMs);
      const timeLimitMs = Number.isSafeInteger(limit) && limit > 0 ? limit : null;
      const { id, upload } = await invoke('scan_begin', {
        name: file.name || 'dosya', size, mode, timeLimitMs,
        javaAllowed: options.policy?.javaExempt !== 'off',
      });
      const started = Date.now();
      const progress = (frac, label, stats = { files: 0, classes: 0 }) =>
        options.onProgress?.({ file: file.name, frac, label, stats, elapsed: Date.now() - started });
      let timer;
      try {
        progress(0, 'Rust taraması hazırlanıyor');
        if (options.cancel?.()) await invoke('scan_cancel', { id });
        if (upload && !options.cancel?.()) {
          const bytes = file.slice ? null : new Uint8Array(
            file.arrayBuffer ? await file.arrayBuffer() : file.data
          );
          const chunkSize = 512 * 1024;
          for (let offset = 0; offset < size; offset += chunkSize) {
            if (options.cancel?.()) {
              await invoke('scan_cancel', { id });
              break;
            }
            const chunk = bytes
              ? bytes.subarray(offset, offset + chunkSize)
              : new Uint8Array(await file.slice(offset, offset + chunkSize).arrayBuffer());
            let binary = '';
            for (let i = 0; i < chunk.length; i += 8192) {
              binary += String.fromCharCode(...chunk.subarray(i, i + 8192));
            }
            await invoke('scan_append', { id, chunk: btoa(binary) });
          }
        }
        if (options.cancel) {
          timer = setInterval(() => {
            if (!options.cancel()) return;
            clearInterval(timer);
            void call('scan_cancel', { id });
          }, 100);
        }
        progress(null, 'Rust ile taranıyor');
        const report = await invoke('scan_run', { id });
        progress(1, 'Tarama tamamlandı', report.stats);
        return report;
      } finally {
        clearInterval(timer);
        await call('scan_discard', { id });
      }
    },
  });
  let pendingZoom = Promise.resolve();
  let wantedZoom = 1;
  Object.defineProperty(window, 'statscanHost', { value: Object.freeze(host) });

  // Decorate the exported scanner before the original UI script can call it.
  let scanner;
  Object.defineProperty(window, 'StatScan', {
    configurable: true,
    get: () => scanner,
    set(api) {
      const existing = api.scanFile;
      api.scanFile = async (file, options = {}) => {
        if (options.rulePack?.rules?.length || options.policy?.trusted?.length
            || options.policy?.javaExempt === 'trusted') return existing(file, options);
        return host.scanFile(file, options);
      };
      scanner = api;
    },
  });

  // Preserve the HTML router and hash history. Mirror the translated title to the window.
  window.addEventListener('DOMContentLoaded', () => {
    const title = document.querySelector('title');
    if (!title) return;
    const update = () => { void host.windowRoute(document.title); };
    new MutationObserver(update).observe(title, { childList: true, characterData: true, subtree: true });
    update();
  }, { once: true });
}
