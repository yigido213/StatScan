'use strict';
/* Sandbox'lı preload: arayuze yalnizca dar bir API verir (contextIsolation acik, node yok). */
const { contextBridge, ipcRenderer } = require('electron');
const call = (ch, ...a) => ipcRenderer.invoke(ch, ...a);
contextBridge.exposeInMainWorld('statscanHost', Object.freeze({
  desktop: true,
  status: () => call('dyn:status'),
  start: (req) => call('dyn:start', req),
  job: (id) => call('dyn:job', String(id)),
  cancel: (id) => call('dyn:cancel', String(id)),
  enableSandbox: () => call('dyn:enable'),
  openFeatures: () => call('dyn:features'),
  openVirusTotal: (url) => call('app:openVT', String(url)),
  showConfig: () => call('app:showConfig'),
  info: () => call('app:info')
}));
