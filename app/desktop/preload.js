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
  info: () => call('app:info'),
  obfTools: () => call('obf:tools'),
  obfSave: (req) => call('obf:save', req),
  obfStart: (req) => call('obf:start', req),
  obfStartPyc: (req) => call('obf:startpyc', req),
  obfJob: (id) => call('obf:job', String(id)),
  obfCancel: (id) => call('obf:cancel', String(id)),
  watchSuggest: () => call('watch:suggest'),
  watchChoose: () => call('watch:choose'),
  watchSet: (l) => call('watch:set', Array.isArray(l) ? l.map(String) : []),
  watchTake: () => call('watch:take'),
  watchLog: () => call('watch:log'),
  watchNote: (k, t, n) => call('watch:note', String(k), String(t), String(n || '')),
  watchNotify: (t, b) => call('watch:notify', String(t), String(b)),
  storeGet: (k) => call('store:get', String(k)),
  storeSet: (k, v) => call('store:set', String(k), String(v))
}));
