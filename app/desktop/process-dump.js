'use strict';
const path = require('node:path');
const fs = require('node:fs/promises');
const { randomUUID } = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

async function worker(mode, values) {
  const ps = path.join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');
  const { stdout } = await promisify(execFile)(ps, ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'process-dump.ps1'), mode], {
    windowsHide: true, timeout: 60000, env: { ...process.env, ...values }
  }).catch(error => { throw new Error(String(error.stderr || error.message).trim().slice(0, 400)); });
  return stdout.trim();
}

async function list(image) {
  if (!path.isAbsolute(image) || path.extname(image).toLowerCase() !== '.exe') throw new Error('Geçerli bir EXE seç.');
  return JSON.parse(await worker('list', { KOVAN_DUMP_IMAGE: image }));
}

async function capture(image, row, destination) {
  if (path.extname(destination).toLowerCase() !== '.dmp') throw new Error('Dosya uzantısı .dmp olmalı.');
  const temporary = path.join(path.dirname(destination), '.kovan-' + randomUUID() + '.tmp');
  try {
    await worker('capture', {
      KOVAN_DUMP_IMAGE: image, KOVAN_DUMP_PID: String(row.id),
      KOVAN_DUMP_STARTED: row.started, KOVAN_DUMP_TEMP: temporary
    });
    const file = await fs.open(temporary, 'r');
    let size;
    try {
      const header = Buffer.alloc(32);
      const { bytesRead } = await file.read(header);
      size = (await file.stat()).size;
      const streams = header.readUInt32LE(8);
      const directory = header.readUInt32LE(12);
      if (bytesRead !== 32 || header.toString('ascii', 0, 4) !== 'MDMP' || !streams ||
          directory < 32 || directory + streams * 12 > size) throw new Error('Döküm başlığı doğrulanamadı.');
    } finally { await file.close(); }
    await fs.rename(temporary, destination);
    return { size, destination };
  } finally { await fs.rm(temporary, { force: true }); }
}

function register({ ipcMain, dialog, window, pageURL }) {
  let selection;
  let busy = false;
  function handle(channel, action) {
    ipcMain.handle(channel, async (event, ...args) => {
      const win = window();
      if (!win || event.sender !== win.webContents || event.senderFrame !== win.webContents.mainFrame ||
          event.senderFrame.url.split('#')[0] !== pageURL) throw new Error('Geçersiz pencere.');
      if (busy) throw new Error('Önceki işlem sürüyor.');
      busy = true;
      try { return await action(win, ...args); } finally { busy = false; }
    });
  }
  handle('dump:list', async (_win, image) => {
    selection = null;
    const rows = await list(image);
    selection = { image, rows, token: randomUUID() };
    return { rows, token: selection.token };
  });
  handle('dump:save', async (win, token, id) => {
    const row = selection?.rows.find(item => item.id === id);
    if (!row || token !== selection.token) throw new Error('Süreç listesini yenile.');
    const { image } = selection;
    const save = await dialog.showSaveDialog(win, {
      title: 'Tanılama dökümünü kaydet', defaultPath: path.basename(image, path.extname(image)) + '-' + id + '.dmp',
      filters: [{ name: 'Windows Minidump', extensions: ['dmp'] }]
    });
    if (save.canceled) return null;
    return capture(image, row, save.filePath);
  });
}
module.exports = { register, list, capture };
