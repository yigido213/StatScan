'use strict';
/* SAHTE Volatility 3 (yalnızca test): kayıtlı JSON çıktıları üretir; gerçek bellek analizi YAPMAZ.
   Ortam: FAKE_FIX (fixtures.json yolu), FAKE_LOG (argv günlüğü, satır başına JSON), FAKE_MODE (symbols | junk | oldnames | big),
   FAKE_SLEEP_MS (her çağrıda bekleme). Giriş: vol [seçenekler] -f DOSYA -r json EKLENTİ */
const fs = require('fs');
const a = process.argv.slice(2);
if (process.env.FAKE_LOG) { try { fs.appendFileSync(process.env.FAKE_LOG, JSON.stringify(a) + '\n'); } catch (e) { /* yok */ } }
if (a.includes('-h') || a.includes('--help') || a.includes('--version')) { process.stdout.write('Volatility 3 Framework 2.28.2-fake\nusage: vol [-h] ...\n'); process.exit(0); }
const plugin = a[a.length - 1]; const offline = a.includes('--offline'); const mode = process.env.FAKE_MODE || '';
const finish = () => {
  if (mode === 'junk') { process.stderr.write('Volatility 3 Framework 2.28.2-fake\nUnable to validate the plugin requirements: [\'plugins.PsList.kernel.layer_name\']\n'); process.stdout.write('\nUnsatisfied requirement plugins.PsList.kernel.layer_name: \n\nA translation layer requirement was not fulfilled.  Please verify that:\n\tThe file is a valid memory image and was acquired cleanly\n'); process.exit(1); }
  if (mode === 'symbols' && offline) { process.stderr.write('Volatility 3 Framework 2.28.2-fake\nUnable to validate the plugin requirements: [\'plugins.PsList.kernel.symbol_table_name\']\n'); process.stdout.write('\nUnsatisfied requirement plugins.PsList.kernel.symbol_table_name: \n\nA symbol table requirement was not fulfilled.  Please verify that:\n\tThe correct symbol file exists in the symbols directory\n'); process.exit(1); }
  if (mode === 'oldnames' && /^windows\.malware\./.test(plugin)) { process.stderr.write("vol: error: argument plugin: invalid choice: '" + plugin + "' (choose from ...)\n"); process.exit(2); }
  const fix = JSON.parse(fs.readFileSync(process.env.FAKE_FIX, 'utf8')); const key = plugin.replace(/^windows\.malware\./, 'windows.');
  let rows = fix[key]; if (!rows) { process.stderr.write("vol: error: argument plugin: invalid choice: '" + plugin + "'\n"); process.exit(2); }
  if (mode === 'big' && key === 'windows.filescan') rows = Array.from({ length: 1200 }, (_, i) => ({ Offset: '0x' + (i * 16).toString(16), Name: '\\Windows\\file' + i + '.dll', __children: [] }));
  process.stderr.write('Volatility 3 Framework 2.28.2-fake\nProgress: 100.00\n'); process.stdout.write('\n' + JSON.stringify(rows, null, 2) + '\n'); process.exit(0);
};
const ms = Number(process.env.FAKE_SLEEP_MS || 0); if (ms > 0) setTimeout(finish, ms); else finish();
