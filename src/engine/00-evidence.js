/* ---------- v3.6: kanit modeli ----------
   basis: 'fact' = bulgunun basligi dosyadan dogrudan okunan/yeniden hesaplanabilen bir olgu (baslik alani, yapi, ozet),
          'inference' = olgulardan davranis/niyet cikarimi (API birlesimi, metin kalibi),
          'heuristic' = istatistiksel/zayif gosterge (entropi, bicim anomalisi).
   loc: kanit konumlari [{o: ofset, n: uzunluk, l: etiket}] (yalnizca kok dosyada arayuzde hex'te acilabilir).
   mitre: ATT&CK etiketleri SINIFLANDIRMA icindir; bir tekniğin gercekten kullanildigini kanitlamaz. */
const TECH = {
  'T1055.008': 'Ptrace System Calls', 'T1098.004': 'SSH Authorized Keys', 'T1003.008': '/etc/passwd and /etc/shadow', 'T1070.003': 'Clear Command History', 'T1555.001': 'Keychain', 'T1553.001': 'Gatekeeper Bypass', 'T1543.001': 'Launch Agent', 'T1059.002': 'AppleScript', 'T1056.002': 'GUI Input Capture', 'T1574.004': 'Dylib Hijacking', 'T1574.006': 'Dynamic Linker Hijacking', T1098: 'Account Manipulation',
  T1005: 'Data from Local System', T1016: 'System Network Configuration Discovery', 'T1016.001': 'Internet Connection Discovery', T1027: 'Obfuscated Files or Information', 'T1027.002': 'Software Packing',
  'T1027.007': 'Dynamic API Resolution', 'T1027.009': 'Embedded Payloads', 'T1027.010': 'Command Obfuscation', T1036: 'Masquerading', 'T1036.002': 'Right-to-Left Override', 'T1036.007': 'Double File Extension', 'T1036.008': 'Masquerade File Type',
  T1047: 'Windows Management Instrumentation', T1053: 'Scheduled Task/Job', 'T1053.005': 'Scheduled Task', T1055: 'Process Injection', 'T1055.001': 'Dynamic-link Library Injection', 'T1055.004': 'Asynchronous Procedure Call', 'T1055.012': 'Process Hollowing',
  T1056: 'Input Capture', 'T1056.001': 'Keylogging', T1057: 'Process Discovery', T1059: 'Command and Scripting Interpreter', 'T1059.001': 'PowerShell', 'T1059.003': 'Windows Command Shell', 'T1059.004': 'Unix Shell', 'T1059.005': 'Visual Basic', 'T1059.006': 'Python', 'T1059.007': 'JavaScript',
  T1070: 'Indicator Removal', 'T1070.001': 'Clear Windows Event Logs', T1071: 'Application Layer Protocol', 'T1071.001': 'Web Protocols', T1082: 'System Information Discovery', T1090: 'Proxy', 'T1090.003': 'Multi-hop Proxy', T1095: 'Non-Application Layer Protocol',
  T1102: 'Web Service', 'T1102.001': 'Dead Drop Resolver', T1105: 'Ingress Tool Transfer', T1106: 'Native API', T1112: 'Modify Registry', T1115: 'Clipboard Data', T1113: 'Screen Capture', T1129: 'Shared Modules', T1134: 'Access Token Manipulation',
  T1137: 'Office Application Startup', T1140: 'Deobfuscate/Decode Files or Information', T1203: 'Exploitation for Client Execution', T1204: 'User Execution', 'T1204.002': 'Malicious File', T1218: 'System Binary Proxy Execution', 'T1218.005': 'Mshta',
  T1221: 'Template Injection', T1486: 'Data Encrypted for Impact', T1490: 'Inhibit System Recovery', T1496: 'Resource Hijacking', T1497: 'Virtualization/Sandbox Evasion', 'T1497.001': 'System Checks', T1518: 'Software Discovery', T1528: 'Steal Application Access Token',
  T1543: 'Create or Modify System Process', 'T1543.002': 'Systemd Service', 'T1543.003': 'Windows Service', T1547: 'Boot or Logon Autostart Execution', 'T1547.001': 'Registry Run Keys / Startup Folder', T1548: 'Abuse Elevation Control Mechanism', 'T1548.002': 'Bypass User Account Control',
  T1553: 'Subvert Trust Controls', 'T1553.002': 'Code Signing', T1555: 'Credentials from Password Stores', 'T1555.003': 'Credentials from Web Browsers', T1562: 'Impair Defenses', 'T1562.001': 'Disable or Modify Tools', T1567: 'Exfiltration Over Web Service', 'T1567.004': 'Exfiltration Over Webhook',
  T1574: 'Hijack Execution Flow', 'T1574.002': 'DLL Side-Loading', T1620: 'Reflective Code Loading', T1622: 'Debugger Evasion', T1003: 'OS Credential Dumping', T1068: 'Exploitation for Privilege Escalation', T1014: 'Rootkit', T1176: 'Browser Extensions', 'T1204.001': 'Malicious Link',
  T1489: 'Service Stop', T1546: 'Event Triggered Execution', T1571: 'Non-Standard Port', T1573: 'Encrypted Channel', T1041: 'Exfiltration Over C2 Channel', T1083: 'File and Directory Discovery', T1012: 'Query Registry', T1033: 'System Owner/User Discovery', T1552: 'Unsecured Credentials', 'T1552.001': 'Credentials In Files'
};
const MITRE = {
  exfil_discord: ['T1567.004'], exfil_telegram: ['T1567'], dl_exe_url: ['T1105'], exfil_paste: ['T1102', 'T1567'], ip_lookup: ['T1016.001'], onion: ['T1090.003'], powershell_enc: ['T1059.001', 'T1027.010'],
  ps_hidden: ['T1059.001'], ps_download: ['T1105', 'T1059.001'], ps_iex: ['T1059.001'], ps_reflect: ['T1620', 'T1059.001'], ps_obf: ['T1027.010'], defender_off: ['T1562.001'], amsi_patch: ['T1562.001'], certutil: ['T1105', 'T1218'],
  wmic_exec: ['T1047'], persist_run: ['T1547.001', 'T1053.005'], shadow_del: ['T1490'], uac_bypass: ['T1548.002'], evt_clear: ['T1070.001'], disable_tools: ['T1562.001'], av_kill: ['T1562.001'], revshell: ['T1059', 'T1095'],
  browser_data: ['T1555.003'], wallet_data: ['T1005'], discord_tok: ['T1528'], telegram_tdata: ['T1005'], steam_data: ['T1005'], mc_launcher: ['T1528'], antivm: ['T1497.001'], ransom: ['T1486'], miner: ['T1496'],
  long_b64_exe: ['T1027.009', 'T1140'], long_b64: ['T1027'], js_active: ['T1059.007'], vbs_exec: ['T1059.005'], sh_pipe: ['T1105', 'T1059.004'], py_exec: ['T1059.006', 'T1027'], py_ctypes: ['T1106'], js_obf: ['T1027'], bat_obf: ['T1027.010'],
  lnk_cmd: ['T1204.002', 'T1059'], lnk_shell: ['T1204.002', 'T1059'], office_macro: ['T1204.002', 'T1059.005'], office_vba: ['T1204.002', 'T1059.005'], ole_vba: ['T1204.002', 'T1059.005'], office_remote: ['T1221'], hta: ['T1218.005'], hardcoded_ip: ['T1071.001'],
  persist_startup: ['T1547.001'], pe_inject: ['T1055'], pe_hollow: ['T1055.012'], pe_keylog: ['T1056.001'], pe_dlexec: ['T1105'], pe_antidbg: ['T1622'], pe_priv: ['T1134'], pe_service: ['T1543.003'], pe_ransom_api: ['T1486'], pe_clip: ['T1115'], pe_screen: ['T1113'],
  pe_dynapi: ['T1027.007'], pe_dpapi: ['T1555.003'], pe_net_obf: ['T1027'], pe_net_load: ['T1620'], pk_packer: ['T1027.002'], pe_highent: ['T1027.002'], pe_embedded: ['T1027.009'], pe_overlay_mz: ['T1027.009'], xor_pe: ['T1027', 'T1140'],
  deobf_pe: ['T1140', 'T1027.009'], deobf_zip: ['T1140'], deobf_layer: ['T1140'], pe_sig_mismatch: ['T1553.002'], ext_mismatch: ['T1036.008'], name_double: ['T1036.007'], name_rtlo: ['T1036.002'], pk_hidden_pe: ['T1036.008', 'T1027.009'],
  js_eval: ['T1059.007', 'T1027'], js_escape: ['T1027'], pdf_active: ['T1204.002', 'T1203'], combo_dropper: ['T1105'], combo_loader: ['T1620'], combo_persist_net: ['T1547.001'], combo_evasion: ['T1497'], combo_obf_risk: ['T1027']
};
const FACT_IDS = new Set(['name_rtlo', 'name_double', 'name_scr', 'ext_mismatch', 'pe_bad', 'pe_rwx', 'pe_ep_out', 'pe_ep_last', 'pe_noimp', 'pe_fewimp', 'pe_overlay', 'pe_overlay_mz', 'pe_embedded', 'xor_pe', 'zip_slip', 'zip_dupe', 'zip_enc', 'pe_sig_ok', 'pe_sig_mismatch', 'pe_sig_bad', 'pe_sig_self', 'pe_signed',
  'pe_ts_future', 'pe_ts_zero', 'pe_noaslr', 'pe_tls', 'office_vba', 'office_remote', 'ole_vba', 'hta', 'deobf_pe', 'deobf_zip', 'deobf_layer', 'arch_exec', 'arch_unsupported', 'pk_hidden_pe', 'pe_fw', 'too_big', 'scan_err', 'pe_virtual', 'jf_trustall', 'j_ver', 'j_badclass', 'j_hidden_class', 'j_modinfo', 'tg_link']);
const HEUR_IDS = new Set(['pe_highent', 'bin_highent', 'txt_oneline', 'js_escape', 'long_b64', 'js_obf', 'bat_obf', 'ps_obf', 'pe_dynapi', 'pk_packer', 'pe_rsrc_blob', 'zip_bomb', 'j_obf', 'j_blob', 'pe_net_obf', 'hardcoded_ip']);
const BASIS_LABEL = { fact: 'Gözlem', inference: 'Çıkarım', heuristic: 'Sezgisel' };
function enrich(x) {
  if (!x.basis) x.basis = FACT_IDS.has(x.id) ? 'fact' : HEUR_IDS.has(x.id) ? 'heuristic' : 'inference';
  if ((!x.mitre || !x.mitre.length) && MITRE[x.id]) x.mitre = MITRE[x.id].slice();
  return x;
}
/* Analiz defteri: bir dosya icin hangi analizin gercekten yapildigi (done/partial/skipped/unsupported). */
const LED = { done: 'Tamamlandı', partial: 'Kısmi', skipped: 'Bu modda yapılmadı', unsupported: 'Yapılamıyor', na: 'Uygulanamaz' };
const led = (id, label, status, note) => ({ id, label, status, note: note || '' });
const EXT = { TECH, MITRE, BASIS_LABEL, LED };
