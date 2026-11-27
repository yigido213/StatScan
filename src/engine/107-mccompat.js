/* Read-only, manifest-based Minecraft instance checks. Keep unknown results distinct from incompatibilities. */
const MCC_LIMIT = { files: 500, jarBytes: 128 * 1048576, classBytes: 64 * 1048576, nestedBytes: 48 * 1048576, nestedCount: 64 };
const MCC_MANIFESTS = [
  ['bukkit', 'plugin.yml'], ['paper', 'paper-plugin.yml'], ['fabric', 'fabric.mod.json'],
  ['quilt', 'quilt.mod.json'], ['forge', 'META-INF/mods.toml'],
  ['neoforge', 'META-INF/neoforge.mods.toml'], ['legacy', 'mcmod.info']
];

function mccVersion(value) {
  const text = String(value ?? '').trim();
  if (!/^\d{1,9}(?:\.\d{1,9}){0,7}(?:\+[-\w.]+)?$/.test(text)) return null;
  return text.split('+')[0].split('.').map(Number);
}

function mccCompare(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff) return Math.sign(diff);
  }
  return 0;
}

function mccCombine(states, mode) {
  if (mode === 'any') return states.includes(true) ? true : states.includes(null) ? null : false;
  return states.includes(false) ? false : states.includes(null) ? null : true;
}

function mccMatches(version, range, style) {
  if (range == null || range === '*' || (style === 'maven' && range === '')) return true;
  if (Array.isArray(range) && range.length) return mccCombine(range.map((part) => mccMatches(version, part, style)), 'any');
  if (typeof range !== 'string' || !version) return null;
  range = range.trim();
  if (version === range || (style !== 'maven' && range === '=' + version)) return true;
  const v = mccVersion(version);
  if (!v) return null;
  if (style === 'maven') {
    if (mccVersion(range)) return true; // A bare Maven version is a soft recommendation.
    const intervals = range.match(/[[(][^\])]*[\])]/g) || [];
    if (!intervals.length || intervals.join(',') !== range.replace(/\s*,\s*(?=[[(])/g, ',')) return null;
    return mccCombine(intervals.map((interval) => {
      const parts = interval.slice(1, -1).split(',').map((p) => p.trim());
      const [lo, hi] = parts.map(mccVersion);
      if (parts.length === 1 && interval[0] === '[' && interval.endsWith(']')) return lo ? mccCompare(v, lo) === 0 : null;
      if (parts.length !== 2 || (parts[0] && !lo) || (parts[1] && !hi)) return null;
      const low = lo ? mccCompare(v, lo) : 1;
      const high = hi ? mccCompare(v, hi) : -1;
      return (low > 0 || (low === 0 && interval[0] === '[')) && (high < 0 || (high === 0 && interval.endsWith(']')));
    }), 'any');
  }
  return mccCombine(range.split(/\s*\|\|\s*/).map((part) => mccCombine(part.split(/\s+/).map((token) => {
    if (token === '*') return true;
    const wildcard = /^(\d{1,9}(?:\.\d{1,9})*)\.(?:x|\*)(?:\.(?:x|\*))*$/i.exec(token);
    if (wildcard) return wildcard[1].split('.').every((n, i) => Number(n) === (v[i] ?? 0));
    const match = /^(>=|<=|>|<|=|~|\^)?(.+)$/.exec(token);
    const base = match && mccVersion(match[2]);
    if (!base) return null;
    const order = mccCompare(v, base);
    switch (match[1]) {
      case '>=': return order >= 0;
      case '<=': return order <= 0;
      case '>': return order > 0;
      case '<': return order < 0;
      case '~': return order >= 0 && v[0] === base[0] && (v[1] ?? 0) === (base[1] ?? 0);
      case '^': return order >= 0 && v[0] === base[0];
      default: return order === 0;
    }
  }), 'all')), 'any');
}

function mccStripComment(line) {
  let quote = '';
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote === '"' && c === '\\') i++;
    else if (c === quote) quote = '';
    else if (!quote && (c === '"' || c === "'")) quote = c;
    else if (!quote && c === '#') return line.slice(0, i).trimEnd();
  }
  return line.trimEnd();
}

function mccUnquote(value) {
  return value.trim().replace(/^(["'])(.*)\1$/, '$2');
}

function mccYaml(text, paper) {
  const values = new Map();
  const lists = new Map();
  const dependencies = new Map();
  const stack = [];
  let limited = false;
  for (const source of text.split(/\r?\n/)) {
    const line = mccStripComment(source);
    if (!line.trim()) continue;
    const item = /^ *-\s+(.+)$/.exec(line);
    if (item && ['depend', 'provides'].includes(stack[0]?.key)) {
      const key = stack[0].key;
      if (!lists.has(key)) lists.set(key, []);
      lists.get(key).push(mccUnquote(item[1]));
      continue;
    }
    const field = /^( *)([\w.-]+|"[^"]+"|'[^']+')\s*:\s*(.*)$/.exec(line);
    if (!field) {
      if (stack[0]?.key === 'dependencies' || ['depend', 'provides'].includes(stack[0]?.key)) limited = true;
      continue;
    }
    const [, spaces, rawKey, raw] = field;
    const indent = spaces.length;
    const key = mccUnquote(rawKey);
    while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();
    stack.push({ indent, key });
    if (indent === 0) {
      if (['name', 'version', 'api-version'].includes(key)) values.set(key, mccUnquote(raw));
      if (['depend', 'provides'].includes(key) && raw) {
        if (/^\[.*\]$/.test(raw)) lists.set(key, raw.slice(1, -1).split(',').map(mccUnquote).filter(Boolean));
        else limited = true;
      }
      if (key === 'dependencies' && raw && raw !== '{}') limited = true;
    }
    if (paper && stack[0]?.key === 'dependencies' && ['server', 'bootstrap'].includes(stack[1]?.key)) {
      if (stack.length === 2 && raw && raw !== '{}') limited = true;
      if (stack.length === 3) {
        const id = stack[1].key + '/' + key;
        if (raw && raw !== '{}') limited = true;
        else dependencies.set(id, { id: key, required: true });
      }
      if (stack.length === 4 && key === 'required') {
        const dependency = dependencies.get(stack[1].key + '/' + stack[2].key);
        if (dependency && /^(true|false)$/i.test(raw)) dependency.required = raw.toLowerCase() === 'true';
        else limited = true;
      }
    }
  }
  const deps = paper ? [...dependencies.values()].filter((x) => x.required) : (lists.get('depend') || []).map((id) => ({ id }));
  return { mods: [{ id: values.get('name'), version: values.get('version'), aliases: lists.get('provides') || [], deps, api: values.get('api-version') }], limited };
}

function mccToml(text, target) {
  const mods = [];
  const dependencies = [];
  let table;
  let limited = false;
  let multiline = '';
  const tracked = new Set(['modId', 'version', 'mandatory', 'type', 'versionRange', 'side']);
  for (const source of text.split(/\r?\n/)) {
    if (multiline) {
      if (source.includes(multiline)) multiline = '';
      continue;
    }
    const line = mccStripComment(source).trim();
    if (line.startsWith('[')) {
      table = null;
      if (/^\[\[\s*mods\s*\]\]$/.test(line)) {
        table = {};
        mods.push(table);
      }
      const owner = /^\[\[\s*dependencies\s*\.\s*([\w.-]+|"[^"]+"|'[^']+')\s*\]\]$/.exec(line);
      if (owner) {
        table = { owner: mccUnquote(owner[1]) };
        dependencies.push(table);
      } else if (/^\[\[\s*dependencies\b/.test(line)) limited = true;
      continue;
    }
    const field = /^(\w+)\s*=\s*(.*)$/.exec(line);
    if (!field) continue;
    const delimiter = /^(?:"""|''')/.exec(field[2]);
    if (delimiter && !field[2].slice(3).includes(delimiter[0])) multiline = delimiter[0];
    if (table && tracked.has(field[1])) table[field[1]] = mccUnquote(field[2]);
  }
  return {
    mods: mods.map((mod) => ({
      id: mod.modId, version: mod.version, aliases: [],
      deps: dependencies.filter((d) => d.owner === mod.modId &&
        (d.type === 'required' || (d.type == null && d.mandatory !== 'false')) &&
        !(d.side === 'CLIENT' && target.side === 'server') && !(d.side === 'SERVER' && target.side === 'client'))
        .map((d) => ({ id: d.modId, range: d.versionRange }))
    })),
    limited
  };
}

function mccManifest(text, kind, target) {
  if (kind === 'bukkit' || kind === 'paper') return mccYaml(text, kind === 'paper');
  if (kind === 'forge' || kind === 'neoforge') return mccToml(text, target);
  const json = JSON.parse(text);
  if (kind === 'legacy') {
    const mods = Array.isArray(json) ? json : json.modList;
    if (!Array.isArray(mods)) throw new Error('mcmod.info');
    return { mods: mods.map((m) => ({ id: m.modid, version: m.version, aliases: [], deps: [] })), limited: true };
  }
  if (kind === 'fabric') {
    const { id, version, provides, depends, jars, environment } = json;
    if (environment && environment !== '*' && environment !== target.side) {
      return { mods: [], inactive: true };
    }
    return {
      mods: [{ id, version, aliases: (provides || []).filter((x) => typeof x === 'string'), deps: Object.entries(depends || {}).map(([id, range]) => ({ id, range })) }],
      nested: (jars || []).map((jar) => jar.file)
    };
  }
  const { id, version, provides, depends, jars } = json.quilt_loader;
  const environment = json.minecraft?.environment;
  if (environment && environment !== '*' && environment !== target.side && ['client', 'server'].includes(environment)) {
    return { mods: [], inactive: true };
  }
  const required = (depends || []).filter((d) => !d?.optional);
  return {
    mods: [{
      id, version,
      aliases: (provides || []).map((p) => typeof p === 'string' ? p : { id: p?.id, version: p?.version }),
      deps: required.filter((d) => typeof d === 'string' || (typeof d?.id === 'string' && !d.unless)).map((d) =>
        typeof d === 'string' ? { id: d } : { id: d.id, range: d.versions })
    }],
    nested: jars || [],
    limited: required.some((d) => typeof d !== 'string' && (typeof d?.id !== 'string' || d.unless))
  };
}

function mccSelect(entries, loader) {
  const found = MCC_MANIFESTS.filter(([, path]) => entries.has(path));
  const order = { paper: ['paper', 'bukkit'], bukkit: ['bukkit'], fabric: ['fabric'], quilt: ['quilt', 'fabric'],
    forge: ['forge', 'legacy'], neoforge: ['neoforge', 'forge'] }[loader];
  const selected = order.map((kind) => found.find(([k]) => k === kind)).find(Boolean);
  return { selected, found: found.map(([kind]) => kind) };
}

async function mccInspect(zip, row, target, depth, budget) {
  const entries = new Map(zip.entries.filter((e) => !e.isDir).map((e) => [e.name, e]));
  const { selected, found } = mccSelect(entries, target.loader);
  if (!selected) {
    if (depth === 0) {
      row.findings.push(found.length ? ['wrongLoader', found.join(', ')] : ['noManifest']);
      if (!found.length) row.metadataPartial = true;
    }
    return;
  }
  const [kind, manifest] = selected;
  let data;
  try {
    data = mccManifest(new TextDecoder().decode(await mzData(zip, entries.get(manifest), 1024 * 1024)), kind, target);
    if (!data.inactive && (!data.mods.length || data.mods.some((m) => typeof m.id !== 'string' || !m.id.trim()))) throw new Error(manifest);
  } catch {
    row.findings.push(['badManifest', manifest]);
    row.metadataPartial = true;
    return;
  }
  if (data.inactive) {
    if (depth === 0) row.findings.push(['inactive']);
    return;
  }
  if (data.limited || (target.loader === 'neoforge' && kind === 'forge')) {
    row.findings.push(['limitedManifest', manifest]);
    row.metadataPartial = true;
  }
  row.mods.push(...data.mods.map((mod) => ({ ...mod, kind, depth })));
  let max = 0;
  let classPartial = false;
  for (const entry of entries.values()) {
    if (!entry.name.endsWith('.class') || entry.name.startsWith('META-INF/') || entry.name === 'module-info.class') continue;
    if (entry.usize > budget.classBytes) {
      classPartial = true;
      continue;
    }
    budget.classBytes -= entry.usize;
    try {
      const major = mmMajor(await mzData(zip, entry, 2 * 1048576));
      if (!major) classPartial = true;
      max = Math.max(max, major);
    } catch {
      classPartial = true;
    }
    if (max > target.java + 44) break;
  }
  if (max > target.java + 44) row.findings.push(['javaClass', max - 44, selected[1]]);
  if (classPartial) row.findings.push(['partialClasses']);
  const nested = [...new Set(data.nested || [])];
  if (['forge', 'neoforge'].includes(kind) && entries.has('META-INF/jarjar/metadata.json')) {
    try {
      const info = JSON.parse(new TextDecoder().decode(await mzData(zip, entries.get('META-INF/jarjar/metadata.json'), 1024 * 1024)));
      nested.push(...info.jars.map((jar) => jar.path));
    } catch {
      row.findings.push(['limitedManifest', 'META-INF/jarjar/metadata.json']);
      row.metadataPartial = true;
    }
  }
  for (const name of new Set(nested)) {
    const entry = entries.get(name);
    if (entry && depth < 3 && budget.nestedCount > 0 && entry.usize <= budget.nestedBytes) {
      budget.nestedCount--;
      budget.nestedBytes -= entry.usize;
      try {
        await mccInspect(mzRead(await mzData(zip, entry, MCC_LIMIT.nestedBytes)), row, target, depth + 1, budget);
        continue;
      } catch { /* report the unread archive below */ }
    }
    row.findings.push(['partialNested', typeof name === 'string' ? name : '—']);
    row.metadataPartial = true;
  }
}

function mccResolve(rows, target) {
  const providers = new Map();
  const topIds = new Map();
  const plugin = target.loader === 'paper' || target.loader === 'bukkit';
  const key = (name) => plugin ? name.toLowerCase() : name;
  const builtins = new Map([['minecraft', target.minecraft], ['java', String(target.java)]]);
  const loaderIds = { fabric: ['fabricloader'], quilt: ['quilt_loader', 'fabricloader'], forge: ['forge'], neoforge: ['neoforge'] }[target.loader] || [];
  for (const id of loaderIds) builtins.set(id, id === 'fabricloader' && target.loader === 'quilt' ? '' : target.loaderVersion);
  const partial = rows.some((row) => row.metadataPartial);
  const addProvider = (name, version) => {
    if (typeof name !== 'string' || !name) return;
    const k = key(name);
    if (!providers.has(k)) providers.set(k, []);
    providers.get(k).push(version);
  };
  for (const row of rows) for (const mod of row.mods) {
    addProvider(mod.id, mod.version);
    for (const alias of mod.aliases) {
      if (typeof alias === 'string') addProvider(alias, mod.version);
      else addProvider(alias?.id, alias?.version);
    }
    if (mod.depth !== 0) continue;
    const id = key(mod.id);
    if (!topIds.has(id)) topIds.set(id, new Set());
    topIds.get(id).add(row);
  }
  for (const row of rows) for (const mod of row.mods) {
    const dup = mod.depth === 0 && topIds.get(key(mod.id));
    if (dup && dup.size > 1) row.findings.push(['duplicate', mod.id, [...dup].filter((other) => other !== row).map((other) => other.name).join(', ')]);
    if (mod.api) {
      const current = mccVersion(target.minecraft);
      const minimum = mccVersion(mod.api);
      if (current && minimum && mccCompare(current, minimum) < 0) row.findings.push(['minecraft', mod.api]);
      else if (!minimum) row.findings.push(['unknownVersion', 'api-version', mod.api]);
    }
    for (const dep of mod.deps) {
      if (typeof dep.id !== 'string' || !dep.id) {
        row.findings.push(['limitedManifest', mod.id]);
        continue;
      }
      const builtin = !plugin && builtins.has(dep.id);
      const versions = builtin ? [builtins.get(dep.id)] : providers.get(key(dep.id));
      if (!versions) {
        row.findings.push([partial ? 'uncertainDependency' : 'missing', dep.id, mod.id]);
        continue;
      }
      const style = ['forge', 'neoforge'].includes(mod.kind) ? 'maven' : 'predicate';
      const result = mccCombine(versions.map((v) => mccMatches(v, dep.range, style)), 'any');
      const range = typeof dep.range === 'string' ? dep.range : JSON.stringify(dep.range);
      if (result === false) {
        if (builtin && dep.id === 'minecraft') row.findings.push(['minecraft', range]);
        else if (builtin && dep.id === 'java') row.findings.push(['javaDeclared', range]);
        else row.findings.push(['dependencyVersion', dep.id, range, versions.join(', ')]);
      } else if (result === null) row.findings.push(['unknownVersion', dep.id, range]);
    }
  }
  for (const row of rows) {
    const unique = new Map(row.findings.map((finding) => [JSON.stringify(finding), finding]));
    row.findings = [...unique.values()];
  }
}

async function mcCheckCompatibility(files, target, progress = () => {}) {
  const list = Array.from(files).filter((file) => /\.jar$/i.test(file.name));
  if (list.length > MCC_LIMIT.files) return { tooMany: MCC_LIMIT.files, rows: [] };
  const rows = [];
  for (const file of list) {
    const row = { name: file.webkitRelativePath || file.name, mods: [], findings: [], metadataPartial: false };
    if (file.size > MCC_LIMIT.jarBytes) {
      row.findings.push(['tooLarge', MCC_LIMIT.jarBytes / 1048576]);
      row.metadataPartial = true;
    } else {
      try {
        const zip = mzRead(new Uint8Array(await file.arrayBuffer()));
        await mccInspect(zip, row, target, 0, { classBytes: MCC_LIMIT.classBytes, nestedBytes: MCC_LIMIT.nestedBytes, nestedCount: MCC_LIMIT.nestedCount });
      } catch {
        row.findings.push(['badJar']);
        row.metadataPartial = true;
      }
    }
    rows.push(row);
    progress(rows.length, list.length);
  }
  mccResolve(rows, target);
  return { rows };
}
