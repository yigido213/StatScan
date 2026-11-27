import assert from 'node:assert/strict';
import { loadEngine } from './engine.mjs';

const E = loadEngine();
const enc = new TextEncoder();
const archive = (items) => E.mzWrite(Object.entries(items).map(([name, data]) => ({
  name, data: typeof data === 'string' ? enc.encode(data) : data
})));
const jar = async (name, items) => new File([await archive(items)], name);
const cls = (major) => Uint8Array.of(0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, major, 0, 0);
const fabric = (id, options = {}) => JSON.stringify({ schemaVersion: 1, id, version: '1.0.0', ...options });
const scan = (files, target = {}) => E.mcCheckCompatibility(files, {
  loader: 'fabric', minecraft: '1.21.4', java: 21, side: 'client', loaderVersion: '0.17.2', ...target
});
const findings = (row) => row.findings.map((f) => f[0]);

const mods = [
  await jar('consumer.jar', {
    'fabric.mod.json': fabric('consumer', {
      depends: { minecraft: ['~1.21.4', '1.22.0'], java: '>=21', fabricloader: '>=0.16.0', library: '^2.0', missing: '*' },
      recommends: { optional: '*' },
      jars: [{ file: 'META-INF/jars/lib.jar' }]
    }),
    'META-INF/jars/lib.jar': await archive({ 'fabric.mod.json': fabric('nested', { version: '2.1.0', provides: ['library'] }) }),
    'Main.class': cls(65),
    'META-INF/versions/26/Main.class': cls(70)
  }),
  await jar('duplicate.jar', { 'fabric.mod.json': fabric('consumer'), 'Main.class': cls(69) }),
  await jar('client.jar', { 'fabric.mod.json': fabric('visual', { environment: 'client' }) }),
  await jar('other.jar', { 'plugin.yml': 'name: WrongLoader\n' })
];
let { rows } = await scan(mods);
assert.deepEqual(findings(rows[0]).sort(), ['duplicate', 'missing']);
assert.equal(rows[0].findings.find((f) => f[0] === 'missing')[1], 'missing');
assert.deepEqual(findings(rows[1]).sort(), ['duplicate', 'javaClass']);
assert.deepEqual(findings(rows[3]), ['wrongLoader']);
({ rows } = await scan(mods, { side: 'server', minecraft: '1.20.4', java: 17, loaderVersion: '' }));
assert.deepEqual(findings(rows[2]), ['inactive']);
for (const code of ['minecraft', 'javaDeclared', 'unknownVersion']) assert.ok(findings(rows[0]).includes(code), code);

({ rows } = await scan([mods[0], new File(['bad'], 'bad.jar')]));
assert.deepEqual(findings(rows[0]), ['uncertainDependency']);
assert.deepEqual(findings(rows[1]), ['badJar']);

const papers = [
  await jar('shop.jar', {
    'paper-plugin.yml': [
      'name: Shop', 'version: "1.0"', "api-version: '26.3'", 'dependencies:',
      '  bootstrap:', '    Vault:', '      required: true',
      '  server:', '    Missing:', '      load: BEFORE', '    Optional:', '      required: false'
    ].join('\n'),
    'plugin.yml': 'name: Shop\nversion: 1.0\ndepend: [LegacyMissing]\n'
  }),
  await jar('provider.jar', { 'plugin.yml': 'name: VaultProvider\nprovides:\n- Vault # alias\n' }),
  mods[1]
];
({ rows } = await scan(papers, { loader: 'paper', minecraft: '26.2', java: 25 }));
assert.deepEqual(findings(rows[0]).sort(), ['minecraft', 'missing']);
assert.equal(rows[0].findings.find((f) => f[0] === 'missing')[1], 'Missing');
assert.deepEqual(findings(rows[1]), []);
assert.deepEqual(findings(rows[2]), ['wrongLoader']);
({ rows } = await scan(papers.slice(0, 1), { loader: 'bukkit', minecraft: '26.3' }));
assert.equal(rows[0].findings[0][1], 'LegacyMissing');

const forgeData = [
  '[[mods]]', 'modId = "example"', 'version = "2.0"', "description = '''",
  'Example with [blocks] and # comments', "'''", '[[dependencies.example]]', 'modId = "minecraft"',
  'type = "required"', 'versionRange = "[1.20.1,1.21)"', 'side = "BOTH"',
  '[[dependencies.example]]', 'modId = "client_dependency"', 'type = "required"', 'side = "CLIENT"'
].join('\n');
for (const [loader, manifest] of [['forge', 'META-INF/mods.toml'], ['neoforge', 'META-INF/neoforge.mods.toml']]) {
  const item = await jar('example.jar', { [manifest]: forgeData });
  ({ rows } = await scan([item], { loader, minecraft: '1.20.1', side: 'server' }));
  assert.deepEqual(findings(rows[0]), []);
  ({ rows } = await scan([item], { loader, minecraft: '1.21', side: 'client' }));
  assert.deepEqual(findings(rows[0]).sort(), ['minecraft', 'missing']);
}

({ rows } = await scan([await jar('quilt.jar', {
  'quilt.mod.json': JSON.stringify({
    quilt_loader: { id: 'native', version: '1.0', depends: [
      { id: 'quilt_loader', versions: '>=0.26.0' }, { id: 'optional', optional: true }, { id: 'minecraft', versions: '1.21.4' }
    ] }
  })
})], { loader: 'quilt', loaderVersion: '0.26.0' }));
assert.deepEqual(findings(rows[0]), []);
assert.deepEqual((await scan([new File(['a'], 'ignore.zip')])).rows, []);
assert.equal((await scan(Array(501).fill(mods[0]))).tooMany, 500);
console.log('OK: Fabric, Quilt, Forge, NeoForge, Bukkit and Paper compatibility checks');

