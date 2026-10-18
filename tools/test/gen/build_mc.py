# Minecraft mod test jar'lari uretir: python3 build_mc.py <cikti_dizini>
import sys, zipfile, json, os
out = sys.argv[1]; os.makedirs(out, exist_ok=True)
def jar(name, files):
    with zipfile.ZipFile(os.path.join(out, name), 'w', zipfile.ZIP_DEFLATED) as z:
        for k, v in files.items(): z.writestr(k, v)
# minimal gecerli class (CAFEBABE + surum) — icerigi onemsiz
CLS = bytes([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 1])
jar('mc_ok.jar', {'fabric.mod.json': json.dumps({'id': 'mymod', 'name': 'My Mod', 'version': '1.0', 'entrypoints': {'main': ['com.me.MyMod']}}), 'com/me/MyMod.class': CLS})
jar('mc_missing_ep.jar', {'fabric.mod.json': json.dumps({'id': 'mymod', 'name': 'My Mod', 'version': '1.0', 'entrypoints': {'main': ['com.me.Gone', 'com.me.Gone2::init']}}), 'com/me/Other.class': CLS})
jar('mc_nested.jar', {'fabric.mod.json': json.dumps({'id': 'a', 'version': '1', 'entrypoints': {'main': ['com.me.A']}, 'jars': [{'file': 'META-INF/jars/ok.jar'}]}), 'com/me/A.class': CLS, 'META-INF/jars/ok.jar': b'PK', 'META-INF/jars/hidden.jar': b'PK'})
jar('mc_mimic.jar', {'fabric.mod.json': json.dumps({'id': 'sodium', 'name': 'Sodium', 'version': '9.9', 'entrypoints': {'main': ['a.B']}}), 'a/B.class': CLS})
jar('mc_plugin_missing.jar', {'plugin.yml': 'name: Foo\nmain: org.foo.Main\nversion: 1\n', 'org/foo/Other.class': CLS})
