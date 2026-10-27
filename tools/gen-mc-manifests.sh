#!/bin/bash
# Vanilla asset manifestleri uretir (sunucu degil, gelistirme araci): her pack_format'in ilk surumu icin dokularin yol+sha1 listesi.
# Kaynak: github.com/InventivetalentDev/minecraft-assets (surum dallari). Cikti: $1/<surum>.json  Kullanim: gen-mc-manifests.sh <cikti_dizini>
set -e; OUT=${1:?cikti}; mkdir -p "$OUT"; W=$(mktemp -d)
VERS="1.8.9 1.9 1.11 1.13 1.15 1.16.2 1.17 1.18 1.19 1.19.3 1.19.4 1.20 1.20.2 1.20.3 1.20.5 1.21 1.21.2 1.21.4 1.21.5 1.21.6 1.21.7 1.21.9 1.21.11 26.1 26.2 26.3"
for v in $VERS; do
  [ -s "$OUT/$v.json" ] && continue
  rm -rf "$W/t"; git clone -q --depth 1 -b "$v" --filter=blob:none --sparse https://github.com/InventivetalentDev/minecraft-assets "$W/t"
  (cd "$W/t" && git sparse-checkout set assets/minecraft/textures assets/minecraft/models assets/minecraft/items assets/minecraft/blockstates assets/minecraft/atlases >/dev/null 2>&1)
  node -e '
const fs=require("fs"),path=require("path"),crypto=require("crypto");const root=process.argv[1]+"/assets/minecraft";const out={};
function walk(d,rel){if(!fs.existsSync(d))return;for(const e of fs.readdirSync(d,{withFileTypes:true})){const p=d+"/"+e.name,r=rel?rel+"/"+e.name:e.name;if(e.isDirectory())walk(p,r);else{const b=fs.readFileSync(p);out[r]=[b.length,crypto.createHash("sha1").update(b).digest("hex").slice(0,16)];}}}
walk(root,"");fs.writeFileSync(process.argv[2],JSON.stringify({v:process.argv[3],files:out}));console.log(process.argv[3],Object.keys(out).length)' "$W/t" "$OUT/$v.json" "$v"
done
rm -rf "$W"
