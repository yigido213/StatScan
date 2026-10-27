#!/bin/bash
# 1.21.4+ surumlerinde vanilla item tanimlarindan "karmasik" (yalnizca basit model olmayan) olanlari cikarir. Kullanim: gen-mc-items.sh <cikti.json>
set -e; OUT=${1:?cikti}; W=$(mktemp -d); echo "{" > "$W/o.json"; first=1
for v in 1.21.4 1.21.5 1.21.6 1.21.7 1.21.9 1.21.11 26.1 26.2 26.3; do
  rm -rf "$W/t"; git clone -q --depth 1 -b "$v" --filter=blob:none --sparse https://github.com/InventivetalentDev/minecraft-assets "$W/t"
  (cd "$W/t" && git sparse-checkout set assets/minecraft/items >/dev/null 2>&1)
  r=$(node -e '
const fs=require("fs");const d=process.argv[1]+"/assets/minecraft/items";const complex=[];let simple=0,total=0;
for(const f of fs.readdirSync(d)){if(!f.endsWith(".json"))continue;total++;const n=f.slice(0,-5);const j=JSON.parse(fs.readFileSync(d+"/"+f,"utf8"));const ks=Object.keys(j);const m=j.model;const ok=ks.length===1&&ks[0]==="model"&&m&&m.type==="minecraft:model"&&Object.keys(m).sort().join()==="model,type"&&typeof m.model==="string";if(ok)simple++;else complex.push(n);}
console.log(JSON.stringify({total,simple,complex:complex.sort()}))' "$W/t")
  [ $first -eq 0 ] && echo "," >> "$W/o.json"; first=0; echo "\"$v\":$r" >> "$W/o.json"
done
echo "}" >> "$W/o.json"; cp "$W/o.json" "$OUT"; rm -rf "$W"
