// Static XOR analysis. Search on bounded prefixes; materialize only the selected candidate.
const XD_LIMIT = 16 * 1024 * 1024;
const xdEncoder = new TextEncoder(), xdDecoder = new TextDecoder();
const xdPop = Uint8Array.from({ length: 256 }, (_, n) => n.toString(2).replace(/0/g, '').length);
const xdRol = (v, n) => ((v << n) | (v >>> (8 - n))) & 255;
function xdApply(src, key, mode, out) {
  for (let i = 0; i < out.length; i++) {
    const k = key[i % key.length];
    out[i] = src[i] ^ (mode === 'key+i' ? k + i : mode === 'rol' ? xdRol(k, i % 8) : k);
  }
  return out;
}
function xdFormat(b) {
  if (b[0] === 77 && b[1] === 90 && b.length >= 64) {
    const p = new DataView(b.buffer, b.byteOffset, b.length).getUint32(60, true);
    if (p >= 64 && p + 24 <= b.length && b[p] === 80 && b[p+1] === 69 && !b[p+2] && !b[p+3]) return 'PE';
    if (latin1(b.subarray(64, 512)).includes('This program cannot be run')) return 'MZ';
  }
  if (b[0] === 80 && b[1] === 75 && b[2] === 3 && b[3] === 4 && b[4] <= 63 && b[5] === 0 && b.length >= 30) return 'ZIP';
  if (b[0] === 202 && b[1] === 254 && b[2] === 186 && b[3] === 190 && b[6] === 0 && b[7] >= 45 && b[7] < 100) return 'class';
  if (b[0] === 127 && b[1] === 69 && b[2] === 76 && b[3] === 70 && [1,2].includes(b[4]) && [1,2].includes(b[5]) && b[6] === 1) return 'ELF';
  if (b[0] === 31 && b[1] === 139 && b[2] === 8 && b[3] < 32 && b.length >= 18) return 'gzip';
  return '';
}
const xdWeights = Float32Array.from({length:256}, (_, b) => {
  const c = String.fromCharCode(b);
  if (c === ' ') return 4;
  if ('etaoinshrdlu'.includes(c)) return 3;
  if (/[a-z]/i.test(c)) return 2;
  if (/[0-9.,!?'":;\-()\/\n\t\r]/.test(c)) return 0.8;
  return b >= 32 && b < 127 ? -0.4 : -5;
});
function xdText(b) {
  if (b.length < 20) return 0;
  const zeros = [0,0];
  for (let i=0; i<b.length; i++) if (!b[i]) zeros[i%2]++;
  const wide = Math.max(...zeros) > b.length * 0.25;
  const str = wide ? new TextDecoder(zeros[1]>zeros[0]?'utf-16le':'utf-16be').decode(b) : xdDecoder.decode(b);
  const letters = (str.match(/\p{L}/gu) || []).length;
  const spaces = (str.match(/\s/g) || []).length;
  const bad = (str.match(/[\x00-\x08\x0b\x0e-\x1f\ufffd]/g) || []).length;
  if (letters < str.length*.55 || spaces < str.length*.035 || spaces > str.length*.35 || bad > str.length*.025) return 0;
  const common = (str.toLowerCase().match(/th|he|in|er|an|en|ar|la|le|or|re|de|ve|bi|is|me|te|es|et|at/g)||[]).length;
  return common < str.length*.05 ? 0 : Math.min(88, 60 + 100*common/str.length);
}
function xdEntropy(b) {
  const counts=new Uint32Array(256);
  for (const v of b) counts[v]++;
  let h=0;
  for (const n of counts) if (n) { const p=n/b.length; h-=p*Math.log2(p); }
  return h;
}
function xdPaddingKey(sample, length) {
  const key=new Uint8Array(length);
  const counts=new Uint16Array(256);
  for(let col=0;col<length;col++){
    counts.fill(0);
    for(let j=col;j<sample.length;j+=length) {
      const byte=sample[j];
      if(++counts[byte]>counts[key[col]]) key[col]=byte;
    }
  }
  return key;
}
function xdLongPEKey(sample, out, fileSize) {
  for(let length=65;length<=256 && length*8<=sample.length;length++) {
    const key=xdPaddingKey(sample,length);
    xdApply(sample,key,'xor',out);
    if(xdFormat(out)!=='PE') continue;
    // Longer keys have fewer observations per column. Require a complete PE
    // header and section ranges before promoting a zero-padding hypothesis.
    const view=new DataView(out.buffer,out.byteOffset,out.length);
    const pe=view.getUint32(60,true), sections=view.getUint16(pe+6,true);
    const optional=pe+24, optionalSize=view.getUint16(pe+20,true);
    const table=optional+optionalSize, tableEnd=table+40*sections;
    if(!sections || sections>96 || optionalSize<96 || tableEnd>out.length) continue;
    const magic=view.getUint16(optional,true);
    if(magic!==0x10b && magic!==0x20b) continue;
    const headerSize=view.getUint32(optional+60,true);
    if(headerSize<tableEnd || headerSize>fileSize) continue;
    let valid=true;
    for(let row=table;row<tableEnd;row+=40) {
      const size=view.getUint32(row+16,true), offset=view.getUint32(row+20,true);
      if(size && (offset<headerSize || offset+size>fileSize)) { valid=false; break; }
    }
    if(valid) return key;
  }
  return null;
}
function xdGuess(src) {
  const sample=src.subarray(0,2048), out=new Uint8Array(sample.length);
  const baseline=xdText(sample), entropy=xdEntropy(sample);
  let best=null;
  function consider(key, mode) {
    xdApply(sample,key,mode,out);
    const format=xdFormat(out);
    let score=format ? (format==='MZ'?92:98) : xdText(out);
    if (!format && (!score || score < baseline+7)) return;
    if (!format && key.length>1) score+=Math.min(3,Math.max(0,entropy-xdEntropy(out)));
    if (!best || score>best.score) best={key:Array.from(key),mode,score,format};
  }
  for (const mode of ['xor','key+i','rol']) for (let k=mode==='key+i'?0:1;k<256;k++) consider([k],mode);
  if (best && best.format) return best;
  const lengths=[];
  for (let n=2;n<=64;n++) {
    const pairs=Math.min(12,Math.floor(sample.length/n)-1);
    if (pairs<4) continue;
    let dist=0;
    for(let i=0;i<pairs*n;i++) dist+=xdPop[sample[i]^sample[i+n]];
    lengths.push({n,dist:dist/(pairs*n)});
  }
  const likely=lengths.sort((a,b)=>a.dist-b.dist).slice(0,10).map(x=>x.n);
  // PE alignment padding often supplies zero plaintext across every column.
  // Accept that assumption only when it also reconstructs a validated header.
  for (const {n} of lengths) {
    const key=xdPaddingKey(sample,n);
    if (key.some(b=>b) && xdFormat(xdApply(sample,key,'xor',out))) consider(key,'xor');
  }
  if(best?.format) return best;
  for (const n of likely) {
    const key=new Uint8Array(n);
    for (let col=0;col<n;col++) {
      let high=-Infinity;
      for (let k=0;k<256;k++) {
        let weight=0;
        for(let j=col;j<sample.length;j+=n) weight+=xdWeights[sample[j]^k];
        if(weight>high){high=weight;key[col]=k;}
      }
    }
    consider(key,'xor');
  }
  // Infer repeated keys from independent header fields and DOS-stub text.
  for(const [offset,plain] of [[0,[80,75,3,4,20,0,0,0]],[0,[202,254,186,190,0,0,0]],[0,[127,69,76,70,2,1,1,0]],[0,[77,90,144,0,3,0,0,0,4,0,0,0,255,255,0,0]],[0x4e,xdEncoder.encode('This program cannot be run in DOS mode')]]) {
    for(let n=2;n<=Math.min(64,plain.length-3);n++){
      if(offset+plain.length>sample.length) continue;
      const key=new Uint8Array(n);
      for(let j=0;j<n;j++) key[(offset+j)%n]=sample[offset+j]^plain[j];
      if(!plain.every((b,j)=>(sample[offset+j]^key[(offset+j)%n])===b)) continue;
      consider(key,'xor');
    }
  }
  if(!best?.format) {
    const longKey=xdLongPEKey(sample,out,src.length);
    if(longKey) consider(longKey,'xor');
  }
  return best;
}
// Locate a masked signature without decoding a complete file for every offset/key.
// Read enough independent header fields to reject accidental two-byte matches.
function xdEmbedded(bytes) {
  const limit=Math.min(bytes.length,2*1024*1024);
  const signatures=[[77,90],[80,75,3,4],[127,69,76,70],[202,254,186,190]];
  const hits=[];
  for (let i=1;i+32<=limit && hits.length<8;i++) {
    for (const sig of signatures) {
      const key=bytes[i]^sig[0];
      if (!key || (bytes[i+1]^key)!==sig[1]) continue;
      if (sig.length>2 && (bytes[i+2]^key)!==sig[2]) continue;
      if (sig.length>3 && (bytes[i+3]^key)!==sig[3]) continue;
      if (sig[0]===77) {
        if(i+64>bytes.length) continue;
        const p=new DataView(bytes.buffer,bytes.byteOffset+i+60,4).getUint32(0,true) ^ Math.imul(key,0x01010101);
        if(p<64 || i+p+24>bytes.length || (bytes[i+p]^key)!==80 || (bytes[i+p+1]^key)!==69 || bytes[i+p+2]!==key || bytes[i+p+3]!==key) continue;
      }
      const header=xorDecode(bytes.subarray(i,i+4096),0,key);
      const format=xdFormat(header);
      if(format || sig[0]===77) {
        hits.push({offset:i,key,format:format||'PE'});
        break;
      }
    }
  }
  return hits;
}
async function xorRecover(input, manualKey) {
  if (!(input instanceof Uint8Array) || !input.length || input.length>XD_LIMIT) throw new RangeError('1 B – 16 MiB');
  if(manualKey && (!(manualKey instanceof Uint8Array) || !manualKey.length)) throw new TypeError('XOR key');
  let data=input, format='', offset=0;
  const layers=[];
  let embedded=[];
  for(let depth=0;depth<5;depth++) {
    format=xdFormat(data);
    if(format==='ZIP' && !manualKey) {
      try {
        const z=mzRead(data), files=z.entries.filter(e=>!e.isDir);
        if(files.some(e=>/\.class$|^META-INF\/MANIFEST\.MF$/i.test(e.name))){format='JAR';break;}
        if(files.length===1 && files[0].usize<=XD_LIMIT && layers.length && depth<4) {
          const inner=await mzData(z,files[0],XD_LIMIT);
          data=inner;layers.push({mode:'zip',name:files[0].name});continue;
        }
      } catch { /* preserve the recovered archive */ }
    }
    if(format==='gzip' && !manualKey) {
      try { const inner=await gunzip(data,XD_LIMIT); if(inner){data=inner;layers.push({mode:'gzip'});continue;} } catch { /* preserve compressed bytes */ }
    }
    const inspectPlainContainer = format && !manualKey && !layers.some(l=>l.key);
    let hits = inspectPlainContainer ? xdEmbedded(data) : [];
    if(format && !manualKey && !hits.length) break;
    if(!manualKey && data.length<4*1024*1024 && data.length>=16 && data.subarray(0,128).every(b=>b<128)) {
      const s=latin1(data).replace(/\s/g,'');
      if(s.length>=16 && !(s.length%2) && /^[\da-f]+$/i.test(s)){
        data=Uint8Array.from({length:s.length/2},(_,i)=>parseInt(s.slice(i*2,i*2+2),16));layers.push({mode:'hex'});continue;
      }
      if(s.length>=16 && !(s.length%4) && /^[a-z\d+/]+={0,2}$/i.test(s) && !/\s/.test(latin1(data).trim().replace(/[\r\n]/g,''))){
        data=Uint8Array.from(atob(s),c=>c.charCodeAt(0));layers.push({mode:'base64'});continue;
      }
    }
    if(layers.some(l=>l.key) && xdText(data.subarray(0,2048))) break;
    let guess=manualKey && !depth ? {mode:'manual',key:Array.from(manualKey),score:null} : hits.length ? null : xdGuess(data);
    let start=0;
    if(!guess?.format && !manualKey) {
      if(!hits.length) hits=xdEmbedded(data);
      if(hits.length) {
        embedded=hits.map((hit,i)=>({...hit,source:data.subarray(hit.offset,hits[i+1]?.offset ?? data.length)}));
        const hit=hits[0];
        guess={key:[hit.key],mode:'xor',score:98};start=hit.offset;
      }
    }
    if(!guess) break;
    if(start) offset=start;
    const end=start && hits.length>1 ? hits[1].offset : data.length;
    data=xdApply(data.subarray(start,end),guess.key,guess.mode,new Uint8Array(end-start));
    layers.push({mode:guess.mode,key:guess.key,score:guess.score,offset:start});
    if (manualKey) break;
  }
  if(!layers.some(l=>l.key)) return null;
  format=xdFormat(data) || 'bin';
  if(format==='ZIP') {
    try { if(mzRead(data).entries.some(e=>/\.class$|^META-INF\/MANIFEST\.MF$/i.test(e.name))) format='JAR'; }
    catch { /* Truncated ZIP data can still be previewed. */ }
  }
  return {data,layers,offset,embedded,format};
}
