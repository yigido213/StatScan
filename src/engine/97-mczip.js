/* Beta 0.0.1: Minecraft donusturuculeri icin ZIP okuma/yazma. Degismeyen girdiler SIKISTIRILMIS HALIYLE oldugu gibi kopyalanir (yeniden sikistirma yok);
   yalnizca degisen/yeni girdiler yazilir. Orijinal dosya asla degistirilmez; cikti yeni bir bayt dizisidir. ZIP64 ve sifreli girdiler desteklenmez (acik hata verilir). */
const MZ_CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function mzCrc(u) { let c = 0xffffffff; for (let i = 0; i < u.length; i++) c = MZ_CRC[(c ^ u[i]) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
class MzError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const MZ_LIM = { entries: 100000, entryCap: 32e6, nameMax: 1024 };

function mzRead(u8) {
  if (!(u8 instanceof Uint8Array) || u8.length < 22) throw new MzError('notzip', 'Dosya bir ZIP arşivi değil (çok küçük).');
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength); let eocd = -1;
  for (let i = u8.length - 22; i >= Math.max(0, u8.length - 65557); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new MzError('notzip', 'ZIP sonu (EOCD) bulunamadı: dosya ZIP değil ya da bozuk.');
  if (eocd >= 20 && dv.getUint32(eocd - 20, true) === 0x07064b50) throw new MzError('zip64', 'ZIP64 arşivler desteklenmiyor.');
  const total = dv.getUint16(eocd + 10, true), cdSize = dv.getUint32(eocd + 12, true), cdOff = dv.getUint32(eocd + 16, true);
  if (total === 0xffff || cdOff === 0xffffffff || cdSize === 0xffffffff) throw new MzError('zip64', 'ZIP64 arşivler desteklenmiyor.');
  if (cdOff + cdSize > eocd || total > MZ_LIM.entries) throw new MzError('bad', 'Merkezi dizin bozuk veya çok büyük (' + total + ' girdi).');
  const entries = [], seen = new Set(); let p = cdOff; const td = new TextDecoder('utf-8');
  for (let n = 0; n < total; n++) {
    if (p + 46 > u8.length || dv.getUint32(p, true) !== 0x02014b50) throw new MzError('bad', 'Merkezi dizin girdisi ' + n + ' bozuk.');
    const flags = dv.getUint16(p + 8, true), method = dv.getUint16(p + 10, true), time = dv.getUint16(p + 12, true), date = dv.getUint16(p + 14, true), crc = dv.getUint32(p + 16, true), csize = dv.getUint32(p + 20, true), usize = dv.getUint32(p + 24, true);
    const nl = dv.getUint16(p + 28, true), el = dv.getUint16(p + 30, true), cl = dv.getUint16(p + 32, true), lho = dv.getUint32(p + 42, true);
    if (nl === 0 || nl > MZ_LIM.nameMax || p + 46 + nl + el + cl > u8.length) throw new MzError('bad', 'Girdi adı geçersiz (girdi ' + n + ').');
    if (csize === 0xffffffff || usize === 0xffffffff || lho === 0xffffffff) throw new MzError('zip64', 'ZIP64 girdi desteklenmiyor.');
    if (flags & 1) throw new MzError('encrypted', 'Şifreli ZIP girdisi var; desteklenmiyor.');
    const nameBytes = u8.subarray(p + 46, p + 46 + nl); const name = td.decode(nameBytes);
    if (lho + 30 > u8.length || dv.getUint32(lho, true) !== 0x04034b50) throw new MzError('bad', 'Yerel başlık bozuk: ' + name);
    const dataOff = lho + 30 + dv.getUint16(lho + 26, true) + dv.getUint16(lho + 28, true);
    if (dataOff + csize > u8.length) throw new MzError('bad', 'Girdi verisi dosya dışına taşıyor: ' + name);
    if (seen.has(name)) throw new MzError('dup', 'Aynı adlı iki girdi var: ' + name);
    seen.add(name); entries.push({ name, nameBytes, utf8: !!(flags & 0x800), method, crc, csize, usize, dataOff, time, date, isDir: name.endsWith('/') });
    p += 46 + nl + el + cl;
  }
  return { entries, u8 };
}
async function mzData(zip, e, cap) {
  cap = cap || MZ_LIM.entryCap; if (e.usize > cap) throw new MzError('big', 'Girdi çok büyük: ' + e.name);
  const raw = zip.u8.subarray(e.dataOff, e.dataOff + e.csize); let d;
  if (e.method === 0) d = raw.slice(); else if (e.method === 8) { try { d = await inflateRaw(raw, cap); } catch (er) { throw new MzError('bad', 'Girdi açılamadı: ' + e.name); } } else throw new MzError('method', 'Desteklenmeyen sıkıştırma yöntemi (' + e.method + '): ' + e.name);
  if (d.length !== e.usize || mzCrc(d) !== e.crc) throw new MzError('bad', 'Girdi bütünlük doğrulaması başarısız (CRC): ' + e.name);
  return d;
}
async function mzDeflate(u8) {
  if (typeof CompressionStream === 'undefined' || u8.length < 64) return null;
  const rd = new Blob([u8]).stream().pipeThrough(new CompressionStream('deflate-raw')).getReader(); const parts = []; let tot = 0;
  for (;;) { const r = await rd.read(); if (r.done) break; parts.push(r.value); tot += r.value.length; }
  const out = new Uint8Array(tot); let o = 0; for (const x of parts) { out.set(x, o); o += x.length; } return out.length < u8.length ? out : null;
}
/* items: { name:string, nameBytes?:Uint8Array, copy:{zip, entry} | data:Uint8Array, time?, date? } */
async function mzWrite(items) {
  const enc = new TextEncoder(); const chunks = [], cds = []; let pos = 0; const DT = { time: 0, date: 0x0021 };
  const push = (u) => { chunks.push(u); pos += u.length; };
  for (const it of items) {
    let method, crc, csize, usize, body, nameBytes, utf8;
    if (it.copy) { const e = it.copy.entry; method = e.method; crc = e.crc; csize = e.csize; usize = e.usize; body = it.copy.zip.u8.subarray(e.dataOff, e.dataOff + e.csize); }
    else { const d = it.data; usize = d.length; crc = mzCrc(d); const z = await mzDeflate(d); if (z) { method = 8; body = z; csize = z.length; } else { method = 0; body = d; csize = d.length; } }
    if (it.nameBytes) { nameBytes = it.nameBytes; utf8 = !!it.utf8; } else { nameBytes = enc.encode(it.name); utf8 = true; }
    const t = it.time != null ? it.time : DT.time, dt = it.date != null ? it.date : DT.date; const flags = utf8 ? 0x800 : 0;
    if (pos + csize + 30 + nameBytes.length > 0xfff00000) throw new MzError('big', 'Çıktı 4 GB sınırını aşıyor (ZIP64 desteklenmiyor).');
    const lh = new DataView(new ArrayBuffer(30)); lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true); lh.setUint16(6, flags, true); lh.setUint16(8, method, true); lh.setUint16(10, t, true); lh.setUint16(12, dt, true); lh.setUint32(14, crc, true); lh.setUint32(18, csize, true); lh.setUint32(22, usize, true); lh.setUint16(26, nameBytes.length, true); lh.setUint16(28, 0, true);
    const off = pos; push(new Uint8Array(lh.buffer)); push(nameBytes); push(body); cds.push({ nameBytes, flags, method, t, dt, crc, csize, usize, off });
  }
  const cdStart = pos;
  for (const c of cds) { const h = new DataView(new ArrayBuffer(46)); h.setUint32(0, 0x02014b50, true); h.setUint16(4, 20, true); h.setUint16(6, 20, true); h.setUint16(8, c.flags, true); h.setUint16(10, c.method, true); h.setUint16(12, c.t, true); h.setUint16(14, c.dt, true); h.setUint32(16, c.crc, true); h.setUint32(20, c.csize, true); h.setUint32(24, c.usize, true); h.setUint16(28, c.nameBytes.length, true); h.setUint32(42, c.off, true); push(new Uint8Array(h.buffer)); push(c.nameBytes); }
  const cdSize = pos - cdStart; if (cds.length > 0xfffe) throw new MzError('big', 'Çok fazla girdi (ZIP64 desteklenmiyor).');
  const e = new DataView(new ArrayBuffer(22)); e.setUint32(0, 0x06054b50, true); e.setUint16(8, cds.length, true); e.setUint16(10, cds.length, true); e.setUint32(12, cdSize, true); e.setUint32(16, cdStart, true); push(new Uint8Array(e.buffer));
  const out = new Uint8Array(pos); let o = 0; for (const c of chunks) { out.set(c, o); o += c.length; } return out;
}
