// Testler icin en basit ZIP yazici (stored, sikistirmasiz)
const crcT = new Uint32Array(256).map((_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
export const crc32 = (u) => { let c = 0xffffffff; for (let i = 0; i < u.length; i++) c = crcT[(c ^ u[i]) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
export function zipStore(entries) {
  const enc = new TextEncoder(); const parts = []; const cen = []; let off = 0;
  for (const [name, data0] of entries) {
    const data = typeof data0 === 'string' ? enc.encode(data0) : data0; const nm = enc.encode(name); const crc = crc32(data);
    const lh = new DataView(new ArrayBuffer(30)); lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true); lh.setUint32(14, crc, true); lh.setUint32(18, data.length, true); lh.setUint32(22, data.length, true); lh.setUint16(26, nm.length, true);
    parts.push(new Uint8Array(lh.buffer), nm, data);
    const ch = new DataView(new ArrayBuffer(46)); ch.setUint32(0, 0x02014b50, true); ch.setUint16(4, 20, true); ch.setUint16(6, 20, true); ch.setUint32(16, crc, true); ch.setUint32(20, data.length, true); ch.setUint32(24, data.length, true); ch.setUint16(28, nm.length, true); ch.setUint32(42, off, true);
    cen.push(new Uint8Array(ch.buffer), nm); off += 30 + nm.length + data.length;
  }
  const cl = cen.reduce((a, b) => a + b.length, 0); const eo = new DataView(new ArrayBuffer(22)); eo.setUint32(0, 0x06054b50, true); eo.setUint16(8, entries.length, true); eo.setUint16(10, entries.length, true); eo.setUint32(12, cl, true); eo.setUint32(16, off, true);
  const all = [...parts, ...cen, new Uint8Array(eo.buffer)]; const out = new Uint8Array(all.reduce((a, b) => a + b.length, 0)); let p = 0; for (const x of all) { out.set(x, p); p += x.length; } return out;
}
