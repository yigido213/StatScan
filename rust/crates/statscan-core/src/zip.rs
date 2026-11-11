//! ZIP okuyucu (yalniz bellekte; hicbir sey diske acilmaz): JS `readZip/readEntry/readBudget`.

use crate::state::St;
use crate::util::fmt_n;
use std::io::Read;

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub method: u16,
    pub csize: u64,
    pub size: u64,
    pub off: u64,
    pub enc: bool,
    pub dir: bool,
}

fn u16_at(u: &[u8], i: usize) -> Result<u16, String> {
    u.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or_else(|| "ZIP: sınır dışı okuma".to_string())
}
fn u32_at(u: &[u8], i: usize) -> Result<u32, String> {
    u.get(i..i + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or_else(|| "ZIP: sınır dışı okuma".to_string())
}
fn u64_at(u: &[u8], i: usize) -> Result<u64, String> {
    u.get(i..i + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .ok_or_else(|| "ZIP: sınır dışı okuma".to_string())
}

pub fn read_zip(u: &[u8]) -> Result<Vec<Entry>, String> {
    let mut eocd: Option<usize> = None;
    if u.len() >= 22 {
        let lo = u.len().saturating_sub(65557);
        let mut i = u.len() - 22;
        loop {
            if u32_at(u, i)? == 0x06054b50 {
                eocd = Some(i);
                break;
            }
            if i == lo {
                break;
            }
            i -= 1;
        }
    }
    let eocd = eocd.ok_or("ZIP sonu bulunamadı")?;
    let mut total = u16_at(u, eocd + 10)? as u64;
    let mut cd_off = u32_at(u, eocd + 16)? as u64;
    if cd_off == 0xffff_ffff || total == 0xffff {
        let lo = eocd.saturating_sub(100);
        let mut i = eocd as i64 - 20;
        while i >= lo as i64 {
            let iu = i as usize;
            if u32_at(u, iu)? == 0x07064b50 {
                let o64 = u64_at(u, iu + 8)? as usize;
                if u32_at(u, o64)? == 0x06064b50 {
                    total = u64_at(u, o64 + 32)?;
                    cd_off = u64_at(u, o64 + 48)?;
                }
                break;
            }
            i -= 1;
        }
    }
    let mut entries = Vec::new();
    let mut p = cd_off as usize;
    let mut n = 0u64;
    while n < total && p + 46 <= u.len() {
        if u32_at(u, p)? != 0x02014b50 {
            break;
        }
        let flag = u16_at(u, p + 8)?;
        let method = u16_at(u, p + 10)?;
        let mut csize = u32_at(u, p + 20)? as u64;
        let mut size = u32_at(u, p + 24)? as u64;
        let nl = u16_at(u, p + 28)? as usize;
        let el = u16_at(u, p + 30)? as usize;
        let cl = u16_at(u, p + 32)? as usize;
        let mut off = u32_at(u, p + 42)? as u64;
        let nend = (p + 46 + nl).min(u.len());
        let name = crate::util::utf8_decode_keep_bom(&u[(p + 46).min(nend)..nend]);
        if size == 0xffff_ffff || csize == 0xffff_ffff || off == 0xffff_ffff {
            let mut q = p + 46 + nl;
            let end = q + el;
            while q + 4 <= end {
                let id = u16_at(u, q)?;
                let sz = u16_at(u, q + 2)? as usize;
                if id == 1 {
                    let mut r = q + 4;
                    if size == 0xffff_ffff {
                        size = u64_at(u, r)?;
                        r += 8;
                    }
                    if csize == 0xffff_ffff {
                        csize = u64_at(u, r)?;
                        r += 8;
                    }
                    if off == 0xffff_ffff {
                        off = u64_at(u, r)?;
                    }
                }
                q += 4 + sz;
            }
        }
        let dir = name.ends_with('/');
        entries.push(Entry { name, method, csize, size, off, enc: flag & 1 != 0, dir });
        p += 46 + nl + el + cl;
        n += 1;
    }
    Ok(entries)
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadErr {
    Limit,
    Bad,
}

pub fn read_entry(u: &[u8], e: &Entry, cap: u64) -> Result<Vec<u8>, ReadErr> {
    let off = e.off as usize;
    if e.off > u.len() as u64 || off + 30 > u.len() {
        return Err(ReadErr::Bad);
    }
    if u32_at(u, off).map_err(|_| ReadErr::Bad)? != 0x04034b50 {
        return Err(ReadErr::Bad);
    }
    let nl = u16_at(u, off + 26).map_err(|_| ReadErr::Bad)? as usize;
    let el = u16_at(u, off + 28).map_err(|_| ReadErr::Bad)? as usize;
    let s = off + 30 + nl + el;
    if s > u.len() || s as u64 + e.csize > u.len() as u64 {
        return Err(ReadErr::Bad);
    }
    let raw = &u[s..s + e.csize as usize];
    match e.method {
        0 => {
            if raw.len() as u64 > cap {
                Err(ReadErr::Limit)
            } else {
                Ok(raw.to_vec())
            }
        }
        8 => {
            let mut d = flate2::read::DeflateDecoder::new(raw).take(cap + 1);
            let mut out = Vec::new();
            d.read_to_end(&mut out).map_err(|_| ReadErr::Bad)?;
            if out.len() as u64 > cap { Err(ReadErr::Limit) } else { Ok(out) }
        }
        _ => Err(ReadErr::Bad),
    }
}

/// Toplam acilmis veri butcesine bagli okuma (JS `readBudget`).
pub fn read_budget(u: &[u8], e: &Entry, st: &mut St) -> Result<Vec<u8>, ()> {
    if st.bytes >= st.cfg.max_total {
        st.limit_hit("bytes", &format!("Toplam açılmış veri sınırına ulaşıldı ({}); kalan girdiler okunmadı.", fmt_n(st.cfg.max_total)));
        st.skip("bytes", 1);
        st.stop = true;
        return Err(());
    }
    let cap = st.entry_cap.min(st.cfg.max_total - st.bytes).max(0.0) as u64;
    match read_entry(u, e, cap) {
        Ok(d) => {
            st.bytes += d.len() as f64;
            Ok(d)
        }
        Err(ReadErr::Limit) => {
            st.limit_hit("entry", &format!("Boyut sınırını aşan girdi(ler) atlandı (tek girdi sınırı {}).", fmt_n(st.entry_cap)));
            st.skip("entrysize", 1);
            Err(())
        }
        Err(ReadErr::Bad) => {
            st.unreadable += 1;
            st.skip("unreadable", 1);
            Err(())
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use flate2::{write::DeflateEncoder, Compression};
    use std::io::Write;

    fn crc32(d: &[u8]) -> u32 {
        let mut c = 0xffff_ffffu32;
        for &b in d {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ 0xedb8_8320 } else { c >> 1 };
            }
        }
        !c
    }

    /// Test icin kucuk ZIP yazici: (ad, veri, deflate mi)
    pub fn make_zip(files: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out: Vec<u8> = vec![];
        let mut cd: Vec<u8> = vec![];
        for (name, data, defl) in files {
            let off = out.len() as u32;
            let (method, comp): (u16, Vec<u8>) = if *defl {
                let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
                e.write_all(data).unwrap();
                (8, e.finish().unwrap())
            } else {
                (0, data.to_vec())
            };
            let crc = crc32(data);
            out.extend_from_slice(&0x04034b50u32.to_le_bytes());
            out.extend_from_slice(&[20, 0, 0, 0]);
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&comp);
            cd.extend_from_slice(&0x02014b50u32.to_le_bytes());
            cd.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            cd.extend_from_slice(&method.to_le_bytes());
            cd.extend_from_slice(&[0, 0, 0, 0]);
            cd.extend_from_slice(&crc.to_le_bytes());
            cd.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0; 12]);
            cd.extend_from_slice(&off.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        out.extend_from_slice(&cd);
        out.extend_from_slice(&0x06054b50u32.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn roundtrip_stored_and_deflated() {
        let z = make_zip(&[("a.txt", b"hello", false), ("dir/b.txt", &vec![b'x'; 5000], true)]);
        let es = read_zip(&z).unwrap();
        assert_eq!(es.len(), 2);
        assert_eq!(read_entry(&z, &es[0], 100).unwrap(), b"hello");
        assert_eq!(read_entry(&z, &es[1], 10_000).unwrap().len(), 5000);
        assert_eq!(read_entry(&z, &es[1], 1000), Err(ReadErr::Limit));
    }

    #[test]
    fn garbage_is_error_not_panic() {
        assert!(read_zip(b"PK\x03\x04 nothing").is_err());
        let mut z = make_zip(&[("a", b"x", false)]);
        let n = z.len();
        z[n - 6] = 0xff; // cd boyutu/ofseti bozuk
        z[n - 5] = 0xff;
        let _ = read_zip(&z);
    }
}
