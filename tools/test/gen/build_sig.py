#!/usr/bin/env python3
"""Imza ve Sertifika Denetcisi testleri icin SENTETIK, Authenticode yapili ornek PE dosyalari uretir.
Gercek bir yazilim degildir; calistirilmaz. Kullanim: python3 build_sig.py <cikti klasoru>
Uretilenler: ok.exe (zincir CA->yaprak, zaman damgali), tampered.exe (imzadan sonra bayt degisti), expired.exe (suresi dolmus, damgasiz),
selfms.exe (kendinden imzali 'Microsoft Corporation'), typo.exe (Micros0ft), typo2.exe (Gooogle), noeku.exe (EKU serverAuth), badmath.exe (imza bozuk),
unsigned.exe, sha1.exe (SHA-1 ozet), ec.exe (ECDSA yaprak) """
import sys, os, hashlib, struct, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec

out = sys.argv[1]; os.makedirs(out, exist_ok=True)
def L(n):
    if n < 0x80: return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big'); return bytes([0x80 | len(b)]) + b
def tlv(t, c): return bytes([t]) + L(len(c)) + c
def seq(*a): return tlv(0x30, b''.join(a))
def sset(*a): return tlv(0x31, b''.join(a))
def oid(s):
    p = [int(x) for x in s.split('.')]; b = bytes([p[0] * 40 + p[1]])
    for v in p[2:]:
        x = [v & 0x7f]; v >>= 7
        while v: x.append((v & 0x7f) | 0x80); v >>= 7
        b += bytes(reversed(x))
    return tlv(6, b)
def octet(b): return tlv(4, b)
def integer(n): b = n.to_bytes((n.bit_length() + 8) // 8, 'big'); return tlv(2, b)
def null(): return b'\x05\x00'
def utc(dt): return tlv(0x17, dt.strftime('%y%m%d%H%M%SZ').encode())
def ctx(n, c, cons=True): return tlv((0xa0 if cons else 0x80) | n, c)

def mkname(cn, o=None, c='US'):
    a = [x509.NameAttribute(NameOID.COUNTRY_NAME, c)]
    if o: a.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, o))
    a.append(x509.NameAttribute(NameOID.COMMON_NAME, cn)); return x509.Name(a)
def mkkey(): return rsa.generate_private_key(public_exponent=65537, key_size=2048)
def mkcert(subj, subj_key, issuer, issuer_key, ca=False, eku=None, nb=None, na=None, hsh=hashes.SHA256(), serial=None, urls=False):
    nb = nb or datetime.datetime(2023, 1, 1); na = na or datetime.datetime(2099, 1, 1)
    b = x509.CertificateBuilder().subject_name(subj).issuer_name(issuer).public_key(subj_key.public_key()).serial_number(serial or x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
    b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if ca: b = b.add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
    else: b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
    if eku is not None: b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if urls:
        b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier('http://crl.acme-test.example/ca.crl')], None, None, None)]), critical=False)
        b = b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier('http://ocsp.acme-test.example'))]), critical=False)
    return b.sign(issuer_key, hsh)

# ---- minimal PE32+ ----
def build_pe(tamper=False):
    sh = 0x200; raw = bytearray(0x400)
    raw[0:2] = b'MZ'; struct.pack_into('<I', raw, 0x3c, 0x80); pe = 0x80
    raw[pe:pe + 4] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', raw, pe + 4, 0x8664, 1, 0x5f000000, 0, 0, 240, 0x22)
    oh = pe + 24
    struct.pack_into('<H', raw, oh, 0x20b); struct.pack_into('<I', raw, oh + 16, 0x1000)  # EP
    struct.pack_into('<Q', raw, oh + 24, 0x140000000)
    struct.pack_into('<II', raw, oh + 32, 0x1000, 0x200)
    struct.pack_into('<HH', raw, oh + 40, 6, 0); struct.pack_into('<HH', raw, oh + 48, 6, 0)
    struct.pack_into('<IIII', raw, oh + 56, 0x2000, sh, 0, 3)  # size image, size hdrs, checksum, subsystem(+dllchar)
    struct.pack_into('<H', raw, oh + 70, 0x8160)
    struct.pack_into('<I', raw, oh + 108, 16)
    sp = oh + 240
    raw[sp:sp + 8] = b'.text\0\0\0'; struct.pack_into('<IIIIIIHHI', raw, sp + 8, 0x100, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    for i in range(0x200): raw[0x200 + i] = (i * 7 + 3) & 0xff
    raw[0x200:0x203] = b'\xc3\x90\x90'
    return bytes(raw), oh
def authhash(raw, oh, alg):
    chk = oh + 64; sd = oh + 112 + 4 * 8; h = hashlib.new(alg)
    h.update(raw[0:chk]); h.update(raw[chk + 4:sd]); h.update(raw[sd + 8:0x200]); h.update(raw[0x200:0x400]); return h.digest()
def spc(digest, alg_oid):
    return seq(seq(oid('1.3.6.1.4.1.311.2.1.15'), seq(tlv(3, b'\x00'), ctx(0, ctx(2, b'', True)))), seq(seq(oid(alg_oid), null()), octet(digest)))

def sign(raw, oh, leaf, leaf_key, chain, hash_name='sha256', ts=None, signing=None, bad=False):
    alg_oid = {'sha256': '2.16.840.1.101.3.4.2.1', 'sha1': '1.3.14.3.2.26'}[hash_name]; hobj = hashes.SHA256() if hash_name == 'sha256' else hashes.SHA1()
    content = spc(authhash(raw, oh, hash_name), alg_oid)
    # icerik oktetleri = SEQ icerigi (etiket+uzunluk haric)
    t = content[1]; hl = 1 + (1 if t < 0x80 else 1 + (t & 0x7f)); body = content[hl:]
    md = hashlib.new(hash_name, body).digest()
    sign_time = signing or datetime.datetime(2024, 6, 1, 12, 0, 0)
    attrs = [seq(oid('1.2.840.113549.1.9.3'), sset(oid('1.3.6.1.4.1.311.2.1.4'))), seq(oid('1.2.840.113549.1.9.5'), sset(utc(sign_time))), seq(oid('1.2.840.113549.1.9.4'), sset(octet(md)))]
    attrs_b = b''.join(sorted(attrs))
    to_sign = tlv(0x31, attrs_b)
    sig = leaf_key.sign(to_sign, padding.PKCS1v15(), hobj) if isinstance(leaf_key, rsa.RSAPrivateKey) else leaf_key.sign(to_sign, ec.ECDSA(hobj))
    if bad: sig = bytes([sig[0] ^ 0xff]) + sig[1:]
    unauth = b''
    if ts: unauth = ctx(1, seq(oid('1.2.840.113549.1.9.6'), sset(seq(integer(1), seq(leaf.issuer.public_bytes(), integer(5)), seq(oid(alg_oid), null()), ctx(0, seq(oid('1.2.840.113549.1.9.5'), sset(utc(ts)))), seq(oid('1.2.840.113549.1.1.1'), null()), octet(b'\x00' * 8)))))
    sig_alg = seq(oid('1.2.840.113549.1.1.1'), null()) if isinstance(leaf_key, rsa.RSAPrivateKey) else seq(oid('1.2.840.10045.4.3.2'))
    si = seq(integer(1), seq(leaf.issuer.public_bytes(), integer(leaf.serial_number)), seq(oid(alg_oid), null()), tlv(0xa0, attrs_b), sig_alg, octet(sig), unauth)
    certs = ctx(0, b''.join(c.public_bytes(serialization.Encoding.DER) for c in [leaf] + chain))
    sd = seq(integer(1), sset(seq(oid(alg_oid), null())), seq(oid('1.3.6.1.4.1.311.2.1.4'), ctx(0, content)), certs, sset(si))
    p7 = seq(oid('1.2.840.113549.1.7.2'), ctx(0, sd))
    wc = struct.pack('<IHH', 8 + len(p7), 0x200, 2) + p7; wc += b'\0' * ((8 - len(wc) % 8) % 8)
    out_raw = bytearray(raw); struct.pack_into('<II', out_raw, oh + 112 + 4 * 8, len(raw), len(wc)); return bytes(out_raw) + wc

def save(name, data): open(os.path.join(out, name), 'wb').write(data); print('yazildi', name, len(data))
raw, oh = build_pe()
save('unsigned.exe', raw)
ca_key = mkkey(); ca = mkcert(mkname('Acme Root CA', 'Acme Trust Services'), ca_key, mkname('Acme Root CA', 'Acme Trust Services'), ca_key, ca=True)
ica_key = mkkey(); ica = mkcert(mkname('Acme Code Signing CA', 'Acme Trust Services'), ica_key, ca.subject, ca_key, ca=True)
leaf_key = mkkey(); eku = [ExtendedKeyUsageOID.CODE_SIGNING]
leaf = mkcert(mkname('Acme Software Ltd', 'Acme Software Ltd'), leaf_key, ica.subject, ica_key, eku=eku, urls=True)
ts = datetime.datetime(2024, 6, 1, 12, 5, 0)
good = sign(raw, oh, leaf, leaf_key, [ica, ca], ts=ts); save('ok.exe', good)
t = bytearray(good); t[0x250] ^= 0xff; save('tampered.exe', bytes(t))
old = mkcert(mkname('Old Vendor Inc', 'Old Vendor Inc'), leaf_key, ica.subject, ica_key, eku=eku, nb=datetime.datetime(2018, 1, 1), na=datetime.datetime(2019, 1, 1))
save('expired.exe', sign(raw, oh, old, leaf_key, [ica, ca], signing=datetime.datetime(2018, 6, 1)))
mk = mkkey(); ms = mkcert(mkname('Microsoft Corporation', 'Microsoft Corporation'), mk, mkname('Microsoft Corporation', 'Microsoft Corporation'), mk, eku=eku)
save('selfms.exe', sign(raw, oh, ms, mk, [], ts=ts))
ty = mkcert(mkname('Micros0ft Corporation', 'Micros0ft Corporation'), leaf_key, ica.subject, ica_key, eku=eku)
save('typo.exe', sign(raw, oh, ty, leaf_key, [ica, ca], ts=ts))
ty2 = mkcert(mkname('Gooogle LLC', 'Gooogle LLC'), leaf_key, ica.subject, ica_key, eku=eku)
save('typo2.exe', sign(raw, oh, ty2, leaf_key, [ica, ca], ts=ts))
ne = mkcert(mkname('Web Only Ltd', 'Web Only Ltd'), leaf_key, ica.subject, ica_key, eku=[ExtendedKeyUsageOID.SERVER_AUTH])
save('noeku.exe', sign(raw, oh, ne, leaf_key, [ica, ca], ts=ts))
save('badmath.exe', sign(raw, oh, leaf, leaf_key, [ica, ca], ts=ts, bad=True))
save('sha1.exe', sign(raw, oh, leaf, leaf_key, [ica, ca], hash_name='sha1', ts=ts))
ek = ec.generate_private_key(ec.SECP256R1()); ecc = mkcert(mkname('EC Maker Ltd', 'EC Maker Ltd'), ek, ica.subject, ica_key, eku=eku)
save('ec.exe', sign(raw, oh, ecc, ek, [ica, ca], ts=ts))
