import struct,sys,os
def ovba(src:bytes):
    out=bytearray([1])
    for i in range(0,len(src),4096):
        ch=src[i:i+4096]; body=bytearray()
        for j in range(0,len(ch),8):
            g=ch[j:j+8]; body.append(0); body+=g
        hdr=((len(body)+2-3)&0xfff)|0x3000|0x8000
        out+=struct.pack('<H',hdr)+body
    return bytes(out)
def cfb(streams, storages_root_children=None):
    # streams: list of (name,parent_index_or_None,data) ; fixed layout described in build()
    pass
def build(path, vba_src, extra_names=None, workbook=False):
    SS=512
    def pad(b,n=4096): return b+b'\0'*((-len(b))%n if len(b)%n else 0) if len(b)>0 else b'\0'*n
    mod=b'\x00'*10+ovba(vba_src)
    ents=[]  # name,type,left,right,child,data
    streams={'PROJECT':b'ID="{00000000-0000-0000-0000-000000000000}"\r\nModule=ThisDocument\r\nDPB="AABBCC"\r\n'.ljust(4096,b'\0'),
             'dir':ovba(b'\x01\x00\x00\x00MODULE')+b'\0'*4096,
             'ThisDocument':pad(mod)}
    if workbook: streams['Workbook']=pad(workbook)
    order=['PROJECT','dir','ThisDocument']+(['Workbook'] if workbook else [])
    # directory entries: 0 root,1 PROJECT,2 VBA,3 dir,4 ThisDocument,5 Workbook
    names=[('Root Entry',5),('PROJECT',2),('VBA',1),('dir',2),('ThisDocument',2)]+([('Workbook',2)] if workbook else [])
    child={0:1,2:3}; right={1:2,3:4}
    if workbook: right[2]=5
    # sectors: 0 FAT, 1 DIR, then data
    secs=[]; start={}
    cur=3
    for n in order:
        d=streams[n]; k=len(d)//SS; start[n]=(cur,len(d)); cur+=k; secs.append(d)
    total=cur
    fat=[0xfffffffe]*0; fat=[0]*128
    fat=[0xffffffff]*128; fat[0]=0xfffffffd; fat[1]=2; fat[2]=0xfffffffe
    for n in order:
        s,l=start[n]; k=l//SS
        for i in range(k): fat[s+i]=s+i+1 if i<k-1 else 0xfffffffe
    dirb=b''
    for i,(nm,t) in enumerate(names):
        u=nm.encode('utf-16le')
        e=u.ljust(64,b'\0')+struct.pack('<HBB',len(u)+2,t,1)+struct.pack('<iii',-1 if i not in [k for k in []] else -1,right.get(i,-1),child.get(i,-1))
        e=u.ljust(64,b'\0')+struct.pack('<HBB',len(u)+2,t,1)+struct.pack('<iii',-1,right.get(i,-1),child.get(i,-1))
        e+=b'\0'*16+b'\0'*4+b'\0'*16
        if t==2: s,l=start[nm]; e+=struct.pack('<IIQ'[:3],s,l,0) if False else struct.pack('<I',s)+struct.pack('<II',l,0)
        elif t==5: e+=struct.pack('<I',0xfffffffe)+struct.pack('<II',0,0)
        else: e+=struct.pack('<I',0)+struct.pack('<II',0,0)
        e=e[:128].ljust(128,b'\0'); dirb+=e
    dirb=dirb.ljust(1024,b'\0')
    hdr=b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'+b'\0'*16+struct.pack('<HHHHH',0x3e,3,0xfffe,9,6)+b'\0'*6
    hdr+=struct.pack('<IIIIIIIII',0,1,1,0,4096,0xfffffffe,0,0xfffffffe,0)
    difat=[0]+[0xffffffff]*108
    hdr+=struct.pack('<109I',*difat)
    hdr=hdr.ljust(512,b'\0')
    open(path,'wb').write(hdr+struct.pack('<128I',*fat)+dirb+b''.join(secs))
src=open(sys.argv[2],'rb').read()
build(sys.argv[1],src)
