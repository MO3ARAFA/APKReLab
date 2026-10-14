import struct, sys
ANDROID="http://schemas.android.com/apk/res/android"

def enc_pool(strings, utf8):
    data=bytearray(); offs=[]
    for s in strings:
        offs.append(len(data))
        if utf8:
            bs=s.encode('utf-8')
            def vl(n): return bytes([n]) if n<0x80 else bytes([((n>>8)&0x7f)|0x80, n&0xff])
            data+=vl(len(s))+vl(len(bs))+bs+b'\0'
        else:
            if len(s)>0x7fff: raise
            data+=struct.pack('<H',len(s))+s.encode('utf-16-le')+b'\0\0'
    while len(data)%4: data+=b'\0'
    n=len(strings); ss=28+4*n
    flags=0x100 if utf8 else 0
    size=ss+len(data)
    h=struct.pack('<HHIIIIII',1,28,size,n,0,flags,ss,0)
    return h+b''.join(struct.pack('<I',o) for o in offs)+bytes(data)

def build(utf8, pkg="com.example.app"):
    S=[]
    def si(s):
        if s not in S: S.append(s)
        return S.index(s)
    # attr names first (resource map covers first few)
    for n in ["name","versionCode","permission","authorities","exported"]: si(n)
    ns=si(ANDROID); prefix=si("android")
    elems=[]  # (type, payload)
    def attr(nsidx,name,val,typ='s'):
        if typ=='s':
            vi=si(val)
            return struct.pack('<IIIHBBI',nsidx,si(name),vi,8,0,3,vi)
        if typ=='b':
            return struct.pack('<IIIHBBI',nsidx,si(name),0xffffffff,8,0,0x12,0xffffffff if val else 0)
        if typ=='i':
            return struct.pack('<IIIHBBI',nsidx,si(name),0xffffffff,8,0,0x10,val)
    def start(el,attrs):
        body=struct.pack('<IIHHHHHH',0xffffffff,si(el),20,20,len(attrs),0,0,0)+b''.join(attrs)
        size=16+len(body)
        return struct.pack('<HHIII',0x102,16,size,1,0xffffffff)+body
    def end(el):
        body=struct.pack('<II',0xffffffff,si(el))
        return struct.pack('<HHIII',0x103,16,24,1,0xffffffff)+body
    A=lambda n,v,t='s': attr(ns,n,v,t)
    out=[]
    out.append(struct.pack('<HHIIIII',0x100,16,24,1,0xffffffff,prefix,ns))
    out.append(start("manifest",[A("versionCode",31,'i'), attr(0xffffffff,"package",pkg), attr(0xffffffff,"split","config.x")]))
    out.append(start("permission",[A("name",pkg+".permission.C2D_MESSAGE")])); out.append(end("permission"))
    out.append(start("uses-permission",[A("name",pkg+".permission.C2D_MESSAGE")])); out.append(end("uses-permission"))
    out.append(start("uses-permission",[A("name","android.permission.INTERNET")])); out.append(end("uses-permission"))
    out.append(start("application",[A("name",".App"), A("permission",pkg+".perm.X")]))
    out.append(start("activity",[A("name",pkg+".ui.Main"),A("exported",1,'b'),A("process",":svc")])); 
    out.append(start("intent-filter",[]))
    out.append(start("category",[A("name",pkg)])); out.append(end("category"))
    out.append(end("intent-filter")); out.append(end("activity"))
    out.append(start("activity",[A("name","Rel"),A("process",pkg+".proc")])); out.append(end("activity"))
    out.append(start("provider",[A("name","androidx.core.content.FileProvider"),A("authorities",pkg+".provider;other.auth;"+pkg)])); out.append(end("provider"))
    out.append(end("application"))
    out.append(end("manifest"))
    out.append(struct.pack('<HHIII',0x101,16,24,1,0xffffffff)+struct.pack('<II',prefix,ns))
    # resource map for first 5 strings
    rm=struct.pack('<HHI',0x180,8,8+4*5)+b''.join(struct.pack('<I',x) for x in [0x01010003,0x0101021b,0x01010006,0x01010018,0x01010010])
    pool=enc_pool(S,utf8)
    body=pool+rm+b''.join(out)
    return struct.pack('<HHI',3,8,8+len(body))+body

for u in (True,False):
    open('t_%s.axml'%('u8' if u else 'u16'),'wb').write(build(u))
open('t_u8_long.axml','wb').write(build(True,"com.some.very.long.package.name.for.testing"))
