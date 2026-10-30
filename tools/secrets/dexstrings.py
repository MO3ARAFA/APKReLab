import zipfile,struct,sys,re,os
def strings(b):
    n,off=struct.unpack("<II",b[0x38:0x40]); out=[]
    for i in range(n):
        o=struct.unpack("<I",b[off+4*i:off+4*i+4])[0]; p=o; sh=0; ln=0
        while True:
            c=b[p]; p+=1; ln|=(c&0x7f)<<sh; sh+=7
            if not c&0x80: break
        e=b.index(b"\0",p); out.append(b[p:e].decode("utf-8","replace"))
    return out
for apk in sys.argv[1:]:
    name=os.path.basename(apk)[:-4]; z=zipfile.ZipFile(apk); S=set()
    for i in z.infolist():
        if re.fullmatch(r"classes\d*\.dex",i.filename): S.update(s for s in strings(z.read(i.filename)) if 12<=len(s)<=600)
        elif i.filename.startswith("res/") and i.filename.endswith(".xml") or i.filename.startswith("assets/") and i.filename.endswith((".json",".xml",".txt",".properties",".js",".html")):
            try:
                t=z.read(i.filename).decode("utf-8","ignore")
                if i.filename.startswith("assets/"): S.update(x for x in re.findall(r"[\"'>=: ]([^\"'<>\s]{12,300})",t))
            except Exception: pass
    open(f"/tmp/sca/strs/{name}.txt","w").write("\n".join(sorted(S))+"\n"); print(name,len(S))
