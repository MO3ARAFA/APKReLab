import re,sys,glob,os
root=sys.argv[1]
idx={}
for f in glob.glob(root+'/smali*/**/*.smali',recursive=True):
    idx[os.path.basename(f)[:-6]]=f
def method_body(cls,name):
    f=idx.get(cls)
    if not f: return None
    t=open(f,encoding='utf8',errors='ignore').read()
    m=re.search(r'^\.method [^\n]*? '+re.escape(name)+r'\(.*?^\.end method',t,re.M|re.S)
    return m.group(0) if m else None
def merged(body):
    return bool(re.search(r'iget-byte|iget(?:-object)? [^\n]*:B\n',body)) and bool(re.search(r'packed-switch|sparse-switch',body))
for spec in sys.argv[2:]:
    c,n=spec.split('.')
    b=method_body(c,n)
    print(spec, 'MISSING' if b is None else ('MERGED-SWITCH' if merged(b) else 'plain'), '' if b is None else '(%d lines)'%b.count('\n'))
