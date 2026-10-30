import re,sys,os,glob
libs=re.findall(r'"([^"]+/)"',open('/home/claude/proj/APKReLab/app/src/main/java/dev/apkrelab/SecurityScanner.kt').read().split('private val libPrefixes')[1].split('private val libOverrides')[0])
ov=["org/schabi/newpipe/extractor/","org/fossify/commons/","com/simplemobiletools/commons/"]
def is_lib(p,pkg):
    if any(p.startswith(o) for o in ov): return True
    s=pkg.split('.'); pref='/'.join(s[:2])+'/'
    if p.startswith(pref): return False
    return any(p.startswith(l) for l in libs)
app,pkg=sys.argv[1],sys.argv[2]
ref=re.compile(r'L([A-Za-z0-9_$/]+);')
classes={}
for f in glob.glob(app+'/smali*/**/*.smali',recursive=True):
    t=open(f,encoding='utf8',errors='ignore').read()
    m=re.search(r'^\.class[^\n]*?L([^;\s]+);',t,re.M)
    if m: classes[m.group(1)]=t
sp=pkg.split('.'); pref='/'.join(sp[:2])+'/'
appset={c for c in classes if c.startswith(pref) and not any(c.startswith(o) for o in ov)}
hits=[]
for c,t in classes.items():
    if c in appset: continue
    if any(c.startswith(o) for o in ov): continue   # intentional library override
    refs={r for r in ref.findall(t)}
    a=[r for r in refs if r in appset]
    if a: hits.append((c,len(a),a[:2]))
print(app,"classes",len(classes),"app",len(appset),"lib-named classes that reference app classes:",len(hits))
for c,n,a in sorted(hits,key=lambda x:-x[1])[:12]: print("  ",c,n,a)
