import struct,sys
def dump(path):
    d=open(path,'rb').read()
    t,h,sz=struct.unpack_from('<HHI',d,0); assert t==3 and sz==len(d),(t,sz,len(d))
    pos=8
    t,h,psz,n,sc,fl,ss,st=struct.unpack_from('<HHIIIIII',d,pos); assert t==1 and sc==0
    utf8=bool(fl&0x100); PP=pos
    offs=struct.unpack_from('<%dI'%n,d,pos+28)
    def S(i):
        if i==0xffffffff: return None
        p=PP+ss+offs[i]
        if utf8:
            c=d[p];p+=1
            if c&0x80: c=((c&0x7f)<<8)|d[p];p+=1
            b=d[p];p+=1
            if b&0x80: b=((b&0x7f)<<8)|d[p];p+=1
            assert d[p+b]==0
            return d[p:p+b].decode('utf-8')
        l=struct.unpack_from('<H',d,p)[0];p+=2
        assert d[p+2*l:p+2*l+2]==b'\0\0'
        return d[p:p+2*l].decode('utf-16-le')
    pos+=psz; lines=[]
    while pos<len(d):
        t,h,sz=struct.unpack_from('<HHI',d,pos)
        if t==0x102:
            ns,name,as_,asz,ac=struct.unpack_from('<IIHHH',d,pos+16)
            al=[]
            for i in range(ac):
                a=pos+16+as_+i*asz
                ans,an,raw,vs,r0,dt,dat=struct.unpack_from('<IIIHBBI',d,a)
                if dt==3:
                    assert S(raw)==S(dat)
                    al.append('%s=%s'%(S(an),S(dat)))
                else: al.append('%s=<t%d:%d>'%(S(an),dt,dat))
            lines.append('<%s %s>'%(S(name),' '.join(al)))
        pos+=sz
    return lines,n,utf8
if __name__=='__main__':
    for l in dump(sys.argv[1])[0]: print(l)
