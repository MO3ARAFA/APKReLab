package dev.apkrelab.ir;

import java.util.ArrayList;
import java.util.List;

/** 0.53.0 (P0): header (type, super, interfaces, fields) and methods of one baksmali class. */
public final class ClassIr {
    public String type = "";                       // "Lcom/x/Y;"
    public String superType = "";                  // "" for java.lang.Object itself
    public String flags = "";
    public final List<String> interfaces = new ArrayList<>();
    public final List<String> fields = new ArrayList<>();   // "name:Ltype;"
    public final List<MethodIr> methods = new ArrayList<>();

    /** 0.66.3: flags parsed once per flags value (immutable holder, safe between threads). */
    private static final class Fl {
        final String src;
        final boolean itf, abs;

        Fl(String src) {
            this.src = src;
            boolean i = false, a = false;
            for (String s : src.split(" ")) {
                if (s.equals("interface")) i = true;
                if (s.equals("abstract") || s.equals("interface")) a = true;
            }
            this.itf = i;
            this.abs = a;
        }
    }

    private volatile Fl fl;

    private Fl fl() {
        Fl f = fl;
        if (f == null || f.src != flags) fl = f = new Fl(flags);
        return f;
    }

    public boolean isInterface() {
        return fl().itf;
    }

    public boolean isAbstract() {
        return fl().abs;
    }

    public MethodIr method(String sig) {
        for (MethodIr m : methods) if (m.sig().equals(sig)) return m;
        return null;
    }

    @Override
    public String toString() {
        return type;
    }
}
