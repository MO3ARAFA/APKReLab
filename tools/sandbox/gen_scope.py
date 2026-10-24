#!/usr/bin/env python3
"""Regenerates Scope.java (the harness copy of SecurityScanner.libPrefixes / libOverrides). Run it again whenever those lists change."""
import re, sys
src = open(sys.argv[1] if len(sys.argv) > 1 else '../../app/src/main/java/dev/apkrelab/SecurityScanner.kt').read()
a = src.index('private val libPrefixes'); b = src.index('private val libOverrides')
libs = re.findall(r'"([^"]+/)"', src[a:b]); ov = re.findall(r'"([^"]+/)"', src[b:src.index('fun codePackage')])
q = lambda l: ",".join('"%s"' % x for x in l)
open('Scope.java', 'w').write('''import java.util.*;
public class Scope {
  static final String[] LIB = {%s};
  static final String[] OV = {%s};
  static boolean isOverride(String type) {
    String p = type.startsWith("L") ? type.substring(1) : type;
    for (String o : OV) if (p.startsWith(o)) return true;
    return false;
  }
  static boolean isLib(String type, String appPkg) {
    String p = type.startsWith("L") ? type.substring(1) : type;
    for (String o : OV) if (p.startsWith(o)) return true;
    if (!appPkg.isEmpty()) {
      String[] s = appPkg.split("\\\\.");
      String pref = (s.length >= 2 ? s[0] + "/" + s[1] : s[0]) + "/";
      if (p.startsWith(pref)) return false;
    }
    for (String l : LIB) if (p.startsWith(l)) return true;
    return false;
  }
}
''' % (q(libs), q(ov)))
