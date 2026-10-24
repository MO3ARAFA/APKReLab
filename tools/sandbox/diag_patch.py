#!/usr/bin/env python3
"""Makes a DIAGNOSTIC copy of TaintIr (outside the project) whose 'top owners of real drops' key carries the method name
(owner.method), so the drop list says WHICH call was lost. Usage: python3 diag_patch.py <src ir dir> <out dir>; compile the out dir instead of the project's ir dir."""
import sys, shutil, os
src, out = sys.argv[1], sys.argv[2]
shutil.rmtree(out, ignore_errors=True); shutil.copytree(src, out)
p = os.path.join(out, 'TaintIr.java'); s = open(p).read()
s = s.replace("noteLibDrop(owner, t);", "noteLibDrop(owner, name, t);")
s = s.replace("private void noteLibDrop(String owner, Tv[] t) {", "private void noteLibDrop(String owner, String mname, Tv[] t) {")
s = s.replace('libOwners.merge((app ? "app " : "") + shortOwner, 1, Integer::sum);', 'libOwners.merge((app ? "app " : "") + shortOwner + "." + mname, 1, Integer::sum);')
open(p, 'w').write(s)
