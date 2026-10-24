# ManifestPatcher test (runs on a PC, not on the phone)
Needs Python 3 and a JDK 21+ (java source launcher).
1. `python3 gen.py` -> t_u8.axml, t_u16.axml, t_u8_long.axml (synthetic binary manifests, UTF-8 and UTF-16 string pools).
2. Make a copy of ManifestPatcher.java with a `Test` main class first in the file (see HANDOFF 0.17.0), run `java Test.java t_u8.axml com.example.app.relab out.axml`.
3. `python3 dump.py out.axml` prints the attributes; `dump.py` also asserts chunk sizes and string terminators.
Result in the sandbox (0.17.0): all 3 files patched, package/permissions/authorities/category/process renamed, relative class names expanded.
