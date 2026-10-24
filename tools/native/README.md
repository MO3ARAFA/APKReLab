# Native library analysis (0.90.0)

`ElfAnalyzer.kt` reads the ELF files in `lib/<abi>/` (pure Kotlin, a byte array; ELF32 and ELF64, little-endian): program headers (GNU_STACK, GNU_RELRO, LOAD alignment), the dynamic section
(BIND_NOW, TEXTREL, RPATH / RUNPATH, SONAME, NEEDED), the dynamic symbol table (`.dynsym` + `.dynstr`; the hash tables give the count when section headers are stripped) and the printable
strings of the allocated, non-executable data sections (the symbol-name tables are skipped). `NativeScanner.kt` turns that into cards.

## Validation against readelf (`oracle.py`, `ElfDump.kt`)
225 libraries extracted from 37 real APKs (arm64-v8a, plus the small armeabi-v7a / x86 / x86_64 ones: ELF32 and ELF64): the reader's fields compared with
`readelf -W -h -l -d --dyn-syms`: class, executable stack, RELRO segment, BIND_NOW, TEXTREL, SONAME, NEEDED, number of dynamic symbols, the exact set of imported (UND) symbols, number of
exports, minimum LOAD alignment, RPATH, RUNPATH = 13 fields. **222 ELF files x 13 = 2,886 comparisons: 0 differences.** 3 files named `.so` are zip archives (Seal stores them like that):
neither the reader nor readelf accepts them. (A first run showed 11 differences in the export count: the oracle's own regex did not read the hexadecimal sizes readelf prints for large
symbols; the reader was right.) `ElfSamples.kt` writes synthetic files (the test builder `ElfTestBuilder`) for readelf as well.

## What the real libraries look like (the calibration of the severities), 100 arm64-v8a libraries
NX 100%, full RELRO 100%, no TEXTREL, 2 with an RPATH / RUNPATH; stack canary 78; FORTIFY (_chk) imports 41; imports of gets / strcpy / strcat / sprintf / system / popen 17; LOAD alignment
below 16 KB in 17 (0x1000), 16 KB in 80, 64 KB in 3. So the classic hardening flags almost never fire on a modern build, a missing canary or a strcpy import is normal in a bundled
library, and the one thing that matters now is the 16 KB page size that Google Play enforces for apps targeting Android 15+.

## Cards (one per concern, never one per library)
`native-16kb-alignment` (MEDIUM when the target SDK is 35+, otherwise INFO; own / unclassified libraries and bundled dependencies named separately), `native-hardening` (executable stack,
no GNU_STACK, TEXTREL, no RELRO, RPATH to a location others can write; MEDIUM for an unclassified library, LOW for a well-known dependency), `native-rpath` (INFO: a private-directory
path), `native-unsafe-imports` (LOW, only for libraries that are not a known generic dependency), `native-secrets` (HIGH, the vendor token formats over the data strings; CRITICAL for a PEM
private key), `native-coverage` (INFO: what was and was not looked at). The list of known dependencies holds only generic libraries (runtime, codecs, crypto, databases, frameworks):
a name specific to one app counts as the app's own.

## Result on the 37 APKs (each with its own target SDK) - `results-37-apks-0.90.0.tsv`
30 apps have native libraries, all analysed in 11 s in total (the slowest, an app with a 49 MB library, 2.5 s). 16 KB: MEDIUM in 3 apps (target SDK 35 / 36), INFO in 3 (target SDK 28 / 31 / 34);
unsafe imports (LOW) in 7 apps; one hardening card; **0 credentials in native data**.
Limits: the native code itself is not analysed (no disassembly); an import shows a library can call a function, not that the call is reachable.
