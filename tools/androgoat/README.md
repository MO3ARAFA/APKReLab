# AndroGoat benchmark (MASTG-APP-0001)
1. Build/download AndroGoat APK, open it in APKReLab, run Deep scan (and Smart scan if wanted).
2. Export the Report (or copy the Security list text) to findings.txt.
3. `python3 compare.py findings.txt` -> OK / MISS per vulnerability. Every MISS is a task for the next version.
Note: some matches are loose (e.g. "WebView") - confirm the finding really points at the AndroGoat class.
