// app.js — Scope-Aware ATT&CK Navigator
//
// ── HOW TO ADD TECHNIQUES ──────────────────────────────────────────────────
// ATTACK_DB is the single source of truth. Add one entry here and it appears
// in the grid, stats bar, filters, SVG export, and PDF export automatically.
//
// Required fields:
//   name        {string}  Display name
//   description {string}  One-sentence description
//   test_note   {string}  Tool / command hint shown on the card
//   platform    {string|string[]}  e.g. "windows", "linux", or ["windows","linux"]
//
// Optional fields:
//   category    {string}  Groups cards under a section header (e.g. "DLL Attacks")
//   mitre_ref   {string}  Parent MITRE ID — shown as "↗ Variant of T1574.001"
//   custom      {bool}    true = no MITRE mapping; shows orange "Custom · Non-MITRE" badge
//
// ID conventions:
//   Standard MITRE  →  T1574.001, T1112   (MITRE link auto-generated)
//   MITRE variant   →  T1574.001-PDH      (set mitre_ref to parent ID)
//   Custom/Non-MITRE→  WIN-CUSTOM-001     (set custom: true)
//
// To add a new platform: add entries with platform: "yourplatform" — the
// dropdown, storage bucket, and exports all provision themselves automatically.
// ──────────────────────────────────────────────────────────────────────────

const ATTACK_DB = {

  // === WINDOWS THICK CLIENT — COMPLETE ATTACK_DB BLOCK (replace existing windows entries) ===
"RECON-1": {
  "name": "Architecture & Tech Stack Discovery",
  "description": "Identify if the application is .NET, Java, C++, Electron, or Delphi.",
  "test_note": "Use 'Detect It Easy' or 'CFF Explorer' to check compiler and linker info.",
  "category": "1_RECON",
  "platform": "windows",
  "custom": true
},
"RECON-2": {
  "name": "Binary Protections Check",
  "description": "Check for exploit mitigation features like ASLR, DEP, SafeSEH, and CFG.",
  "test_note": "Run 'PESecurity' or 'WinCheck' against the main .exe and loaded .dlls.",
  "category": "1_RECON",
  "mitre_ref": "CWE-693",
  "custom": true,
  "platform": "windows"
},
"RECON-3": {
  "name": "Endpoint & API Discovery",
  "description": "Identify hardcoded URLs, IP addresses, and API endpoints for backend communication.",
  "test_note": "Use 'Strings' or 'HTTPAnalyze' to extract URL patterns from the binary.",
  "category": "1_RECON",
  "mitre_ref": "T1590",
  "platform": "windows"
},

"STATIC-1": {
  "name": "Hardcoded Secrets & Strings",
  "description": "Search for credentials, API keys, or hardcoded IP addresses in the binary.",
  "test_note": "Use 'strings.exe' or 'floss' for obfuscated strings; search for 'pwd', 'conn', 'key'.",
  "category": "2_STATIC",
  "mitre_ref": "T1552.001",
  "platform": "windows"
},
"STATIC-2": {
  "name": "Decompilation & Logic Review",
  "description": "Decompile the binary to understand business logic and identify hidden features.",
  "test_note": "Use 'dnSpy' for .NET, 'JD-GUI' for Java, or 'Ghidra' for native C++ binaries.",
  "category": "2_STATIC",
  "mitre_ref": "CWE-327",
  "custom": true,
  "platform": "windows"
},
"STATIC-3": {
  "name": "Weak Binary Permissions",
  "description": "Verify if the application installation directory has weak ACLs allowing modification.",
  "test_note": "icacls \"C:\\Program Files\\App\"; look for (M) or (F) for Users/Authenticated Users.",
  "category": "2_STATIC",
  "mitre_ref": "T1544",
  "platform": "windows"
},
"STATIC-4": {
  "name": "Config File Analysis",
  "description": "Audit .config, .xml, and .ini files for sensitive cleartext data.",
  "test_note": "Search AppDir and %AppData% for connection strings or developer notes.",
  "category": "2_STATIC",
  "mitre_ref": "T1552.006",
  "platform": "windows"
},

"TRAFFIC-1": {
  "name": "Intercept HTTP/HTTPS Traffic",
  "description": "Capture and analyze web-based API calls made by the thick client.",
  "test_note": "Configure Proxy in app or use 'Burp Suite' with 'Echo Mirage' for non-proxy apps.",
  "category": "3_TRAFFIC",
  "mitre_ref": "T1048",
  "platform": "windows"
},
"TRAFFIC-2": {
  "name": "Broken Cryptography (TLS/SSL)",
  "description": "Check for weak TLS versions, expired certificates, or lack of certificate pinning.",
  "test_note": "Attempt MiTM with Burp; check if app accepts self-signed certs.",
  "category": "3_TRAFFIC",
  "mitre_ref": "CWE-295",
  "custom": true,
  "platform": "windows"
},
"TRAFFIC-3": {
  "name": "Insecure Communication (Cleartext)",
  "description": "Identify sensitive data transmitted over unencrypted protocols (TCP/UDP).",
  "test_note": "Run 'Wireshark' while performing login/actions; search for cleartext credentials.",
  "category": "3_TRAFFIC",
  "mitre_ref": "T1040",
  "platform": "windows"
},

// 4_CSTest — all DLL variants + IPC (exactly as on GitHub + your requested Name Impersonation)
"T1574.001": {
  "name": "DLL Search Order Hijacking",
  "description": "Adversaries may hijack DLL search order to load malicious DLLs.",
  "test_note": "ProcMon filter: NAME NOT FOUND on .dll in app dir; drop payload",
  "category": "4_CSTest",
  "platform": "windows"
},
"T1574.001-PDH": {
  "name": "Phantom DLL Hijacking",
  "description": "App references a DLL that doesn't exist; attacker drops it into a searched path.",
  "test_note": "ProcMon: filter Result=NAME NOT FOUND + Path ends in .dll; plant payload DLL",
  "category": "4_CSTest",
  "mitre_ref": "T1574.001",
  "platform": "windows"
},
"T1574.001-RED": {
  "name": "DLL Redirection",
  "description": "Redirect DLL resolution via .manifest file or DllRedirection registry key.",
  "test_note": "Create <app>.exe.manifest with redirect entry; verify via ProcMon load path",
  "category": "4_CSTest",
  "mitre_ref": "T1574.001",
  "platform": "windows"
},
"T1574.001-SUB": {
  "name": "DLL Substitution",
  "description": "Replace a legitimately-loaded DLL in a user-writable directory with a malicious proxy.",
  "test_note": "Identify DLLs loaded from writable dirs (icacls); overwrite with proxy DLL",
  "category": "4_CSTest",
  "mitre_ref": "T1574.001",
  "platform": "windows"
},
"T1574.002": {
  "name": "DLL Side-Loading",
  "description": "Load malicious DLL by placing it alongside a legitimate signed EXE that imports it.",
  "test_note": "Find EXEs with missing imports (Dependencies tool); drop crafted DLL beside EXE",
  "category": "4_CSTest",
  "platform": "windows"
},
"WIN-DLL-UNSIGNED": {
  "name": "Unsigned DLL Loading",
  "description": "Application loads DLLs without Authenticode verification.",
  "test_note": "Sigcheck -e on process DLLs; Sysmon Event 7 for unsigned modules",
  "category": "4_CSTest",
  "custom": true,
  "platform": "windows"
},
"CSTEST-1": {
  "name": "Named Pipe Impersonation",
  "description": "Insecure IPC via Named Pipes (Name Impersonation).",
  "test_note": "Use 'PipeList' or 'IOREACH' to find pipes; check permissions with AccessEnum.",
  "category": "4_CSTest",
  "mitre_ref": "T1559",
  "platform": "windows"
},
"T1055.001": {
  "name": "Process Injection (DLL)",
  "description": "Inject DLL into legitimate process via CreateRemoteThread.",
  "test_note": "Process Hacker + classic CreateRemoteThread",
  "category": "4_CSTest",
  "platform": "windows"
},

// 5_BLIssue — already on GitHub + your requested Client-Side Trust & Parameter Tampering
"BLISSUE-1": {
  "name": "GUI Element Manipulation",
  "description": "Enable disabled buttons, hidden tabs, or unmask password fields in the UI.",
  "test_note": "Use 'WinSpy++' or 'Window Detective' to change object properties (Enable/Visible).",
  "category": "5_BLIssue",
  "custom": true,
  "platform": "windows"
},
"BLISSUE-2": {
  "name": "Client-Side Trust Issues",
  "description": "Check if critical logic (authorization, price calc) is performed solely on client side.",
  "test_note": "Modify local logic via dnSpy/Patching and see if backend accepts forged state.",
  "category": "5_BLIssue",
  "mitre_ref": "CWE-602",
  "custom": true,
  "platform": "windows"
},
"BLISSUE-3": {
  "name": "Parameter Tampering (Memory / Config)",
  "description": "Modify values in memory or local files to bypass business rules.",
  "test_note": "Use 'Cheat Engine' to find and modify local variables (Balance, RoleID) in RAM.",
  "category": "5_BLIssue",
  "mitre_ref": "CWE-20",
  "custom": true,
  "platform": "windows"
},

// 6_MEMORY — Sensitive Data in Memory (your flagged missing item)
"MEMORY-1": {
  "name": "Sensitive Data in Memory",
  "description": "Passwords, tokens, PII stored in cleartext within the application's RAM.",
  "test_note": "procdump -ma <PID> dump.dmp && strings dump.dmp | findstr -i pass; WinDbg !heap",
  "category": "6_MEMORY",
  "mitre_ref": "T1003",
  "platform": "windows"
},
"MEMORY-2": {
  "name": "Heap Inspection Post-Authentication",
  "description": "Sensitive data remaining in heap/stack after login or crypto ops.",
  "test_note": "x64dbg/x32dbg + Search Pattern; Frida on .NET thick clients",
  "category": "6_MEMORY",
  "custom": true,
  "platform": "windows"
},

// 7_REGISTRY + remaining high-impact vectors
"REG-1": {
  "name": "Registry Configuration Tampering & Enumeration",
  "description": "Abuse weak ACLs or insecure storage in HKCU/HKLM application-specific keys.",
  "test_note": "reg query \"HKCU\\Software\\<App>\" /s; icacls on reg keys; ProcMon RegSetValue",
  "category": "7_REGISTRY",
  "custom": true,
  "platform": "windows"
},
"REG-2": {
  "name": "Autoruns & Persistence via Registry",
  "description": "App-specific Run keys, Shell extensions, COM objects.",
  "test_note": "Autoruns.exe filtered by app; HKLM\\...\\Run keys",
  "category": "7_REGISTRY",
  "mitre_ref": "T1547.001",
  "platform": "windows"
},

"STORAGE-1": {
  "name": "Insecure Local Storage (Files / DBs)",
  "description": "Plaintext or weakly protected data in %AppData%, SQLite/JSON/XML files.",
  "test_note": "grep -i pass *.db *.json *.xml in install dir; DB Browser for SQLite",
  "category": "8_STORAGE",
  "custom": true,
  "platform": "windows"
},
"STORAGE-2": {
  "name": "Crash Dumps & Log File Exposure",
  "description": "Sensitive info in .dmp, .log, or temp files left in writable locations.",
  "test_note": "Search %LocalAppData%\\<App> *.dmp *.log; ProcMon during forced crash",
  "category": "8_STORAGE",
  "custom": true,
  "platform": "windows"
},

"FILE-1": {
  "name": "Symlink / Junction Attacks",
  "description": "Plant symbolic links/junctions in writable directories used by the thick client.",
  "test_note": "mklink /J or /D; ProcMon CreateFile monitoring on app paths",
  "category": "9_FILEOPS",
  "custom": true,
  "platform": "windows"
},
"FILE-2": {
  "name": "Directory Traversal in File Dialogs",
  "description": "Path traversal via save/open dialogs and file handling routines.",
  "test_note": "../../.. payloads in filename fields; monitor ProcMon for unexpected paths",
  "category": "9_FILEOPS",
  "mitre_ref": "CWE-22",
  "custom": true,
  "platform": "windows"
},

"UPDATE-1": {
  "name": "Insecure Auto-Update Mechanism",
  "description": "Unsigned manifests, MITM-able update channels, executable replacement.",
  "test_note": "Intercept update traffic; replace update EXE/DLL; check code signing + hash",
  "category": "10_UPDATE",
  "custom": true,
  "platform": "windows"
},

"IPC-1": {
  "name": "COM / DCOM / CLSID Hijacking",
  "description": "Abuse COM objects, Image File Execution Options, or CLSID registration.",
  "test_note": "reg query HKCR\\CLSID; OleView; IFEO registry tampering",
  "category": "11_IPC",
  "mitre_ref": "T1546.003",
  "custom": true,
  "platform": "windows"
},

  // === LINUX THICK CLIENT ===
"RECON-1": {
  "name": "Binary Fingerprinting (ELF)",
  "description": "Identify architecture, PIE, RELRO, NX, stripping, and linked libraries.",
  "test_note": "file binary; checksec --file=binary; readelf -h -d binary; ldd binary",
  "category": "1_RECON",
  "platform": "linux",
  "custom": true
},
"RECON-2": {
  "name": "Binary Protections & Hardening",
  "description": "Check ASLR, stack canaries, FORTIFY_SOURCE, and compiler flags.",
  "test_note": "checksec --format=cli binary; objdump -d binary | grep -E 'canary|fortify'",
  "category": "1_RECON",
  "mitre_ref": "CWE-693",
  "platform": "linux"
},

"STATIC-1": {
  "name": "Hardcoded Secrets & Strings",
  "description": "Extract credentials, keys, tokens from ELF strings and symbols.",
  "test_note": "strings -n 8 binary | grep -Ei 'pass|key|token|secret|api'; floss binary",
  "category": "2_STATIC",
  "mitre_ref": "T1552.001",
  "platform": "linux"
},
"STATIC-2": {
  "name": "Decompilation & Logic Review",
  "description": "Reverse engineer ELF with Ghidra, radare2, or IDA.",
  "test_note": "ghidra binary; r2 -A binary; nm -a binary | grep -E 'main|auth'",
  "category": "2_STATIC",
  "mitre_ref": "CWE-327",
  "platform": "linux"
},
"STATIC-3": {
  "name": "Weak File & Directory Permissions",
  "description": "Installation dir, .so files, configs writable by non-root.",
  "test_note": "ls -la /opt/App /usr/local/bin/App; find /opt/App -type f -perm -o=w",
  "category": "2_STATIC",
  "mitre_ref": "T1544",
  "platform": "linux"
},

"TRAFFIC-1": {
  "name": "Intercept HTTP/HTTPS Traffic",
  "description": "Proxy thick-client outbound traffic (Electron/Qt/WebView).",
  "test_note": "mitmproxy or Burp with SSLKEYLOGFILE; set http_proxy && https_proxy",
  "category": "3_TRAFFIC",
  "mitre_ref": "T1048",
  "platform": "linux"
},
"TRAFFIC-2": {
  "name": "Broken TLS / Certificate Validation",
  "description": "Weak ciphers, no pinning, self-signed acceptance.",
  "test_note": "openssl s_client; test with Burp CA; Wireshark TLS handshake",
  "category": "3_TRAFFIC",
  "mitre_ref": "CWE-295",
  "platform": "linux"
},

// 4_CSTest — merged all existing SO/DLL hijacks + new
"T1574.006": {
  "name": "LD_PRELOAD Hijacking",
  "description": "Hijack shared object loading via environment variable.",
  "test_note": "LD_PRELOAD=./evil.so ./app; gcc -shared -fPIC -o evil.so evil.c",
  "category": "4_CSTest",
  "platform": "linux"
},
"T1574.007": {
  "name": "PATH Interception",
  "description": "Hijack via malicious binary in $PATH.",
  "test_note": "export PATH=./malicious:$PATH; ./app",
  "category": "4_CSTest",
  "platform": "linux"
},
"T1574.010": {
  "name": "Service Binary Hijack",
  "description": "Replace writable service binary with malicious ELF.",
  "test_note": "find / -perm -o=w -type f -name '*.service' 2>/dev/null",
  "category": "4_CSTest",
  "platform": "linux"
},
"LINUX-SO-1": {
  "name": "Shared Object Side-Loading",
  "description": "Drop malicious .so in RPATH or LD_LIBRARY_PATH.",
  "test_note": "objdump -p binary | grep RPATH; LD_LIBRARY_PATH=./evil ./app",
  "category": "4_CSTest",
  "platform": "linux"
},

"5_MEMORY-1": {
  "name": "Process Memory Dump & Analysis",
  "description": "Extract secrets from running process RAM (gcore, /proc/pid/mem).",
  "test_note": "gcore <PID>; strings core.<PID> | grep -Ei 'pass|key|token'",
  "category": "5_MEMORY",
  "mitre_ref": "T1003",
  "platform": "linux"
},
"5_MEMORY-2": {
  "name": "Heap / Strace Inspection",
  "description": "Trace syscalls and inspect heap for sensitive data post-auth.",
  "test_note": "strace -p <PID> -e trace=open,read; gdb --pid=<PID>",
  "category": "5_MEMORY",
  "platform": "linux"
},

"6_PRIVESC-1": {
  "name": "SUID / SGID Binary Abuse",
  "description": "Exploit setuid binaries for privilege escalation.",
  "test_note": "find / -type f -perm -4000 2>/dev/null; GTFOBins lookup",
  "category": "6_PRIVESC",
  "mitre_ref": "T1548.001",
  "platform": "linux"
},
"6_PRIVESC-2": {
  "name": "sudoers / Polkit Misconfig",
  "description": "NOPASSWD entries, weak sudo rules, polkit bypass.",
  "test_note": "sudo -l; pkexec --version; check /etc/sudoers",
  "category": "6_PRIVESC",
  "mitre_ref": "T1548.003",
  "platform": "linux"
},

"7_PERSIST-1": {
  "name": "Cron / rc.local Persistence",
  "description": "User/root cron jobs or boot scripts.",
  "test_note": "crontab -l; ls -la /etc/rc.local /etc/cron.*",
  "category": "7_PERSISTENCE",
  "mitre_ref": "T1053.003",
  "platform": "linux"
},
"7_PERSIST-2": {
  "name": "Systemd / .desktop Autostart",
  "description": "User systemd units or .desktop files in ~/.config/autostart.",
  "test_note": "systemctl --user list-unit-files; ls ~/.config/autostart",
  "category": "7_PERSISTENCE",
  "mitre_ref": "T1543.002",
  "platform": "linux"
},
"7_PERSIST-3": {
  "name": ".bashrc / Shell Profile Hijack",
  "description": "Append payload to shell config files.",
  "test_note": "echo 'payload' >> ~/.bashrc",
  "category": "7_PERSISTENCE",
  "mitre_ref": "T1546.004",
  "platform": "linux"
},

"8_STORAGE-1": {
  "name": "Insecure Config / DB Storage",
  "description": "Plaintext secrets in ~/.config/App, SQLite, JSON.",
  "test_note": "grep -RiE 'pass|key|token' ~/.config/App ~/.local/share/App",
  "category": "8_STORAGE",
  "platform": "linux"
},

"9_GUI-1": {
  "name": "GUI Spying & Control Bypass",
  "description": "xprop, xdotool, xspy to manipulate hidden UI elements.",
  "test_note": "xprop -id $(xdotool getactivewindow); xdotool key F12",
  "category": "9_GUI",
  "platform": "linux"
},

"10_UPDATE-1": {
  "name": "Insecure Auto-Update",
  "description": "Unsigned .AppImage, .deb, or repo-based updates.",
  "test_note": "curl update URL | grep -E 'http|unsigned'",
  "category": "10_UPDATE",
  "platform": "linux"
},

"11_IPC-1": {
  "name": "D-Bus / IPC Abuse",
  "description": "Insecure D-Bus services for inter-process communication.",
  "test_note": "dbus-send --session --dest=...; busctl list",
  "category": "11_IPC",
  "platform": "linux"
},

// === ANDROID MOBILE ===
"ARECON-1": {
  "name": "APK Fingerprint & Manifest Analysis",
  "description": "Extract package name, permissions, exported components, debuggable flag.",
  "test_note": "apktool d app.apk; cat AndroidManifest.xml | grep -E 'exported|permission|debuggable|allowBackup'",
  "category": "1_ARECON",
  "platform": "android",
  "custom": true
},
"ARECON-2": {
  "name": "Static APK Analysis (MobSF)",
  "description": "Automated static scan for hardcoded secrets, insecure configs, and surface mapping.",
  "test_note": "mobsf app.apk; review Manifest, Strings, and API calls in report",
  "category": "1_ARECON",
  "platform": "android",
  "custom": true
},

"ASTATIC-1": {
  "name": "Decompilation & Code Review",
  "description": "Decompile to Java/Kotlin and search for logic flaws.",
  "test_note": "jadx-gui app.apk; grep -rE 'password|token|secret|api_key' sources/",
  "category": "2_ASTATIC",
  "platform": "android",
  "mitre_ref": "CWE-327",
  "custom": true
},
"ASTATIC-2": {
  "name": "Hardcoded Secrets & Strings",
  "description": "Credentials, keys, or tokens embedded in code or resources.",
  "test_note": "strings app.apk | grep -Ei 'pass|key|token|secret'; or MobSF Strings tab",
  "category": "2_ASTATIC",
  "platform": "android",
  "mitre_ref": "T1552.001"
},

"ATRAFFIC-1": {
  "name": "Intercept HTTP/HTTPS Traffic",
  "description": "Capture and tamper with all outbound API calls.",
  "test_note": "Burp + Android proxy (Wi-Fi advanced settings); set http_proxy env if needed",
  "category": "3_ATRAFFIC",
  "platform": "android",
  "mitre_ref": "T1048"
},
"ATRAFFIC-2": {
  "name": "Broken TLS / Certificate Pinning",
  "description": "Weak pinning, expired certs, or no validation.",
  "test_note": "Objection: android sslpinning disable; or Frida script + Burp CA",
  "category": "3_ATRAFFIC",
  "platform": "android",
  "mitre_ref": "CWE-295"
},

"ACRYPTO-1": {
  "name": "Weak Cryptography Implementation",
  "description": "Hardcoded keys, insecure algorithms (DES, MD5), improper IV/nonce.",
  "test_note": "grep -rE 'Cipher|DES|MD5|SHA1' sources/; check KeyStore usage",
  "category": "4_ACRYPTO",
  "platform": "android",
  "mitre_ref": "CWE-327"
},
"ACRYPTO-2": {
  "name": "Insecure Random Number Generation",
  "description": "Use of Math.random or weak SecureRandom.",
  "test_note": "grep -rE 'Random|SecureRandom' sources/; Frida hook java.util.Random",
  "category": "4_ACRYPTO",
  "platform": "android",
  "custom": true
},

"ASTORAGE-1": {
  "name": "Insecure Local Storage (SharedPreferences / SQLite)",
  "description": "Plaintext credentials or PII in private files/DBs.",
  "test_note": "adb shell run-as com.app.id cat /data/data/com.app.id/shared_prefs/*.xml; DB Browser for SQLite",
  "category": "5_ASTORAGE",
  "platform": "android",
  "mitre_ref": "T1555"
},
"ASTORAGE-2": {
  "name": "Backup & ADB Extraction Abuse",
  "description": "allowBackup=true exposes data via adb backup.",
  "test_note": "adb backup -apk com.app.id; unpack with Android Backup Extractor",
  "category": "5_ASTORAGE",
  "platform": "android",
  "custom": true
},

"AAUTH-1": {
  "name": "Client-Side Authentication Flaws",
  "description": "Auth logic performed only on device (bypass via Frida).",
  "test_note": "Objection: android hooking list; Frida hook login methods and force return true",
  "category": "6_AAUTH",
  "platform": "android",
  "mitre_ref": "CWE-602"
},
"AAUTH-2": {
  "name": "Insecure Session Management",
  "description": "Tokens stored in plaintext or predictable sessions.",
  "test_note": "Frida: trace java.net.CookieManager; check SharedPreferences for tokens",
  "category": "6_AAUTH",
  "platform": "android",
  "custom": true
},

"APLATFORM-1": {
  "name": "Exported Components (Activities/Services)",
  "description": "Deep-link or intent hijacking via exported components.",
  "test_note": "apktool d; check android:exported=true; adb shell am start -n com.app/.VulnActivity",
  "category": "7_APLATFORM",
  "platform": "android",
  "mitre_ref": "T1579"
},
"APLATFORM-2": {
  "name": "WebView JavaScript Interface Injection",
  "description": "JS-to-native bridge allows arbitrary code execution.",
  "test_note": "grep -r 'addJavascriptInterface' sources/; test XSS payload",
  "category": "7_APLATFORM",
  "platform": "android",
  "mitre_ref": "CWE-79"
},

"AREVERSE-1": {
  "name": "Root Detection Bypass",
  "description": "App checks for su, Magisk, or known root paths.",
  "test_note": "Objection: android root disable; Frida script hook root detection methods",
  "category": "8_AREVERSE",
  "platform": "android",
  "custom": true
},
"AREVERSE-2": {
  "name": "Anti-Tampering & RASP Checks",
  "description": "Integrity checks, debugger detection, emulator detection.",
  "test_note": "Frida: bypass emulator checks; hook PackageManager.getInstallerPackageName",
  "category": "8_AREVERSE",
  "platform": "android",
  "custom": true
},

"ARUNTIME-1": {
  "name": "Runtime Memory & Heap Inspection",
  "description": "Sensitive data in RAM (tokens, keys) via Frida.",
  "test_note": "frida -U -f com.app.id -l memory_dump.js; objection memory dump",
  "category": "9_ARUNTIME",
  "platform": "android",
  "mitre_ref": "T1003"
},
"ARUNTIME-2": {
  "name": "Dynamic Method Hooking (Frida/Objection)",
  "description": "Bypass any client-side logic at runtime.",
  "test_note": "objection -g com.app.id explore; android hooking set return_value true",
  "category": "9_ARUNTIME",
  "platform": "android",
  "custom": true
},

"AIPC-1": {
  "name": "Insecure Content Provider / IPC Abuse",
  "description": "Exposed providers allow data leakage or injection.",
  "test_note": "drozer console; run scanner.provider.finduris; query content://com.app.provider",
  "category": "10_AIPC",
  "platform": "android",
  "mitre_ref": "T1559"
},

// === iOS MOBILE ===
"IRECON-1": {
  "name": "IPA Fingerprint & Info.plist Analysis",
  "description": "Extract entitlements, ATS settings, keychain usage, bundle ID.",
  "test_note": "unzip app.ipa; plutil -p Payload/*.app/Info.plist; codesign -d --entitlements :- Payload/*.app",
  "category": "1_IRECON",
  "platform": "ios",
  "custom": true
},
"IRECON-2": {
  "name": "Static IPA Analysis (MobSF)",
  "description": "Automated scan for hardcoded secrets and weak configs.",
  "test_note": "mobsf app.ipa; review Binary Analysis and Strings tabs",
  "category": "1_IRECON",
  "platform": "ios",
  "custom": true
},

"ISTATIC-1": {
  "name": "Hardcoded Secrets & Strings",
  "description": "Credentials or keys in binary/strings.",
  "test_note": "strings Payload/*.app/* | grep -Ei 'pass|key|token|secret'; or MobSF",
  "category": "2_ISTATIC",
  "platform": "ios",
  "mitre_ref": "T1552.001"
},
"ISTATIC-2": {
  "name": "Decompilation & Logic Review",
  "description": "Reverse Mach-O with Hopper or Ghidra.",
  "test_note": "Hopper app; search for auth/login functions",
  "category": "2_ISTATIC",
  "platform": "ios",
  "mitre_ref": "CWE-327"
},

"ITRAFFIC-1": {
  "name": "Intercept HTTP/HTTPS Traffic",
  "description": "Capture all outbound calls with Burp.",
  "test_note": "Burp CA installed via device proxy; Frida SSL pinning bypass",
  "category": "3_ITRAFFIC",
  "platform": "ios",
  "mitre_ref": "T1048"
},
"ITRAFFIC-2": {
  "name": "Broken TLS / Certificate Validation",
  "description": "No pinning or weak cert checks.",
  "test_note": "objection sslpinning disable; or Frida script (SSLKillSwitch)",
  "category": "3_ITRAFFIC",
  "platform": "ios",
  "mitre_ref": "CWE-295"
},

"ICRYPTO-1": {
  "name": "Weak Cryptography Implementation",
  "description": "Hardcoded keys or insecure CommonCrypto usage.",
  "test_note": "grep -rE 'CCCrypt|kCCAlgorithm' Payload/; check SecKey API calls",
  "category": "4_ICRYPTO",
  "platform": "ios",
  "mitre_ref": "CWE-327"
},

"ISTORAGE-1": {
  "name": "Insecure Local Storage (Keychain / Plist / Files)",
  "description": "Plaintext data in Keychain, .plist, or Documents folder.",
  "test_note": "objection keychain dump; or frida dump keychain; check /var/mobile/Containers/Data/Application/",
  "category": "5_ISTORAGE",
  "platform": "ios",
  "mitre_ref": "T1555"
},
"ISTORAGE-2": {
  "name": "iTunes Backup Abuse",
  "description": "Sensitive data exposed in unencrypted backups.",
  "test_note": "iTunes backup + iBackup Viewer; search for app data",
  "category": "5_ISTORAGE",
  "platform": "ios",
  "custom": true
},

"IAUTH-1": {
  "name": "Client-Side Auth / Authorization Flaws",
  "description": "Logic performed on device only.",
  "test_note": "Frida hook login methods; force return true via Objection",
  "category": "6_IAUTH",
  "platform": "ios",
  "mitre_ref": "CWE-602"
},

"IPLATFORM-1": {
  "name": "Jailbreak Detection Bypass",
  "description": "App checks for Cydia, file paths, or syscalls.",
  "test_note": "objection jailbreak disable; Frida script hook jailbreak checks",
  "category": "7_IPLATFORM",
  "platform": "ios",
  "custom": true
},
"IPLATFORM-2": {
  "name": "WebView / WKWebView Injection",
  "description": "JS bridge or improper allowFileAccess.",
  "test_note": "Frida trace WKWebView; test javascript:alert(1) or file:// payloads",
  "category": "7_IPLATFORM",
  "platform": "ios",
  "mitre_ref": "CWE-79"
},

"IREVERSE-1": {
  "name": "Anti-Tampering & RASP Checks",
  "description": "Debugger, tweak, or integrity detection.",
  "test_note": "Frida: bypass ptrace/anti-debug; hook _dyld_get_image_name",
  "category": "8_IREVERSE",
  "platform": "ios",
  "custom": true
},

"IRUNTIME-1": {
  "name": "Runtime Memory & Keychain Dump",
  "description": "Extract tokens/keys from live process.",
  "test_note": "objection memory dump; frida -U -f com.app.id -l dump.js",
  "category": "9_IRUNTIME",
  "platform": "ios",
  "mitre_ref": "T1003"
},
"IRUNTIME-2": {
  "name": "Dynamic Method Hooking (Frida/Objection)",
  "description": "Bypass any client-side logic at runtime.",
  "test_note": "objection -g com.app.id explore; ios hooking set return_value true",
  "category": "9_IRUNTIME",
  "platform": "ios",
  "custom": true
},

"IIPC-1": {
  "name": "URL Scheme / Universal Link Hijacking",
  "description": "Malicious deep links or custom schemes.",
  "test_note": "check Info.plist for CFBundleURLTypes; test custom://payload",
  "category": "10_IIPC",
  "platform": "ios",
  "mitre_ref": "T1579"
},

// === GCP CLOUD ===
"GCPRECON-1": {
  "name": "Project & Asset Enumeration",
  "description": "Discover projects, IAM policies, enabled APIs, and service accounts.",
  "test_note": "gcloud projects list; gcloud asset search-all-resources; gcloud services list --available",
  "category": "1_GCPRECON",
  "platform": "gcp",
  "custom": true
},
"GCPRECON-2": {
  "name": "IAM & Service Account Recon",
  "description": "Enumerate service accounts, keys, and permission grants.",
  "test_note": "gcloud iam service-accounts list; gcloud iam list-grantable-roles",
  "category": "1_GCPRECON",
  "platform": "gcp",
  "mitre_ref": "T1589"
},

"GCPSTATIC-1": {
  "name": "IaC Scanning (Terraform/Deployment Manager)",
  "description": "Detect misconfigured GCP resources in IaC templates.",
  "test_note": "tfsec .; checkov -d . --framework terraform; gcloud deployment-manager deployments list",
  "category": "2_GCPSTATIC",
  "platform": "gcp",
  "custom": true
},
"GCPSTATIC-2": {
  "name": "Hardcoded Secrets in Code",
  "description": "Credentials, keys, tokens in source, logs, or Cloud Build.",
  "test_note": "gcloud secrets list; trufflehog git; grep -rE 'AIza|GOOGLE|secret' .",
  "category": "2_GCPSTATIC",
  "platform": "gcp",
  "mitre_ref": "T1552.001"
},

"GCPMISCONFIG-1": {
  "name": "Bucket & Storage Misconfigurations",
  "description": "Public GCS buckets, uniform access disabled, ACL leaks.",
  "test_note": "gsutil ls -r gs://; gsutil iam get gs://bucket; ScoutSuite --provider gcp",
  "category": "3_GCPMISCONFIG",
  "platform": "gcp",
  "mitre_ref": "T1530"
},
"GCPMISCONFIG-2": {
  "name": "Firewall & VPC Misconfigs",
  "description": "Overly permissive firewall rules or default networks.",
  "test_note": "gcloud compute firewall-rules list; gcloud compute networks list",
  "category": "3_GCPMISCONFIG",
  "platform": "gcp",
  "mitre_ref": "T1190"
},

"GCPIDENTITY-1": {
  "name": "IAM Privilege Escalation",
  "description": "Over-privileged service accounts, custom roles with dangerous permissions.",
  "test_note": "gcloud iam roles describe; Prowler -p gcp -c iam",
  "category": "4_GCPIDENTITY",
  "platform": "gcp",
  "mitre_ref": "T1098.003"
},
"GCPIDENTITY-2": {
  "name": "Workload Identity Federation Abuse",
  "description": "Misconfigured federation allowing external identity escalation.",
  "test_note": "gcloud iam workload-identity-pools list; check oidc/aws federation bindings",
  "category": "4_GCPIDENTITY",
  "platform": "gcp",
  "custom": true
},

"GCPSTORAGE-1": {
  "name": "Sensitive Data in GCS / Secret Manager",
  "description": "Plaintext secrets or PII in buckets/Secret Manager.",
  "test_note": "gsutil ls -r gs://; gcloud secrets versions access latest --secret=NAME",
  "category": "5_GCPSTORAGE",
  "platform": "gcp",
  "mitre_ref": "T1555"
},

"GCPNETWORK-1": {
  "name": "VPC & Private Service Connect Exposure",
  "description": "Exposed endpoints or misconfigured Private Google Access.",
  "test_note": "gcloud compute instances list; gcloud compute networks subnets list",
  "category": "6_GCPNETWORK",
  "platform": "gcp",
  "mitre_ref": "T1190"
},

"GCPRUNTIME-1": {
  "name": "Cloud Run / GKE Runtime Misconfigs",
  "description": "Insecure containers, env vars leaking secrets.",
  "test_note": "gcloud run services list; kubectl get secrets --all-namespaces",
  "category": "7_GCPRUNTIME",
  "platform": "gcp",
  "custom": true
},

"GCPPERSIST-1": {
  "name": "Backdoor via Cloud Functions / Scheduler",
  "description": "Persistence through scheduled jobs or functions.",
  "test_note": "gcloud functions list; gcloud scheduler jobs list",
  "category": "8_GCPPERSISTENCE",
  "platform": "gcp",
  "mitre_ref": "T1053.007"
},

// === AWS CLOUD ===
"AWSRECON-1": {
  "name": "Account & Resource Enumeration",
  "description": "Discover accounts, regions, and enabled services.",
  "test_note": "aws sts get-caller-identity; aws ec2 describe-regions; aws organizations list-accounts",
  "category": "1_AWSRECON",
  "platform": "aws",
  "custom": true
},
"AWSRECON-2": {
  "name": "IAM & Role Recon",
  "description": "Enumerate users, roles, policies, and trust relationships.",
  "test_note": "aws iam list-users; aws iam list-roles; Prowler -p aws -c iam",
  "category": "1_AWSRECON",
  "platform": "aws",
  "mitre_ref": "T1589"
},

"AWSSTATIC-1": {
  "name": "IaC Scanning (CloudFormation/Terraform)",
  "description": "Detect insecure resources in templates.",
  "test_note": "cfn_nag; tfsec .; checkov -d .",
  "category": "2_AWSSTATIC",
  "platform": "aws",
  "custom": true
},
"AWSSTATIC-2": {
  "name": "Hardcoded Secrets in Code/Logs",
  "description": "Keys, tokens in Lambda, S3, or build artifacts.",
  "test_note": "aws secretsmanager list-secrets; trufflehog; ScoutSuite --provider aws",
  "category": "2_AWSSTATIC",
  "platform": "aws",
  "mitre_ref": "T1552.001"
},

"AWSMISCONFIG-1": {
  "name": "S3 Bucket Misconfigurations",
  "description": "Public buckets, ACLs, bucket policies allowing anonymous access.",
  "test_note": "aws s3 ls; aws s3api get-bucket-policy --bucket NAME; Prowler -p aws -c s3",
  "category": "3_AWSMISCONFIG",
  "platform": "aws",
  "mitre_ref": "T1530"
},
"AWSMISCONFIG-2": {
  "name": "Security Group & NACL Over-Permission",
  "description": "0.0.0.0/0 rules or overly broad ingress/egress.",
  "test_note": "aws ec2 describe-security-groups; aws ec2 describe-network-acls",
  "category": "3_AWSMISCONFIG",
  "platform": "aws",
  "mitre_ref": "T1190"
},

"AWSIDENTITY-1": {
  "name": "IAM Role Trust Policy Abuse",
  "description": "Overly permissive AssumeRole relationships.",
  "test_note": "aws iam list-role-policies; pacu iam__enum_roles",
  "category": "4_AWSIDENTITY",
  "platform": "aws",
  "mitre_ref": "T1098.003"
},
"AWSIDENTITY-2": {
  "name": "Federation & SSO Misconfig",
  "description": "Weak SAML/OIDC or external identity providers.",
  "test_note": "aws iam list-open-id-connect-providers",
  "category": "4_AWSIDENTITY",
  "platform": "aws",
  "custom": true
},

"AWSSTORAGE-1": {
  "name": "Sensitive Data in S3 / Secrets Manager",
  "description": "Unencrypted or publicly accessible data.",
  "test_note": "aws s3api get-bucket-encryption; aws secretsmanager list-secrets",
  "category": "5_AWSSTORAGE",
  "platform": "aws",
  "mitre_ref": "T1555"
},

"AWSNETWORK-1": {
  "name": "VPC & Transit Gateway Exposure",
  "description": "Public subnets, open endpoints, or peering misconfigs.",
  "test_note": "aws ec2 describe-vpcs; aws ec2 describe-instances",
  "category": "6_AWSNETWORK",
  "platform": "aws",
  "mitre_ref": "T1190"
},

"AWSRUNTIME-1": {
  "name": "Lambda / ECS / EKS Runtime Misconfigs",
  "description": "Env vars, IAM roles attached to containers/functions.",
  "test_note": "aws lambda list-functions; aws ecs describe-clusters",
  "category": "7_AWSRUNTIME",
  "platform": "aws",
  "custom": true
},

"AWSPERSIST-1": {
  "name": "Backdoor via EventBridge / Lambda",
  "description": "Persistence through scheduled events or triggers.",
  "test_note": "aws events list-rules; aws lambda list-event-source-mappings",
  "category": "8_AWSPERSISTENCE",
  "platform": "aws",
  "mitre_ref": "T1053.007"
}

};

// Derived automatically from ATTACK_DB — do NOT edit this directly.
// To add/remove a technique: edit ATTACK_DB above.
// Display order follows ATTACK_DB insertion order.
const TECHNIQUES = (() => {
  const map = {};
  Object.entries(ATTACK_DB).forEach(([id, entry]) => {
    const platforms = Array.isArray(entry.platform) ? entry.platform : [entry.platform];
    platforms.forEach(p => {
      if (p) { if (!map[p]) map[p] = []; map[p].push(id); }
    });
  });
  return map;
})();

let currentPlatform = 'windows';
let currentFilter = 'all';
let coverage = {}; // keyed by platform name — populated dynamically from TECHNIQUES

const STATUS_LABELS = {
  "not-tested": "Not Tested",
  "in-progress": "In Progress",
  "completed": "Completed",
  "out-of-scope": "Out of Scope",
  "blocked": "Blocked"
};

const COVERAGE_KEY     = 'scopeAwareCoverage';
const PROJECT_NAME_KEY = 'attck_project_name';
const PENTESTER_KEY    = 'attck_pentester_name';
const CREDIT           = '🧙 Vibed by 0xdhanesh 🤖';

// ── Data model ─────────────────────────────────────────────────────────────
// Each entry is { status, notes }. Old string-only entries are migrated on read.

function getEntry(id) {
  const raw = coverage[currentPlatform][id];
  if (!raw) return { status: 'not-tested', notes: '' };
  if (typeof raw === 'string') return { status: raw, notes: '' }; // backward compat
  return { status: raw.status || 'not-tested', notes: raw.notes || '' };
}

function setEntry(id, patch) {
  coverage[currentPlatform][id] = { ...getEntry(id), ...patch };
  saveCoverage();
}

function loadCoverage() {
  try {
    const saved = localStorage.getItem(COVERAGE_KEY);
    if (saved) coverage = JSON.parse(saved);
  } catch (_) {}
  // Ensure every platform in ATTACK_DB has a coverage bucket.
  Object.keys(TECHNIQUES).forEach(p => {
    if (!coverage[p]) coverage[p] = {};
  });
}

// ── Platform select (auto-populated from unique platform values in ATTACK_DB) ──

function populatePlatformSelect() {
  const select = document.getElementById('platform-select');
  while (select.firstChild) select.removeChild(select.firstChild);
  Object.keys(TECHNIQUES).forEach(platform => {
    const opt = document.createElement('option');
    opt.value = platform;
    opt.textContent = platform.charAt(0).toUpperCase() + platform.slice(1);
    if (platform === currentPlatform) opt.selected = true;
    select.appendChild(opt);
  });
}

function saveCoverage() {
  localStorage.setItem(COVERAGE_KEY, JSON.stringify(coverage));
}

// ── Project name ───────────────────────────────────────────────────────────

function getProjectName() {
  return localStorage.getItem(PROJECT_NAME_KEY) || 'ATT&CK Scope Navigator';
}

function saveProjectName(name) {
  const trimmed = name.trim();
  localStorage.setItem(PROJECT_NAME_KEY, trimmed || 'ATT&CK Scope Navigator');
}

function initProjectName() {
  const input = document.getElementById('project-name-input');
  input.value = getProjectName();
  input.addEventListener('focus', () => { input.select(); });
  input.addEventListener('blur', () => {
    if (!input.value.trim()) input.value = 'ATT&CK Scope Navigator';
    saveProjectName(input.value);
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') input.blur();
    if (e.key === 'Escape') { input.value = getProjectName(); input.blur(); }
  });
}

// ── Pentester name ──────────────────────────────────────────────────────────

function getPentesterName() {
  return localStorage.getItem(PENTESTER_KEY) || '';
}

function savePentesterName(name) {
  localStorage.setItem(PENTESTER_KEY, name.trim());
}

function initPentesterName() {
  const input = document.getElementById('pentester-input');
  input.value = getPentesterName();
  input.addEventListener('focus', () => { input.select(); });
  input.addEventListener('blur', () => { savePentesterName(input.value); });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') input.blur();
    if (e.key === 'Escape') { input.value = getPentesterName(); input.blur(); }
  });
}

// ── Card HTML ──────────────────────────────────────────────────────────────

function getCardHTML(id) {
  const tech = ATTACK_DB[id];
  const { status, notes } = getEntry(id);
  const hasNotes = notes.length > 0;

  // Category chip
  const categoryHtml = tech.category
    ? `<span class="category-tag">${esc(tech.category)}</span>`
    : '';

  // Sub-technique reference or custom badge
  let refHtml = '';
  if (tech.custom) {
    refHtml = `<span class="custom-tag">Custom · Non-MITRE</span>`;
  } else if (tech.mitre_ref) {
    refHtml = `<span class="mitre-ref-tag">↗ ${esc(tech.mitre_ref)}</span>`;
  }

  return `
    <div class="technique-card status-${status}" data-id="${esc(id)}">
      <div class="card-header">
        <span class="technique-id">${esc(id)}</span>
        ${categoryHtml}
        <span class="status-badge badge-${status}">${STATUS_LABELS[status]}</span>
      </div>
      <div class="technique-name">${esc(tech.name)}</div>
      ${refHtml}
      <div class="technique-desc">${esc(tech.description)}</div>
      <div class="test-note">${esc(tech.test_note)}</div>
      <div class="card-footer">
        <button class="status-btn" data-status="not-tested">Not Tested</button>
        <button class="status-btn" data-status="in-progress">In Progress</button>
        <button class="status-btn" data-status="completed">Completed</button>
        <button class="status-btn" data-status="out-of-scope">OOS</button>
        <button class="status-btn" data-status="blocked">Blocked</button>
      </div>
      <button class="notes-toggle" data-id="${esc(id)}">${hasNotes ? 'Hide notes' : 'Add notes'}</button>
      <textarea class="notes-area" data-id="${esc(id)}" placeholder="Test notes, evidence, tool output…" maxlength="2000"${hasNotes ? '' : ' hidden'}></textarea>
    </div>`;
}

// ── Stats & progress ───────────────────────────────────────────────────────

function updateStatsAndProgress() {
  const techIds = TECHNIQUES[currentPlatform];
  const counts = { "not-tested": 0, "in-progress": 0, "completed": 0, "out-of-scope": 0, "blocked": 0 };
  techIds.forEach(id => { counts[getEntry(id).status]++; });

  Object.keys(counts).forEach(key => {
    const el = document.getElementById(`cnt-${key}`);
    if (el) el.textContent = counts[key];
  });

  const total = techIds.length;
  const pct = Math.round((counts.completed / total) * 100) || 0;
  document.getElementById('progress-pct').textContent = `${pct}%`;
  document.querySelector('.seg-completed').style.width    = `${(counts.completed / total) * 100}%`;
  document.querySelector('.seg-in-progress').style.width  = `${(counts["in-progress"] / total) * 100}%`;
  document.querySelector('.seg-blocked').style.width      = `${(counts.blocked / total) * 100}%`;
  document.querySelector('.seg-out-of-scope').style.width = `${(counts["out-of-scope"] / total) * 100}%`;
}

// ── Grid render ────────────────────────────────────────────────────────────

function renderGrid() {
  const grid = document.getElementById('technique-grid');
  grid.innerHTML = '';
  const techIds = TECHNIQUES[currentPlatform];
  const filteredIds = techIds.filter(id => {
    const { status } = getEntry(id);
    return currentFilter === 'all' || status === currentFilter;
  });

  if (filteredIds.length === 0) {
    grid.innerHTML = `<div class="empty-state"><h3>No techniques match filter</h3><p>Try another filter or reset.</p></div>`;
    updateStatsAndProgress();
    return;
  }

  // Group by category if any technique in this platform has one
  const hasCategories = filteredIds.some(id => ATTACK_DB[id].category);

  if (hasCategories) {
    // Build ordered category → ids map preserving TECHNIQUES order
    const grouped = new Map();
    filteredIds.forEach(id => {
      const cat = ATTACK_DB[id].category || 'Uncategorised';
      if (!grouped.has(cat)) grouped.set(cat, []);
      grouped.get(cat).push(id);
    });
    grouped.forEach((ids, cat) => {
      // Category section header (spans full grid width)
      grid.innerHTML += `<div class="category-header"><span>${esc(cat)}</span><span class="category-count">${ids.length}</span></div>`;
      ids.forEach(id => { grid.innerHTML += getCardHTML(id); });
    });
  } else {
    filteredIds.forEach(id => { grid.innerHTML += getCardHTML(id); });
  }

  // Set textarea values safely after DOM insertion (never via innerHTML)
  grid.querySelectorAll('.notes-area').forEach(ta => {
    ta.value = getEntry(ta.dataset.id).notes;
  });

  // Status button listeners
  grid.querySelectorAll('.status-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopImmediatePropagation();
      const id = btn.closest('.technique-card').dataset.id;
      setEntry(id, { status: btn.dataset.status });
      renderGrid();
      updateStatsAndProgress();
    });
  });

  // Notes toggle listeners
  grid.querySelectorAll('.notes-toggle').forEach(toggle => {
    const id = toggle.dataset.id;
    const ta = grid.querySelector(`.notes-area[data-id="${id}"]`);
    toggle.addEventListener('click', () => {
      ta.hidden = !ta.hidden;
      toggle.textContent = ta.hidden ? 'Add notes' : 'Hide notes';
      if (!ta.hidden) ta.focus();
    });
  });

  // Notes save on input
  grid.querySelectorAll('.notes-area').forEach(ta => {
    ta.addEventListener('input', () => {
      setEntry(ta.dataset.id, { notes: ta.value });
      const toggle = grid.querySelector(`.notes-toggle[data-id="${ta.dataset.id}"]`);
      if (toggle) toggle.textContent = ta.value.length > 0 ? 'Hide notes' : 'Add notes';
    });
  });

  updateStatsAndProgress();
}

// ── Platform & filter ──────────────────────────────────────────────────────

function switchPlatform(platform) {
  currentPlatform = platform;
  currentFilter = 'all';
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.filter === 'all'));
  renderGrid();
}

function setFilter(filter) {
  currentFilter = filter;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.filter === filter));
  renderGrid();
}

// ── Helpers ────────────────────────────────────────────────────────────────

const FONT_UI  = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif";
const FONT_MONO = "'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, 'Courier New', monospace";

function getMitreUrl(id) {
  const entry = ATTACK_DB[id];
  // Custom entries have no MITRE page
  if (entry && entry.custom) return null;
  // Sub-technique variants (e.g. T1574.001-PDH) → link to parent MITRE technique
  const ref = (entry && entry.mitre_ref) ? entry.mitre_ref : id;
  // Non-T-prefixed custom IDs have no MITRE page
  if (!ref.match(/^T\d/)) return null;
  const dotIdx = ref.indexOf('.');
  if (dotIdx !== -1) {
    const base = ref.slice(0, dotIdx);
    const sub  = ref.slice(dotIdx + 1).replace(/[^0-9]/g, ''); // strip variant suffix
    return `https://attack.mitre.org/techniques/${base}/${sub}/`;
  }
  return `https://attack.mitre.org/techniques/${ref}/`;
}

function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ── SVG export ─────────────────────────────────────────────────────────────

function exportToSVG() {
  const projectName = getProjectName();
  const svgNS = "http://www.w3.org/2000/svg";
  // Pre-calculate canvas dimensions so bg rect and svg get correct height upfront
  const techIds = TECHNIQUES[currentPlatform];
  const cols = 4; const cardW = 290; const cardH = 152; const gap = 20;
  const startX = 40; const startY = 96;
  const rows = Math.ceil(techIds.length / cols);
  const canvasH = startY + rows * (cardH + gap) - gap + 44 + 30;

  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("width", "1320");
  svg.setAttribute("height", String(canvasH));
  svg.setAttribute("viewBox", `0 0 1320 ${canvasH}`);
  svg.setAttribute("xmlns", svgNS);

  // Background
  const bg = document.createElementNS(svgNS, "rect");
  bg.setAttribute("width", "1320"); bg.setAttribute("height", String(canvasH)); bg.setAttribute("fill", "#0d1117");
  svg.appendChild(bg);

  // Header bar
  const headerBar = document.createElementNS(svgNS, "rect");
  headerBar.setAttribute("x", "0"); headerBar.setAttribute("y", "0");
  headerBar.setAttribute("width", "1320"); headerBar.setAttribute("height", "72");
  headerBar.setAttribute("fill", "#161b22");
  svg.appendChild(headerBar);

  // Header bottom border
  const headerBorder = document.createElementNS(svgNS, "line");
  headerBorder.setAttribute("x1", "0"); headerBorder.setAttribute("y1", "72");
  headerBorder.setAttribute("x2", "1320"); headerBorder.setAttribute("y2", "72");
  headerBorder.setAttribute("stroke", "#30363d"); headerBorder.setAttribute("stroke-width", "1");
  svg.appendChild(headerBorder);

  // Project title
  const title = document.createElementNS(svgNS, "text");
  title.setAttribute("x", "40"); title.setAttribute("y", "44");
  title.setAttribute("fill", "#e6edf3");
  title.setAttribute("font-size", "22");
  title.setAttribute("font-family", FONT_UI);
  title.setAttribute("font-weight", "700");
  title.setAttribute("letter-spacing", "-0.3");
  title.textContent = projectName;
  svg.appendChild(title);

  // Platform pill — dynamic width and right-aligned
  const pillLabel = currentPlatform.toUpperCase();
  const pillW = Math.max(64, pillLabel.length * 8 + 24);
  const pillX = 1320 - pillW - 40;
  const pill = document.createElementNS(svgNS, "rect");
  pill.setAttribute("x", String(pillX)); pill.setAttribute("y", "24");
  pill.setAttribute("width", String(pillW)); pill.setAttribute("height", "24");
  pill.setAttribute("rx", "12"); pill.setAttribute("fill", "rgba(56,139,253,0.15)");
  pill.setAttribute("stroke", "#388bfd"); pill.setAttribute("stroke-width", "1");
  svg.appendChild(pill);

  const pillText = document.createElementNS(svgNS, "text");
  pillText.setAttribute("x", String(pillX + pillW / 2)); pillText.setAttribute("y", "40");
  pillText.setAttribute("fill", "#79c0ff");
  pillText.setAttribute("font-size", "11");
  pillText.setAttribute("font-family", FONT_UI);
  pillText.setAttribute("font-weight", "600");
  pillText.setAttribute("text-anchor", "middle");
  pillText.setAttribute("letter-spacing", "0.8");
  pillText.textContent = pillLabel;
  svg.appendChild(pillText);

  // Cards

  const STATUS_COLORS = {
    "completed":    { stroke: "#238636", text: "#3fb950", bg: "#0d2010" },
    "in-progress":  { stroke: "#388bfd", text: "#79c0ff", bg: "#0d1a2e" },
    "blocked":      { stroke: "#8957e5", text: "#d2a8ff", bg: "#170e28" },
    "out-of-scope": { stroke: "#6e402a", text: "#f0883e", bg: "#1a0f08" },
    "not-tested":   { stroke: "#30363d", text: "#7d8590", bg: "#161b22" },
  };

  techIds.forEach((id, i) => {
    const tech = ATTACK_DB[id];
    const { status } = getEntry(id);
    const col = i % cols; const row = Math.floor(i / cols);
    const x = startX + col * (cardW + gap);
    const y = startY + row * (cardH + gap);
    const sc = STATUS_COLORS[status] || STATUS_COLORS["not-tested"];

    // Card background
    const card = document.createElementNS(svgNS, "rect");
    card.setAttribute("x", x); card.setAttribute("y", y);
    card.setAttribute("width", cardW); card.setAttribute("height", cardH);
    card.setAttribute("rx", "8"); card.setAttribute("fill", sc.bg);
    card.setAttribute("stroke", sc.stroke); card.setAttribute("stroke-width", "1.5");
    svg.appendChild(card);

    // Left accent bar
    const accent = document.createElementNS(svgNS, "rect");
    accent.setAttribute("x", x); accent.setAttribute("y", y);
    accent.setAttribute("width", "4"); accent.setAttribute("height", cardH);
    accent.setAttribute("rx", "8"); accent.setAttribute("fill", sc.stroke);
    svg.appendChild(accent);

    // Technique ID
    const idText = document.createElementNS(svgNS, "text");
    idText.setAttribute("x", x + 18); idText.setAttribute("y", y + 28);
    idText.setAttribute("fill", "#388bfd");
    idText.setAttribute("font-size", "11");
    idText.setAttribute("font-family", FONT_MONO);
    idText.setAttribute("font-weight", "600");
    idText.setAttribute("letter-spacing", "0.5");
    idText.textContent = id;
    svg.appendChild(idText);

    // Status badge (right-aligned)
    const statusLabel = STATUS_LABELS[status].toUpperCase();
    const statusX = x + cardW - 14;
    const statusText = document.createElementNS(svgNS, "text");
    statusText.setAttribute("x", statusX); statusText.setAttribute("y", y + 28);
    statusText.setAttribute("fill", sc.text);
    statusText.setAttribute("font-size", "9");
    statusText.setAttribute("font-family", FONT_UI);
    statusText.setAttribute("font-weight", "700");
    statusText.setAttribute("text-anchor", "end");
    statusText.setAttribute("letter-spacing", "0.8");
    statusText.textContent = statusLabel;
    svg.appendChild(statusText);

    // Divider
    const divider = document.createElementNS(svgNS, "line");
    divider.setAttribute("x1", x + 14); divider.setAttribute("y1", y + 38);
    divider.setAttribute("x2", x + cardW - 14); divider.setAttribute("y2", y + 38);
    divider.setAttribute("stroke", sc.stroke); divider.setAttribute("stroke-width", "0.5"); divider.setAttribute("opacity", "0.5");
    svg.appendChild(divider);

    // Technique name
    const maxChars = 32;
    const displayName = tech.name.length > maxChars ? tech.name.slice(0, maxChars - 1) + '…' : tech.name;
    const nameText = document.createElementNS(svgNS, "text");
    nameText.setAttribute("x", x + 18); nameText.setAttribute("y", y + 62);
    nameText.setAttribute("fill", "#e6edf3");
    nameText.setAttribute("font-size", "13");
    nameText.setAttribute("font-family", FONT_UI);
    nameText.setAttribute("font-weight", "600");
    nameText.textContent = displayName;
    svg.appendChild(nameText);

    // Description (truncated)
    const descMaxChars = 40;
    const displayDesc = tech.description.length > descMaxChars ? tech.description.slice(0, descMaxChars - 1) + '…' : tech.description;
    const descText = document.createElementNS(svgNS, "text");
    descText.setAttribute("x", x + 18); descText.setAttribute("y", y + 84);
    descText.setAttribute("fill", "#7d8590");
    descText.setAttribute("font-size", "10");
    descText.setAttribute("font-family", FONT_UI);
    descText.textContent = displayDesc;
    svg.appendChild(descText);

    // MITRE link / custom label
    const mitreUrl = getMitreUrl(id);
    const linkText = document.createElementNS(svgNS, "text");
    linkText.setAttribute("x", x + 18); linkText.setAttribute("y", y + 112);
    linkText.setAttribute("font-size", "9");
    linkText.setAttribute("font-family", FONT_MONO);
    linkText.setAttribute("opacity", "0.7");
    if (mitreUrl) {
      linkText.setAttribute("fill", "#388bfd");
      linkText.textContent = mitreUrl.replace('https://', '');
    } else if (ATTACK_DB[id].mitre_ref) {
      linkText.setAttribute("fill", "#79c0ff");
      linkText.textContent = `↗ Variant of ${ATTACK_DB[id].mitre_ref}`;
    } else {
      linkText.setAttribute("fill", "#f0883e");
      linkText.textContent = 'Custom · Non-MITRE';
    }
    svg.appendChild(linkText);

    // Notes line (truncated) — only rendered if notes exist
    const { notes } = getEntry(id);
    if (notes) {
      const noteDivider = document.createElementNS(svgNS, "line");
      noteDivider.setAttribute("x1", x + 14); noteDivider.setAttribute("y1", y + 120);
      noteDivider.setAttribute("x2", x + cardW - 14); noteDivider.setAttribute("y2", y + 120);
      noteDivider.setAttribute("stroke", sc.stroke); noteDivider.setAttribute("stroke-width", "0.5"); noteDivider.setAttribute("opacity", "0.3");
      svg.appendChild(noteDivider);

      const maxNoteChars = 48;
      const noteDisplay = notes.length > maxNoteChars ? notes.slice(0, maxNoteChars - 1) + '…' : notes;
      const noteText = document.createElementNS(svgNS, "text");
      noteText.setAttribute("x", x + 18); noteText.setAttribute("y", y + 136);
      noteText.setAttribute("fill", "#7d8590");
      noteText.setAttribute("font-size", "9");
      noteText.setAttribute("font-family", FONT_UI);
      noteText.setAttribute("font-style", "italic");
      noteText.textContent = noteDisplay;
      svg.appendChild(noteText);
    }
  });

  // Watermark bar at bottom — positioned dynamically
  const wBarY = canvasH - 30;
  const wBar = document.createElementNS(svgNS, "rect");
  wBar.setAttribute("x", "0"); wBar.setAttribute("y", String(wBarY));
  wBar.setAttribute("width", "1320"); wBar.setAttribute("height", "30");
  wBar.setAttribute("fill", "#161b22");
  svg.appendChild(wBar);

  const wText = document.createElementNS(svgNS, "text");
  wText.setAttribute("x", "660"); wText.setAttribute("y", String(wBarY + 20));
  wText.setAttribute("fill", "#484f58");
  wText.setAttribute("font-size", "11");
  wText.setAttribute("font-family", FONT_UI);
  wText.setAttribute("font-weight", "500");
  wText.setAttribute("text-anchor", "middle");
  wText.setAttribute("letter-spacing", "0.5");
  wText.textContent = CREDIT;
  svg.appendChild(wText);

  const svgString = new XMLSerializer().serializeToString(svg);
  const blob = new Blob([svgString], { type: "image/svg+xml" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `scope-navigator-${currentPlatform}.svg`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast("SVG exported");
}

// ── PDF export ─────────────────────────────────────────────────────────────

function exportToPDF() {
  const techIds       = TECHNIQUES[currentPlatform];
  const counts        = { "not-tested": 0, "in-progress": 0, "completed": 0, "out-of-scope": 0, "blocked": 0 };
  techIds.forEach(id => { counts[getEntry(id).status]++; });

  const projectName   = getProjectName();
  const pentester     = getPentesterName();
  const platformLabel = currentPlatform.charAt(0).toUpperCase() + currentPlatform.slice(1);
  const dateStr       = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
  const covered       = techIds.filter(id => getEntry(id).status !== 'not-tested').length;

  const BADGE = {
    "completed":    "background:#dcfce7;color:#166534;border:1px solid #bbf7d0",
    "in-progress":  "background:#dbeafe;color:#1e40af;border:1px solid #bfdbfe",
    "blocked":      "background:#f3e8ff;color:#6b21a8;border:1px solid #e9d5ff",
    "out-of-scope": "background:#ffedd5;color:#9a3412;border:1px solid #fed7aa",
    "not-tested":   "background:#f3f4f6;color:#4b5563;border:1px solid #e5e7eb",
  };

  const techniqueRows = techIds.map(id => {
    const { status, notes } = getEntry(id);
    const noteRow = notes
      ? `<tr><td colspan="4" style="padding:3px 10px 9px 24px;border-bottom:1px solid #f3f4f6;font-size:11px;color:#6b7280;font-style:italic;line-height:1.5">
           <span style="font-weight:700;font-style:normal;color:#374151">Notes:</span> ${esc(notes)}
         </td></tr>`
      : '';
    return `<tr>
      <td style="font-family:monospace;font-size:11px;color:#1d4ed8;white-space:nowrap">${esc(id)}</td>
      <td style="font-weight:600">${esc(ATTACK_DB[id].name)}</td>
      <td style="white-space:nowrap">
        <span style="display:inline-block;padding:2px 9px;border-radius:10px;font-size:10px;font-weight:700;letter-spacing:0.4px;${BADGE[status]}">${esc(STATUS_LABELS[status])}</span>
      </td>
      <td style="font-family:monospace;font-size:10px">${(() => {
        const u = getMitreUrl(id);
        const entry = ATTACK_DB[id];
        if (u) return `<a href="${esc(u)}" style="color:#1d4ed8;text-decoration:none">${esc(u)}</a>`;
        if (entry.mitre_ref) {
          const pu = getMitreUrl(entry.mitre_ref);
          return pu
            ? `<span style="color:#6b7280">Variant of </span><a href="${esc(pu)}" style="color:#1d4ed8;text-decoration:none">${esc(entry.mitre_ref)}</a>`
            : `<span style="color:#6b7280">Variant of ${esc(entry.mitre_ref)}</span>`;
        }
        return `<span style="color:#9a3412;font-weight:600">Custom · Non-MITRE</span>`;
      })()}</td>
    </tr>${noteRow}`;
  }).join('');

  // Open a fresh window — zero CSS conflict with the dark app theme
  const w = window.open('', '_blank', 'width=900,height=700');
  if (!w) { showToast('Pop-up blocked — allow pop-ups and try again.'); return; }

  w.document.write(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>${esc(projectName)} — ATT&amp;CK Report</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    @page { margin: 18mm 16mm; size: A4 portrait; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
      font-size: 13px; color: #111; background: #fff;
    }
    /* ── Page break ── */
    .pdf-page { padding-bottom: 32px; page-break-after: always; }
    .pdf-page:last-child { page-break-after: avoid; }
    /* ── Header ── */
    .hdr {
      display: flex; justify-content: space-between; align-items: flex-end;
      border-bottom: 3px solid #1d4ed8; padding-bottom: 12px; margin-bottom: 28px;
    }
    .hdr-title { font-size: 22px; font-weight: 800; color: #0f172a; letter-spacing: -0.4px; }
    .hdr-meta  { font-size: 11px; color: #6b7280; text-align: right; line-height: 1.8; }
    /* ── Eyebrow label ── */
    .eyebrow {
      font-size: 10px; font-weight: 700; letter-spacing: 1.5px;
      text-transform: uppercase; color: #9ca3af; margin-bottom: 14px;
    }
    /* ── Stat grid ── */
    .stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 32px; }
    .stat-box  { border-radius: 8px; padding: 18px 20px; border: 1px solid #e5e7eb; background: #f9fafb; }
    .stat-box.blue   { border-color: #93c5fd; background: #eff6ff; }
    .stat-box.green  { border-color: #86efac; background: #f0fdf4; }
    .stat-box.purple { border-color: #d8b4fe; background: #faf5ff; }
    .stat-box.amber  { border-color: #fcd34d; background: #fffbeb; }
    .stat-lbl { font-size: 10px; font-weight: 700; letter-spacing: 0.6px; text-transform: uppercase; color: #6b7280; margin-bottom: 6px; }
    .stat-val { font-size: 40px; font-weight: 900; line-height: 1; color: #0f172a; }
    .stat-box.blue   .stat-val { color: #1d4ed8; }
    .stat-box.green  .stat-val { color: #16a34a; }
    .stat-box.purple .stat-val { color: #7c3aed; }
    .stat-box.amber  .stat-val { color: #d97706; }
    .stat-sub { font-size: 12px; color: #9ca3af; margin-top: 4px; }
    /* ── Detail table ── */
    .dtable { width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 8px; }
    .dtable td { padding: 9px 0; border-bottom: 1px solid #f3f4f6; }
    .dtable td:first-child { color: #6b7280; font-weight: 600; width: 180px; }
    /* ── Technique table ── */
    .ttable { width: 100%; border-collapse: collapse; font-size: 12px; }
    .ttable th {
      padding: 9px 10px; text-align: left; font-size: 10px; font-weight: 700;
      letter-spacing: 0.8px; text-transform: uppercase; color: #6b7280;
      background: #f8fafc;
      border-top: 2px solid #e5e7eb; border-bottom: 2px solid #e5e7eb;
    }
    .ttable td { padding: 8px 10px; border-bottom: 1px solid #f3f4f6; vertical-align: middle; }
    .ttable tr:nth-child(even) td { background: #fafafa; }
    .pdf-footer {
      margin-top: 40px; padding-top: 10px; border-top: 1px solid #e5e7eb;
      text-align: center; font-size: 10px; color: #9ca3af; letter-spacing: 0.3px;
    }
    @media print {
      .stat-box.blue   { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .stat-box.green  { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .stat-box.purple { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .stat-box.amber  { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .ttable tr:nth-child(even) td { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    }
  </style>
</head>
<body>

  <!-- PAGE 1: SUMMARY -->
  <div class="pdf-page">
    <div class="hdr">
      <div class="hdr-title">${esc(projectName)}</div>
      <div class="hdr-meta">Platform: <strong>${esc(platformLabel)}</strong><br>Report Date: ${esc(dateStr)}</div>
    </div>

    <div class="eyebrow">Assessment Overview</div>
    <div class="stat-grid">
      <div class="stat-box blue">
        <div class="stat-lbl">Covered Tests</div>
        <div class="stat-val">${covered}</div>
        <div class="stat-sub">out of ${techIds.length} total</div>
      </div>
      <div class="stat-box green">
        <div class="stat-lbl">Completed</div>
        <div class="stat-val">${counts['completed']}</div>
        <div class="stat-sub">fully tested</div>
      </div>
      <div class="stat-box purple">
        <div class="stat-lbl">Blocked</div>
        <div class="stat-val">${counts['blocked']}</div>
        <div class="stat-sub">could not be tested</div>
      </div>
      <div class="stat-box amber">
        <div class="stat-lbl">In Progress</div>
        <div class="stat-val">${counts['in-progress']}</div>
        <div class="stat-sub">testing underway</div>
      </div>
    </div>

    <div class="eyebrow">Details</div>
    <table class="dtable">
      <tr><td>Target</td><td>${esc(projectName)}</td></tr>
      <tr><td>Pentester</td><td>${pentester ? esc(pentester) : '<span style="color:#9ca3af">—</span>'}</td></tr>
      <tr><td>Platform</td><td>${esc(platformLabel)}</td></tr>
      <tr><td>Total Techniques</td><td>${techIds.length}</td></tr>
      <tr><td>Not Tested</td><td>${counts['not-tested']}</td></tr>
      <tr><td>Out of Scope</td><td>${counts['out-of-scope']}</td></tr>
      <tr><td>Report Date</td><td>${esc(dateStr)}</td></tr>
    </table>
    <div class="pdf-footer">${esc(CREDIT)}</div>
  </div>

  <!-- PAGE 2: MITRE ATT&CK TECHNIQUES -->
  <div class="pdf-page">
    <div class="hdr">
      <div class="hdr-title">MITRE ATT&amp;CK Technique Coverage</div>
      <div class="hdr-meta">Platform: <strong>${esc(platformLabel)}</strong><br>Report Date: ${esc(dateStr)}</div>
    </div>

    <div class="eyebrow">Technique Reference</div>
    <table class="ttable">
      <thead>
        <tr>
          <th style="width:95px">ID</th>
          <th>Technique</th>
          <th style="width:105px">Status</th>
          <th>ATT&amp;CK Reference</th>
        </tr>
      </thead>
      <tbody>${techniqueRows}</tbody>
    </table>
    <div class="pdf-footer">${esc(CREDIT)}</div>
  </div>

  <script>
    window.onload = function() { window.print(); };
  <\/script>
</body>
</html>`);
  w.document.close();
}

// ── Toast ──────────────────────────────────────────────────────────────────

function showToast(msg) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2200);
}

// ── Bootstrap ──────────────────────────────────────────────────────────────

window.onload = () => {
  loadCoverage();
  initProjectName();
  initPentesterName();
  populatePlatformSelect();

  // Platform dropdown
  const platformSelect = document.getElementById('platform-select');
  platformSelect.addEventListener('change', () => switchPlatform(platformSelect.value));

  // Filter pills
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => setFilter(btn.dataset.filter));
  });

  // Export buttons
  document.getElementById('btn-export-svg').addEventListener('click', exportToSVG);
  document.getElementById('btn-export-pdf').addEventListener('click', exportToPDF);

  // Reset button
  document.getElementById('btn-reset').addEventListener('click', () => {
    if (confirm('Reset all statuses and notes for current platform?')) {
      coverage[currentPlatform] = {};
      saveCoverage();
      renderGrid();
      showToast("Platform reset");
    }
  });

  renderGrid();
};
