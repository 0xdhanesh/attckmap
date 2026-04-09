# 🎯 ATT&CK Scope Navigator

**A guided pentest methodology tracker mapped to MITRE ATT&CK. 17 platforms. 200+ techniques. Zero backend.**

An open-source, fully client-side web app for tracking penetration test coverage across multiple security domains. Every technique card tells you what to test, which tool to run, and lets you track progress from recon to exploitation.

What [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) did for threat intelligence visibility, this does for pentest execution.

🔗 **Live Tool:** [https://0xdhanesh.github.io/attckmap/](https://0xdhanesh.github.io/attckmap/)

---

## 🔥 Why This Exists

Every pentest engagement has the same problems:

- Spreadsheets go stale by day two
- New testers join with zero context on what's been covered
- Team members duplicate work or miss entire attack paths
- Report day arrives and nobody's sure if everything was tested

ATT&CK Scope Navigator gives every pentester (junior or senior) a structured, visual path through an engagement with built-in methodology guidance.

---

## 🛡️ Platforms Covered

| Domain | Platforms | Techniques |
|--------|-----------|------------|
| 🖥️ Thick Client | Windows, Linux | Recon → IPC, memory, code injection, DLL hijacking, and more |
| 📱 Mobile | Android, iOS | Recon → data storage, IPC, network, binary analysis |
| ☁️ Cloud | AWS, Azure, GCP | Recon → IAM, storage, compute, lateral movement |
| ⚙️ ICS/OT | OPC-UA, MQTT, Modbus, EtherNet/IP, Profinet, Hardware | Recon → protocol abuse, firmware, fieldbus attacks |
| 🤖 AI/ML | AI Security | Recon → model extraction, prompt injection, training data poisoning |
| 🔬 Reverse Engineering | RE | Recon → static analysis, dynamic analysis, anti-reversing bypass |

> **17 platforms. 200+ techniques. All mapped from recon to exploitation.**

---

## ✨ Features

- **Guided methodology** — each technique card includes a description, tool/command hints, and test notes
- **Status tracking** — mark each technique as Not Tested, In Progress, Completed, Out of Scope, or Blocked
- **Notes per technique** — document findings as you go
- **Platform auto-provisioning** — add a new platform in `ATTACK_DB` and it appears everywhere automatically
- **Coverage dashboard** — real-time stats bar showing progress per platform
- **Filter by status** — quickly find what's left to test
- **Export to PDF & SVG** — for reporting and documentation
- **Fully client-side** — no backend, no accounts, no dependencies, works offline
- **localStorage persistence** — your progress survives browser refreshes
- **Custom techniques** — add non-MITRE test cases with the `custom: true` flag

---

## 🚀 Getting Started

**Use it instantly:** [https://0xdhanesh.github.io/attckmap/](https://0xdhanesh.github.io/attckmap/)

**Or run locally:**

```bash
git clone https://github.com/0xdhanesh/attckmap.git
cd attckmap
# Open index.html in your browser. That's it.
```

No build step. No npm install. No Docker. Just HTML, CSS, and JS.

---

## 📝 Adding Techniques

`ATTACK_DB` in `app.js` is the **single source of truth**. Add one entry and it appears in the grid, stats bar, filters, SVG export, and PDF export automatically.

### Entry Format

```javascript
"YOUR-ID": {
  name:        "Short display name",
  description: "One-sentence description.",
  test_note:   "Tool / command hint.",
  platform:    "windows",
  category:    "Category Name",
  mitre_ref:   "T1574.001",       // optional — links to MITRE technique
  custom:      true                // optional — shows non-MITRE badge
}
```

### ID Conventions

| Type | Format | Example |
|------|--------|---------|
| Standard MITRE | `T<num>.<sub>` | `T1574.001` |
| MITRE variant | `T<num>.<sub>-TAG` + `mitre_ref` | `T1574.001-PDH` |
| Custom / non-MITRE | `PLATFORM-CATEGORY-NNN` + `custom: true` | `WIN-MEM-001` |

### Multi-Platform Techniques

```javascript
platform: "windows"                  // single platform
platform: ["windows", "linux"]       // appears under both tabs
```

### Example: Custom Technique

```javascript
"WIN-MEM-HEAP": {
  name:        "Heap Inspection",
  description: "Sensitive data left in process heap after use.",
  test_note:   "Attach WinDbg; !heap -p -a <addr>; search for creds/tokens",
  platform:    "windows",
  category:    "Memory",
  custom:      true
},
```

### Example: MITRE Variant

```javascript
"T1055.001-EARLYBIRD": {
  name:        "Early Bird APC Injection",
  description: "Queue APC to a newly-spawned process before its main thread runs.",
  test_note:   "CreateProcess (suspended) → QueueUserAPC → ResumeThread",
  platform:    "windows",
  category:    "Code Injection",
  mitre_ref:   "T1055.001"
},
```

---

## 🌐 Adding a New Platform

Add entries to `ATTACK_DB` with your platform name. The dropdown, stats bar, progress bar, filters, and exports all provision themselves automatically.

```javascript
"MOB-CUSTOM-001": {
  name:        "Insecure Data Storage",
  description: "App stores sensitive data in plaintext on device storage.",
  test_note:   "Pull /data/data/<pkg>/shared_prefs; grep for credentials",
  platform:    "mobile",
  category:    "Data Exposure",
  custom:      true
},
```

Reload the page. "Mobile" appears in the platform dropdown. Done.

---

## 🗂️ File Reference

| File | Purpose |
|------|---------|
| `app.js` | All technique data (`ATTACK_DB`) and application logic |
| `index.html` | App shell |
| `styles.css` | Visual theme |
| `data/attack.json` | Legacy reference only (not loaded by the app) |

---

## 🗺️ Roadmap

- [x] Thick client coverage (Windows & Linux)
- [x] Mobile coverage (Android & iOS)
- [x] Cloud coverage (AWS, Azure, GCP)
- [x] ICS/OT coverage (OPC-UA, MQTT, Modbus, EtherNet/IP, Profinet, Hardware)
- [x] AI/ML security coverage
- [x] Reverse Engineering coverage
- [x] PDF & SVG export
- [x] Notes per technique
- [ ] 🚧 Web application pentest coverage (in progress)
- [ ] Tracker import/export for team collaboration
- [ ] GitHub Actions for automated MITRE data sync
- [ ] API & network infrastructure coverage
- [ ] Wireless pentest coverage

---

## 🤝 Contributing

**Not code. Methodology.**

If you pentest any of these domains and have test cases worth sharing, contributing is simple. Each technique is a single JS object entry in `app.js`. No framework knowledge needed.

**What makes a great contribution:**
- A technique you always test but rarely see documented
- A specific tool command that saves time on engagements
- A test case that teams commonly miss
- Coverage for platforms you specialize in (ICS, cloud, mobile, AI/ML, web)

Open a PR or an issue. Every technique you add helps the next pentester who uses this tool.

---

## 📄 License

Open source. See repository for details.

---
*🧙 Vibed by **0xdhanesh** 🤖*
