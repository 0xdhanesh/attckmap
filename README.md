# ATT&CK Scope Navigator

A 100% static, GitHub Pages-ready web app for tracking MITRE ATT&CK technique coverage during thick-client penetration tests. No backend, no CDN dependencies — all state lives in `localStorage`.

---

## Adding Techniques

`ATTACK_DB` in `app.js` is the **single source of truth**. Add one entry there and it appears in the grid, stats bar, filters, SVG export, and PDF export automatically — no other file needs to change.

### Entry format

```js
"YOUR-ID": {
  name:        "Short display name",         // required
  description: "One-sentence description.",  // required
  test_note:   "Tool / command hint.",       // required — shown on the card
  platform:    "windows",                   // required — controls which tab shows this
  category:    "Category Name",             // optional — groups cards under a section header
  mitre_ref:   "T1574.001",                 // optional — shown as "↗ Variant of T1574.001"
  custom:      true                         // optional — shows orange "Custom · Non-MITRE" badge
}
```

### ID conventions

| Type | Format | Example |
|------|--------|---------|
| Standard MITRE | `T<num>.<sub>` | `T1574.001` |
| MITRE variant / sub-test | `T<num>.<sub>-TAG` + `mitre_ref` | `T1574.001-PDH` |
| Custom / non-MITRE | `PLATFORM-CATEGORY-NNN` + `custom: true` | `WIN-MEM-001` |

### `platform` field

Accepts a string or an array for techniques that apply to multiple platforms:

```js
platform: "windows"                  // single platform
platform: ["windows", "linux"]       // appears under both tabs
```

### Example — custom non-MITRE technique

```js
"WIN-MEM-HEAP": {
  name:        "Heap Inspection",
  description: "Sensitive data left in process heap after use.",
  test_note:   "Attach WinDbg; !heap -p -a <addr>; search for creds/tokens",
  platform:    "windows",
  category:    "Memory",
  custom:      true
},
```

### Example — MITRE variant

```js
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

## Adding a New Platform

Add entries to `ATTACK_DB` with `platform: "yourplatform"`. That's it. The dropdown, localStorage bucket, stats bar, progress bar, filter pills, SVG export, and PDF export all provision themselves automatically.

```js
"MOB-CUSTOM-001": {
  name:        "Insecure Data Storage",
  description: "App stores sensitive data in plaintext on device storage.",
  test_note:   "Pull /data/data/<pkg>/shared_prefs; grep for credentials",
  platform:    "mobile",
  category:    "Data Exposure",
  custom:      true
},
```

Reload the page — "Mobile" appears in the platform dropdown.

---

## Display order

Techniques appear in the grid in the same order they are defined in `ATTACK_DB`. To reorder, move entries up or down in the object.

---

## File reference

| File | Purpose |
|------|---------|
| `app.js` | All technique data (`ATTACK_DB`) and application logic |
| `index.html` | App shell — no technique data here |
| `styles.css` | Visual theme — edit only for styling changes |
| `data/attack.json` | Legacy reference only — not loaded by the app |

---

*🧙 Vibed by **0xdhanesh** 🤖*
