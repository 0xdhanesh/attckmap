# ATT&CK Map for Pentesters

A 100% static, GitHub Pages-ready web app for tracking MITRE ATT&CK technique coverage during thick-client penetration tests. No backend, no CDN dependencies — all state lives in `localStorage`.

---

## Adding Techniques

All technique data lives in two places inside `app.js`:

- **`ATTACK_DB`** — the technique catalogue (name, description, test notes, metadata)
- **`TECHNIQUES`** — per-platform lists of technique IDs that appear in the UI

Adding a technique is always a two-step process: add it to `ATTACK_DB`, then reference its ID in `TECHNIQUES`.

---

### Step 1 — Add the entry to `ATTACK_DB`

Open `app.js` and find the `ATTACK_DB` object. Add a new key/value pair. The key is the technique ID; the value is an object with the fields below.

```js
"YOUR-ID": {
  name:        "Short display name",         // required
  description: "One-sentence description.",  // required
  test_note:   "Tool/command hint.",         // required — shown on the card
  category:    "Category Name",             // optional — groups cards under a header
  mitre_ref:   "T1574.001",                 // optional — links this to a parent MITRE ID
  custom:      true                         // optional — marks it as non-MITRE
}
```

#### ID conventions

| Type | ID format | When to use |
|------|-----------|-------------|
| Standard MITRE technique | `T1574.001`, `T1112` | Exact match to a published MITRE technique |
| MITRE variant / sub-test | `T1574.001-PDH`, `T1574.001-RED` | A specific pentest scenario under a MITRE technique — set `mitre_ref` to the parent ID |
| Custom / non-MITRE | `WIN-CUSTOM-001`, `LNX-MEM-001` | No MITRE mapping exists — set `custom: true` |

#### `mitre_ref` vs `custom`

- `mitre_ref: "T1574.001"` — the card shows `↗ Variant of T1574.001` and links to the parent technique on attack.mitre.org
- `custom: true` — the card shows an orange **Custom · Non-MITRE** badge; no external link is generated

---

### Step 2 — Add the ID to `TECHNIQUES`

Find the `TECHNIQUES` object and append your new ID to the relevant platform array. **Order matters** — techniques appear in the grid exactly as listed here, grouped by `category`.

```js
const TECHNIQUES = {
  windows: [
    // DLL Attacks
    "T1574.001", "T1574.001-PDH", "T1574.001-RED", "T1574.001-SUB",
    "T1574.002", "WIN-DLL-UNSIGNED",
    "YOUR-NEW-ID",   // <-- append here, inside the right comment group
    // Persistence
    ...
  ],
  linux: [
    ...
    "YOUR-NEW-LINUX-ID"
  ]
};
```

That's it. Reload the page — the technique appears in the grid with the correct category header.

---

## Adding a New Platform

To add an entirely new platform (e.g. mobile, web, network):

**1.** Add all its technique entries to `ATTACK_DB` (following the same conventions above).

**2.** Add a new key to `TECHNIQUES`:

```js
const TECHNIQUES = {
  windows: [ ... ],
  linux:   [ ... ],
  mobile:  [           // <-- new platform
    "MOB-CUSTOM-001",
    "T1411",
    ...
  ]
};
```

The platform dropdown, localStorage bucket, stats bar, progress bar, filter pills, SVG export, and PDF export all provision themselves automatically — no other changes needed.

---

## Complete Examples

**Adding a Windows memory-inspection test case with no MITRE mapping:**

```js
// In ATTACK_DB — add inside the appropriate comment section:
"WIN-MEM-HEAP": {
  name:        "Heap Inspection",
  description: "Sensitive data left in process heap after use.",
  test_note:   "Attach WinDbg; !heap -p -a <addr>; search for creds/tokens",
  category:    "Memory",
  custom:      true
},

// In TECHNIQUES — append to the windows array:
windows: [
  ...existing IDs...,
  "WIN-MEM-HEAP"
]
```

**Adding a variant of an existing MITRE technique:**

```js
// In ATTACK_DB:
"T1055.001-EARLYBIRD": {
  name:        "Early Bird APC Injection",
  description: "Queue APC to a newly-spawned process before its main thread runs.",
  test_note:   "CreateProcess (suspended) → QueueUserAPC → ResumeThread",
  category:    "Code Injection",
  mitre_ref:   "T1055.001"
},

// In TECHNIQUES — windows array:
"T1055.001", "T1055.001-EARLYBIRD",
```

---

## File Reference

| File | Purpose |
|------|---------|
| `app.js` | All technique data (`ATTACK_DB`, `TECHNIQUES`) and application logic |
| `index.html` | App shell — no technique data here |
| `styles.css` | Visual theme — edit only for styling changes |
| `data/attack.json` | Legacy reference only — not loaded by the app |

---

*🚀 Vibed by **0xdhanesh** *
