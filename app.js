// app.js — Scope-Aware ATT&CK Navigator
//
// EXTENDING THIS TEMPLATE
// ──────────────────────────────────────────────────────────────────────────
// Each entry in ATTACK_DB accepts these fields:
//   name        {string}  Display name
//   description {string}  Short description
//   test_note   {string}  Pentest procedure / tool hint
//   category    {string}  Optional grouping label (e.g. "DLL Attacks", "Recon")
//   mitre_ref   {string}  Optional — parent MITRE ID for sub-techniques/variants
//   custom      {bool}    true = not in MITRE ATT&CK at all
//
// ID conventions:
//   Standard MITRE  →  T1574.001, T1112  (links auto-generated)
//   MITRE variant   →  T1574.001-PDH     (set mitre_ref to link to parent)
//   Custom/Non-MITRE→  WIN-CUSTOM-001    (set custom:true, no MITRE link)
//
// To add a new platform: add its techniques to TECHNIQUES below — everything
// else (dropdown, storage, exports, filters, stats) auto-provisions itself.
// ──────────────────────────────────────────────────────────────────────────

const ATTACK_DB = {

  // ── DLL Attacks (Windows) ────────────────────────────────────────────────
  "T1574.001": {
    name: "DLL Search Order Hijacking",
    description: "Adversaries may hijack DLL search order to load malicious DLLs.",
    test_note: "ProcMon filter: NAME NOT FOUND on .dll in app dir; drop payload",
    category: "DLL Attacks"
  },
  "T1574.001-PDH": {
    name: "Phantom DLL Hijacking",
    description: "App references a DLL that doesn't exist; attacker drops it into a searched path.",
    test_note: "ProcMon: filter Result=NAME NOT FOUND + Path ends in .dll; plant payload DLL",
    category: "DLL Attacks",
    mitre_ref: "T1574.001"
  },
  "T1574.001-RED": {
    name: "DLL Redirection",
    description: "Redirect DLL resolution via .manifest file or DllRedirection registry key.",
    test_note: "Create <app>.exe.manifest with redirect entry; verify via ProcMon load path",
    category: "DLL Attacks",
    mitre_ref: "T1574.001"
  },
  "T1574.001-SUB": {
    name: "DLL Substitution",
    description: "Replace a legitimately-loaded DLL in a user-writable directory with a malicious proxy.",
    test_note: "Identify DLLs loaded from writable dirs (icacls); overwrite with proxy DLL + original export forwarding",
    category: "DLL Attacks",
    mitre_ref: "T1574.001"
  },
  "T1574.002": {
    name: "DLL Side-Loading",
    description: "Load malicious DLL by placing it alongside a legitimate signed EXE that imports it.",
    test_note: "Find EXEs with missing imports (Dependencies tool); drop crafted DLL beside EXE",
    category: "DLL Attacks"
  },
  "WIN-DLL-UNSIGNED": {
    name: "Unsigned DLL Loading",
    description: "Application loads DLLs without Authenticode verification, allowing arbitrary DLL injection.",
    test_note: "Sigcheck -e on process DLLs; ListDLLs / Sysmon Event 7 for unsigned modules",
    category: "DLL Attacks",
    custom: true
  },

  // ── Persistence (Windows) ────────────────────────────────────────────────
  "T1547.001": {
    name: "Registry Run Keys",
    description: "Persistence via HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.",
    test_note: "Write to Run key + test reboot",
    category: "Persistence"
  },
  "T1543.003": {
    name: "Windows Service",
    description: "Create/modify service for persistence/escalation.",
    test_note: "sc create / sc config + weak permissions check",
    category: "Persistence"
  },
  "T1053.005": {
    name: "Scheduled Task",
    description: "Persistence via schtasks.",
    test_note: "schtasks /create + test trigger",
    category: "Persistence"
  },
  "T1547.004": {
    name: "Winlogon Helper DLL",
    description: "Winlogon helper DLL hijack.",
    test_note: "Set HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
    category: "Persistence"
  },

  // ── Privilege Escalation (Windows) ──────────────────────────────────────
  "T1548.002": {
    name: "Bypass UAC",
    description: "UAC bypass techniques.",
    test_note: "fodhelper.exe / eventvwr.exe classic bypass",
    category: "Privilege Escalation"
  },

  // ── Credential Access (Windows) ─────────────────────────────────────────
  "T1003.001": {
    name: "LSASS Memory Dump",
    description: "Credential dumping from LSASS.",
    test_note: "Mimikatz / procdump lsass.exe",
    category: "Credential Access"
  },

  // ── Code Injection (Windows) ─────────────────────────────────────────────
  "T1055.001": {
    name: "Process Injection (DLL)",
    description: "Inject DLL into legitimate process.",
    test_note: "Process Hacker + classic CreateRemoteThread",
    category: "Code Injection"
  },

  // ── Defense Evasion / Registry (Windows) ────────────────────────────────
  "T1112": {
    name: "Modify Registry",
    description: "Registry modifications for defense evasion/persistence.",
    test_note: "Regedit + common keys (AppInit_DLLs, etc.)",
    category: "Defense Evasion"
  },
  "T1559.001": {
    name: "COM Hijacking",
    description: "Component Object Model hijacking.",
    test_note: "CLSID registry hijack",
    category: "Defense Evasion"
  },
  "T1574.011": {
    name: "Hijack Execution Flow: Services",
    description: "Service image path hijack.",
    test_note: "Modify ImagePath in registry",
    category: "Defense Evasion"
  },

  // ── Linux ────────────────────────────────────────────────────────────────
  "T1574.006": { name: "LD_PRELOAD", description: "Hijack shared library loading.", test_note: "LD_PRELOAD=./evil.so ./app", category: "DLL/SO Attacks" },
  "T1574.007": { name: "PATH Interception", description: "Hijack via PATH env var.", test_note: "Prepend malicious dir to $PATH", category: "DLL/SO Attacks" },
  "T1548.001": { name: "Setuid/Setgid", description: "Abuse SUID binaries for escalation.", test_note: "find / -perm -4000 + test writeable SUID", category: "Privilege Escalation" },
  "T1053.003": { name: "Cron", description: "Persistence via cron jobs.", test_note: "crontab -e + root cron", category: "Persistence" },
  "T1547.006": { name: "rc.local", description: "Boot autostart scripts.", test_note: "/etc/rc.local", category: "Persistence" },
  "T1546.004": { name: "Unix Shell Config Modification", description: ".bashrc / .profile hijack", test_note: "Append payload to ~/.bashrc", category: "Persistence" },
  "T1543.002": { name: "Systemd Service", description: "Create systemd unit for persistence.", test_note: "systemctl --user enable malicious.service", category: "Persistence" },
  "T1036.004": { name: "Masquerade Task or Service", description: "Rename binary to look legit", test_note: "Rename to mimic legitimate binary", category: "Defense Evasion" },
  "T1548.003": { name: "sudoers Modification", description: "Modify sudoers for escalation", test_note: "Edit /etc/sudoers NOPASSWD entry", category: "Privilege Escalation" },
  "T1055.008": { name: "Process Injection: ptrace", description: "ptrace-based injection on Linux", test_note: "Attach ptrace to running process + shellcode", category: "Code Injection" },
  "T1556.003": { name: "PAM Backdoor", description: "Modify PAM config to create auth backdoor.", test_note: "Edit /etc/pam.d/common-auth + test login", category: "Credential Access" },
  "T1574.010": { name: "Service Binary Hijack", description: "Service binary hijack on Linux via weak file permissions.", test_note: "Replace service binary with malicious one", category: "DLL/SO Attacks" }
};

const TECHNIQUES = {
  // ── Windows thick-client ─────────────────────────────────────────────────
  // To add a new test case: add it to ATTACK_DB above then append the ID here.
  windows: [
    // DLL Attacks
    "T1574.001", "T1574.001-PDH", "T1574.001-RED", "T1574.001-SUB",
    "T1574.002", "WIN-DLL-UNSIGNED",
    // Persistence
    "T1547.001", "T1543.003", "T1053.005", "T1547.004",
    // Privilege Escalation
    "T1548.002",
    // Credential Access
    "T1003.001",
    // Code Injection
    "T1055.001",
    // Defense Evasion / Registry
    "T1112", "T1559.001", "T1574.011"
  ],

  // ── Linux thick-client ───────────────────────────────────────────────────
  linux: [
    "T1574.006","T1574.007","T1548.001","T1053.003","T1547.006",
    "T1546.004","T1543.002","T1036.004","T1548.003","T1055.008",
    "T1556.003","T1574.010"
  ]

  // ── To add a new platform, simply add a new key here: ───────────────────
  // mobile: ["MOB-CUSTOM-001", "T1411", ...],
  // web:    ["WEB-CUSTOM-001", "T1190", ...],
  // ics:    ["ICS-CUSTOM-001", "T0817", ...],
};

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
const CREDIT           = '🚀 Vibed by 0xdhanesh';

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
  // Ensure every platform defined in TECHNIQUES has a coverage bucket.
  // This means adding a new platform to TECHNIQUES is the only step needed.
  Object.keys(TECHNIQUES).forEach(p => {
    if (!coverage[p]) coverage[p] = {};
  });
}

// ── Platform select (populated from TECHNIQUES — add new platforms there) ──

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
    ? `<span class="category-tag">${tech.category}</span>`
    : '';

  // Sub-technique reference or custom badge
  let refHtml = '';
  if (tech.custom) {
    refHtml = `<span class="custom-tag">Custom · Non-MITRE</span>`;
  } else if (tech.mitre_ref) {
    refHtml = `<span class="mitre-ref-tag">↗ ${tech.mitre_ref}</span>`;
  }

  return `
    <div class="technique-card status-${status}" data-id="${id}">
      <div class="card-header">
        <span class="technique-id">${id}</span>
        ${categoryHtml}
        <span class="status-badge badge-${status}">${STATUS_LABELS[status]}</span>
      </div>
      <div class="technique-name">${tech.name}</div>
      ${refHtml}
      <div class="technique-desc">${tech.description}</div>
      <div class="test-note">${tech.test_note}</div>
      <div class="card-footer">
        <button class="status-btn" data-status="not-tested">Not Tested</button>
        <button class="status-btn" data-status="in-progress">In Progress</button>
        <button class="status-btn" data-status="completed">Completed</button>
        <button class="status-btn" data-status="out-of-scope">OOS</button>
        <button class="status-btn" data-status="blocked">Blocked</button>
      </div>
      <button class="notes-toggle" data-id="${id}">${hasNotes ? 'Hide notes' : 'Add notes'}</button>
      <textarea class="notes-area" data-id="${id}" placeholder="Test notes, evidence, tool output…" maxlength="2000"${hasNotes ? '' : ' hidden'}></textarea>
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
      grid.innerHTML += `<div class="category-header"><span>${cat}</span><span class="category-count">${ids.length}</span></div>`;
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
    .replace(/"/g, '&quot;');
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
