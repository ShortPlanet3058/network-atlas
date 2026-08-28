"use strict";

/* Network Atlas viewer.
 *
 * Only devices that are actually online are rendered: a scanned /24 reports a
 * couple of hundred addresses that answered nothing, and listing them hides the
 * network instead of showing it. The API applies that filter server-side.
 */

const TYPES = {
  router:           { label: "Router",        plural: "Routers",        icon: "ic-router" },
  switch:           { label: "Switch",        plural: "Switches",       icon: "ic-switch" },
  "access-point":   { label: "Access point",  plural: "Access points",  icon: "ic-access-point" },
  firewall:         { label: "Firewall",      plural: "Firewalls",      icon: "ic-firewall" },
  "network-device": { label: "Network gear",  plural: "Network gear",   icon: "ic-network-device" },
  computer:         { label: "Computer",      plural: "Computers",      icon: "ic-computer" },
  phone:            { label: "Phone",         plural: "Phones",         icon: "ic-phone" },
  server:           { label: "Server",        plural: "Servers",        icon: "ic-server" },
  printer:          { label: "Printer",       plural: "Printers",       icon: "ic-printer" },
  storage:          { label: "Storage",       plural: "Storage",        icon: "ic-storage" },
  media:            { label: "Media device",  plural: "Media devices",  icon: "ic-media" },
  camera:           { label: "Camera",        plural: "Cameras",        icon: "ic-camera" },
  "game-console":   { label: "Game console",  plural: "Game consoles",  icon: "ic-game-console" },
  iot:              { label: "Smart device",  plural: "Smart devices",  icon: "ic-iot" },
  unknown:          { label: "Unidentified",  plural: "Unidentified",   icon: "ic-unknown" },
};

const OS_LABELS = {
  windows: "Windows", "windows-server": "Windows Server", apple: "macOS",
  "apple-mobile": "iOS / iPadOS", android: "Android", linux: "Linux",
  bsd: "BSD", "network-os": "Network OS", embedded: "Embedded",
};

const SCAN_KINDS = [
  { id: "sweep", title: "Full sweep", icon: "ic-radar", needsTarget: true,
    detail: "Everything: neighbours, ports, names, then a passive listen. Best first run." },
  { id: "scan", title: "Active scan", icon: "ic-port", needsTarget: true, hasProfile: true,
    detail: "Probe the range for live hosts, open ports, service versions and OS." },
  { id: "passive", title: "Passive listen", icon: "ic-ear", needsDuration: true, capability: "passive_capture",
    detail: "Send nothing. Finds quiet devices and reads switch topology from LLDP/CDP." },
  { id: "names", title: "Resolve names", icon: "ic-pin", needsTarget: true,
    detail: "Look up names over DNS, mDNS and NetBIOS for devices already known." },
  { id: "web-identity", title: "Read web pages", icon: "ic-globe", capability: "web_identity",
    detail: "Opens the management page of devices with a web port and reads what it says they are. Fetches the landing page only." },
  { id: "neighbours", title: "Read caches", icon: "ic-clock",
    detail: "Instant. Imports the kernel ARP and IPv6 neighbour tables." },
  { id: "audit", title: "Check for issues", icon: "ic-shield-check",
    detail: "Reviews what is already known for exposed services, weak TLS and published exploits. Sends no scan traffic beyond TLS checks." },
];

const state = {
  token: null,
  capabilities: {},
  profiles: [],
  vantage: null,
  summary: null,
  tree: { nodes: [], roots: [], gateway_id: null },
  services: [],
  scans: [],
  jobs: [],
  changes: [],
  devicesById: new Map(),
  selectedId: null,
  tab: "overview",
  layout: "topology",
  collapsed: new Set(),
  typeFilter: new Set(),
  mapSearch: "",
  deviceSearch: "",
  portSearch: "",
  riskOnly: false,
  sort: { key: "display_name", direction: 1 },
  scanKind: "sweep",
  scanProfile: "standard",
  activeJob: null,
  findings: [],
  findingSummary: {},
  events: [],
  flows: [],
  schedule: { entries: [], monitoring: false },
  findingSearch: "",
  findingKinds: new Set(),
  showMuted: false,
  eventFilter: "all",
  expandedFindings: new Set(),
};

const SEVERITY = {
  high:   { label: "High",   rank: 0 },
  medium: { label: "Medium", rank: 1 },
  low:    { label: "Low",    rank: 2 },
  info:   { label: "Info",   rank: 3 },
};

// A readable label for each finding category and change kind.
const FINDING_KINDS = {
  "exposed-service": "Exposed service",
  "cleartext-service": "Unencrypted service",
  "known-exploits": "Known exploits",
  "tls-protocol": "Outdated TLS",
  "tls-ciphers": "Weak ciphers",
  "tls-certificate": "Certificate",
  "tls-vulnerability": "TLS vulnerability",
  "admin-interface": "Management interface",
  "ipv6-exposure": "IPv6 exposure",
  "unapproved-device": "Unapproved device",
  "unidentified-device": "Unidentified device",
};

const EVENT_LABELS = {
  "device-appeared": "New device",
  "device-left": "Went offline",
  "device-returned": "Came back",
  "port-opened": "Port opened",
  "port-closed": "Port closed",
  "address-reassigned": "Address moved",
  "address-conflict": "Address conflict",
  "hostname-changed": "Name changed",
  "vendor-changed": "Vendor changed",
  "os_family-changed": "System changed",
  "type-changed": "Reclassified",
};

const severityColor = (severity) => `var(--sev-${SEVERITY[severity] ? severity : "info"})`;
const severitySoft = (severity) => `var(--sev-${SEVERITY[severity] ? severity : "info"}-soft)`;

function tintSeverity(node, severity) {
  node.style.setProperty("--sev-color", severityColor(severity));
  node.style.setProperty("--sev-soft", severitySoft(severity));
  return node;
}

function formatInterval(seconds) {
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86400)} d`;
}

/* ---------- small helpers ---------- */
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function icon(symbol, className) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  if (className) svg.setAttribute("class", className);
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `#${symbol}`);
  svg.append(use);
  return svg;
}

const typeMeta = (type) => TYPES[type] || TYPES.unknown;
const typeColor = (type) => `var(--t-${TYPES[type] ? type : "unknown"})`;

function tinted(node, type) {
  node.style.setProperty("--type-color", typeColor(type));
  return node;
}

function glyph(type, className = "node-glyph") {
  const wrap = tinted(el("span", className), type);
  wrap.append(icon(typeMeta(type).icon));
  return wrap;
}

function relativeTime(value) {
  if (!value) return "never";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "unknown";
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 45) return "just now";
  if (seconds < 5400) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} d ago`;
}

const absoluteTime = (value) => (value ? new Date(value).toLocaleString() : "—");

let toastTimer = null;
function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => node.classList.remove("show"), 4000);
}

/* ---------- API ---------- */
async function get(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

async function post(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Atlas-Token": state.token || "" },
    body: JSON.stringify(body || {}),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `${response.status} ${response.statusText}`);
  return payload;
}

/* ---------- theme ---------- */
const THEME_KEY = "network-atlas-theme";

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  try { window.localStorage.setItem(THEME_KEY, theme); } catch { /* private mode */ }
}

function initTheme() {
  let stored = null;
  try { stored = window.localStorage.getItem(THEME_KEY); } catch { /* private mode */ }
  // Light is the product default; the OS preference only applies if never chosen.
  applyTheme(stored === "dark" || stored === "light" ? stored : "light");
  $("#theme-toggle").addEventListener("click", () => {
    applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
  });
}

/* ---------- loading ---------- */
async function loadSession() {
  const session = await get("/api/session");
  state.token = session.token;
  state.capabilities = session.capabilities || {};
  state.profiles = session.profiles || [];
  state.vantage = session.vantage || null;
  state.scanProfile = (state.profiles[1] || state.profiles[0] || {}).id || "standard";
  renderVantageLine();
  renderIsolationBanner();
}

async function loadData() {
  const [summary, tree, services, scans, jobs, changes, findings, events, flows, schedule] =
    await Promise.all([
      get("/api/summary"), get("/api/tree"), get("/api/services"),
      get("/api/scans?limit=40"), get("/api/jobs"), get("/api/changes?limit=24"),
      get(`/api/findings?muted=${state.showMuted ? 1 : 0}`),
      get("/api/events?limit=200"), get("/api/flows?limit=400"), get("/api/schedule"),
    ]);
  state.summary = summary;
  state.tree = tree;
  state.services = services;
  state.scans = scans;
  state.jobs = jobs;
  state.changes = changes;
  state.findings = findings.findings || [];
  state.findingSummary = findings.summary || {};
  state.events = events;
  state.flows = flows;
  state.schedule = schedule;
  state.devicesById = new Map(tree.nodes.map((node) => [node.id, node]));
  if (state.selectedId && !state.devicesById.has(state.selectedId)) closeDrawer();
  renderAll();
}

function renderAll() {
  renderStats();
  renderTypeCards();
  renderVantageFacts();
  renderAttention();
  renderChanges();
  renderLegend();
  renderTree();
  renderTypeFilters();
  renderDeviceTable();
  renderPorts();
  renderScanHistory();
  renderJobHistory();
  renderFindings();
  renderEvents();
  renderSchedule();
  renderMonitorToggle();
  if (state.selectedId) renderDrawer(state.devicesById.get(state.selectedId));
}

/* ---------- overview ---------- */
function renderIsolationBanner() {
  const container = state.vantage?.container;
  const banner = $("#isolation-banner");
  if (!container?.network_isolated) {
    banner.hidden = true;
    return;
  }
  banner.hidden = false;
  $("#isolation-detail").textContent =
    `Running in a ${container.runtime} container where ${container.isolation_reason}. `
    + "Scans will return almost nothing until that changes — use host networking or "
    + "macvlan on Linux, or run Network Atlas on a machine that is on the network. "
    + "See README-docker.md.";
}

function renderVantageLine() {
  const vantage = state.vantage;
  if (!vantage) return;
  const parts = [];
  if (vantage.primary_target) parts.push(vantage.primary_target);
  if (vantage.primary_gateway) parts.push(`gateway ${vantage.primary_gateway}`);
  const active = (vantage.interfaces || []).filter((entry) => entry.state === "UP");
  if (active.length) parts.push(active.map((entry) => entry.interface).join(", "));
  $("#vantage-line").textContent = parts.join(" · ") || "No local network detected";
}

function renderStats() {
  const summary = state.summary;
  if (!summary) return;
  $("#stat-devices").textContent = summary.online;
  const hidden = Math.max(0, (summary.known_total || 0) - summary.online);
  $("#stat-devices-note").textContent = hidden
    ? `${hidden} seen before, not responding now`
    : "All known devices responding";
  $("#stat-identified").textContent = summary.identified;
  const share = summary.online ? Math.round((summary.identified / summary.online) * 100) : 0;
  $("#stat-identified-note").textContent = `${share}% recognised by type`;
  $("#stat-ports").textContent = summary.services;
  $("#stat-links").textContent = summary.links;
  const findings = summary.findings || {};
  const open = (findings.high || 0) + (findings.medium || 0) + (findings.low || 0);
  $("#stat-findings").textContent = open;
  $("#stat-findings-note").textContent = findings.high
    ? `${findings.high} need attention first`
    : open ? "None urgent" : "Nothing outstanding";
  $("#tab-count-devices").textContent = summary.online;
  $("#tab-count-ports").textContent = state.services.length;
  $("#tab-count-findings").textContent = open;
  $("#tab-count-events").textContent = summary.unacknowledged_events || 0;
  $("#posture-high").textContent = findings.high || 0;
  $("#posture-medium").textContent = findings.medium || 0;
  $("#posture-low").textContent = findings.low || 0;
  $("#posture-resolved").textContent = summary.findings_resolved || 0;
}

function renderTypeCards() {
  const container = $("#type-cards");
  container.replaceChildren();
  const types = Object.entries(state.summary?.types || {}).sort((a, b) => b[1] - a[1]);
  if (!types.length) {
    container.append(el("p", "empty-list", "No devices discovered yet."));
    return;
  }
  for (const [type, count] of types) {
    const meta = typeMeta(type);
    const card = tinted(el("button", "type-card"), type);
    card.append(glyph(type, "type-glyph"));
    const body = el("span", "type-meta");
    body.append(el("span", "type-count", count), el("span", "type-name", count === 1 ? meta.label : meta.plural));
    card.append(body);
    card.addEventListener("click", () => {
      state.typeFilter = new Set([type]);
      state.layout = "groups";
      renderTypeFilters();
      renderDeviceTable();
      renderTree();
      switchTab("devices");
    });
    container.append(card);
  }
}

function renderVantageFacts() {
  const list = $("#vantage-facts");
  list.replaceChildren();
  const vantage = state.vantage;
  if (!vantage) return;
  const active = (vantage.interfaces || []).filter((entry) => entry.state === "UP");
  const rows = [
    ["Scanning range", vantage.primary_target || "not detected"],
    ["Default gateway", vantage.primary_gateway || "none"],
    ["Interfaces", active.length
      ? active.map((entry) => `${entry.interface} (${entry.address}${entry.wireless ? ", Wi-Fi" : ""})`).join(" · ")
      : "none up"],
    ["Deep scanning", state.capabilities.raw_packets
      ? "Available — OS detection and traceroute enabled"
      : "Limited — no raw packet access"],
    ["Passive listening", state.capabilities.passive_capture
      ? "Available"
      : "Unavailable — needs packet-capture rights"],
  ];
  if (vantage.container?.in_container) {
    rows.push(["Running in", vantage.container.network_isolated
      ? `${vantage.container.runtime} container — network isolated, discovery limited`
      : `${vantage.container.runtime} container with host networking`]);
  }
  for (const [term, value] of rows) {
    list.append(el("dt", "", term), el("dd", "", value));
  }
}

function renderAttention() {
  const container = $("#attention-list");
  container.replaceChildren();
  const top = state.findings
    .filter((finding) => !finding.muted)
    .slice(0, 6);
  if (!top.length) {
    container.append(el("p", "empty-list",
      "Nothing outstanding. Run a check after a scan to look for issues."));
    return;
  }
  for (const finding of top) {
    const item = tintSeverity(el("button", "attention-item"), finding.severity);
    item.style.setProperty("--glyph-color", severityColor(finding.severity));
    const marker = el("span", "item-glyph");
    marker.append(icon(finding.severity === "high" ? "ic-alert" : "ic-wrench"));
    const body = el("span", "item-body");
    body.append(
      el("strong", "", finding.title),
      el("span", "", `${finding.device_name} — ${FINDING_KINDS[finding.kind] || finding.kind}`),
    );
    item.append(marker, body, el("span", "item-time", SEVERITY[finding.severity]?.label || ""));
    item.addEventListener("click", () => {
      state.expandedFindings.add(finding.id);
      renderFindings();
      switchTab("findings");
    });
    container.append(item);
  }
}

function renderChanges() {
  const container = $("#changes-list");
  container.replaceChildren();
  if (!state.changes.length) {
    container.append(el("p", "empty-list", "No activity recorded yet."));
    return;
  }
  for (const change of state.changes.slice(0, 10)) {
    const device = state.devicesById.get(change.device_id);
    const type = device?.effective_type || change.device_type || "unknown";
    const item = el("button", "change-item");
    item.style.setProperty("--glyph-color", typeColor(type));
    const marker = el("span", "item-glyph");
    marker.append(icon(change.kind === "port-opened" ? "ic-port" : typeMeta(type).icon));
    const body = el("span", "item-body");
    body.append(
      el("strong", "", change.name),
      el("span", "", change.kind === "port-opened" ? `Port ${change.detail}` : change.detail),
    );
    item.append(marker, body, el("span", "item-time", relativeTime(change.at)));
    item.addEventListener("click", () => openDevice(change.device_id));
    container.append(item);
  }
}

/* ---------- map ---------- */
function renderLegend() {
  const legend = $("#map-legend");
  legend.replaceChildren();
  const types = Object.keys(state.summary?.types || {});
  for (const type of types) {
    const item = tinted(el("span", "legend-item"), type);
    item.append(el("i", "legend-swatch"), el("span", "", typeMeta(type).plural));
    legend.append(item);
  }
}

function matchesSearch(device, query) {
  if (!query) return true;
  const haystack = [
    device.display_name, device.hostname, device.mac, device.vendor,
    device.os_name, device.os_family, device.effective_type, ...(device.addresses || []),
  ].filter(Boolean).join(" ").toLowerCase();
  return haystack.includes(query);
}

function visibleMapNodes() {
  const query = state.mapSearch.trim().toLowerCase();
  return state.tree.nodes.filter((node) => {
    const typeAllowed = !state.typeFilter.size || state.typeFilter.has(node.effective_type);
    return typeAllowed && matchesSearch(node, query);
  });
}

function renderTree() {
  const container = $("#tree");
  container.replaceChildren();
  const nodes = visibleMapNodes();
  $("#map-empty").hidden = nodes.length > 0;
  container.hidden = nodes.length === 0;
  if (!nodes.length) return;

  if (state.layout === "topology") renderTopologyTree(container, nodes);
  else renderGroupedTree(container, nodes, state.layout);
}

function renderTopologyTree(container, nodes) {
  const visible = new Set(nodes.map((node) => node.id));
  const children = new Map();
  const roots = [];
  for (const node of nodes) {
    // A node whose parent was filtered out is promoted to a root so it stays visible.
    const parent = node.parent_id !== null && visible.has(node.parent_id) ? node.parent_id : null;
    if (parent === null) roots.push(node);
    else {
      if (!children.has(parent)) children.set(parent, []);
      children.get(parent).push(node);
    }
  }
  const order = (list) => list.slice().sort((a, b) => {
    if (a.is_infrastructure !== b.is_infrastructure) return a.is_infrastructure ? -1 : 1;
    if (b.child_count !== a.child_count) return b.child_count - a.child_count;
    return String(a.display_name).localeCompare(String(b.display_name), undefined, { numeric: true });
  });

  const list = el("ul");
  list.setAttribute("role", "group");
  // An explicit Internet root makes the shape of the network obvious at a glance.
  const internet = el("li");
  const uplink = el("div");
  const uplinkNode = el("div", "tree-node");
  uplinkNode.style.setProperty("--type-color", "var(--t-internet)");
  const twisty = el("button", "twisty open");
  twisty.append(icon("ic-chevron"));
  const uplinkGlyph = el("span", "node-glyph");
  uplinkGlyph.style.setProperty("--type-color", "var(--t-internet)");
  uplinkGlyph.append(icon("ic-globe"));
  const uplinkMain = el("div", "node-main");
  const uplinkTitle = el("div", "node-title");
  uplinkTitle.append(el("strong", "", "Internet"));
  const uplinkSub = el("div", "node-sub");
  uplinkSub.append(el("span", "", "Everything below reaches the outside through your gateway"));
  uplinkMain.append(uplinkTitle, uplinkSub);
  uplinkNode.append(twisty, uplinkGlyph, uplinkMain);
  uplink.append(uplinkNode);
  internet.append(uplink);

  const rootList = el("ul");
  rootList.setAttribute("role", "group");
  for (const node of order(roots)) rootList.append(treeItem(node, children, order));
  internet.append(rootList);
  twisty.addEventListener("click", (event) => {
    event.stopPropagation();
    const open = twisty.classList.toggle("open");
    rootList.hidden = !open;
  });
  list.append(internet);
  container.append(list);
}

function treeItem(node, children, order) {
  const item = el("li");
  const kids = order(children.get(node.id) || []);
  const row = treeRow(node, kids.length);
  item.append(row.element);
  if (kids.length) {
    const sublist = el("ul");
    sublist.setAttribute("role", "group");
    for (const child of kids) sublist.append(treeItem(child, children, order));
    sublist.hidden = state.collapsed.has(node.id);
    row.twisty.classList.toggle("open", !sublist.hidden);
    row.twisty.addEventListener("click", (event) => {
      event.stopPropagation();
      const open = !sublist.hidden;
      if (open) state.collapsed.add(node.id);
      else state.collapsed.delete(node.id);
      sublist.hidden = open;
      row.twisty.classList.toggle("open", !open);
    });
    item.append(sublist);
  }
  return item;
}

function treeRow(node, childCount) {
  const type = node.effective_type;
  const button = tinted(el("div", "tree-node"), type);
  button.dataset.id = node.id;
  button.setAttribute("role", "treeitem");
  button.tabIndex = 0;
  if (node.is_local) button.classList.add("is-local");
  if (node.id === state.selectedId) button.classList.add("selected");

  const twisty = el("button", `twisty${childCount ? "" : " leaf"}`);
  twisty.append(icon("ic-chevron"));
  twisty.setAttribute("aria-label", childCount ? "Toggle children" : "");
  if (!childCount) twisty.tabIndex = -1;

  const main = el("div", "node-main");
  const title = el("div", "node-title");
  title.append(el("strong", "", node.display_name));
  title.append(tinted(el("span", "badge", typeMeta(type).label), type));
  if (node.is_local) title.append(el("span", "badge you", "This device"));
  if (childCount) title.append(el("span", "badge neutral", `${childCount} below`));

  const sub = el("div", "node-sub");
  if (node.primary_address) {
    const address = el("code", "", node.primary_address);
    sub.append(address);
  }
  if (node.vendor) sub.append(el("span", "", node.vendor));
  if (node.os_family && OS_LABELS[node.os_family]) sub.append(el("span", "", OS_LABELS[node.os_family]));
  if (node.uplink_port) sub.append(el("span", "uplink", `port ${node.uplink_port}`));
  main.append(title, sub);

  const meta = el("div", "node-meta");
  if (node.service_count) {
    const pill = el("span", "port-pill");
    pill.append(icon("ic-port"), el("span", "", `${node.service_count}`));
    meta.append(pill);
  }
  meta.append(el("span", "", relativeTime(node.last_seen)));

  button.append(twisty, glyph(type), main, meta);
  button.addEventListener("click", () => openDevice(node.id));
  button.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      openDevice(node.id);
    }
  });
  return { element: button, twisty };
}

function subnetOf(node) {
  const ipv4 = (node.addresses || []).find((address) => /^\d+\.\d+\.\d+\.\d+$/.test(address));
  if (!ipv4) return "Other addresses";
  return `${ipv4.split(".").slice(0, 3).join(".")}.0/24`;
}

function renderGroupedTree(container, nodes, mode) {
  const groups = new Map();
  for (const node of nodes) {
    const key = mode === "groups" ? node.effective_type : subnetOf(node);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(node);
  }
  const ordered = Array.from(groups.entries()).sort((a, b) => b[1].length - a[1].length);
  const list = el("ul");
  for (const [key, members] of ordered) {
    const item = el("li");
    const heading = el("div", "tree-group-label");
    if (mode === "groups") {
      heading.style.setProperty("--type-color", typeColor(key));
      heading.append(icon(typeMeta(key).icon), el("span", "", `${typeMeta(key).plural} · ${members.length}`));
    } else {
      heading.append(icon("ic-network-device"), el("span", "", `${key} · ${members.length}`));
    }
    item.append(heading);
    const sublist = el("ul");
    for (const node of members.slice().sort((a, b) =>
      String(a.display_name).localeCompare(String(b.display_name), undefined, { numeric: true })
    )) {
      const leaf = el("li");
      leaf.append(treeRow(node, 0).element);
      sublist.append(leaf);
    }
    item.append(sublist);
    list.append(item);
  }
  container.append(list);
}

/* ---------- devices table ---------- */
function renderTypeFilters() {
  const container = $("#type-filters");
  container.replaceChildren();
  const types = Object.entries(state.summary?.types || {}).sort((a, b) => b[1] - a[1]);
  if (types.length > 1) {
    const all = el("button", `chip${state.typeFilter.size ? "" : " active"}`, "");
    all.append(el("span", "", "All"), el("b", "", String(state.summary.online)));
    all.addEventListener("click", () => {
      state.typeFilter.clear();
      renderTypeFilters(); renderDeviceTable(); renderTree();
    });
    container.append(all);
  }
  for (const [type, count] of types) {
    const chip = el("button", `chip${state.typeFilter.has(type) ? " active" : ""}`);
    chip.style.setProperty("--chip-color", typeColor(type));
    chip.append(icon(typeMeta(type).icon), el("span", "", typeMeta(type).plural), el("b", "", String(count)));
    chip.addEventListener("click", () => {
      if (state.typeFilter.has(type)) state.typeFilter.delete(type);
      else state.typeFilter.add(type);
      renderTypeFilters(); renderDeviceTable(); renderTree();
    });
    container.append(chip);
  }
}

function sortedDevices() {
  const query = state.deviceSearch.trim().toLowerCase();
  const rows = state.tree.nodes.filter((node) =>
    (!state.typeFilter.size || state.typeFilter.has(node.effective_type)) && matchesSearch(node, query)
  );
  const { key, direction } = state.sort;
  return rows.sort((a, b) => {
    let left = a[key];
    let right = b[key];
    if (key === "primary_address") {
      left = addressKey(a.primary_address);
      right = addressKey(b.primary_address);
    }
    if (typeof left === "number" || typeof right === "number") {
      return ((left || 0) - (right || 0)) * direction;
    }
    return String(left ?? "").localeCompare(String(right ?? ""), undefined, { numeric: true }) * direction;
  });
}

function addressKey(address) {
  if (!address) return Number.MAX_SAFE_INTEGER;
  const parts = address.split(".");
  if (parts.length !== 4) return Number.MAX_SAFE_INTEGER - 1;
  return parts.reduce((total, part) => total * 256 + (Number(part) || 0), 0);
}

function renderDeviceTable() {
  const body = $("#device-rows");
  body.replaceChildren();
  const rows = sortedDevices();
  $("#devices-empty").hidden = rows.length > 0;
  $$("#device-table th.sortable").forEach((header) => {
    header.classList.toggle("sorted", header.dataset.sort === state.sort.key);
    header.classList.toggle("desc", header.dataset.sort === state.sort.key && state.sort.direction === -1);
  });

  for (const device of rows) {
    const type = device.effective_type;
    const row = el("tr");
    row.dataset.id = device.id;
    if (device.id === state.selectedId) row.classList.add("selected");

    const nameCell = el("td");
    const wrap = tinted(el("div", "cell-device"), type);
    wrap.append(glyph(type, "cell-glyph"));
    const text = el("div", "cell-device-text");
    text.append(el("strong", "", device.display_name));
    text.append(el("small", "", device.is_local ? "This device" : (device.mac || "no hardware address")));
    wrap.append(text);
    nameCell.append(wrap);

    const typeCell = el("td");
    typeCell.append(tinted(el("span", "badge", typeMeta(type).label), type));

    const addressCell = el("td");
    if (device.primary_address) {
      addressCell.append(el("code", "mono", device.primary_address));
      const extra = (device.addresses || []).length - 1;
      if (extra > 0) addressCell.append(el("small", "muted", ` +${extra}`));
    } else {
      addressCell.append(el("span", "muted", "link-layer only"));
    }

    const osLabel = OS_LABELS[device.os_family] || (device.os_name ? "Detected" : null);
    const confidence = Math.round((device.confidence || 0) * 100);
    const certaintyCell = el("td", "numeric");
    const bar = el("span", "mini-bar");
    const track = el("span", "mini-track");
    const fill = el("i");
    fill.style.width = `${confidence}%`;
    track.style.setProperty("--bar-color", confidence >= 70 ? "var(--ok)" : confidence >= 40 ? "var(--warn)" : "var(--danger)");
    track.append(fill);
    bar.append(el("span", "muted", `${confidence}%`), track);
    certaintyCell.append(bar);

    row.append(
      nameCell,
      typeCell,
      addressCell,
      el("td", device.vendor ? "" : "muted", device.vendor || "unknown"),
      el("td", osLabel ? "" : "muted", osLabel || "—"),
      el("td", "numeric", device.service_count || 0),
      certaintyCell,
      el("td", "muted", relativeTime(device.last_seen)),
    );
    row.addEventListener("click", () => openDevice(device.id));
    body.append(row);
  }
}

/* ---------- ports ---------- */
function renderPorts() {
  const container = $("#port-list");
  container.replaceChildren();
  const query = state.portSearch.trim().toLowerCase();
  const rows = state.services.filter((service) => {
    if (state.riskOnly && !service.risk) return false;
    if (!query) return true;
    return `${service.port} ${service.protocol} ${service.name} ${service.products.join(" ")}`
      .toLowerCase().includes(query);
  });
  $("#ports-empty").hidden = rows.length > 0;
  for (const service of rows) {
    const card = el("article", `port-card${service.risk ? " risky" : ""}`);
    const head = el("button", "port-head");
    head.append(el("span", "port-number", `${service.port}/${service.protocol}`));
    const info = el("div", "port-info");
    info.append(el("strong", "", service.name));
    info.append(el("span", "", service.risk ? service.risk.note : (service.products.join(", ") || "No product detail")));
    head.append(info);
    head.append(el("span", "port-count", `${service.device_count} device${service.device_count === 1 ? "" : "s"}`));
    const chevron = el("span", "twisty");
    chevron.append(icon("ic-chevron"));
    head.append(chevron);

    const devices = el("div", "port-devices");
    devices.hidden = true;
    for (const deviceId of service.device_ids) {
      const device = state.devicesById.get(deviceId);
      if (!device) continue;
      const chip = tinted(el("button", "device-chip"), device.effective_type);
      chip.append(icon(typeMeta(device.effective_type).icon), el("span", "", device.display_name));
      chip.addEventListener("click", () => openDevice(deviceId));
      devices.append(chip);
    }
    head.addEventListener("click", () => {
      devices.hidden = !devices.hidden;
      chevron.classList.toggle("open", !devices.hidden);
    });
    card.append(head, devices);
    container.append(card);
  }
}

/* ---------- findings ---------- */
function findingKindCounts() {
  const counts = new Map();
  for (const finding of state.findings) {
    counts.set(finding.kind, (counts.get(finding.kind) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

function renderFindingFilters() {
  const container = $("#finding-filters");
  container.replaceChildren();
  const kinds = findingKindCounts();
  if (kinds.length <= 1) return;
  const all = el("button", `chip${state.findingKinds.size ? "" : " active"}`);
  all.append(el("span", "", "All"), el("b", "", String(state.findings.length)));
  all.addEventListener("click", () => {
    state.findingKinds.clear();
    renderFindings();
  });
  container.append(all);
  for (const [kind, count] of kinds) {
    const chip = el("button", `chip${state.findingKinds.has(kind) ? " active" : ""}`);
    chip.append(el("span", "", FINDING_KINDS[kind] || kind), el("b", "", String(count)));
    chip.addEventListener("click", () => {
      if (state.findingKinds.has(kind)) state.findingKinds.delete(kind);
      else state.findingKinds.add(kind);
      renderFindings();
    });
    container.append(chip);
  }
}

function visibleFindings() {
  const query = state.findingSearch.trim().toLowerCase();
  return state.findings.filter((finding) => {
    if (state.findingKinds.size && !state.findingKinds.has(finding.kind)) return false;
    if (!query) return true;
    return [
      finding.title, finding.detail, finding.remediation, finding.evidence,
      finding.device_name, finding.device_address, finding.kind, String(finding.port || ""),
    ].filter(Boolean).join(" ").toLowerCase().includes(query);
  });
}

function findingCard(finding, { compact = false } = {}) {
  const card = tintSeverity(el("article", `finding${finding.muted ? " muted" : ""}`), finding.severity);

  const head = el("button", "finding-head");
  head.append(tintSeverity(el("span", "severity-pill", SEVERITY[finding.severity]?.label || finding.severity), finding.severity));
  const main = el("div", "finding-main");
  main.append(el("strong", "", finding.title));
  const where = el("div", "finding-where");
  if (!compact) {
    where.append(el("span", "", finding.device_name));
    if (finding.device_address) where.append(el("code", "", finding.device_address));
  }
  where.append(el("span", "", FINDING_KINDS[finding.kind] || finding.kind));
  if (finding.port) where.append(el("code", "", `${finding.port}/${finding.protocol || "tcp"}`));
  main.append(where);
  head.append(main);
  head.append(el("span", "finding-age", `seen ${relativeTime(finding.last_seen)}`));
  const chevron = el("span", "twisty");
  chevron.append(icon("ic-chevron"));
  head.append(chevron);

  const body = el("div", "finding-body collapsed");
  if (finding.detail) {
    const section = el("div", "finding-section");
    section.append(el("h4", "", "Why this matters"), el("p", "", finding.detail));
    body.append(section);
  }
  if (finding.evidence) {
    const section = el("div", "finding-section");
    section.append(el("h4", "", "What was observed"), el("div", "finding-evidence", finding.evidence));
    body.append(section);
  }
  if (finding.remediation) {
    const fix = el("div", "finding-section finding-fix");
    fix.append(el("h4", "", "How to fix it"), el("p", "", finding.remediation));
    body.append(fix);
  }

  const actions = el("div", "finding-actions");
  if (!compact) {
    const open = el("button", "ghost-button", "Open device");
    open.addEventListener("click", () => openDevice(finding.device_id));
    actions.append(open);
  }
  const mute = el("button", "ghost-button");
  mute.append(icon("ic-mute"), el("span", "", finding.muted ? "Stop ignoring" : "Ignore this"));
  mute.addEventListener("click", async () => {
    try {
      await post("/api/findings/mute", { id: finding.id, muted: !finding.muted });
      toast(finding.muted ? "No longer ignored" : "Ignored — it will stay hidden");
      await loadData();
    } catch (error) {
      toast(error.message);
    }
  });
  actions.append(mute);
  const firstSeen = el("span", "finding-age", `first seen ${relativeTime(finding.first_seen)}`);
  actions.append(firstSeen);
  body.append(actions);

  const expanded = state.expandedFindings.has(finding.id);
  body.classList.toggle("collapsed", !expanded);
  chevron.classList.toggle("open", expanded);
  head.addEventListener("click", () => {
    const nowOpen = body.classList.contains("collapsed");
    body.classList.toggle("collapsed", !nowOpen);
    chevron.classList.toggle("open", nowOpen);
    if (nowOpen) state.expandedFindings.add(finding.id);
    else state.expandedFindings.delete(finding.id);
  });

  card.append(head, body);
  return card;
}

function renderFindings() {
  renderFindingFilters();
  const container = $("#finding-list");
  container.replaceChildren();
  const rows = visibleFindings();
  $("#findings-empty").hidden = rows.length > 0;
  container.hidden = rows.length === 0;
  for (const finding of rows) container.append(findingCard(finding));
}

/* ---------- timeline ---------- */
function renderEvents() {
  const container = $("#event-list");
  container.replaceChildren();
  const notableOnly = state.eventFilter === "notable";
  const rows = state.events.filter(
    (event) => !notableOnly || ["high", "medium"].includes(event.severity)
  );
  $("#events-empty").hidden = rows.length > 0;
  container.hidden = rows.length === 0;
  for (const event of rows) {
    const row = tintSeverity(el("div", `event${event.acknowledged ? "" : " unseen"}`), event.severity);
    row.append(tintSeverity(el("i", "event-dot"), event.severity));
    const main = el("div", "event-main");
    const title = el("strong", "", event.title);
    main.append(title);
    const parts = [EVENT_LABELS[event.kind] || event.kind];
    if (event.detail) parts.push(event.detail);
    main.append(el("span", "", parts.join(" — ")));
    row.append(main, el("span", "event-time", relativeTime(event.occurred_at)));
    if (event.device_id) {
      row.style.cursor = "pointer";
      row.addEventListener("click", () => openDevice(event.device_id));
    }
    container.append(row);
  }
}

/* ---------- schedule ---------- */
function renderSchedule() {
  const container = $("#schedule-list");
  container.replaceChildren();
  const entries = state.schedule.entries || [];
  if (!entries.length) {
    container.append(el("p", "empty-list", "No scheduled collections."));
    return;
  }
  const titles = {
    neighbours: "Read address caches",
    passive: "Listen passively",
    scan: "Quick sweep for who is online",
    names: "Resolve device names",
    "web-identity": "Read web interfaces",
    audit: "Check for issues",
  };
  for (const entry of entries) {
    const item = el("div", "schedule-item");
    const main = el("div", "schedule-main");
    main.append(el("strong", "", titles[entry.kind] || entry.kind));
    const bits = [`every ${formatInterval(entry.interval_seconds)}`];
    if (entry.last_run_at) bits.push(`last ran ${relativeTime(entry.last_run_at)}`);
    else if (entry.enabled) bits.push("not run yet");
    main.append(el("span", "", bits.join(" · ")));
    item.append(main);
    const toggle = el("button", `schedule-toggle${entry.enabled ? " on" : ""}`);
    toggle.setAttribute("aria-label", `Toggle ${entry.kind}`);
    toggle.addEventListener("click", async () => {
      try {
        await post("/api/schedule", { kind: entry.kind, enabled: !entry.enabled });
        await loadData();
      } catch (error) {
        toast(error.message);
      }
    });
    item.append(toggle);
    container.append(item);
  }
}

function renderMonitorToggle() {
  const active = Boolean(state.schedule.monitoring);
  const button = $("#monitor-toggle");
  button.classList.toggle("on", active);
  $("#monitor-label").textContent = active ? "Monitoring on" : "Monitoring off";
  button.title = active
    ? "Collections run automatically while the viewer is open. Click to stop."
    : "Turn on automatic collection while the viewer is open.";
}

/* ---------- activity ---------- */
function renderScanHistory() {
  const container = $("#scan-history");
  container.replaceChildren();
  if (!state.scans.length) {
    container.append(el("p", "empty-list", "No collections recorded yet."));
    return;
  }
  for (const scan of state.scans.slice(0, 24)) {
    const item = el("div", "scan-item");
    const tone = scan.status === "complete" ? "var(--ok)" : scan.status === "failed" ? "var(--danger)" : "var(--accent)";
    item.style.setProperty("--glyph-color", tone);
    const marker = el("span", "item-glyph");
    marker.append(icon(scan.status === "failed" ? "ic-alert" : "ic-radar"));
    const body = el("span", "item-body");
    body.append(el("strong", "", `${scan.source} · ${scan.status}`));
    body.append(el("span", "", scan.error || scan.detail || scan.target || "local segment"));
    item.append(marker, body, el("span", "item-time", relativeTime(scan.finished_at || scan.started_at)));
    container.append(item);
  }
}

function renderJobHistory() {
  const container = $("#job-history");
  container.replaceChildren();
  if (!state.jobs.length) {
    container.append(el("p", "empty-list", "No scans started from this browser yet."));
    return;
  }
  for (const job of state.jobs) {
    const item = el("div", "scan-item");
    const tone = job.status === "complete" ? "var(--ok)" : job.status === "failed" ? "var(--danger)" : "var(--accent)";
    item.style.setProperty("--glyph-color", tone);
    const marker = el("span", "item-glyph");
    marker.append(icon(job.status === "failed" ? "ic-alert" : "ic-radar"));
    const body = el("span", "item-body");
    body.append(el("strong", "", `${job.kind} · ${job.status}`));
    body.append(el("span", "", job.error || job.detail || ""));
    item.append(marker, body, el("span", "item-time", relativeTime(job.finished_at || job.started_at)));
    container.append(item);
  }
}

/* ---------- drawer ---------- */
function openDevice(deviceId) {
  const device = state.devicesById.get(deviceId);
  if (!device) return;
  state.selectedId = deviceId;
  $("#drawer").hidden = false;
  renderDrawer(device);
  $$(".tree-node").forEach((node) => node.classList.toggle("selected", Number(node.dataset.id) === deviceId));
  $$("#device-rows tr").forEach((row) => row.classList.toggle("selected", Number(row.dataset.id) === deviceId));
}

function closeDrawer() {
  $("#drawer").hidden = true;
  state.selectedId = null;
  $$(".tree-node.selected, #device-rows tr.selected").forEach((node) => node.classList.remove("selected"));
}

function renderDrawer(device) {
  if (!device) return;
  const type = device.effective_type;
  const card = $(".drawer-card");
  card.style.setProperty("--type-color", typeColor(type));

  const avatar = $("#drawer-icon");
  avatar.replaceChildren(icon(typeMeta(type).icon));
  $("#drawer-type").textContent = typeMeta(type).label;
  $("#drawer-name").textContent = device.display_name;
  $("#drawer-sub").textContent = (device.addresses || []).join("  ·  ") || device.mac || "no address";

  const confidence = Math.round((device.confidence || 0) * 100);
  $("#drawer-confidence").textContent = `${confidence}%`;
  $("#drawer-confidence-bar").style.width = `${confidence}%`;

  const reasons = $("#drawer-reasons");
  reasons.replaceChildren();
  const why = device.metadata?.classification_reasons || [];
  if (!why.length) reasons.append(el("li", "", "No classification evidence recorded yet."));
  for (const reason of why) reasons.append(el("li", "", reason));

  const identity = $("#drawer-identity");
  identity.replaceChildren();
  const facts = [
    ["Addresses", (device.addresses || []).join(", ") || "—"],
    ["Hardware address", device.mac || "not observed"],
    ["Manufacturer", device.vendor || "unknown"],
    ["Operating system", device.os_name || OS_LABELS[device.os_family] || "not detected"],
    ["Owner", device.owner || "not set"],
    ["Location", device.location || "not set"],
    ["Expected here", device.approved === 1 ? "Approved"
      : device.approved === 0 ? "Not approved" : "Undecided"],
    ["Detected by", (device.source_list || []).join(", ") || "—"],
    ["First seen", absoluteTime(device.first_seen)],
    ["Last seen", `${relativeTime(device.last_seen)} (${absoluteTime(device.last_seen)})`],
  ];
  for (const [term, value] of facts) identity.append(el("dt", "", term), el("dd", "", value));

  const topology = $("#drawer-topology");
  topology.replaceChildren();
  const parent = device.parent_id ? state.devicesById.get(device.parent_id) : null;
  if (parent) {
    const row = el("div", "topology-row");
    row.append(icon(typeMeta(parent.effective_type).icon), el("span", "", "Connects through"));
    // Navigable: the obvious next question is "what is that device?".
    const link = tinted(el("button", "inline-link", parent.display_name), parent.effective_type);
    link.addEventListener("click", () => openDevice(parent.id));
    row.append(link);
    topology.append(row);
    if (device.parent_reason) topology.append(el("div", "topology-row", device.parent_reason));
    if (device.uplink_port) topology.append(el("div", "topology-row", `Switch port: ${device.uplink_port}`));
  } else {
    topology.append(el("div", "topology-row", "Sits at the top of the map."));
  }
  const children = state.tree.nodes.filter((node) => node.parent_id === device.id);
  if (children.length) {
    const plural = children.length === 1 ? "" : "s";
    topology.append(el("div", "topology-row",
      `${children.length} device${plural} connect through this one:`));
    const list = el("div", "child-chips");
    for (const child of children.slice(0, 24)) {
      const chip = tinted(el("button", "device-chip"), child.effective_type);
      chip.append(icon(typeMeta(child.effective_type).icon), el("span", "", child.display_name));
      chip.addEventListener("click", () => openDevice(child.id));
      list.append(chip);
    }
    if (children.length > 24) {
      list.append(el("span", "muted", `+${children.length - 24} more`));
    }
    topology.append(list);
  }

  const deviceFindings = state.findings.filter((finding) => finding.device_id === device.id);
  $("#drawer-fix-count").textContent = deviceFindings.length;
  const fixPane = $("#drawer-findings");
  fixPane.replaceChildren();
  if (!deviceFindings.length) {
    fixPane.append(el("p", "empty-list", "Nothing outstanding for this device."));
  }
  for (const finding of deviceFindings) {
    fixPane.append(findingCard(finding, { compact: true }));
  }

  const flowPane = $("#drawer-flows");
  flowPane.replaceChildren();
  const deviceFlows = state.flows
    .filter((flow) => flow.source_device_id === device.id)
    .slice(0, 12);
  if (!deviceFlows.length) {
    flowPane.append(el("p", "empty-list",
      "No traffic observed yet. A passive listen records which devices this one connects to."));
  }
  for (const flow of deviceFlows) {
    const row = el("div", "flow-row");
    const type = flow.target_type || "unknown";
    row.style.setProperty("--type-color", flow.external ? "var(--sev-medium)" : typeColor(type));
    row.append(icon(flow.external ? "ic-globe" : typeMeta(type).icon));
    const target = el("div", "flow-target");
    target.append(el("strong", flow.external ? "flow-external" : "",
      flow.external ? (flow.target_address || "outside the network") : flow.target_name));
    target.append(el("span", "", `port ${flow.port}/${flow.protocol}`));
    row.append(target);
    row.append(el("span", "flow-count", `${flow.packets}×`));
    if (!flow.external && flow.target_device_id) {
      row.style.cursor = "pointer";
      row.addEventListener("click", () => openDevice(flow.target_device_id));
    }
    flowPane.append(row);
  }

  const ports = $("#drawer-ports");
  ports.replaceChildren();
  const services = device.services || [];
  if (!services.length) {
    ports.append(el("p", "empty-list", "No open ports recorded. Run a Standard or Deep scan to inventory services."));
  }
  for (const service of services) {
    const row = el("div", "port-detail-row");
    row.append(el("span", "port-number", `${service.port}/${service.protocol}`));
    const text = el("div", "port-detail-text");
    text.append(el("strong", "", service.name || "unknown service"));
    const description = [service.product, service.version, service.extra].filter(Boolean).join(" · ");
    text.append(el("span", "", description || "No version detail"));
    row.append(text);
    ports.append(row);
  }

  const evidence = $("#drawer-evidence");
  evidence.replaceChildren();
  const observations = device.evidence || [];
  if (!observations.length) {
    evidence.append(el("p", "empty-list", "No observations recorded."));
  }
  for (const observation of observations) {
    const item = el("div", "evidence-item");
    const head = el("div", "evidence-head");
    head.append(
      el("span", "evidence-source", `${observation.source} · ${observation.key}`),
      el("span", "item-time", relativeTime(observation.observed_at)),
    );
    item.append(head, el("p", "", observation.value));
    evidence.append(item);
  }

  $("#edit-name").value = device.manual_name || "";
  $("#edit-owner").value = device.owner || "";
  $("#edit-location").value = device.location || "";
  $("#edit-notes").value = device.notes || "";
  const approvedValue = device.approved === null || device.approved === undefined
    ? "" : String(device.approved);
  $$("[data-approved]").forEach((button) => {
    button.classList.toggle("active", button.dataset.approved === approvedValue);
  });
  const select = $("#edit-type");
  select.replaceChildren();
  const auto = el("option", "", `Automatic (${typeMeta(device.device_type).label})`);
  auto.value = "";
  select.append(auto);
  for (const key of Object.keys(TYPES)) {
    const option = el("option", "", typeMeta(key).label);
    option.value = key;
    if (device.manual_type === key) option.selected = true;
    select.append(option);
  }
  $("#edit-status").hidden = true;
}

/* ---------- scan control ---------- */
function renderScanKinds() {
  const container = $("#scan-kinds");
  container.replaceChildren();
  for (const kind of SCAN_KINDS) {
    const available = !kind.capability || state.capabilities[kind.capability];
    const card = el("button", `scan-kind${state.scanKind === kind.id ? " active" : ""}`);
    if (!available) card.disabled = true;
    const marker = el("span", "item-glyph");
    marker.append(icon(kind.icon));
    const text = el("div", "scan-kind-text");
    text.append(el("strong", "", kind.title));
    text.append(el("span", "", available ? kind.detail : "Not available: packet capture rights are missing."));
    card.append(marker, text);
    card.addEventListener("click", () => {
      state.scanKind = kind.id;
      renderScanKinds();
      updateScanForm();
    });
    container.append(card);
  }
}

function currentScanKind() {
  return SCAN_KINDS.find((kind) => kind.id === state.scanKind) || SCAN_KINDS[0];
}

function updateScanForm() {
  const kind = currentScanKind();
  $("#scan-target").closest(".field").hidden = !kind.needsTarget;
  $("#scan-profile-field").hidden = !kind.hasProfile;
  const listens = kind.needsDuration || kind.id === "sweep";
  $("#scan-duration-field").hidden = !listens;
  $("#scan-interface-field").hidden = !listens;
  const hints = [];
  if (kind.needsTarget) {
    hints.push(`Leave the range blank to use the detected ${state.vantage?.primary_target || "local subnet"}.`);
  }
  if (kind.hasProfile && state.scanProfile === "deep") {
    hints.push("Deep probes all 65,535 ports on every host and can take hours on a large range.");
  }
  if (kind.id === "scan" || kind.id === "sweep") {
    hints.push(state.capabilities.raw_packets
      ? "Raw packet access is available, so OS detection and traceroute are included."
      : "Without raw packet access this falls back to a connect scan with no OS detection.");
  }
  if (kind.needsDuration || kind.id === "sweep") {
    hints.push("Switch topology (LLDP/CDP) only travels over wired links, so a wired interface finds more.");
  }
  hints.push("Only scan networks you own or are authorized to administer.");
  $("#scan-hint").textContent = hints.join(" ");
  $("#scan-error").hidden = true;
}

function renderInterfaceOptions() {
  const select = $("#scan-interface");
  select.replaceChildren();
  const preferred = state.vantage?.capture_interface;
  const up = (state.vantage?.interfaces || []).filter((entry) => entry.state === "UP");
  const seen = new Set();
  const auto = el("option", "", preferred ? `Automatic (${preferred})` : "Automatic");
  auto.value = "";
  select.append(auto);
  for (const entry of up) {
    if (seen.has(entry.interface)) continue;
    seen.add(entry.interface);
    const option = el("option", "",
      `${entry.interface} — ${entry.address}${entry.wireless ? " (Wi-Fi)" : " (wired)"}`);
    option.value = entry.interface;
    select.append(option);
  }
}

function renderProfileOptions() {
  const select = $("#scan-profile");
  select.replaceChildren();
  for (const profile of state.profiles) {
    const option = el("option", "", profile.label);
    option.value = profile.id;
    if (profile.id === state.scanProfile) option.selected = true;
    select.append(option);
  }
}

function openScanModal() {
  $("#scan-modal").hidden = false;
  $("#scan-target").placeholder = state.vantage?.primary_target || "192.168.1.0/24";
  renderProfileOptions();
  renderInterfaceOptions();
  renderScanKinds();
  updateScanForm();
}

const closeScanModal = () => { $("#scan-modal").hidden = true; };

async function startScan() {
  const kind = currentScanKind();
  const parameters = {};
  if (kind.needsTarget) {
    const target = $("#scan-target").value.trim();
    if (target) parameters.target = target;
  }
  if (kind.hasProfile) parameters.profile = state.scanProfile;
  if (kind.needsDuration || kind.id === "sweep") {
    parameters.duration = Number($("#scan-duration").value) || 60;
    const chosen = $("#scan-interface").value;
    if (chosen) parameters.interface = chosen;
  }
  const button = $("#scan-start");
  button.disabled = true;
  try {
    const job = await post("/api/scan", { kind: kind.id, parameters });
    state.activeJob = job;
    updateLivePill(job);
    closeScanModal();
    toast(`${kind.title} started`);
  } catch (error) {
    const box = $("#scan-error");
    box.textContent = error.message;
    box.hidden = false;
  } finally {
    button.disabled = false;
  }
}

function updateLivePill(job) {
  const pill = $("#live-pill");
  const running = job && (job.status === "queued" || job.status === "running");
  pill.hidden = !running;
  if (!running) return;
  $("#live-label").textContent = (currentKindTitle(job.kind) || job.kind);
  $("#live-detail").textContent = job.detail || "";
  $("#live-bar").style.width = `${Math.max(2, job.progress || 0)}%`;
}

function currentKindTitle(id) {
  const kind = SCAN_KINDS.find((entry) => entry.id === id);
  return kind ? kind.title : id;
}

/* ---------- events ---------- */
let reloadTimer = null;
function scheduleReload() {
  window.clearTimeout(reloadTimer);
  reloadTimer = window.setTimeout(() => {
    loadData().catch((error) => toast(`Could not refresh: ${error.message}`));
  }, 500);
}

function connectEvents() {
  const source = new EventSource("/api/stream");
  source.addEventListener("job", (event) => {
    let job;
    try { job = JSON.parse(event.data); } catch { return; }
    state.activeJob = job;
    updateLivePill(job);
    const index = state.jobs.findIndex((entry) => entry.id === job.id);
    if (index >= 0) state.jobs[index] = job;
    else state.jobs.unshift(job);
    renderJobHistory();
    if (job.status === "complete") {
      const high = job.result?.summary?.high;
      toast(high
        ? `${currentKindTitle(job.kind)} finished — ${high} high-severity finding(s)`
        : `${currentKindTitle(job.kind)} finished`);
    }
    if (job.status === "failed") toast(`${currentKindTitle(job.kind)} failed: ${job.error || "unknown error"}`);
  });
  source.addEventListener("inventory", scheduleReload);
  source.addEventListener("schedule", scheduleReload);
  source.addEventListener("error", () => {
    // EventSource reconnects on its own; nothing to do but stop showing stale progress.
  });
}

/* ---------- wiring ---------- */
function switchTab(name) {
  state.tab = name;
  $$(".tab").forEach((tab) => {
    const active = tab.dataset.tab === name;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  $$(".panel-view").forEach((view) => view.classList.toggle("active", view.dataset.view === name));
}

function wire() {
  $$(".tab").forEach((tab) => tab.addEventListener("click", () => switchTab(tab.dataset.tab)));
  $$(".segment").forEach((segment) => segment.addEventListener("click", () => {
    state.layout = segment.dataset.layout;
    $$(".segment").forEach((other) => other.classList.toggle("active", other === segment));
    renderTree();
  }));
  $$(".drawer-tab").forEach((tab) => tab.addEventListener("click", () => {
    $$(".drawer-tab").forEach((other) => other.classList.toggle("active", other === tab));
    $$(".drawer-pane").forEach((pane) => pane.classList.toggle("active", pane.dataset.dpane === tab.dataset.dtab));
  }));

  $("#map-search").addEventListener("input", (event) => {
    state.mapSearch = event.target.value;
    renderTree();
  });
  $("#device-search").addEventListener("input", (event) => {
    state.deviceSearch = event.target.value;
    renderDeviceTable();
  });
  $("#port-search").addEventListener("input", (event) => {
    state.portSearch = event.target.value;
    renderPorts();
  });
  $("#risk-only").addEventListener("change", (event) => {
    state.riskOnly = event.target.checked;
    renderPorts();
  });
  $$("#device-table th.sortable").forEach((header) => header.addEventListener("click", () => {
    const key = header.dataset.sort;
    if (state.sort.key === key) state.sort.direction *= -1;
    else state.sort = { key, direction: 1 };
    renderDeviceTable();
  }));

  $("#expand-all").addEventListener("click", () => { state.collapsed.clear(); renderTree(); });
  $("#collapse-all").addEventListener("click", () => {
    state.tree.nodes.forEach((node) => { if (node.child_count) state.collapsed.add(node.id); });
    renderTree();
  });

  $("#finding-search").addEventListener("input", (event) => {
    state.findingSearch = event.target.value;
    renderFindings();
  });
  $("#show-muted").addEventListener("change", async (event) => {
    state.showMuted = event.target.checked;
    await loadData();
  });
  $("#run-audit").addEventListener("click", async () => {
    try {
      await post("/api/scan", { kind: "audit", parameters: {} });
      toast("Checking for issues…");
    } catch (error) {
      toast(error.message);
    }
  });
  $$("[data-events]").forEach((segment) => segment.addEventListener("click", () => {
    state.eventFilter = segment.dataset.events;
    $$("[data-events]").forEach((other) => other.classList.toggle("active", other === segment));
    renderEvents();
  }));
  $("#ack-events").addEventListener("click", async () => {
    try {
      await post("/api/events/acknowledge", {});
      await loadData();
      toast("Timeline marked as seen");
    } catch (error) {
      toast(error.message);
    }
  });
  $("#monitor-toggle").addEventListener("click", async () => {
    const turningOn = !state.schedule.monitoring;
    try {
      await post("/api/monitoring", { enabled: turningOn });
      await loadData();
      toast(turningOn
        ? "Monitoring on — collections run while this viewer is open"
        : "Monitoring off");
    } catch (error) {
      toast(error.message);
    }
  });

  $("#refresh").addEventListener("click", () => {
    loadData().then(() => toast("Inventory reloaded")).catch((error) => toast(error.message));
  });
  $("#open-scan").addEventListener("click", openScanModal);
  $("#scan-start").addEventListener("click", startScan);
  $("#scan-profile").addEventListener("change", (event) => {
    state.scanProfile = event.target.value;
    updateScanForm();
  });
  $$("[data-close-modal]").forEach((node) => node.addEventListener("click", closeScanModal));
  $$("[data-close-drawer]").forEach((node) => node.addEventListener("click", closeDrawer));
  $("#live-cancel").addEventListener("click", async () => {
    if (!state.activeJob) return;
    try {
      await post("/api/scan/cancel", { id: state.activeJob.id });
      toast("Stopping the scan…");
    } catch (error) {
      toast(error.message);
    }
  });

  $$("[data-approved]").forEach((button) => button.addEventListener("click", () => {
    $$("[data-approved]").forEach((other) => other.classList.toggle("active", other === button));
  }));

  $("#edit-save").addEventListener("click", async () => {
    const device = state.devicesById.get(state.selectedId);
    if (!device) return;
    const selected = $$("[data-approved]").find((button) => button.classList.contains("active"));
    const approvedRaw = selected ? selected.dataset.approved : "";
    try {
      await post("/api/label", {
        selector: String(device.id),
        name: $("#edit-name").value.trim(),
        type: $("#edit-type").value,
      });
      await post("/api/device", {
        selector: String(device.id),
        owner: $("#edit-owner").value.trim(),
        location: $("#edit-location").value.trim(),
        notes: $("#edit-notes").value.trim(),
        approved: approvedRaw === "" ? null : approvedRaw === "1",
      });
      const status = $("#edit-status");
      status.textContent = "Saved.";
      status.hidden = false;
      toast("Device updated");
      await loadData();
    } catch (error) {
      toast(`Could not save: ${error.message}`);
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    if (!$("#scan-modal").hidden) closeScanModal();
    else if (!$("#drawer").hidden) closeDrawer();
  });
}

/* ---------- boot ---------- */
async function boot() {
  initTheme();
  wire();
  try {
    await loadSession();
    await loadData();
    connectEvents();
    const running = state.jobs.find((job) => job.status === "running" || job.status === "queued");
    if (running) { state.activeJob = running; updateLivePill(running); }
    if (!state.summary.online) {
      toast("No devices yet — run a scan to map your network");
    }
  } catch (error) {
    toast(`Could not load: ${error.message}`);
  }
}

boot();
