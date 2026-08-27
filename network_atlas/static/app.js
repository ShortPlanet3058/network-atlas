"use strict";

const SVG_NS = "http://www.w3.org/2000/svg";
const TYPES = {
  unknown:       { icon: "?", color: "#71868c", label: "Unknown" },
  computer:      { icon: "▣", color: "#55c8ff", label: "Computers" },
  phone:         { icon: "▯", color: "#c18cff", label: "Phones" },
  server:        { icon: "▤", color: "#67e8a5", label: "Servers" },
  printer:       { icon: "▰", color: "#f6bd60", label: "Printers" },
  router:        { icon: "◆", color: "#ff8b70", label: "Routers" },
  switch:        { icon: "⇄", color: "#58f5c4", label: "Switches" },
  "access-point": { icon: "⌁", color: "#4ce1e6", label: "Access points" },
  firewall:      { icon: "⬢", color: "#ff6b7f", label: "Firewalls" },
  "network-device": { icon: "◇", color: "#58f5c4", label: "Network devices" },
  storage:       { icon: "▥", color: "#98d57d", label: "Storage" },
  media:         { icon: "▶", color: "#f29fd4", label: "Media" },
  camera:        { icon: "◉", color: "#ff9b67", label: "Cameras" },
  "game-console": { icon: "✣", color: "#b9a1ff", label: "Game consoles" },
  iot:           { icon: "✦", color: "#d9ce6a", label: "IoT" },
  subnet:        { icon: "⌘", color: "#668b94", label: "Subnets" }
};

const state = {
  graph: { nodes: [], edges: [] }, summary: null, scans: [], selected: null,
  activeTypes: new Set(), activeEdges: new Set(["lldp", "switch-port", "route", "membership"]),
  search: "", positions: new Map(), scale: 1, tx: 0, ty: 0, simulation: null
};

const $ = selector => document.querySelector(selector);
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
};
const svgEl = (tag, attrs = {}) => {
  const node = document.createElementNS(SVG_NS, tag);
  Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, String(value)));
  return node;
};
const typeMeta = type => TYPES[type] || TYPES.unknown;
const formatTime = value => value ? new Date(value).toLocaleString() : "Never";
const showToast = message => {
  const toast = $("#toast"); toast.textContent = message; toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 3500);
};

async function request(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

async function load() {
  $("#scan-status").textContent = "Refreshing inventory…";
  try {
    const [summary, graph, scans] = await Promise.all([
      request("/api/summary"), request("/api/graph"), request("/api/scans?limit=12")
    ]);
    state.summary = summary; state.graph = graph; state.scans = scans;
    $("#state-dot").className = "ready";
    $("#scan-status").textContent = summary.last_scan
      ? `Last collection ${formatTime(summary.last_scan.finished_at || summary.last_scan.started_at)}`
      : "Database ready — no collections yet";
    renderSummary(); renderFilters(); initializePositions(); renderGraph(); renderScans();
    if (state.selected) selectDevice(state.selected.id);
  } catch (error) {
    $("#state-dot").className = "error"; $("#scan-status").textContent = "Viewer could not load data";
    showToast(`Unable to load inventory: ${error.message}`);
  }
}

function renderSummary() {
  $("#metric-devices").textContent = state.summary.devices;
  $("#metric-online").textContent = state.summary.online;
  $("#metric-services").textContent = state.summary.services;
  $("#metric-links").textContent = state.summary.links;
  const unknown = state.summary.types?.unknown || 0;
  const classified = state.summary.devices ? Math.round((state.summary.devices - unknown) / state.summary.devices * 100) : 0;
  $("#metric-classified").textContent = `${classified}%`;
}

function renderFilters() {
  const container = $("#type-filters"); container.replaceChildren();
  const counts = state.summary.types || {};
  Object.entries(counts).sort((a, b) => b[1] - a[1]).forEach(([type, count]) => {
    const meta = typeMeta(type); const button = el("button", "type-button active");
    button.dataset.type = type; button.style.setProperty("--type-color", meta.color);
    button.append(el("i"), el("span", "", meta.label), el("b", "", count));
    if (!state.activeTypes.size || state.activeTypes.has(type)) button.classList.add("active");
    else button.classList.remove("active");
    button.addEventListener("click", () => {
      if (!state.activeTypes.size) Object.keys(counts).forEach(value => state.activeTypes.add(value));
      state.activeTypes.has(type) ? state.activeTypes.delete(type) : state.activeTypes.add(type);
      if (state.activeTypes.size === Object.keys(counts).length) state.activeTypes.clear();
      renderFilters(); renderGraph(false);
    });
    container.append(button);
  });
}

function filteredRealNodes() {
  const query = state.search.trim().toLowerCase();
  return state.graph.nodes.filter(node => {
    const typeAllowed = !state.activeTypes.size || state.activeTypes.has(node.effective_type);
    const haystack = [node.display_name, node.hostname, node.mac, node.vendor, node.os_name, ...(node.addresses || [])]
      .filter(Boolean).join(" ").toLowerCase();
    return typeAllowed && (!query || haystack.includes(query));
  });
}

function subnetFor(node) {
  const ipv4 = (node.addresses || []).find(address => /^\d+\.\d+\.\d+\.\d+$/.test(address));
  if (!ipv4) return null;
  const parts = ipv4.split(".");
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function subnetId(name) {
  let hash = 0;
  for (const character of name) hash = ((hash << 5) - hash + character.charCodeAt(0)) | 0;
  return -1000000 - Math.abs(hash);
}

function filteredGraph() {
  const nodes = filteredRealNodes();
  const ids = new Set(nodes.map(node => node.id));
  const edges = state.graph.edges.filter(edge => ids.has(edge.source_device_id)
    && ids.has(edge.target_device_id) && state.activeEdges.has(edge.edge_type));
  if (state.activeEdges.has("membership")) {
    const groups = new Map();
    nodes.forEach(node => {
      const subnet = subnetFor(node); if (!subnet) return;
      if (!groups.has(subnet)) groups.set(subnet, []); groups.get(subnet).push(node);
    });
    groups.forEach((members, subnet) => {
      if (members.length < 2) return;
      const id = subnetId(subnet);
      nodes.push({ id, display_name: subnet, effective_type: "subnet", status: "online", confidence: 1, addresses: [], virtual: true });
      members.forEach(member => edges.push({
        id: `membership-${id}-${member.id}`, source_device_id: id, target_device_id: member.id,
        edge_type: "membership", confidence: .35, evidence: "Shared IPv4 /24 segment"
      }));
    });
  }
  return { nodes, edges };
}

function initializePositions(force = false) {
  const svg = $("#network-map"); const width = svg.clientWidth || 700; const height = svg.clientHeight || 600;
  if (force) state.positions.clear();
  const displayNodes = filteredGraph().nodes;
  const count = Math.max(displayNodes.length, 1);
  displayNodes.forEach((node, index) => {
    if (!state.positions.has(node.id)) {
      const angle = index * Math.PI * (3 - Math.sqrt(5));
      const radius = node.virtual ? 0 : 45 + Math.sqrt(index / count) * Math.min(width, height) * .36;
      state.positions.set(node.id, { x: width / 2 + Math.cos(angle) * radius, y: height / 2 + Math.sin(angle) * radius, vx: 0, vy: 0, fixed: false });
    }
  });
}

function renderGraph(simulate = true) {
  const { nodes, edges } = filteredGraph();
  nodes.forEach(node => {
    if (!state.positions.has(node.id)) initializePositions(false);
  });
  const realNodeCount = nodes.filter(node => !node.virtual).length;
  $("#visible-count").textContent = realNodeCount; $("#empty-map").hidden = realNodeCount !== 0;
  const edgeLayer = $("#edges"), edgeLabels = $("#edge-labels"), nodeLayer = $("#nodes"); edgeLayer.replaceChildren(); edgeLabels.replaceChildren(); nodeLayer.replaceChildren();
  const selectedId = state.selected?.id;
  const connectedIds = new Set();
  if (selectedId) edges.forEach(edge => {
    if (edge.source_device_id === selectedId) connectedIds.add(edge.target_device_id);
    if (edge.target_device_id === selectedId) connectedIds.add(edge.source_device_id);
  });
  edges.forEach(edge => {
    const connected = selectedId && (edge.source_device_id === selectedId || edge.target_device_id === selectedId);
    const dimmed = selectedId && !connected;
    const line = svgEl("line", { class: `edge ${edge.edge_type}${connected ? " connected" : ""}${dimmed ? " dimmed" : ""}`, "data-source": edge.source_device_id, "data-target": edge.target_device_id });
    const title = svgEl("title"); title.textContent = [edge.edge_type, edge.source_port, edge.target_port, edge.evidence].filter(Boolean).join(" · ");
    line.append(title); edgeLayer.append(line);
    const portLabel = edge.source_port || edge.target_port;
    if (portLabel && edge.edge_type !== "membership") {
      const labelText = String(portLabel).slice(0, 22), width = Math.max(28, labelText.length * 4.5 + 8);
      const group = svgEl("g", { class: "edge-label", "data-source": edge.source_device_id, "data-target": edge.target_device_id });
      group.append(svgEl("rect", { x: -width / 2, y: -6, width, height: 12 }), svgEl("text", { y: 0 }));
      group.querySelector("text").textContent = labelText; edgeLabels.append(group);
    }
  });
  nodes.forEach(node => {
    const meta = typeMeta(node.effective_type);
    const dimmed = selectedId && node.id !== selectedId && !connectedIds.has(node.id);
    const group = svgEl("g", { class: `node ${node.status}${node.virtual ? " virtual" : ""}${state.selected?.id === node.id ? " selected" : ""}${dimmed ? " dimmed" : ""}`, "data-id": node.id });
    group.style.setProperty("--node-color", meta.color);
    const radius = node.virtual ? 21 : 17;
    group.append(svgEl("circle", { class: "halo", r: radius + 7 }), svgEl("circle", { class: "body", r: radius }));
    if (!node.virtual) {
      const confidence = Math.max(0, Math.min(100, (node.confidence || 0) * 100));
      group.append(svgEl("circle", { class: "confidence-ring", r: radius + 4, pathLength: 100, "stroke-dasharray": `${confidence} 100` }), svgEl("circle", { class: "status-dot", cx: 13, cy: -13, r: 4 }));
    }
    const icon = svgEl("text", { class: "icon", y: 0 }); icon.textContent = meta.icon;
    const labelText = String(node.display_name).slice(0, 30), labelWidth = Math.min(154, Math.max(48, labelText.length * 5.3 + 12));
    const labelBg = svgEl("rect", { class: "label-bg", x: -labelWidth / 2, y: 23, width: labelWidth, height: 17, rx: 5 });
    const label = svgEl("text", { class: "label", y: 34 }); label.textContent = labelText;
    const sub = svgEl("text", { class: "sub", y: 48 }); sub.textContent = node.virtual ? "logical segment" : (node.addresses || [])[0] || node.mac || "unaddressed";
    group.append(icon, labelBg, label, sub);
    if (!node.virtual) group.addEventListener("click", event => { event.stopPropagation(); selectDevice(node.id); });
    installNodeDrag(group, node.id); nodeLayer.append(group);
  });
  updatePositions(); renderDeviceList();
  if (simulate) startSimulation(nodes, edges);
}

function updatePositions() {
  document.querySelectorAll("#nodes .node").forEach(node => {
    const point = state.positions.get(Number(node.dataset.id)); if (point) node.setAttribute("transform", `translate(${point.x} ${point.y})`);
  });
  document.querySelectorAll("#edges .edge").forEach(edge => {
    const a = state.positions.get(Number(edge.dataset.source)); const b = state.positions.get(Number(edge.dataset.target));
    if (a && b) { edge.setAttribute("x1", a.x); edge.setAttribute("y1", a.y); edge.setAttribute("x2", b.x); edge.setAttribute("y2", b.y); }
  });
  document.querySelectorAll("#edge-labels .edge-label").forEach(label => {
    const a = state.positions.get(Number(label.dataset.source)); const b = state.positions.get(Number(label.dataset.target));
    if (a && b) label.setAttribute("transform", `translate(${(a.x + b.x) / 2} ${(a.y + b.y) / 2})`);
  });
}

function startSimulation(nodes, edges) {
  if (state.simulation) cancelAnimationFrame(state.simulation);
  const nodeMap = new Map(nodes.map(node => [node.id, state.positions.get(node.id)]));
  let frame = 0; const svg = $("#network-map"), width = svg.clientWidth, height = svg.clientHeight;
  const tick = () => {
    frame += 1; const cooling = Math.max(.03, 1 - frame / 260);
    const points = [...nodeMap.values()];
    if (points.length < 260) {
      for (let i = 0; i < points.length; i++) for (let j = i + 1; j < points.length; j++) {
        const a = points[i], b = points[j]; let dx = a.x - b.x, dy = a.y - b.y;
        const distance2 = Math.max(dx * dx + dy * dy, 90); const force = 650 * cooling / distance2;
        const length = Math.sqrt(distance2); dx /= length; dy /= length;
        if (!a.fixed) { a.vx += dx * force; a.vy += dy * force; }
        if (!b.fixed) { b.vx -= dx * force; b.vy -= dy * force; }
      }
    }
    edges.forEach(edge => {
      const a = nodeMap.get(edge.source_device_id), b = nodeMap.get(edge.target_device_id); if (!a || !b) return;
      let dx = b.x - a.x, dy = b.y - a.y; const length = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
      const target = edge.edge_type === "route" ? 135 : edge.edge_type === "membership" ? 125 : 100; const force = (length - target) * .0025 * cooling;
      dx /= length; dy /= length;
      if (!a.fixed) { a.vx += dx * force; a.vy += dy * force; }
      if (!b.fixed) { b.vx -= dx * force; b.vy -= dy * force; }
    });
    points.forEach(point => {
      if (point.fixed) return;
      point.vx += (width / 2 - point.x) * .00035 * cooling; point.vy += (height / 2 - point.y) * .00035 * cooling;
      point.vx *= .84; point.vy *= .84; point.x += point.vx; point.y += point.vy;
    });
    updatePositions();
    if (frame < 260) state.simulation = requestAnimationFrame(tick);
  };
  state.simulation = requestAnimationFrame(tick);
}

function selectDevice(id) {
  const device = state.graph.nodes.find(node => node.id === id); if (!device) return;
  state.selected = device; document.querySelectorAll(".node").forEach(node => node.classList.toggle("selected", Number(node.dataset.id) === id));
  renderGraph(false);
  $("#detail-empty").hidden = true; $("#detail-content").hidden = false;
  const meta = typeMeta(device.effective_type); $("#detail-icon").textContent = meta.icon; $("#detail-icon").style.setProperty("--detail-color", meta.color);
  $("#detail-type").textContent = meta.label.replace(/s$/, ""); $("#detail-name").textContent = device.display_name; $("#detail-status").textContent = device.status;
  const identity = $("#identity"); identity.replaceChildren();
  [["Addresses", (device.addresses || []).join(", ") || "—"], ["MAC", device.mac || "—"], ["Vendor", device.vendor || "—"], ["Operating system", device.os_name || "—"], ["First seen", formatTime(device.first_seen)], ["Last seen", formatTime(device.last_seen)]].forEach(([term, value]) => identity.append(el("dt", "", term), el("dd", "", value)));
  const confidence = Math.round((device.confidence || 0) * 100); $("#confidence-label").textContent = `${confidence}%`; $("#confidence-bar").style.width = `${confidence}%`;
  let metadata = {}; try { metadata = JSON.parse(device.metadata_json || "{}"); } catch (_) { metadata = {}; }
  const reasons = $("#reasons"); reasons.replaceChildren(); (metadata.classification_reasons || ["No classification evidence yet"]).forEach(reason => reasons.append(el("li", "", reason)));
  const services = $("#services"); services.replaceChildren();
  if (!device.services?.length) services.append(el("span", "empty-list", "No open services recorded"));
  else device.services.forEach(service => { const item = el("div", "service"); item.append(el("code", "", `${service.port}/${service.protocol}`), el("span", "", [service.name, service.product, service.version].filter(Boolean).join(" · ") || "Unknown service")); services.append(item); });
  const evidence = $("#evidence"); evidence.replaceChildren();
  if (!device.evidence?.length) evidence.append(el("span", "empty-list", "No detailed observations recorded"));
  else device.evidence.forEach(observation => { const item = el("div", "evidence-item"); item.append(el("b", "", `${observation.source} · ${observation.key}`), el("span", "", observation.value)); evidence.append(item); });
}

function renderDeviceList() {
  const container = $("#device-list"); container.replaceChildren();
  const nodes = filteredRealNodes(); $("#list-count").textContent = nodes.length;
  nodes.sort((a, b) => String(a.display_name).localeCompare(String(b.display_name))).forEach(node => {
    const meta = typeMeta(node.effective_type), row = el("button", `device-row${state.selected?.id === node.id ? " active" : ""}`);
    row.style.setProperty("--row-color", meta.color);
    const icon = el("span", "device-row-icon", meta.icon), main = el("span", "device-row-main");
    main.append(el("strong", "", node.display_name), el("small", "", (node.addresses || [])[0] || node.mac || meta.label));
    row.append(icon, main, el("i", `device-row-status ${node.status}`));
    row.addEventListener("click", () => focusDevice(node.id)); container.append(row);
  });
}

function focusDevice(id) {
  selectDevice(id); const point = state.positions.get(id), svg = $("#network-map"); if (!point) return;
  state.scale = Math.max(state.scale, 1.15); state.tx = svg.clientWidth / 2 - point.x * state.scale; state.ty = svg.clientHeight / 2 - point.y * state.scale; applyView();
}

function renderScans() {
  const container = $("#scan-list"); container.replaceChildren();
  if (!state.scans.length) { container.append(el("span", "empty-list", "No collection history yet")); return; }
  state.scans.forEach(scan => { const item = el("article", "scan"), top = el("div"); top.append(el("strong", scan.status, scan.source), el("span", "", formatTime(scan.finished_at || scan.started_at))); item.append(top, el("p", "", scan.target || "Local broadcast domain")); container.append(item); });
}

function installNodeDrag(group, id) {
  group.addEventListener("pointerdown", event => {
    event.stopPropagation(); group.setPointerCapture(event.pointerId); const point = state.positions.get(id); point.fixed = true;
    const start = screenToGraph(event.clientX, event.clientY);
    const offset = { x: point.x - start.x, y: point.y - start.y };
    const move = moveEvent => { const current = screenToGraph(moveEvent.clientX, moveEvent.clientY); point.x = current.x + offset.x; point.y = current.y + offset.y; updatePositions(); };
    const up = () => { group.removeEventListener("pointermove", move); group.removeEventListener("pointerup", up); group.removeEventListener("pointercancel", up); };
    group.addEventListener("pointermove", move); group.addEventListener("pointerup", up); group.addEventListener("pointercancel", up);
  });
}

function screenToGraph(clientX, clientY) { const rect = $("#network-map").getBoundingClientRect(); return { x: (clientX - rect.left - state.tx) / state.scale, y: (clientY - rect.top - state.ty) / state.scale }; }
function applyView() { $("#viewport").setAttribute("transform", `translate(${state.tx} ${state.ty}) scale(${state.scale})`); }
function fitMap() {
  const { nodes } = filteredGraph(); if (!nodes.length) return; const svg = $("#network-map"), points = nodes.map(node => state.positions.get(node.id));
  const minX = Math.min(...points.map(p => p.x)) - 60, maxX = Math.max(...points.map(p => p.x)) + 60, minY = Math.min(...points.map(p => p.y)) - 60, maxY = Math.max(...points.map(p => p.y)) + 60;
  state.scale = Math.min(2, Math.max(.2, Math.min(svg.clientWidth / Math.max(maxX - minX, 1), svg.clientHeight / Math.max(maxY - minY, 1))));
  state.tx = (svg.clientWidth - (minX + maxX) * state.scale) / 2; state.ty = (svg.clientHeight - (minY + maxY) * state.scale) / 2; applyView();
}

function installMapControls() {
  const svg = $("#network-map"); let pan = null;
  svg.addEventListener("wheel", event => { event.preventDefault(); const rect = svg.getBoundingClientRect(), x = event.clientX - rect.left, y = event.clientY - rect.top, old = state.scale; state.scale = Math.min(3, Math.max(.18, state.scale * Math.exp(-event.deltaY * .001))); state.tx = x - (x - state.tx) * state.scale / old; state.ty = y - (y - state.ty) * state.scale / old; applyView(); }, { passive: false });
  svg.addEventListener("pointerdown", event => { if (event.target.closest(".node")) return; pan = { x: event.clientX - state.tx, y: event.clientY - state.ty }; svg.setPointerCapture(event.pointerId); svg.classList.add("dragging"); });
  svg.addEventListener("pointermove", event => { if (!pan) return; state.tx = event.clientX - pan.x; state.ty = event.clientY - pan.y; applyView(); });
  const end = () => { pan = null; svg.classList.remove("dragging"); }; svg.addEventListener("pointerup", end); svg.addEventListener("pointercancel", end);
}

$("#search").addEventListener("input", event => { state.search = event.target.value; initializePositions(false); renderGraph(false); });
$("#clear-filters").addEventListener("click", () => { state.activeTypes.clear(); state.search = ""; $("#search").value = ""; renderFilters(); renderGraph(false); });
document.querySelectorAll("[data-edge]").forEach(box => box.addEventListener("change", () => { box.checked ? state.activeEdges.add(box.dataset.edge) : state.activeEdges.delete(box.dataset.edge); renderGraph(false); }));
$("#refresh").addEventListener("click", load); $("#fit-map").addEventListener("click", fitMap);
$("#zoom-in").addEventListener("click", () => { state.scale = Math.min(3, state.scale * 1.2); applyView(); });
$("#zoom-out").addEventListener("click", () => { state.scale = Math.max(.18, state.scale / 1.2); applyView(); });
$("#relayout").addEventListener("click", () => { initializePositions(true); renderGraph(true); window.setTimeout(fitMap, 700); });
installMapControls(); load().then(() => window.setTimeout(fitMap, 800));
